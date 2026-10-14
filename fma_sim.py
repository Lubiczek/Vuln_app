"""
fma_sim.py - offline teaching simulator for FindMeAccess labs.

A mitmproxy addon that answers Microsoft Entra ID token requests locally,
using a simplified, editable "tenant" in policy.json. Nothing is forwarded
to the internet: every request the proxy sees gets a local answer.

THIS IS A TEACHING MODEL, NOT MICROSOFT ENTRA ID. Error codes are chosen to
match what FindMeAccess parses; real Conditional Access evaluation is far
richer. Use it to practise the workflow, then confirm on a real test tenant.

Run:  mitmdump -s fma_sim.py --listen-host 127.0.0.1 --listen-port 8080
Use:  findmeaccess audit -u alice@lab.example -p '...' --proxy http://127.0.0.1:8080
"""
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

from mitmproxy import http

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "policy.json"
LOG_FILE = HERE / "signin-log.jsonl"
FAKE_TENANT_ID = "00000000-1ab0-4000-8000-000000000001"
LOGIN_HOSTS = {"login.microsoft.com", "login.microsoftonline.com"}

_failures = {}      # upn -> [count, locked_until]
_refresh = {}       # refresh token -> upn


def load_policy():
    # Re-read on every request so students can edit and re-run immediately.
    return json.loads(POLICY_FILE.read_text())


def platform_from_ua(ua):
    # Mirrors the idea (not the code) of Entra: the platform is read from the
    # User-Agent header, which the client controls.
    if "Windows Phone" in ua or "CrOS" in ua:
        return "unknown"
    if "Android" in ua:
        return "android"
    if "iPhone" in ua or "iPad" in ua:
        return "iOS"
    if "Windows NT" in ua:
        return "windows"
    if "Macintosh" in ua:
        return "macOS"
    if "Linux" in ua or "X11" in ua:
        return "linux"
    return "unknown"


def matches(value, include, exclude):
    inc = include or ["all"]
    if "all" not in inc and value not in inc:
        return False
    return value not in (exclude or [])


def user_in_scope(user, pol):
    groups = set(user.get("groups", []))
    inc = pol.get("include_groups", ["all"])
    exc = set(pol.get("exclude_groups", []))
    if groups & exc:
        return False
    return "all" in inc or bool(groups & set(inc))


def evaluate(tenant, user, resource, platform):
    """Return (decision, per-policy results). decision: allow|mfa|block|compliant."""
    results, enforced = [], []
    sd = tenant.get("security_defaults", False)
    # Security defaults and Conditional Access are mutually exclusive in Entra.
    for pol in ([] if sd else tenant.get("policies", [])):
        state = pol.get("state", "off")
        if state == "off":
            continue
        applies = (
            user_in_scope(user, pol)
            and matches(resource, pol.get("include_resources"), pol.get("exclude_resources"))
            and matches(platform, pol.get("include_platforms"), pol.get("exclude_platforms"))
            and matches("mobileAppsAndDesktopClients", pol.get("client_app_types"), [])
        )
        grant = pol.get("grant", "mfa")
        if not applies:
            results.append({"policy": pol["name"], "state": state, "result": "notApplied"})
        elif state == "reportOnly":
            results.append({"policy": pol["name"], "state": state, "result": "reportOnlyFailure", "grant": grant})
        else:
            results.append({"policy": pol["name"], "state": state, "result": "failure", "grant": grant})
            enforced.append(grant)
    for g in ("block", "compliant", "mfa"):
        if g in enforced:
            # A user with no MFA method can't satisfy MFA: Entra asks them to register first.
            if g == "mfa" and not user.get("mfa_registered", False):
                return "register", results
            return g, results
    if sd and not user.get("mfa_registered", False):
        return "register", results
    if sd and resource in tenant.get("security_defaults_mfa_resources", []):
        return "mfa", results
    return "allow", results


def aad_error(code, text, status=400):
    body = {"error": "invalid_grant", "error_description": f"{code}: {text} [SIMULATED]",
            "error_codes": [int(code[6:])]}
    return status, body


def log(entry):
    entry["createdDateTime"] = datetime.now(timezone.utc).isoformat()
    with LOG_FILE.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def password_grant(form, ua):
    tenant = load_policy()
    upn = form.get("username", [""])[0].lower()
    pw = form.get("password", [""])[0]
    resource = form.get("resource", [""])[0]
    client_id = form.get("client_id", [""])[0]
    platform = platform_from_ua(ua)
    base = {"userPrincipalName": upn, "appId": client_id, "resource": resource,
            "userAgent": ua, "devicePlatform": platform, "authenticationProtocol": "ropc",
            "clientAppUsed": "Mobile Apps and Desktop clients"}
    users = {u["upn"].lower(): u for u in tenant.get("users", [])}
    user = users.get(upn)
    if not pw:
        status, body = aad_error("AADSTS900144", "The request body must contain the parameter 'password'.")
    elif user is None:
        status, body = aad_error("AADSTS50034", "The user account does not exist in the directory.")
    elif not user.get("enabled", True):
        status, body = aad_error("AADSTS50057", "The user account is disabled.")
    else:
        cnt, until = _failures.get(upn, [0, 0])
        threshold = tenant.get("lockout_threshold", 10)
        if until > time.time():
            status, body = aad_error("AADSTS50053", "The account is locked.")
        elif pw != user["password"]:
            cnt += 1
            _failures[upn] = [cnt, time.time() + tenant.get("lockout_seconds", 60) if cnt >= threshold else 0]
            status, body = aad_error("AADSTS50126", "Error validating credentials due to invalid username or password.")
        else:
            _failures[upn] = [0, 0]
            decision, results = evaluate(tenant, user, resource, platform)
            base["appliedConditionalAccessPolicies"] = results
            if decision == "block":
                status, body = aad_error("AADSTS53003", "Access has been blocked by Conditional Access policies.")
            elif decision == "compliant":
                status, body = aad_error("AADSTS53000", "Device is not in required device state: compliant.")
            elif decision == "mfa":
                status, body = aad_error("AADSTS50076", "Due to a configuration change made by your administrator, you must use multi-factor authentication.")
            elif decision == "register":
                status, body = aad_error("AADSTS50079", "The user is required to use multi-factor authentication (registration required).")
            else:
                rt = "SIMULATED-RT-" + uuid.uuid4().hex
                _refresh[rt] = upn
                status, body = 200, {
                    "token_type": "Bearer", "scope": "SIMULATED-scope-not-modelled",
                    "expires_in": "3599", "resource": resource,
                    "access_token": "SIMULATED-AT-" + uuid.uuid4().hex,
                    "refresh_token": rt, "id_token": "SIMULATED-IDT-" + uuid.uuid4().hex}
    base["status"] = "success" if status == 200 else body["error_description"].split(":")[0]
    log(base)
    return status, body


def refresh_grant(form, ua):
    tenant = load_policy()
    rt = form.get("refresh_token", [""])[0]
    upn = _refresh.get(rt)
    revoked = {u.lower() for u in tenant.get("revoked_sessions", [])}
    users = {u["upn"].lower(): u for u in tenant.get("users", [])}
    scope = form.get("scope", [""])[0]
    resource = scope.split("/.default")[0] if "/.default" in scope else scope
    decision = "allow"
    if upn in users:
        # Conditional Access is evaluated again when a refresh token is redeemed.
        decision, _ = evaluate(tenant, users[upn], resource, platform_from_ua(ua))
    if upn is None or upn in revoked:
        status, body = aad_error("AADSTS50173", "The provided grant has expired due to it being revoked.")
    elif decision in ("mfa", "register"):
        status, body = aad_error("AADSTS50076", "Due to a configuration change made by your administrator, you must use multi-factor authentication.")
    elif decision == "block":
        status, body = aad_error("AADSTS53003", "Access has been blocked by Conditional Access policies.")
    elif decision == "compliant":
        status, body = aad_error("AADSTS53000", "Device is not in required device state: compliant.")
    else:
        status, body = 200, {"token_type": "Bearer", "scope": form.get("scope", [""])[0],
                             "expires_in": "3599", "access_token": "SIMULATED-AT-" + uuid.uuid4().hex}
    log({"userPrincipalName": upn, "appId": form.get("client_id", [""])[0],
         "authenticationProtocol": "refreshToken (non-interactive)", "userAgent": ua,
         "resource": resource, "status": "success" if status == 200 else body["error_description"].split(":")[0]})
    return status, body


def request(flow: http.HTTPFlow) -> None:
    try:
        handle(flow)
    except Exception as exc:  # fail closed: never let a request through to the internet
        body = {"error": "simulator_error",
                "error_description": f"fma_sim error (check policy.json with: jq . policy.json): {exc}"}
        flow.response = http.Response.make(500, json.dumps(body), {"Content-Type": "application/json"})


def handle(flow: http.HTTPFlow) -> None:
    host, path = flow.request.pretty_host, flow.request.path
    ua = flow.request.headers.get("User-Agent", "")
    if host not in LOGIN_HOSTS:
        # Fail closed: the simulator never forwards anything to the internet.
        flow.response = http.Response.make(403, b"Blocked by fma_sim (lab is offline)")
        return
    if flow.request.method == "GET" and path.endswith("/.well-known/openid-configuration"):
        body = {"authorization_endpoint": f"https://login.microsoftonline.com/{FAKE_TENANT_ID}/oauth2/authorize"}
        flow.response = http.Response.make(200, json.dumps(body), {"Content-Type": "application/json"})
        return
    if flow.request.method == "POST" and re.search(r"/oauth2/(v2\.0/)?token$", path):
        form = parse_qs(flow.request.get_text() or "")
        grant = form.get("grant_type", [""])[0]
        if grant == "password":
            status, body = password_grant(form, ua)
        elif grant == "refresh_token":
            status, body = refresh_grant(form, ua)
        else:
            status, body = aad_error("AADSTS70003", "Grant type not supported by the simulator.")
        flow.response = http.Response.make(status, json.dumps(body), {"Content-Type": "application/json"})
        return
    flow.response = http.Response.make(404, b"Not modelled by fma_sim")
