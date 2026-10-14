# FindMeAccess offline lab kit (fma_sim)

Teaching simulator for the FindMeAccess identity-security lab. It imitates the Microsoft Entra ID
token endpoint that FindMeAccess talks to, using the editable model tenant in `policy.json`.
It is a simplified model, not Microsoft Entra ID. Confirm lessons on a real test tenant when you can.

Tested with FindMeAccess v3.3.0 (commit d14cf1b), mitmproxy 12.2.3, Ubuntu 24.04, Python 3.12.

| File | Purpose |
| --- | --- |
| fma_sim.py | mitmproxy add-on: answers token requests, writes signin-log.jsonl, blocks all other traffic |
| policy.json | The model tenant students edit (users, groups, policies) |
| policy.baseline.json | Known-good copy used by reset-lab.sh |
| start-sim.sh / stop-sim.sh | Start or stop the simulator (default 127.0.0.1:8080; pass 10.10.10.20 for the two-VM layout) |
| reset-lab.sh | Restore policy.json, empty the log, restart the simulator |
| audit-small.conf | Small FindMeAccess --config file (3 resources x 2 clients x 2 user agents) |

Quick start (after installing FindMeAccess and mitmproxy with pipx):

    ./start-sim.sh
    findmeaccess audit -u lab-s1-nomfa@lab.example -r "Microsoft Graph API" -c "Microsoft Office" --proxy http://127.0.0.1:8080

Every password in policy.json is a test-only value for this offline model. Never reuse them anywhere.
