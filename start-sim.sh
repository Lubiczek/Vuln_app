#!/usr/bin/env bash
# Start the offline FindMeAccess simulator.
# Usage: ./start-sim.sh [listen-address]   (default 127.0.0.1; use 10.10.10.20 on the two-VM layout)
# connection_strategy=lazy + upstream_cert=false: mitmproxy never opens a connection to the real login servers.
set -euo pipefail
cd "$(dirname "$0")"
LISTEN="${1:-127.0.0.1}"
mitmdump -q -s fma_sim.py --listen-host "$LISTEN" --listen-port 8080 \
  --set connection_strategy=lazy --set upstream_cert=false > sim-console.log 2>&1 &
echo $! > sim.pid
sleep 3
if kill -0 "$(cat sim.pid)" 2>/dev/null; then
  echo "[+] fma_sim listening on ${LISTEN}:8080 (pid $(cat sim.pid))"
else
  echo "[!] fma_sim failed to start - see sim-console.log"; exit 1
fi
