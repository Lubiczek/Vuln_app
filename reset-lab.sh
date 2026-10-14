#!/usr/bin/env bash
# Return the simulator to its known-good starting state between exercises.
set -euo pipefail
cd "$(dirname "$0")"
./stop-sim.sh || true
cp policy.baseline.json policy.json          # undo every policy edit
: > signin-log.jsonl                         # empty the simulated sign-in log
./start-sim.sh "${1:-127.0.0.1}"
echo "[+] Lab reset. Remember to delete *-accessible.txt files and clear any saved tokens on the attacker VM."
