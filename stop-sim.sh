#!/usr/bin/env bash
# Stop the simulator started by start-sim.sh (clears in-memory refresh tokens and lockout counters).
cd "$(dirname "$0")"
[ -f sim.pid ] && kill "$(cat sim.pid)" 2>/dev/null && echo "[+] fma_sim stopped"
rm -f sim.pid
