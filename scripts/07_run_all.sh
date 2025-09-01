#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Assumes 01_ttp_setup.sh has already run and .runtime.env is present
if [ ! -f .runtime.env ]; then
  echo "[runner] .runtime.env missing; run 01_ttp_setup.sh first" >&2
  exit 1
fi

set -a; source .runtime.env; set +a



METRICS_FILE_BASE=${METRICS_FILE_BASE:-metrics/results}

if ! command -v gnome-terminal >/dev/null 2>&1; then
  echo "[runner] gnome-terminal is required for this script (no background fallback)." >&2
  exit 1
fi

launch_cmd() {
  local title="$1"; shift
  local cmd="$*"
  gnome-terminal --title="$title" -- bash -lc "$cmd; exec bash" &
}

# No env overrides here; rely on .runtime.env and caller's shell

# 02 issuers
launch_cmd "issuers" "cd scripts/.. && bash scripts/02_start_issuers.sh"

# 03 opener aggregator
launch_cmd "aggregator" "cd scripts/.. && bash scripts/03_start_opener_aggregator.sh"

# 04 threshold openers
launch_cmd "openers" "cd scripts/.. && bash scripts/04_start_threshold_openers.sh"

# 05 client (user)
launch_cmd "client" "cd scripts/.. && bash scripts/05_run_user.sh"

# 06 service provider (auto open/revoke)
launch_cmd "service_provider" "cd scripts/.. && bash scripts/06_run_service_provider.sh"

echo "[runner] launched processes in gnome-terminal windows. To stop: pkill -f cargo; pkill -f node; pkill -f hardhat"
wait


