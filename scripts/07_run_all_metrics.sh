#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Assumes 01_ttp_setup.sh has already run and .runtime.env is present
if [ ! -f .runtime.env ]; then
  echo "[runner] .runtime.env missing; run 01_ttp_setup.sh first" >&2
  exit 1
fi

set -a; source .runtime.env; set +a

# Optional overrides
CHAIN_ID=${CHAIN_ID:-31337}
THRESHOLD_ISSUER=${THRESHOLD_ISSUER:-${ISSUER_THRESHOLD:-${THRESHOLD:-${T:-3}}}}
THRESHOLD_OPENER=${THRESHOLD_OPENER:-${OPENER_THRESHOLD:-${THRESHOLD:-${T:-3}}}}
TOTAL=${TOTAL:-${N:-3}}
METRICS_FILE_BASE=${METRICS_FILE_BASE:-metrics/results}

# Use tmux if available; else background processes
use_tmux=false
if [ "${USE_TMUX:-}" = "1" ] || [ "${USE_TMUX:-}" = "true" ]; then
  use_tmux=true
fi
if $use_tmux && ! command -v tmux >/dev/null 2>&1; then
  echo "[runner] USE_TMUX=1 but tmux not found; falling back to GUI/background"
  use_tmux=false
fi

session="tbbs_metrics"
if $use_tmux; then
  tmux new-session -d -s "$session" -n main
fi

launch_cmd() {
  local title="$1"; shift
  local cmd="$*"
  if $use_tmux; then
    tmux new-window -t "$session" -n "$title" "$cmd"
  else
    # Try GUI terminals in order unless overridden by USE_GUI_TERMINAL
    if command -v gnome-terminal >/dev/null 2>&1; then
      gnome-terminal --title="$title" -- bash -lc "$cmd; exec bash" &
    elif command -v konsole >/dev/null 2>&1; then
      konsole -p tabtitle="$title" -e bash -lc "$cmd; exec bash" &
    elif command -v xfce4-terminal >/dev/null 2>&1; then
      xfce4-terminal --title "$title" -e "bash -lc '$cmd; exec bash'" &
    elif command -v kitty >/dev/null 2>&1; then
      kitty --title "$title" bash -lc "$cmd; exec bash" &
    elif command -v alacritty >/dev/null 2>&1; then
      alacritty -t "$title" -e bash -lc "$cmd; exec bash" &
    elif command -v tilix >/dev/null 2>&1; then
      tilix -t "$title" -e bash -lc "$cmd; exec bash" &
    elif command -v wezterm >/dev/null 2>&1; then
      wezterm start -- bash -lc "$cmd; exec bash" &
    elif command -v xterm >/dev/null 2>&1; then
      xterm -T "$title" -e bash -lc "$cmd; read -p 'Press Enter to close...'" &
    else
      # Fallback to background if no GUI terminal available
      bash -lc "$cmd" &
    fi
  fi
}

# Common env exports
export METRICS=1
export THRESHOLD_ISSUER THRESHOLD_OPENER TOTAL

# 02 issuers
launch_cmd "issuers" "cd scripts/.. && METRICS=1 THRESHOLD_ISSUER=$THRESHOLD_ISSUER TOTAL=$TOTAL bash scripts/02_start_issuers.sh"

# 03 opener aggregator
launch_cmd "aggregator" "cd scripts/.. && METRICS=1 THRESHOLD_OPENER=$THRESHOLD_OPENER TOTAL=$TOTAL bash scripts/03_start_opener_aggregator.sh"

# 04 threshold openers
launch_cmd "openers" "cd scripts/.. && METRICS=1 THRESHOLD_OPENER=$THRESHOLD_OPENER TOTAL=$TOTAL bash scripts/04_start_threshold_openers.sh"

# 05 client (user)
launch_cmd "client" "cd scripts/.. && METRICS=1 bash scripts/05_run_user.sh"

# 06 service provider (auto open/revoke)
launch_cmd "service_provider" "cd scripts/.. && METRICS=1 SP_AUTO_OPEN=true SP_AUTO_REVOKE=true bash scripts/06_run_service_provider.sh"

if $use_tmux; then
  tmux select-window -t "$session:main"
  tmux attach-session -t "$session"
else
  echo "[runner] started in GUI terminals or background. To stop: pkill -f cargo; pkill -f node; pkill -f hardhat"
  wait
fi


