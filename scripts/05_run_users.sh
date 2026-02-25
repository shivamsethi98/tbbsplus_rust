#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run multiple users in parallel, each in its own tmux pane.
#
# Usage:
#   ./05_run_users.sh              # runs all 5 users
#   ./05_run_users.sh 3            # runs 3 users
#   ./05_run_users.sh 1            # runs 1 user (same as 05_run_user.sh)
#
# Each user gets their own CLIENT_PK → distinct on-chain userId.
# Anvil deterministic private keys (accounts #1,#2,#4,#5,#6 — #0 is deployer,
# #3 is opener, #7 is SP).
#
# Navigate panes: Ctrl-B then arrow keys.  Kill session: Ctrl-B then :kill-session
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
cd "$ROOT_DIR"

# Load env produced by stage 1
if [[ -f .runtime.env ]]; then
	set -a
	source .runtime.env
	set +a
fi

if [[ -z "${ETH_WS:-}" || -z "${CHAIN_ID:-}" || -z "${REQ_CONTRACT:-}" || -z "${REGISTRY_CONTRACT:-}" || -z "${PARAMS_CONTRACT:-}" || -z "${CRED_NAME:-}" || -z "${MESSAGE_COUNT:-}" ]]; then
	echo "Missing required env. Ensure 01_ttp_setup.sh was run." >&2
	exit 1
fi

# Anvil deterministic private keys (accounts #1,#2,#4,#5,#6)
KEYS=(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # Account #1
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # Account #2
  "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"  # Account #4
  "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"  # Account #5
  "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e"  # Account #6
)

ADDRS=(
  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # Account #1
  "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"  # Account #2
  "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"  # Account #4
  "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"  # Account #5
  "0x976EA74026E726554dB657fA54763abd0C3a0aa9"  # Account #6
)

NUM_USERS=${1:-${#KEYS[@]}}
if (( NUM_USERS > ${#KEYS[@]} )); then
  echo "Max ${#KEYS[@]} users supported (limited by available Anvil keys)." >&2
  NUM_USERS=${#KEYS[@]}
fi

# Build once before spawning
echo "[users] building client binary..."
cargo build --bin client --features mpc,interactive 2>&1 | tail -3

# ---- Build the command each user pane will run ----
user_cmd() {
  local idx=$1
  local pk="${KEYS[$idx]}"
  local addr="${ADDRS[$idx]}"
  local num=$((idx + 1))
  # Source ALL env vars from .runtime.env so nothing is missed (VERIFY_CONTRACT, ACC_CONTRACT, etc.)
  cat <<EOF
cd "$ROOT_DIR" && \\
  set -a && source .runtime.env && set +a && \\
  CLIENT_PK="$pk" \\
  cargo run --bin client --features mpc,interactive; \\
  echo '--- user $num exited, press enter ---'; read
EOF
}

SESSION="users"

# Kill any existing session with this name
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create session with first user
echo "[users] launching $NUM_USERS users in tmux session '$SESSION'"
tmux new-session -d -s "$SESSION" -x 200 -y 50 "$(user_cmd 0)"
tmux rename-window -t "$SESSION" "user-1 (${ADDRS[0]:0:10}..)"

# Add remaining users as split panes
for (( i=1; i<NUM_USERS; i++ )); do
  USER_NUM=$((i + 1))
  # Alternate between horizontal and vertical splits for a grid layout
  tmux split-window -t "$SESSION" "$(user_cmd $i)"
  # Re-tile after each split so panes stay even
  tmux select-layout -t "$SESSION" tiled
  # Small delay to stagger credential requests and avoid nonce collisions
  sleep 1
done

tmux select-layout -t "$SESSION" tiled

echo "[users] tmux session '$SESSION' created with $NUM_USERS panes."
echo "  Attach:  tmux attach -t $SESSION"
echo "  Navigate panes:  Ctrl-B  then  arrow keys"
echo "  Kill all:  tmux kill-session -t $SESSION"
echo ""

# If we're in an interactive terminal, attach automatically
if [[ -t 0 ]]; then
  tmux attach -t "$SESSION"
else
  echo "(non-interactive shell — run 'tmux attach -t $SESSION' to connect)"
fi
