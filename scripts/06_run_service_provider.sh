#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Ensure runtime
if [ ! -f .runtime.env ]; then
  echo "[sp] .runtime.env missing; run 01_ttp_setup.sh first" >&2
  exit 1
fi
set -a; source .runtime.env; set +a

export SP_AUTO_OPEN=${SP_AUTO_OPEN:-true}
export SP_AUTO_REVOKE=${SP_AUTO_REVOKE:-true}

echo "[sp] starting service_provider (auto open/revoke: $SP_AUTO_OPEN/$SP_AUTO_REVOKE)"
RUST_LOG=info cargo run -q --bin service_provider

# Persist potentially updated runtime (if service writes env)
if [ -n "${RUNTIME_OUT:-}" ] && [ -f "$RUNTIME_OUT" ]; then
  cp "$RUNTIME_OUT" ./.runtime.env
  echo "[sp] updated .runtime.env from $RUNTIME_OUT"
fi

