#!/usr/bin/env bash
# bench_full.sh — Run issuance + presentation benchmarks back-to-back,
# then produce summary tables via bench_summary.
#
# Prerequisites (start once before running this script):
#   anvil --hardfork pragueEOF --gas-limit 300000000 -p 8545
#   BATCH_SIZE_REQ=1 BATCH_SIZE_PRES=1 bash scripts/01_ttp_setup.sh
#   source .runtime.env
#   Start issuers        — bash scripts/02_start_issuers.sh  (they poll batch_size from chain)
#   Start aggregators/SP — see E2E_TEST.md T5a/T5b/T5c (each in its own terminal)
#
# Usage:
#   BENCH_SIZES="1 2 4 8 16 32 64 128" bash scripts/bench_full.sh
set -euo pipefail

BENCH_SIZES="${BENCH_SIZES:-1 2 4 8 16}"
export BENCH_SIZES

echo "╔══════════════════════════════════════════╗"
echo "║         FULL BENCHMARK SUITE             ║"
echo "║  Sizes: $BENCH_SIZES"
echo "╚══════════════════════════════════════════╝"
echo ""

# Phase 1: Issuance E2E
echo "── Phase 1: Issuance E2E ──"
bash scripts/bench_issuance_e2e.sh
echo ""

# Phase 2: Presentation E2E
# (credentials are now issued; bench_presentation uses Mode::Verify to fetch from registry)
echo "── Phase 2: Presentation E2E ──"
bash scripts/bench_presentation_e2e.sh
echo ""

# Phase 3: Summary
echo "── Phase 3: Summary ──"
echo ""

# Build bench_summary binary
cargo build --bin bench_summary 2>&1 | tail -1

# Collect all archived NDJSON files
REQ_FILES=(metrics/results/request_aggregator_n*.ndjson)
ISSUER_FILES=(metrics/results/issuer_*_n*.ndjson)
OPENER_FILES=(metrics/results/aggregator_n*.ndjson)
SP_FILES=(metrics/results/service_provider_n*.ndjson)
PRES_FILES=(metrics/results/presentation_aggregator_n*.ndjson)
CLIENT_FILES=(metrics/results/client_n*.ndjson metrics/results/client_pres_n*.ndjson)

echo "Running bench_summary..."
echo ""
target/debug/bench_summary \
  --req    "${REQ_FILES[@]}" \
  --issuer "${ISSUER_FILES[@]}" \
  --opener "${OPENER_FILES[@]}" \
  --sp     "${SP_FILES[@]}" \
  --pres   "${PRES_FILES[@]}" \
  --client "${CLIENT_FILES[@]}" \
  2>/dev/null || echo "[warn] bench_summary failed — some NDJSON files may be missing"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         BENCHMARK COMPLETE               ║"
echo "╚══════════════════════════════════════════╝"
