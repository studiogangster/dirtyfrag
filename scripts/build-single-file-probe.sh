#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/release}"

"$ROOT_DIR/scripts/build-single-file-probes.sh" "$OUT_DIR"

echo "Primary amd64 script: $OUT_DIR/dirtyfrag-probe-linux-amd64.sh"
