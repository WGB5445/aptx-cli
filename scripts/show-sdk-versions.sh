#!/usr/bin/env bash
# show-sdk-versions.sh — print the currently pinned SDK version for each implementation
#
# Usage:
#   ./scripts/show-sdk-versions.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Currently pinned SDK versions:"
echo ""

# TypeScript
TS_PKG="$ROOT/implementations/typescript/package.json"
if [[ -f "$TS_PKG" ]]; then
  TS_VER=$(python3 -c "import json; p=json.load(open('$TS_PKG')); print(p['dependencies'].get('@aptos-labs/ts-sdk','(not set)'))" 2>/dev/null || echo "(parse error)")
  echo "  typescript  @aptos-labs/ts-sdk  $TS_VER"
else
  echo "  typescript  (package.json not found)"
fi

# Go
GO_MOD="$ROOT/implementations/go/go.mod"
if [[ -f "$GO_MOD" ]]; then
  GO_VER=$(grep "github.com/aptos-labs/aptos-go-sdk" "$GO_MOD" | awk '{print $NF}' | grep "^v" | head -1)
  echo "  go          aptos-go-sdk        ${GO_VER:-(not set)}"
else
  echo "  go          (go.mod not found)"
fi

# Python
PY_TOML="$ROOT/implementations/python/pyproject.toml"
if [[ -f "$PY_TOML" ]]; then
  PY_VER=$(grep -E '"aptos-sdk' "$PY_TOML" 2>/dev/null | tr -d ' ",' | sed 's/aptos-sdk//' | head -1)
  echo "  python      aptos-sdk           ${PY_VER:-(not set)}"
else
  echo "  python      (pyproject.toml not found)"
fi

# Rust
CARGO_TOML="$ROOT/implementations/rust/Cargo.toml"
if [[ -f "$CARGO_TOML" ]]; then
  RUST_VER=$(grep -E '^aptos-sdk' "$CARGO_TOML" 2>/dev/null | grep -oE 'version = "[^"]*"' | grep -oE '"[^"]*"' | tr -d '"' | head -1)
  echo "  rust        aptos-sdk           ${RUST_VER:-(not set)}"
else
  echo "  rust        (Cargo.toml not found)"
fi

echo ""
echo "To update a version:  ./scripts/set-sdk-version.sh <impl> <version>"
echo "To run conformance:   python3 conformance/run.py"
