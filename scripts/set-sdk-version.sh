#!/usr/bin/env bash
# set-sdk-version.sh — pin an implementation's SDK to a specific version or git ref
#
# Usage:
#   ./scripts/set-sdk-version.sh typescript 6.2.0
#   ./scripts/set-sdk-version.sh typescript github:aptos-labs/aptos-ts-sdk#main
#   ./scripts/set-sdk-version.sh go v1.13.0
#   ./scripts/set-sdk-version.sh go main
#
# After updating, run:
#   python3 conformance/run.py
# to verify the new version is still conformant, or:
#   python3 conformance/run.py --compare-baseline conformance/baselines/<saved>.json
# to check compatibility against a saved baseline.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  echo "Usage: $0 <impl> <version-or-ref>"
  echo ""
  echo "  impl:    typescript | go | python | rust"
  echo "  version: semver (e.g. 6.2.0, v1.13.0) or git ref"
  echo ""
  echo "Examples:"
  echo "  $0 typescript 6.2.0"
  echo "  $0 typescript github:aptos-labs/aptos-ts-sdk#main"
  echo "  $0 go v1.13.0"
  echo "  $0 go main"
  exit 1
}

[[ $# -ne 2 ]] && usage

IMPL="$1"
VERSION="$2"

case "$IMPL" in

  typescript)
    TS_DIR="$ROOT/implementations/typescript"
    echo "Setting TypeScript SDK (@aptos-labs/ts-sdk) to: $VERSION"

    # Detect whether this is a registry version or a git ref
    if [[ "$VERSION" =~ ^[0-9] ]]; then
      # Plain semver: use npm/pnpm registry
      SPEC="@aptos-labs/ts-sdk@$VERSION"
    else
      # Git ref or custom specifier passed as-is
      SPEC="$VERSION"
    fi

    cd "$TS_DIR"
    pnpm add "$SPEC"
    echo ""
    echo "TypeScript SDK updated. New package.json dependency:"
    node -e "const p=require('./package.json'); console.log('  @aptos-labs/ts-sdk:', p.dependencies['@aptos-labs/ts-sdk'])"
    ;;

  go)
    GO_DIR="$ROOT/implementations/go"
    echo "Setting Go SDK (github.com/aptos-labs/aptos-go-sdk) to: $VERSION"

    cd "$GO_DIR"
    GOCACHE="$ROOT/.cache/go-build" go get "github.com/aptos-labs/aptos-go-sdk@$VERSION"
    GOCACHE="$ROOT/.cache/go-build" go mod tidy
    echo ""
    echo "Go SDK updated. New go.mod entry:"
    grep "aptos-go-sdk" go.mod | head -1 | sed 's/^/  /'
    ;;

  python)
    PY_DIR="$ROOT/implementations/python"
    PYPROJECT="$PY_DIR/pyproject.toml"
    echo "Setting Python SDK (aptos-sdk) to: $VERSION"

    if [[ "$VERSION" =~ ^[0-9] ]]; then
      # Plain semver: pin to >= that version
      sed -i.bak "s|\"aptos-sdk[^\"]*\"|\"aptos-sdk>=$VERSION\"|g" "$PYPROJECT"
      rm -f "$PYPROJECT.bak"
    else
      echo "Git refs for Python SDK are not supported via this script."
      echo "Manually update pyproject.toml to:"
      echo "  aptos-sdk @ git+https://github.com/aptos-labs/aptos-python-sdk@$VERSION"
      exit 1
    fi

    echo ""
    echo "Python SDK updated. New pyproject.toml dependency:"
    grep "aptos-sdk" "$PYPROJECT" | sed 's/^/  /'
    echo ""
    echo "Re-install with:  pip install -e implementations/python"
    ;;

  rust)
    RUST_DIR="$ROOT/implementations/rust"
    CARGO_TOML="$RUST_DIR/Cargo.toml"
    echo "Setting Rust SDK (aptos-sdk) to: $VERSION"

    if [[ "$VERSION" =~ ^[0-9] ]]; then
      # Plain semver: update version = "X.Y.Z" in the aptos-sdk entry
      sed -i.bak "s|aptos-sdk = { version = \"[^\"]*\"|aptos-sdk = { version = \"$VERSION\"|g" "$CARGO_TOML"
      rm -f "$CARGO_TOML.bak"
    else
      # Git ref: replace with git source
      sed -i.bak "s|aptos-sdk = {[^}]*}|aptos-sdk = { git = \"https://github.com/aptos-labs/aptos-rust-sdk\", branch = \"$VERSION\", default-features = false, features = [\"ed25519\"] }|g" "$CARGO_TOML"
      rm -f "$CARGO_TOML.bak"
    fi

    echo ""
    echo "Rust SDK updated. New Cargo.toml entry:"
    grep "aptos-sdk" "$CARGO_TOML" | sed 's/^/  /'
    echo ""
    echo "Rebuild with:  cd implementations/rust && cargo build"
    ;;

  *)
    echo "Unknown implementation: $IMPL"
    echo "Known implementations: typescript, go, python, rust"
    exit 1
    ;;
esac
