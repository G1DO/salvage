#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit is required; install it with: cargo install cargo-audit --locked" >&2
    exit 1
fi

echo "Checking formatting"
cargo fmt --all -- --check

echo "Checking clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

echo "Running tests"
cargo test --workspace --all-targets --locked

echo "Auditing dependencies"
cargo audit

if [[ ! -f tests/fixtures/invalid.rs ]]; then
    echo "negative fixture is missing: tests/fixtures/invalid.rs" >&2
    exit 1
fi

negative_fixture_directory="$(mktemp -d)"
trap 'rm -rf "$negative_fixture_directory"' EXIT

echo "Checking negative fixture"
if rustc --edition 2024 tests/fixtures/invalid.rs --emit=metadata \
    -o "$negative_fixture_directory/invalid.rmeta" \
    >"$negative_fixture_directory/compiler.log" 2>&1; then
    cat "$negative_fixture_directory/compiler.log" >&2
    echo "negative fixture unexpectedly compiled" >&2
    exit 1
fi
