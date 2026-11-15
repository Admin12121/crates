#!/usr/bin/env bash
# Run the hardware-independent core test suite on the host.
#
# The repository root targets `xtensa-esp32s3-none-elf` with `-Z build-std`
# (correct for firmware, unusable for a hosted test harness). Cargo reads
# `.cargo/config.toml` from the current directory upwards, so tests run from a
# neutral temporary directory with an explicit manifest path. The result is the
# same `cargo test` semantics developers expect, for every host platform.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$root/crates/cyberdeck-core/Cargo.toml"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$work"
exec cargo test --manifest-path "$manifest" "$@"
