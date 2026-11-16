#!/usr/bin/env bash
# Build the simulator-specific ESP32-S3 firmware used by wokwi.toml.
# Does not overwrite target/xtensa-esp32s3-none-elf/debug/cyberdeck (hardware build).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [[ -f "${HOME}/export-esp.sh" ]]; then
  # espup's Xtensa linker directory is required on Linux/macOS.
  source "${HOME}/export-esp.sh"
fi

export CYBERDECK_SIM=wokwi
export CYBERDECK_BOARD=core
export CARGO_TARGET_DIR="$root/target/wokwi"
cargo build --locked --bin cyberdeck

artifact="$CARGO_TARGET_DIR/xtensa-esp32s3-none-elf/debug/cyberdeck"
if [[ ! -s "$artifact" ]]; then
  echo "Wokwi firmware ELF was not produced: $artifact" >&2
  exit 1
fi
echo "Wokwi firmware ready: $artifact"
echo "Open VS Code and run: Wokwi: Start Simulator"
