#!/bin/sh
# Compiles the Touch ID helper, deadbolt-enclave, for both macOS
# architectures, the way crates/enclave/build.rs does (keep them in step), into
# <out>/aarch64/deadbolt-enclave and <out>/x86_64/deadbolt-enclave, signed
# ad hoc. The Release workflow signs these with the Developer ID before
# building `deadbolt` and `deadbolt-ui`, which pin their exact bytes through
# DEADBOLT_ENCLAVE_PREBUILT=<out> (docs/touch-id.md, docs/releasing.md).
#
#   crates/enclave/scripts/build-enclave.sh <out>
set -eu

[ "$(uname -s)" = Darwin ] || { echo "Building deadbolt-enclave requires macOS." >&2; exit 1; }
[ $# -eq 1 ] || { echo "Usage: $0 <out>" >&2; exit 1; }
src=$(cd "$(dirname "$0")/.." && pwd)/swift
out=$1

for arch in aarch64 x86_64; do
  case "$arch" in
    aarch64) triple=arm64-apple-macosx12.0 ;;
    x86_64) triple=x86_64-apple-macosx12.0 ;;
  esac
  mkdir -p "$out/$arch"
  bin="$out/$arch/deadbolt-enclave"
  swiftc -O -parse-as-library -target "$triple" "$src/enclave.swift" "$src/identify.swift" \
    -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker "$src/Info.plist" \
    -o "$bin"
  strip "$bin"
  codesign --force --sign - "$bin"
  codesign --verify --strict "$bin"
  echo "$bin: $(lipo -archs "$bin")"
done
