#!/bin/sh
# Packs one platform's CLI release tarball, deadbolt-<version>-<platform>.tar.gz,
# from a Cargo release directory: `deadbolt` at the root, and on macOS the
# Touch ID helper `deadbolt-enclave` beside it (the agent looks for it next to
# its own executable; docs/touch-id.md). The install script and the Homebrew
# formula install both files into one directory.
#
#   scripts/package-cli.sh <version> <platform> <cargo release dir> <out>
#
# <platform> is linux-x64, linux-arm64 (glibc, the app built in),
# linux-x64-musl, linux-arm64-musl (static, no app), darwin-x64 or darwin-arm64.
set -eu

[ $# -eq 4 ] || { echo "Usage: $0 <version> <platform> <cargo release dir> <out>" >&2; exit 1; }
version=$1 platform=$2 bin=$3 out=$4
root=$(cd "$(dirname "$0")/.." && pwd)

case "$platform" in
  linux-x64 | linux-arm64 | linux-x64-musl | linux-arm64-musl) files=deadbolt ;;
  darwin-x64 | darwin-arm64) files="deadbolt deadbolt-enclave" ;;
  *) echo "Unknown platform $platform." >&2; exit 1 ;;
esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
for file in $files; do
  [ -f "$bin/$file" ] || { echo "$bin/$file is missing." >&2; exit 1; }
  cp "$bin/$file" "$stage/$file"
  chmod 755 "$stage/$file"
done
"$root/scripts/check-ca-roots.sh" "$stage/deadbolt"

mkdir -p "$out"
tarball="$out/deadbolt-$version-$platform.tar.gz"
# shellcheck disable=SC2086 # $files is a list of plain names.
COPYFILE_DISABLE=1 tar -czf "$tarball" -C "$stage" $files
echo "$tarball"
