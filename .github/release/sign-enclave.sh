#!/usr/bin/env bash
# sign-enclave.sh <in> <out>: signs the two thin Touch ID helpers
# (<in>/aarch64/deadbolt-enclave and <in>/x86_64/deadbolt-enclave, from
# crates/cli/scripts/build-enclave.sh) with the Developer ID, hardened runtime
# and secure timestamp, into the same layout under <out>. build-macos then
# compiles `deadbolt` against these exact bytes (DEADBOLT_ENCLAVE_PREBUILT), so
# nothing may sign them again (docs/touch-id.md). They are data here: never run.
#
# Environment: DEADBOLT_SIGNING_IDENTITY, DEADBOLT_KEYCHAIN (macos-credentials.sh),
# DEADBOLT_TEAM_ID.
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

in=$1
out=$2
expected=$(printf '%s\n' aarch64/deadbolt-enclave x86_64/deadbolt-enclave)
found=$(cd "$in" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort)
[ "$found" = "$expected" ] || die "The enclave build must hold exactly the two helpers, not: $(echo "$found" | tr '\n' ' ')"

for arch in aarch64 x86_64; do
  case "$arch" in
    aarch64) lipo=arm64 ;;
    x86_64) lipo=x86_64 ;;
  esac
  mkdir -p "$out/$arch"
  helper="$out/$arch/deadbolt-enclave"
  cp "$in/$arch/deadbolt-enclave" "$helper"
  [ "$(lipo -archs "$helper")" = "$lipo" ] || die "$arch/deadbolt-enclave is not a thin $lipo Mach-O."
  codesign -d --verbose=2 "$helper" 2>&1 | grep -qx "Identifier=$DEADBOLT_ENCLAVE_ID" ||
    die "$arch/deadbolt-enclave does not embed the identifier $DEADBOLT_ENCLAVE_ID."
  codesign --force --timestamp --options runtime --identifier "$DEADBOLT_ENCLAVE_ID" \
    --keychain "$DEADBOLT_KEYCHAIN" --sign "$DEADBOLT_SIGNING_IDENTITY" "$helper"
  check_developer_id "$DEADBOLT_ENCLAVE_ID" "$helper"
  sha256 "$helper"
done
