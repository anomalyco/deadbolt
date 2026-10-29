#!/usr/bin/env bash
# Checks a signed macOS release (.github/release/sign-macos.sh's output) the
# way a user's Mac and a future updater would, and runs it briefly. The
# Release workflow's verify-macos job runs this without secrets.
#
#   scripts/verify-macos-release.sh <signed dir> <version>
#
# - DMG and app: stapled, accepted by Gatekeeper, the zip's app identical to
#   the DMG's, and the app meets crates/app/update-requirement.txt.
# - Every Mach-O is Developer ID-signed with the hardened runtime as its
#   identity (pw.deadbolt.app, pw.deadbolt.cli, pw.deadbolt.app.enclave).
# - Touch ID pin: each architecture slice of `deadbolt` embeds the SHA-256 of
#   the same slice of the deadbolt-enclave beside it (docs/touch-id.md).
# - The app's CLI, helper and app start; the CLI tarballs' `deadbolt` reports
#   the version.
#
# Environment: DEADBOLT_TEAM_ID.
root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=.github/release/lib.sh
. "$root/.github/release/lib.sh"

[ $# -eq 2 ] || die "Usage: $0 <signed dir> <version>"
dir=$1
v=$2
dmg="$dir/Deadbolt-$v-macos-universal.dmg"
zip="$dir/Deadbolt-$v-macos-universal.zip"
check=$(mktemp -d)
trap 'hdiutil detach -quiet "$check/dmg" 2>/dev/null || true; rm -rf "$check"' EXIT

# check_pin <deadbolt> <deadbolt-enclave> <arch>: the arch slice of deadbolt
# pins the arch slice of the helper.
check_pin() {
  local slice="$check/slice"
  if [ "$(lipo -archs "$2")" = "$3" ]; then cp "$2" "$slice"; else lipo -thin "$3" "$2" -output "$slice"; fi
  local digest
  digest=$(sha256 "$slice" | cut -c1-64)
  if [ "$(lipo -archs "$1")" = "$3" ]; then cp "$1" "$slice"; else lipo -thin "$3" "$1" -output "$slice"; fi
  LC_ALL=C grep -aqF "$digest" "$slice" || die "$1 ($3) does not pin $2 ($digest)."
  echo "$1 ($3) pins deadbolt-enclave $digest"
  rm -f "$slice"
}

check_app() {
  local app=$1
  local plist="$app/Contents/Info.plist"
  [ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist")" = "$DEADBOLT_APP_ID" ] || die "$app has the wrong identifier."
  [ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$plist")" = "$v" ] || die "$app is not version $v."
  xcrun stapler validate "$app"
  codesign --verify --deep --strict --verbose=2 -R="$(cat "$root/crates/app/update-requirement.txt")" "$app"
  spctl --assess --type execute --verbose=2 "$app"
  check_developer_id "$DEADBOLT_APP_ID" "$app"
  check_developer_id "$DEADBOLT_CLI_ID" "$app/Contents/Helpers/deadbolt"
  check_developer_id "$DEADBOLT_ENCLAVE_ID" "$app/Contents/Helpers/deadbolt-enclave"
  for arch in arm64 x86_64; do
    check_pin "$app/Contents/Helpers/deadbolt" "$app/Contents/Helpers/deadbolt-enclave" "$arch"
  done
}

xcrun stapler validate "$dmg"
spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$check/dmg" "$dmg"
/usr/bin/ditto -x -k "$zip" "$check/update"
check_app "$check/dmg/Deadbolt.app"
check_app "$check/update/Deadbolt.app"
diff -qr "$check/dmg/Deadbolt.app" "$check/update/Deadbolt.app"

app="$check/update/Deadbolt.app"
"$app/Contents/Helpers/deadbolt" --version | grep -qF "deadbolt $v" || die "The app's deadbolt is not version $v."
"$app/Contents/Helpers/deadbolt-enclave" status
"$app/Contents/MacOS/Deadbolt" --list-scenes > /dev/null
codesign -dv "$app" 2>&1 | grep -E '^(Identifier|TeamIdentifier|Authority=Developer)' >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

native=$(uname -m)
for pair in darwin-arm64=arm64 darwin-x64=x86_64; do
  platform=${pair%%=*} arch=${pair#*=}
  cli="$check/cli/$platform"
  mkdir -p "$cli"
  tar -xzf "$dir/deadbolt-$v-$platform.tar.gz" -C "$cli"
  check_developer_id "$DEADBOLT_CLI_ID" "$cli/deadbolt"
  check_developer_id "$DEADBOLT_ENCLAVE_ID" "$cli/deadbolt-enclave"
  check_pin "$cli/deadbolt" "$cli/deadbolt-enclave" "$arch"
  # Bare executables cannot be stapled; Gatekeeper looks their ticket up.
  codesign --verify --check-notarization -R='notarized' "$cli/deadbolt" ||
    echo "::warning::Could not confirm the notarization of $platform/deadbolt online."
  if [ "$arch" = "$native" ]; then
    "$cli/deadbolt" --version | grep -qF "deadbolt $v" || die "$platform/deadbolt is not version $v."
  fi
done
echo "Verified Deadbolt $v for macOS."
