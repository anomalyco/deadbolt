#!/usr/bin/env bash
# sign-macos.sh <unsigned Deadbolt.app zip> <CLI tarball dir> <out dir>: signs
# Deadbolt's macOS release with the Developer ID (hardened runtime, secure
# timestamp), notarizes it, and writes into <out dir>:
#
#   deadbolt-<version>-darwin-arm64.tar.gz   the CLI tarballs, `deadbolt` signed
#   deadbolt-<version>-darwin-x64.tar.gz     and notarized (not stapled: bare
#                                            Mach-O files cannot hold a ticket)
#   Deadbolt-<version>-macos-universal.zip   root Deadbolt.app, stapled (updater)
#   Deadbolt-<version>-macos-universal.dmg   signed, notarized, stapled
#
# The Touch ID helper, deadbolt-enclave, arrives already signed by
# sign-enclave.sh, and `deadbolt` pins its exact bytes (docs/touch-id.md): it
# is checked and never signed again, and its bytes must come out unchanged.
# Everything here is data: nothing from the build is ever run.
#
# Environment: DEADBOLT_VERSION, DEADBOLT_TEAM_ID, DEADBOLT_SIGNING_IDENTITY,
# DEADBOLT_KEYCHAIN, DEADBOLT_NOTARY_KEY (macos-credentials.sh),
# DEADBOLT_NOTARY_KEY_ID, DEADBOLT_NOTARY_ISSUER.
# shellcheck source=.github/release/lib.sh
. "$(dirname "$0")/lib.sh"

app_zip=$1
cli=$2
out=$3
v=$DEADBOLT_VERSION
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

sign() {
  codesign --force --timestamp --options runtime --keychain "$DEADBOLT_KEYCHAIN" --sign "$DEADBOLT_SIGNING_IDENTITY" "$@"
}
notarize() {
  local result="$work/notary.json"
  xcrun notarytool submit "$1" --key "$DEADBOLT_NOTARY_KEY" --key-id "$DEADBOLT_NOTARY_KEY_ID" \
    --issuer "$DEADBOLT_NOTARY_ISSUER" --wait --timeout 45m --output-format json > "$result" || true
  if [ "$(jq -r '.status // empty' "$result")" != Accepted ]; then
    cat "$result" >&2
    id=$(jq -r '.id // empty' "$result")
    [ -z "$id" ] || xcrun notarytool log "$id" --key "$DEADBOLT_NOTARY_KEY" --key-id "$DEADBOLT_NOTARY_KEY_ID" \
      --issuer "$DEADBOLT_NOTARY_ISSUER" >&2 || true
    die "Notarization of $(basename "$1") was not accepted."
  fi
  echo "Notarized $(basename "$1") ($(jq -r .id "$result"))."
}
# A digest of the helper, so signing around it provably left it alone.
helper_digest() {
  sha256 "$1" | cut -c1-64
}

# ---- The CLI tarballs -------------------------------------------------------

for pair in darwin-arm64=arm64 darwin-x64=x86_64; do
  platform=${pair%%=*} arch=${pair#*=}
  tarball="$cli/deadbolt-$v-$platform.tar.gz"
  [ -f "$tarball" ] || die "The macOS build has no deadbolt-$v-$platform.tar.gz."
  dir="$work/cli/$platform"
  mkdir -p "$dir"
  tar -xzf "$tarball" -C "$dir"
  [ "$(cd "$dir" && find . -mindepth 1 | sed 's|^\./||' | LC_ALL=C sort | tr '\n' ' ')" = "deadbolt deadbolt-enclave " ] ||
    die "$platform must hold exactly deadbolt and deadbolt-enclave."
  for file in deadbolt deadbolt-enclave; do
    [ "$(lipo -archs "$dir/$file")" = "$arch" ] || die "$platform/$file is not a thin $arch Mach-O."
  done
  check_developer_id "$DEADBOLT_ENCLAVE_ID" "$dir/deadbolt-enclave"
  before=$(helper_digest "$dir/deadbolt-enclave")
  sign --identifier "$DEADBOLT_CLI_ID" "$dir/deadbolt"
  check_developer_id "$DEADBOLT_CLI_ID" "$dir/deadbolt"
  [ "$(helper_digest "$dir/deadbolt-enclave")" = "$before" ] || die "$platform/deadbolt-enclave changed while signing."
done
/usr/bin/ditto -c -k --sequesterRsrc "$work/cli" "$work/cli-notarize.zip"
notarize "$work/cli-notarize.zip"
for platform in darwin-arm64 darwin-x64; do
  COPYFILE_DISABLE=1 tar -czf "$out/deadbolt-$v-$platform.tar.gz" -C "$work/cli/$platform" deadbolt deadbolt-enclave
done

# ---- Deadbolt.app -----------------------------------------------------------

zip="$out/Deadbolt-$v-macos-universal.zip"
dmg="$out/Deadbolt-$v-macos-universal.dmg"
/usr/bin/ditto -x -k "$app_zip" "$work/unpacked"
app="$work/unpacked/Deadbolt.app"
if [ ! -d "$app" ] || [ "$(find "$work/unpacked" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" != 1 ]; then
  die "The macOS build must hold exactly Deadbolt.app."
fi
plist() { /usr/libexec/PlistBuddy -c "Print :$1" "$app/Contents/Info.plist"; }
[ "$(plist CFBundleIdentifier)" = "$DEADBOLT_APP_ID" ] || die "Deadbolt.app has the wrong bundle identifier."
[ "$(plist CFBundleShortVersionString)" = "$v" ] || die "Deadbolt.app is not version $v."

# Every Mach-O in the bundle must be one this script expects.
expected=$(printf '%s\n' Contents/Helpers/deadbolt Contents/Helpers/deadbolt-enclave Contents/MacOS/Deadbolt | LC_ALL=C sort)
found=$(mach_o_files "$app")
[ "$found" = "$expected" ] || die "Unexpected code in Deadbolt.app: $(diff <(echo "$expected") <(echo "$found") | grep '^[<>]' | tr '\n' ' ')"
for file in $expected; do
  [ "$(lipo -archs "$app/$file" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ')" = "arm64 x86_64 " ] ||
    die "$file is not universal (arm64 and x86_64)."
done

helper="$app/Contents/Helpers/deadbolt-enclave"
check_developer_id "$DEADBOLT_ENCLAVE_ID" "$helper"
before=$(helper_digest "$helper")
sign --identifier "$DEADBOLT_CLI_ID" "$app/Contents/Helpers/deadbolt"
sign "$app"
codesign --verify --deep --strict --verbose=2 "$app"
check_developer_id "$DEADBOLT_APP_ID" "$app"
check_developer_id "$DEADBOLT_CLI_ID" "$app/Contents/Helpers/deadbolt"
[ "$(helper_digest "$helper")" = "$before" ] || die "Contents/Helpers/deadbolt-enclave changed while signing."

# Notarize the app first so its ticket is stapled inside both targets.
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$app" "$work/app-notarize.zip"
notarize "$work/app-notarize.zip"
xcrun stapler staple "$app"
xcrun stapler validate "$app"

/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"

mkdir "$work/staging"
/usr/bin/ditto "$app" "$work/staging/Deadbolt.app"
ln -s /Applications "$work/staging/Applications"
hdiutil create -quiet -fs HFS+ -format UDZO -volname Deadbolt -srcfolder "$work/staging" "$dmg"
codesign --force --timestamp --keychain "$DEADBOLT_KEYCHAIN" --sign "$DEADBOLT_SIGNING_IDENTITY" "$dmg"
notarize "$dmg"
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
ls -l "$out"
