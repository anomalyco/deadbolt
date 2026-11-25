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
#   identity (anomaly.deadbolt, anomaly.deadbolt.cli, anomaly.deadbolt.enclave).
# - Touch ID pin: each architecture slice of `deadbolt` and of the app
#   (`deadbolt-ui`) embeds the SHA-256 of the same slice of the
#   deadbolt-enclave it ships with (docs/touch-id.md).
# - The headless `deadbolt` (the app's helper and the CLI tarballs') has no
#   GPU or windowing code in it: it never links Metal.
# - The app's CLI, helper and app start; the CLI tarballs hold only
#   `deadbolt` and `deadbolt-enclave`, and their `deadbolt` reports the version.
# - Live daemons, each in a fresh, isolated home: the app's helper and the
#   native CLI tarball's `deadbolt` set up a store, start their daemon and
#   pass their own check of its code signature (team and identifier), and the
#   CLI takes the app's daemon and the app's helper the CLI's (the split
#   Homebrew/npm + Deadbolt.app install).
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

# smoke <starts the daemon> <talks to it>: in a fresh home, the first
# `deadbolt` sets up a store and starts its daemon, and both drive it, so
# each client's check of the daemon's signature runs for real.
smoke() {
  local home
  home=$(mktemp -d "$check/home.XXXXXX")
  (
    export HOME="$home" DEADBOLT_HOME="$home/store" XDG_RUNTIME_DIR="$home/run"
    mkdir -m 700 "$XDG_RUNTIME_DIR"
    trap '"$1" debug daemon stop > /dev/null 2>&1 || true' EXIT
    DEADBOLT_PASSPHRASE="release check" "$1" init --device-name release < /dev/null
    for bin in "$1" "$2"; do
      "$bin" debug daemon status | grep -qx unlocked || die "$bin does not take the daemon $1 started."
      "$bin" debug whoami > /dev/null || die "$bin's daemon does not answer whoami."
    done
    "$2" new login --name Example username=release password=release-check-password < /dev/null
    "$1" ls < /dev/null | grep Example > /dev/null || die "$1 does not list what $2 saved."
    "$1" debug daemon stop
  )
  echo "$1 and $2 share a live daemon."
}

# headless <deadbolt>: the CLI and daemon carry none of the app.
headless() {
  if otool -L "$1" | grep -q 'Metal.framework'; then die "$1 links Metal: it has the app in it."; fi
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
    check_pin "$app/Contents/MacOS/Deadbolt" "$app/Contents/Helpers/deadbolt-enclave" "$arch"
  done
  headless "$app/Contents/Helpers/deadbolt"
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
  [ "$(cd "$cli" && echo *)" = "deadbolt deadbolt-enclave" ] || die "$platform's tarball must hold exactly deadbolt and deadbolt-enclave."
  headless "$cli/deadbolt"
  check_developer_id "$DEADBOLT_CLI_ID" "$cli/deadbolt"
  check_developer_id "$DEADBOLT_ENCLAVE_ID" "$cli/deadbolt-enclave"
  check_pin "$cli/deadbolt" "$cli/deadbolt-enclave" "$arch"
  # Bare executables cannot be stapled; Gatekeeper looks their ticket up.
  codesign --verify --check-notarization -R='notarized' "$cli/deadbolt" ||
    echo "::warning::Could not confirm the notarization of $platform/deadbolt online."
  if [ "$arch" = "$native" ]; then
    "$cli/deadbolt" --version | grep -qF "deadbolt $v" || die "$platform/deadbolt is not version $v."
    bundled="$app/Contents/Helpers/deadbolt"
    smoke "$bundled" "$bundled"
    smoke "$cli/deadbolt" "$cli/deadbolt"
    smoke "$bundled" "$cli/deadbolt"
    smoke "$cli/deadbolt" "$bundled"
  fi
done
echo "Verified Deadbolt $v for macOS."
