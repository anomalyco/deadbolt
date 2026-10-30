#!/usr/bin/env bash
# Compiles DeadboltAutoFill.appex (pw.deadbolt.app.autofill) from
# crates/app/autofill/*.swift, stamps Info.plist and the control protocol
# version from crates/client/src/protocol.rs, and signs ad hoc (or with
# DEADBOLT_APPLE_SIGNING_IDENTITY + DEADBOLT_AUTOFILL_PROVISION_PROFILE).
#
#   crates/app/scripts/build-autofill.sh [--universal] <out.appex> [version] [build]
set -euo pipefail

[[ $(uname -s) == Darwin ]] || { echo "Building DeadboltAutoFill.appex requires macOS." >&2; exit 1; }

universal=false
if [[ ${1:-} == --universal ]]; then
  universal=true
  shift
fi

[[ $# -ge 1 && $# -le 3 ]] || {
  echo "Usage: $0 [--universal] <out.appex> [version] [build]" >&2
  exit 1
}

root=$(cd "$(dirname "$0")/../../.." && pwd)
out=$1
[[ $out == /* ]] || out="$PWD/$out"
[[ ! -e "$out" && ! -L "$out" ]] || { echo "Refusing to replace $out; choose a fresh output path." >&2; exit 1; }

version=${2:-}
build=${3:-}
if [[ -z $version ]]; then
  version=$(cargo +stable metadata --manifest-path "$root/Cargo.toml" --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "deadbolt-app"))')
fi
if [[ -z $build ]]; then
  case "$version" in
    0.0.0-dev-*) build=${version#0.0.0-dev-}; build=${build%%.*} ;;
    *) build=$(printf '%s\n' "${version%%-*}" | awk -F. '{ print ($1 * 10000) + ($2 * 100) + $3 }') ;;
  esac
fi

proto_v=$(sed -n 's/^pub const PROTOCOL_VERSION: u32 = \([0-9][0-9]*\);$/\1/p' "$root/crates/client/src/protocol.rs")
[[ -n $proto_v ]] || { echo "Could not read PROTOCOL_VERSION from crates/client/src/protocol.rs." >&2; exit 1; }

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

printf 'public let generatedProtocolVersion: UInt32 = %s\n' "$proto_v" > "$scratch/ProtocolVersion.swift"

src_dir="$root/crates/app/autofill"
sources=(
  "$scratch/ProtocolVersion.swift"
  "$src_dir/Protocol.swift"
  "$src_dir/PeerCheck.swift"
  "$src_dir/SocketClient.swift"
  "$src_dir/IdentitySync.swift"
  "$src_dir/ControllerModel.swift"
  "$src_dir/AutoFillView.swift"
  "$src_dir/CredentialProviderViewController.swift"
)

compile_slice() {
  local triple=$1
  local dest=$2
  swiftc -O -swift-version 6 -warnings-as-errors \
    -module-name DeadboltAutoFill \
    -parse-as-library \
    -application-extension \
    -target "$triple" \
    "${sources[@]}" \
    -framework AppKit \
    -framework AuthenticationServices \
    -framework Security \
    -Xlinker -e -Xlinker _NSExtensionMain \
    -o "$dest"
}

appex="$scratch/DeadboltAutoFill.appex"
mkdir -p "$appex/Contents/MacOS"

if $universal; then
  compile_slice arm64-apple-macosx14.0 "$scratch/DeadboltAutoFill-arm64"
  compile_slice x86_64-apple-macosx14.0 "$scratch/DeadboltAutoFill-x86_64"
  lipo -create \
    "$scratch/DeadboltAutoFill-arm64" \
    "$scratch/DeadboltAutoFill-x86_64" \
    -output "$appex/Contents/MacOS/DeadboltAutoFill"
else
  case "$(uname -m)" in
    arm64) compile_slice arm64-apple-macosx14.0 "$appex/Contents/MacOS/DeadboltAutoFill" ;;
    x86_64) compile_slice x86_64-apple-macosx14.0 "$appex/Contents/MacOS/DeadboltAutoFill" ;;
    other) echo "Unsupported macOS architecture: $other" >&2; exit 1 ;;
  esac
fi
chmod 755 "$appex/Contents/MacOS/DeadboltAutoFill"

sed \
  -e "s|@VERSION@|$version|g" \
  -e "s|@BUILD@|$build|g" \
  "$src_dir/Info.plist.in" > "$appex/Contents/Info.plist"
plutil -lint "$appex/Contents/Info.plist" >/dev/null

if [[ -n ${DEADBOLT_AUTOFILL_PROVISION_PROFILE:-} ]]; then
  cp "$DEADBOLT_AUTOFILL_PROVISION_PROFILE" "$appex/Contents/embedded.provisionprofile"
fi

sign_id=${DEADBOLT_APPLE_SIGNING_IDENTITY:--}
if [[ $sign_id != "-" ]]; then
  team_id=${DEADBOLT_APPLE_TEAM_ID:-}
  if [[ -z $team_id && $sign_id =~ \(([A-Za-z0-9]{10})\)$ ]]; then
    team_id=${BASH_REMATCH[1]}
  fi
  [[ -n $team_id ]] || {
    echo "DEADBOLT_APPLE_SIGNING_IDENTITY ($sign_id) names no team: set DEADBOLT_APPLE_TEAM_ID." >&2
    exit 1
  }
  cat > "$scratch/autofill.entitlements" <<ENTITLEMENTS
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.developer.authentication-services.autofill-credential-provider</key>
    <true/>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>${team_id}.pw.deadbolt</string>
    </array>
</dict>
</plist>
ENTITLEMENTS
  plutil -lint "$scratch/autofill.entitlements" >/dev/null
  codesign --force --options runtime --timestamp \
    --identifier pw.deadbolt.app.autofill \
    --entitlements "$scratch/autofill.entitlements" \
    --sign "$sign_id" \
    "$appex"
else
  codesign --force --identifier pw.deadbolt.app.autofill --sign - "$appex"
fi

codesign --verify --strict "$appex"

mkdir -p "$(dirname "$out")"
mv "$appex" "$out"
echo "$out"
