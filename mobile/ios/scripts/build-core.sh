#!/bin/sh
# Builds crates/mobile-core for iOS and writes what the Xcode project links:
#   mobile/ios/Generated/Bindings/DeadboltCore.swift      (UniFFI Swift)
#   mobile/ios/Generated/DeadboltMobileCore.xcframework   (static libs + FFI module)
#   mobile/ios/Generated/Fonts/*.ttf                      (Rune's fonts, from the pin)
#
# usage: build-core.sh [sim|device|all]   (default: all)
# PROFILE=release builds optimized libraries (default: debug).
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
ios="$root/mobile/ios"
gen="$ios/Generated"
which=${1:-all}
profile=${PROFILE:-debug}
cd "$root"

export IPHONEOS_DEPLOYMENT_TARGET=17.0
cargo_flags=""
[ "$profile" = release ] && cargo_flags="--release"

targets=""
case "$which" in
  sim) targets="aarch64-apple-ios-sim" ;;
  device) targets="aarch64-apple-ios" ;;
  all) targets="aarch64-apple-ios-sim aarch64-apple-ios" ;;
  *) echo "usage: build-core.sh [sim|device|all]" >&2; exit 2 ;;
esac

target_dir=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
for t in $targets; do
  case "$t" in
    aarch64-apple-ios-sim) min_version_flag="-mios-simulator-version-min=$IPHONEOS_DEPLOYMENT_TARGET" ;;
    aarch64-apple-ios) min_version_flag="-miphoneos-version-min=$IPHONEOS_DEPLOYMENT_TARGET" ;;
  esac
  # BLAKE3 tracks CFLAGS, but not IPHONEOS_DEPLOYMENT_TARGET. Include the
  # minimum here too so Cargo rebuilds C objects cached under another SDK.
  # shellcheck disable=SC2086
  CFLAGS="${CFLAGS:+$CFLAGS }$min_version_flag" \
    cargo build -p deadbolt-mobile-core --lib --target "$t" $cargo_flags
done

# Swift bindings come from the host build of the same crate (library mode).
rm -rf "$gen/uniffi" "$gen/Bindings" "$gen/include" "$gen/DeadboltMobileCore.xcframework"
mkdir -p "$gen/Bindings" "$gen/include"
proto_v=$(sed -n 's/^pub const PROTOCOL_VERSION: u32 = \([0-9][0-9]*\);$/\1/p' "$root/crates/client/src/protocol.rs")
[ -n "$proto_v" ] || { echo "Could not read PROTOCOL_VERSION" >&2; exit 1; }
printf 'public let generatedProtocolVersion: UInt32 = %s\n' "$proto_v" > "$gen/ProtocolVersion.swift"
sh crates/mobile-core/scripts/bindings.sh "$gen/uniffi"
cp "$gen/uniffi/DeadboltCore.swift" "$gen/Bindings/"
cp "$gen/uniffi/DeadboltCoreFFI.h" "$gen/include/"
cp "$gen/uniffi/DeadboltCoreFFI.modulemap" "$gen/include/module.modulemap"

set --
for t in $targets; do
  set -- "$@" -library "$target_dir/$t/$profile/libdeadbolt_mobile_core.a" -headers "$gen/include"
done
# Inter and IBM Plex Mono exactly as the pinned rune-theme-opencode ships them.
rune_theme=$(cargo metadata --format-version 1 --manifest-path crates/app/Cargo.toml | python3 -c '
import json, os, sys
for p in json.load(sys.stdin)["packages"]:
    if p["name"] == "rune-theme-opencode":
        print(os.path.dirname(p["manifest_path"]))
        break
')
rm -rf "$gen/Fonts"
mkdir -p "$gen/Fonts"
cp "$rune_theme/assets/fonts/InterVariable.ttf" "$rune_theme/assets/fonts/IBMPlexMono-Regular.ttf" \
  "$rune_theme/assets/fonts/IBMPlexMono-Medium.ttf" "$rune_theme"/assets/fonts/*-LICENSE.txt "$gen/Fonts/"

xcodebuild -create-xcframework "$@" -output "$gen/DeadboltMobileCore.xcframework"
echo "$gen/DeadboltMobileCore.xcframework"
