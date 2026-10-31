#!/bin/bash
# Run on macOS. Local builds: hivemind run --kind cargo --fetch .lab-output -- bash crates/app/scripts/bundle.sh
# CI can invoke this script directly. --universal requires both Rust Darwin targets.
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo 'Bundling requires macOS.' >&2; exit 1; }
universal=false
if [[ ${1:-} == --universal ]]; then universal=true; shift; fi
root=$(cd "$(dirname "$0")/../../.." && pwd)
# A relative output path is relative to where the script was run from.
out=${1:-$root/.lab-output/Deadbolt.app}
[[ $out == /* ]] || out="$PWD/$out"
[[ ! -e "$out" && ! -L "$out" ]] || { echo "Refusing to replace $out; choose a fresh output path." >&2; exit 1; }
cd "$root"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export MACOSX_DEPLOYMENT_TARGET=12.0
version=$(cargo +stable metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "deadbolt-cli"))')
# CFBundleVersion must be numeric: a dev build's run number, or X.Y.Z as XXYYZZ.
case "$version" in
  0.0.0-dev-*) build=${version#0.0.0-dev-}; build=${build%%.*} ;;
  *) build=$(printf '%s\n' "${version%%-*}" | awk -F. '{ print ($1 * 10000) + ($2 * 100) + $3 }') ;;
esac
target=$(cargo +stable metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
# One program: `deadbolt` with the app built in. Contents/MacOS/Deadbolt and
# Contents/Helpers/deadbolt are two copies of it, signed apart (the app as
# pw.deadbolt.app, the CLI and agent as deadbolt), so the agent tells the app
# from the CLI by signature and path; run as MacOS/Deadbolt it is only ever
# the app.
if $universal; then
  for arch in aarch64 x86_64; do
    cargo +stable build --release --locked -p deadbolt-cli --target "$arch-apple-darwin" -j 2
  done
  for bin in deadbolt deadbolt-enclave; do
    lipo -create "$target/aarch64-apple-darwin/release/$bin" "$target/x86_64-apple-darwin/release/$bin" -output "$scratch/$bin"
  done
else
  cargo +stable build --release --locked -p deadbolt-cli -j 2
  cp "$target/release/deadbolt" "$target/release/deadbolt-enclave" "$scratch/"
fi
app="$scratch/Deadbolt.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Resources"
cp "$scratch/deadbolt" "$app/Contents/MacOS/Deadbolt"
cp "$scratch/deadbolt" "$app/Contents/Helpers/deadbolt"
cp "$scratch/deadbolt-enclave" "$app/Contents/Helpers/deadbolt-enclave"
chmod 755 "$app/Contents/MacOS/Deadbolt" "$app/Contents/Helpers/deadbolt" "$app/Contents/Helpers/deadbolt-enclave"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Deadbolt</string>
<key>CFBundleDisplayName</key><string>Deadbolt</string>
<key>CFBundleIdentifier</key><string>pw.deadbolt.app</string>
<key>CFBundleExecutable</key><string>Deadbolt</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$build</string>
<key>CFBundleIconFile</key><string>Deadbolt</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict></plist>
PLIST
swift crates/app/scripts/icon.swift "$scratch/icon.png"
mkdir "$scratch/Deadbolt.iconset"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$scratch/icon.png" --out "$scratch/Deadbolt.iconset/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z "$double" "$double" "$scratch/icon.png" --out "$scratch/Deadbolt.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$scratch/Deadbolt.iconset" -o "$app/Contents/Resources/Deadbolt.icns"

if $universal; then
  bash crates/app/scripts/build-autofill.sh --universal "$scratch/DeadboltAutoFill.appex" "$version" "$build" >/dev/null
else
  bash crates/app/scripts/build-autofill.sh "$scratch/DeadboltAutoFill.appex" "$version" "$build" >/dev/null
fi

bundle_autofill=false
if [[ ${DEADBOLT_BUNDLE_AUTOFILL:-} == 1 ]]; then
  bundle_autofill=true
elif [[ ${DEADBOLT_BUNDLE_AUTOFILL:-} == 0 ]]; then
  bundle_autofill=false
elif [[ -n ${DEADBOLT_AUTOFILL_PROVISION_PROFILE:-} || -z ${DEADBOLT_ENCLAVE_PREBUILT:-} ]]; then
  bundle_autofill=true
fi
if $bundle_autofill; then
  mkdir -p "$app/Contents/PlugIns"
  cp -R "$scratch/DeadboltAutoFill.appex" "$app/Contents/PlugIns/DeadboltAutoFill.appex"
fi
if [[ -n ${DEADBOLT_APP_PROVISION_PROFILE:-} ]]; then
  cp "$DEADBOLT_APP_PROVISION_PROFILE" "$app/Contents/embedded.provisionprofile"
fi

# Nested executable first, outer seal last.
# Do NOT re-sign `Contents/Helpers/deadbolt-enclave` here: `crates/cli/build.rs`
# already signed it (or took the release workflow's Developer ID-signed helper
# from `DEADBOLT_ENCLAVE_PREBUILT`; docs/releasing.md) (using `DEADBOLT_APPLE_SIGNING_IDENTITY` with `--options runtime
# --timestamp` when set, or ad-hoc `-` otherwise) before embedding its whole-file
# SHA-256 (`DEADBOLT_ENCLAVE_SHA256`) into `deadbolt` (both copies). Re-signing `deadbolt-enclave`
# after `deadbolt` is compiled would alter its `__LINKEDIT` signature bytes and
# break the agent's SHA-256 verification.
sign_id=${DEADBOLT_APPLE_SIGNING_IDENTITY:--}
if [[ $sign_id != "-" ]]; then
  team_id=${DEADBOLT_APPLE_TEAM_ID:-}
  if [[ -z $team_id && $sign_id =~ \(([A-Za-z0-9]{10})\)$ ]]; then
    team_id=${BASH_REMATCH[1]}
  fi
  if [[ -n $team_id ]]; then
    cat > "$scratch/app.entitlements" <<ENTITLEMENTS
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.application-groups</key>
<array><string>${team_id}.pw.deadbolt</string></array>
</dict></plist>
ENTITLEMENTS
    plutil -lint "$scratch/app.entitlements" >/dev/null
    codesign --force --options runtime --timestamp --identifier deadbolt --entitlements "$scratch/app.entitlements" --sign "$sign_id" "$app/Contents/Helpers/deadbolt"
    codesign --force --options runtime --timestamp --entitlements "$scratch/app.entitlements" --sign "$sign_id" "$app"
  else
    codesign --force --options runtime --timestamp --identifier deadbolt --sign "$sign_id" "$app/Contents/Helpers/deadbolt"
    codesign --force --options runtime --timestamp --sign "$sign_id" "$app"
  fi
else
  codesign --force --identifier deadbolt --sign - "$app/Contents/Helpers/deadbolt"
  codesign --force --sign - "$app"
fi
plutil -lint "$app/Contents/Info.plist"
codesign --verify --strict "$app/Contents/Helpers/deadbolt-enclave"
if $bundle_autofill; then
  plutil -lint "$app/Contents/PlugIns/DeadboltAutoFill.appex/Contents/Info.plist"
  codesign --verify --strict "$app/Contents/PlugIns/DeadboltAutoFill.appex"
fi
codesign --verify --deep --strict "$app"
# The app pins the helper it ships: it is `deadbolt`, built against it.
helper="$app/Contents/Helpers/deadbolt-enclave"
if $universal; then slices="arm64 x86_64"; else slices=thin; fi
for slice in $slices; do
  if [[ $slice == thin ]]; then cp "$helper" "$scratch/helper-$slice"; else lipo "$helper" -thin "$slice" -output "$scratch/helper-$slice"; fi
  pin=$(shasum -a 256 "$scratch/helper-$slice" | cut -d' ' -f1)
  grep -aqF "$pin" "$app/Contents/MacOS/Deadbolt" || { echo "Deadbolt doesn't pin its $slice deadbolt-enclave ($pin)." >&2; exit 1; }
done
"$app/Contents/Helpers/deadbolt" --version
"$app/Contents/Helpers/deadbolt-enclave" status >/dev/null
"$app/Contents/MacOS/Deadbolt" --list-scenes >/dev/null
mkdir -p "$(dirname "$out")"
mv "$app" "$out"
echo "$out"
