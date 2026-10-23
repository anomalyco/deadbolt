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
version=$(cargo +stable metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "deadbolt-app"))')
target=$(cargo +stable metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
if $universal; then
  for arch in aarch64 x86_64; do
    cargo +stable build --release --locked -p deadbolt-cli -p deadbolt-app --target "$arch-apple-darwin" -j 2
  done
  for bin in deadbolt deadbolt-app; do
    lipo -create "$target/aarch64-apple-darwin/release/$bin" "$target/x86_64-apple-darwin/release/$bin" -output "$scratch/$bin"
  done
else
  cargo +stable build --release --locked -p deadbolt-cli -p deadbolt-app -j 2
  cp "$target/release/deadbolt" "$target/release/deadbolt-app" "$scratch/"
fi
app="$scratch/Deadbolt.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Resources"
cp "$scratch/deadbolt-app" "$app/Contents/MacOS/Deadbolt"
cp "$scratch/deadbolt" "$app/Contents/Helpers/deadbolt"
chmod 755 "$app/Contents/MacOS/Deadbolt" "$app/Contents/Helpers/deadbolt"
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
<key>CFBundleVersion</key><string>$version</string>
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
# Nested executable first, outer seal last. Development-only ad-hoc signature.
codesign --force --sign - "$app/Contents/Helpers/deadbolt"
codesign --force --sign - "$app"
plutil -lint "$app/Contents/Info.plist"
codesign --verify --deep --strict "$app"
"$app/Contents/Helpers/deadbolt" --version
"$app/Contents/MacOS/Deadbolt" --list-scenes >/dev/null
mkdir -p "$(dirname "$out")"
mv "$app" "$out"
echo "$out"
