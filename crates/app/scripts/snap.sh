#!/bin/sh
# Renders the app's scenes headless (offscreen, no window) to PNGs.
# Usage: crates/app/scripts/snap.sh [OUT] [extra Rune flags...]   (default OUT: crates/app/snaps)
set -eu
cd "$(dirname "$0")/.."
out=${1:-snaps}
[ $# -gt 0 ] && shift
mkdir -p "$out"
bin=$(cargo build --release --quiet -p deadbolt-app --message-format=json | sed -n 's/.*"executable":"\([^"]*deadbolt-app\)".*/\1/p' | tail -1)
for scene in locked locked-error vault search revealed empty setup failed; do
  "$bin" --scene "$scene" --snap "$out/$scene.png" "$@"
done
# The copy notice mid-countdown: 2.4 s after copying.
"$bin" --scene copied --at 2.4 --snap "$out/copied.png" "$@"
"$bin" --scene copied --at 2.4 --theme light --snap "$out/copied-light.png" "$@"
"$bin" --scene locked --theme light --snap "$out/locked-light.png" "$@"
