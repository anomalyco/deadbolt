#!/bin/sh
# Records holding ↓ then ↑ through the 243-item `vault-243` scene, headless,
# with the keys drawn: crates/app/scripts/hold-down.sh [OUT.mp4] [extra Rune flags...]
set -eu
cd "$(dirname "$0")/.."
out=${1:-hold-down.mp4}
[ $# -gt 0 ] && shift
# The app is built into `deadbolt`, and runs in-process as `deadbolt ui`.
bin=$(cargo build --release --quiet -p deadbolt-cli --message-format=json | sed -n 's/.*"executable":"\([^"]*\/deadbolt\)".*/\1/p' | tail -1)
app() { "$bin" ui "$@"; }
app --scene vault-243 --script scripts/hold-down.json --keys --video "$out" "$@"
