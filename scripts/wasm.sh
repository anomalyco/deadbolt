#!/bin/sh
# Builds a browser crate to WebAssembly and its JS glue:
#   scripts/wasm.sh <crate dir> <out dir>
# e.g. `scripts/wasm.sh crates/send-web site/src/receive/wasm` (the site's
# receive page) or `scripts/wasm.sh crates/ext-core extension/wasm` (the
# extension's `--standalone` build). Paths are relative to the repository
# root. Needs the wasm32-unknown-unknown target and wasm-bindgen-cli of the
# exact version the crate pins:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version <pinned> --locked
set -eu
if [ $# -ne 2 ]; then
  echo "usage: scripts/wasm.sh <crate dir> <out dir>" >&2
  exit 2
fi
crate=$1
out=$2
cd "$(dirname "$0")/.."
manifest="$crate/Cargo.toml"
if [ ! -f "$manifest" ]; then
  echo "$manifest does not exist" >&2
  exit 1
fi
PATH="$PATH:${CARGO_HOME:-$HOME/.cargo}/bin"
package=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$manifest" | head -n 1)
want=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' "$manifest")
if [ -z "$package" ] || [ -z "$want" ]; then
  echo "$manifest needs a package name and an exact wasm-bindgen pin (wasm-bindgen = \"=x.y.z\")" >&2
  exit 1
fi
have=$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2 || true)
if [ "$have" != "$want" ]; then
  echo "wasm-bindgen $want is needed (found: ${have:-none}):" >&2
  echo "  cargo install wasm-bindgen-cli --version $want --locked" >&2
  exit 1
fi
# Browser downloads favour size; keep the native release profile unchanged.
# Apply this to dependencies too, including the public-suffix lookup tables.
CARGO_PROFILE_RELEASE_OPT_LEVEL=z cargo build -p "$package" --target wasm32-unknown-unknown --release --locked
# Wherever cargo put it: CARGO_TARGET_DIR, a config's build.target-dir, or target/.
target=$(cargo metadata --format-version 1 --no-deps --locked | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
wasm-bindgen --target web --out-dir "$out" \
  "$target/wasm32-unknown-unknown/release/$(echo "$package" | tr - _).wasm"
