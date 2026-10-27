#!/bin/sh
# Builds the receive page's WebAssembly (crates/send-web) into src/receive/wasm.
# Needs the wasm32-unknown-unknown target and wasm-bindgen-cli of the version
# crates/send-web pins:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version <pinned> --locked
set -eu
cd "$(dirname "$0")/../.."
PATH="$PATH:${CARGO_HOME:-$HOME/.cargo}/bin"
want=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' crates/send-web/Cargo.toml)
have=$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2 || true)
if [ "$have" != "$want" ]; then
  echo "wasm-bindgen $want is needed (found: ${have:-none}):" >&2
  echo "  cargo install wasm-bindgen-cli --version $want --locked" >&2
  exit 1
fi
cargo build -p deadbolt-send-web --target wasm32-unknown-unknown --release --locked
wasm-bindgen --target web --out-dir site/src/receive/wasm \
  target/wasm32-unknown-unknown/release/deadbolt_send_web.wasm
