#!/bin/sh
# Builds the receive page's WebAssembly (crates/send-web) into src/receive/wasm
# with the repository's shared wasm build (scripts/wasm.sh, which lists what
# it needs).
set -eu
exec sh "$(dirname "$0")/../../scripts/wasm.sh" crates/send-web site/src/receive/wasm
