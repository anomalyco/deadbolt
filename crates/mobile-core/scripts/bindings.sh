#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
out=${1:?usage: bindings.sh OUT_DIR}
cargo build -p deadbolt-mobile-core
target=$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
case "$(uname -s)" in
  Darwin) lib="$target/debug/libdeadbolt_mobile_core.dylib" ;;
  Linux) lib="$target/debug/libdeadbolt_mobile_core.so" ;;
  *) echo "Generate bindings on macOS or Linux" >&2; exit 1 ;;
esac
cargo run -p deadbolt-mobile-core --features bindings --bin deadbolt-mobile-bindgen -- generate \
  --library "$lib" --language swift --language kotlin --no-format --out-dir "$out"
