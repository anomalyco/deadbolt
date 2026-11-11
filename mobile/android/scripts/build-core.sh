#!/usr/bin/env bash
# Cross-compiles crates/mobile-core for Android (arm64-v8a) and generates its
# UniFFI Kotlin bindings. Gradle runs this before every build (see
# app/build.gradle.kts); cargo keeps it incremental.
#
#   scripts/build-core.sh <kotlin-out-dir> <jnilibs-out-dir> [debug|release]
#
# Needs the Android NDK (ANDROID_NDK_HOME, or the newest one under
# $ANDROID_HOME/ndk) and `rustup target add aarch64-linux-android`.
set -euo pipefail

kotlin_out=${1:?kotlin output dir}
jni_out=${2:?jniLibs output dir}
profile=${3:-debug}

repo=$(cd "$(dirname "$0")/../../.." && pwd)
sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}
ndk=${ANDROID_NDK_HOME:-$(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -1)}
[[ -d $ndk ]] || { echo "build-core: no Android NDK (set ANDROID_NDK_HOME)" >&2; exit 1; }
case $(uname -s) in
  Darwin) host=darwin-x86_64 ;; # the NDK ships universal binaries under this name
  Linux) host=linux-x86_64 ;;
  *) echo "build-core: unsupported host $(uname -s)" >&2; exit 1 ;;
esac
bin=$ndk/toolchains/llvm/prebuilt/$host/bin
api=30 # keep in step with minSdk
target=aarch64-linux-android

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$bin/$target$api-clang
export CC_aarch64_linux_android=$bin/$target$api-clang
export CXX_aarch64_linux_android=$bin/$target$api-clang++
export AR_aarch64_linux_android=$bin/llvm-ar
export RANLIB_aarch64_linux_android=$bin/llvm-ranlib

cargo_flags=(-p deadbolt-mobile-core --lib --target "$target" --manifest-path "$repo/Cargo.toml")
[[ $profile == release ]] && cargo_flags+=(--release)
cargo build "${cargo_flags[@]}"

lib=$repo/target/$target/$profile/libdeadbolt_mobile_core.so
# UniFFI reads its metadata from the library's symbols, which release strips:
# take the bindings from a debug build in that case (the interface is the same).
meta=$lib
if [[ $profile == release ]]; then
  cargo build -p deadbolt-mobile-core --lib --target "$target" --manifest-path "$repo/Cargo.toml"
  meta=$repo/target/$target/debug/libdeadbolt_mobile_core.so
fi

rm -rf "$kotlin_out" "$jni_out"
mkdir -p "$kotlin_out" "$jni_out/arm64-v8a"
cargo run --quiet --manifest-path "$repo/Cargo.toml" -p deadbolt-mobile-core \
  --features bindings --bin deadbolt-mobile-bindgen -- \
  generate --library "$meta" --language kotlin --no-format --out-dir "$kotlin_out"
# Debug info only bloats the APK (the bindings were read from the unstripped file).
"$bin/llvm-strip" --strip-debug -o "$jni_out/arm64-v8a/libdeadbolt_mobile_core.so" "$lib"
