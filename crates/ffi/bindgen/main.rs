//! `uniffi-bindgen generate --library libdeadbolt_ffi.a --language swift
//! --out-dir <dir>`: the Swift bindings for deadbolt-ffi.

fn main() {
    uniffi::uniffi_bindgen_main();
}
