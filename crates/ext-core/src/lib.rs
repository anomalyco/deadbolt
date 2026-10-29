//! The standalone extension device: the Rust vault, encrypted store and sync
//! in a browser worker (`device`, wasm only), and the rules it keeps that
//! the host can test (`policy`).

pub mod policy;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod device;
