//! Deadbolt's wire schemas, the one source of truth for both of its
//! protocols: pure data and serde, no IO.
//!
//! - [`daemon`]: the control protocol between clients (the CLI, the desktop
//!   app, the browser host, macOS AutoFill) and the daemon, line-delimited
//!   JSON over the daemon's Unix socket.
//! - [`browser`]: the native messaging protocol between the browser
//!   extension and `deadbolt browser-host`. Its TypeScript bindings,
//!   `extension/src/gen/proto.ts`, are generated from these types by
//!   `bun run gen:proto` (the `gen-ts` binary), and CI fails when they drift.
//!
//! The two protocols are versioned separately: each version changes only when
//! its own messages do.

pub mod browser;
pub mod daemon;
pub mod typescript;

/// The daemon control protocol's version, sent as `v` in every request and
/// as `protocol` in `status`. Clients and the daemon must speak the same
/// one; `deadbolt_client::ensure_running` replaces an older daemon and
/// refuses a newer one. Bump it on any change to [`daemon`]'s messages.
/// `crates/app/scripts/build-autofill.sh` reads this line to stamp the macOS
/// AutoFill extension, so keep it a plain literal.
pub const DAEMON_PROTOCOL_VERSION: u32 = 29;

/// The browser native messaging protocol's version, sent as `protocol` in
/// the host's `hello` reply and checked by the extension (`PROTOCOL` in
/// `extension/src/gen/proto.ts`). Bump it on a change to [`browser`]'s
/// messages that an extension of the old version would misread.
pub const BROWSER_PROTOCOL_VERSION: u32 = 3;
