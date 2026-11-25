//! Deadbolt for Swift, through UniFFI. `crates/app/scripts/build-autofill.sh`
//! links the static library into `DeadboltAutoFill.appex` and generates its
//! Swift bindings with `bindgen/`, UniFFI's generator at this crate's
//! `uniffi` version.
//!
//! With `client` (the default): the macOS AutoFill extension's side of the
//! App Group socket. One request per connection, line-delimited JSON in
//! [`deadbolt_proto::daemon`]'s schema, with a deadline and a
//! [`CallHandle`] that cancels at once, and the daemon's code checked by
//! [`deadbolt_client::peer::check`] before anything is sent to it. Swift
//! keeps only what needs AppKit or Foundation: finding its bundle and App
//! Group container, and launching the app.

uniffi::setup_scaffolding!();

#[cfg(feature = "client")]
mod autofill;
#[cfg(feature = "client")]
mod call;

#[cfg(feature = "client")]
pub use autofill::*;
#[cfg(feature = "client")]
pub use call::{CallHandle, CallOutcome, autofill_call};
