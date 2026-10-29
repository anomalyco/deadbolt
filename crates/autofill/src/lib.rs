//! Deadbolt's autofill engine: which fields of a page hold a username, a
//! password or a one-time code, and what each form is for.
//!
//! The engine is a pure function of a [`Snapshot`]: no DOM, no I/O, no clock
//! and no secrets, so the same snapshot always gives the same [`Analysis`].
//! The content script collects snapshots (without values); the engine runs
//! natively in tests and corpus replays, and later in the extension as wasm.
//!
//! - [`snapshot`]: the input model, with caps enforced on parse.
//! - [`text`]: normalisation shared by phrases and page text.
//! - [`clues`]: the TOML clue tables and their compiled matcher.
//! - [`classify`]: the passes, producing an [`Analysis`] with a trace of every
//!   contribution.
//!
//! See `README.md` for the design and how to add a clue.

pub mod classify;
pub mod clues;
pub mod snapshot;
pub mod text;

pub use classify::{
    Analysis, Contribution, Engine, FieldAnalysis, FieldType, FormKind, FrameAnalysis,
    GroupAnalysis,
};
pub use clues::{Rules, RulesError};
pub use snapshot::{Snapshot, SnapshotError};
