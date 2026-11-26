//! The app's integration tests, one binary: each file here is a module, not
//! a test target of its own (AGENTS.md).

#![cfg(test)]

// Counts each thread's allocations, so `budget` can hold the hot paths to a ceiling.
#[global_allocator]
static ALLOC: procwatch::alloc::Counting = procwatch::alloc::Counting::system();

// Only daemon, autofill, codes and import use it, and they run in debug builds only.
#[cfg(debug_assertions)]
mod support;

mod deadbolt;

#[cfg(all(debug_assertions, target_os = "macos"))]
mod autofill;
mod budget;
mod codes;
mod daemon;
mod edit;
mod health;
mod import;
mod install;
mod instant;
mod keymap;
mod keys;
mod labels;
mod motion;
mod onboarding;
mod panel;
mod place;
mod shortcut;
mod tags;
// DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
mod upgrade;
