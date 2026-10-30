//! The app's integration tests, one binary: each file here is a module, not
//! a test target of its own (AGENTS.md).

#![cfg(test)]

// Only agent, autofill, codes and import use it, and they run in debug builds only.
#[cfg(debug_assertions)]
mod support;

mod agent;
#[cfg(all(debug_assertions, target_os = "macos"))]
mod autofill;
mod codes;
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
