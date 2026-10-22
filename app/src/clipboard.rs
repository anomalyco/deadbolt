//! Copying secrets: hidden from clipboard history, and cleared later only if
//! the clipboard still holds what we put there, so a later copy of the user's
//! own survives. Tests and headless runs use an in-memory clipboard so they
//! never touch the real one.

use std::hash::{BuildHasher, RandomState};
use std::sync::{Arc, Mutex};

pub struct Clipboard {
    /// Per-process keys for fingerprints.
    keys: RandomState,
    backend: Backend,
}

enum Backend {
    System,
    Memory(Arc<Mutex<Option<String>>>),
}

/// A fingerprint of what we copied, so the value itself needn't stay in
/// memory until the clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Copied(u64);

impl Clipboard {
    pub fn system() -> Clipboard {
        Clipboard {
            keys: RandomState::new(),
            backend: Backend::System,
        }
    }

    /// A clipboard that lives in the returned cell.
    pub fn memory() -> (Clipboard, Arc<Mutex<Option<String>>>) {
        let cell = Arc::new(Mutex::new(None));
        (
            Clipboard {
                keys: RandomState::new(),
                backend: Backend::Memory(cell.clone()),
            },
            cell,
        )
    }

    pub fn copy(&self, text: &str) -> Result<Copied, String> {
        match &self.backend {
            Backend::System => {
                let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
                let set = clipboard.set();
                #[cfg(target_os = "macos")]
                let set = arboard::SetExtApple::exclude_from_history(set);
                #[cfg(all(unix, not(target_os = "macos")))]
                let set = arboard::SetExtLinux::exclude_from_history(set);
                #[cfg(windows)]
                let set = arboard::SetExtWindows::exclude_from_history(set);
                set.text(text).map_err(|e| e.to_string())?;
            }
            Backend::Memory(cell) => {
                *cell.lock().unwrap_or_else(|e| e.into_inner()) = Some(text.into())
            }
        }
        Ok(Copied(self.keys.hash_one(text)))
    }

    /// Clears the clipboard if it still holds `copied`. True when it did.
    pub fn clear(&self, copied: Copied) -> bool {
        let ours = |text: &str| Copied(self.keys.hash_one(text)) == copied;
        match &self.backend {
            Backend::System => {
                let Ok(mut clipboard) = arboard::Clipboard::new() else {
                    return false;
                };
                clipboard.get_text().is_ok_and(|text| ours(&text)) && clipboard.clear().is_ok()
            }
            Backend::Memory(cell) => {
                let mut cell = cell.lock().unwrap_or_else(|e| e.into_inner());
                let mine = cell.as_deref().is_some_and(ours);
                if mine {
                    *cell = None;
                }
                mine
            }
        }
    }
}
