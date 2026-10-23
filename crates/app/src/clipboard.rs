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
    /// Opened on first use and kept open: on X11 the process serves the
    /// selection, and closing the last handle takes the copy with it.
    System(Option<arboard::Clipboard>),
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
            backend: Backend::System(None),
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

    pub fn copy(&mut self, text: &str) -> Result<Copied, String> {
        match &mut self.backend {
            Backend::System(open) => {
                let clipboard = system(open)?;
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
    pub fn clear(&mut self, copied: Copied) -> bool {
        let keys = &self.keys;
        let ours = |text: &str| Copied(keys.hash_one(text)) == copied;
        match &mut self.backend {
            Backend::System(open) => {
                let Ok(clipboard) = system(open) else {
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

fn system(open: &mut Option<arboard::Clipboard>) -> Result<&mut arboard::Clipboard, String> {
    if open.is_none() {
        *open = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
    }
    open.as_mut().ok_or_else(|| "no clipboard".to_owned())
}
