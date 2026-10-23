//! Copying secrets: hidden from clipboard history, and cleared later only if
//! the clipboard still holds what we put there, so a later copy of the user's
//! own survives. Tests and headless runs use an in-memory clipboard so they
//! never touch the real one.
//!
//! One `Clipboard` per process, shared by every window (clones are handles to
//! it). Each copy gets the next id, and only the latest copy can be cleared on
//! its timer: a window whose copy another window has since replaced lets its
//! countdown go quietly.
//!
//! Not Rune's `Tx::copy_secret`: it can't clear early (lock), say whether a
//! copy is still the latest, or report a failed write (docs/app.md).

use std::hash::{BuildHasher, RandomState};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub struct Clipboard(Arc<Mutex<Owner>>);

struct Owner {
    /// Per-process keys for fingerprints.
    keys: RandomState,
    backend: Backend,
    /// The last copy's id; ids only go up.
    last: u64,
    /// The latest copy, until it's cleared.
    held: Option<Copied>,
}

enum Backend {
    /// Opened on first use and kept open: on X11 the process serves the
    /// selection, and closing the last handle takes the copy with it.
    System(Option<arboard::Clipboard>),
    Memory(Arc<Mutex<Option<String>>>),
}

/// One copy: its id, and a fingerprint of the text so the value itself
/// needn't stay in memory until the clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Copied {
    id: u64,
    print: u64,
}

impl Clipboard {
    pub fn system() -> Clipboard {
        Clipboard::with(Backend::System(None))
    }

    /// A clipboard that lives in the returned cell.
    pub fn memory() -> (Clipboard, Arc<Mutex<Option<String>>>) {
        let cell = Arc::new(Mutex::new(None));
        (Clipboard::with(Backend::Memory(cell.clone())), cell)
    }

    fn with(backend: Backend) -> Clipboard {
        Clipboard(Arc::new(Mutex::new(Owner {
            keys: RandomState::new(),
            backend,
            last: 0,
            held: None,
        })))
    }

    fn owner(&self) -> MutexGuard<'_, Owner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Puts `text` on the clipboard as the latest copy.
    pub fn copy(&self, text: &str) -> Result<Copied, String> {
        let mut owner = self.owner();
        match &mut owner.backend {
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
        owner.last += 1;
        let copied = Copied {
            id: owner.last,
            print: owner.keys.hash_one(text),
        };
        owner.held = Some(copied);
        Ok(copied)
    }

    /// Whether `copied` is still the latest copy and not yet cleared.
    pub fn holds(&self, copied: Copied) -> bool {
        self.owner().held == Some(copied)
    }

    /// `copied`'s time is up: clears the clipboard if `copied` is the latest
    /// copy and the clipboard still holds it. True when it did.
    pub fn clear(&self, copied: Copied) -> bool {
        let mut owner = self.owner();
        if owner.held != Some(copied) {
            return false;
        }
        owner.clear_held()
    }

    /// Lock or quit: clears the latest copy, whichever window made it, if the
    /// clipboard still holds it.
    pub fn clear_latest(&self) -> bool {
        self.owner().clear_held()
    }
}

impl Owner {
    fn clear_held(&mut self) -> bool {
        let Some(copied) = self.held.take() else {
            return false;
        };
        let keys = &self.keys;
        let ours = |text: &str| keys.hash_one(text) == copied.print;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_latest_copy_clears() {
        let (clipboard, cell) = Clipboard::memory();
        let other = clipboard.clone();
        let first = clipboard.copy("hunter2").unwrap();
        let second = other.copy("hunter2").unwrap();
        assert!(!clipboard.holds(first) && other.holds(second));
        assert!(!clipboard.clear(first), "a replaced copy can't clear");
        assert_eq!(cell.lock().unwrap().as_deref(), Some("hunter2"));
        assert!(other.clear(second));
        assert_eq!(*cell.lock().unwrap(), None);
    }

    #[test]
    fn a_lock_clears_the_latest_copy_from_any_handle() {
        let (clipboard, cell) = Clipboard::memory();
        let other = clipboard.clone();
        let copied = other.copy("hunter2").unwrap();
        assert!(clipboard.clear_latest());
        assert_eq!(*cell.lock().unwrap(), None);
        assert!(!other.holds(copied), "its countdown ends quietly");
        assert!(!other.clear(copied) && !clipboard.clear_latest());
    }

    #[test]
    fn a_copy_of_the_users_own_survives() {
        let (clipboard, cell) = Clipboard::memory();
        let copied = clipboard.copy("hunter2").unwrap();
        *cell.lock().unwrap() = Some("their own".into());
        assert!(!clipboard.clear(copied));
        assert!(!clipboard.clear_latest());
        assert_eq!(cell.lock().unwrap().as_deref(), Some("their own"));
    }
}
