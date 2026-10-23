//! A passphrase field. Rune's text field shows its `TextEdit`'s text and keeps
//! an undo history, so the field edits a mask of dots while the passphrase
//! lives here, zeroized on drop. Typing and deleting are handled before the
//! editor sees them; anything else that inserts text (paste, an IME commit)
//! is folded in afterwards and the mask's history is dropped.

use rune::{Key, KeyEvent, TextEdit};
use zeroize::{Zeroize, Zeroizing};

const DOT: char = '•';

#[derive(Default)]
pub struct SecretEdit {
    /// What the field shows and edits: one dot per character.
    pub mask: TextEdit,
    secret: Zeroizing<String>,
    /// Counts changes to the passphrase.
    edits: u64,
}

impl SecretEdit {
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Goes up whenever the passphrase changes.
    pub fn edits(&self) -> u64 {
        self.edits
    }

    pub fn is_empty(&self) -> bool {
        self.secret.is_empty()
    }

    /// Empties the field, keeping its focus.
    pub fn clear(&mut self) {
        self.secret.zeroize();
        self.set_mask(0);
    }

    /// Takes the passphrase out, leaving the field empty.
    pub fn take(&mut self) -> Zeroizing<String> {
        let secret = std::mem::take(&mut self.secret);
        self.set_mask(0);
        secret
    }

    /// Handles a key before the editor does; true when it was handled here.
    /// Copy, cut and undo do nothing, so the passphrase can't leave the field.
    pub fn key(&mut self, ev: &KeyEvent) -> bool {
        let (start, end) = self.selection();
        let word = ev.mods.alt || ev.mods.cmd;
        match &ev.key {
            Key::Text(s) if !ev.mods.cmd && !ev.mods.ctrl => {
                let s = printable(s.chars());
                if !s.is_empty() {
                    self.splice(start, end, &s);
                }
                true
            }
            Key::Backspace => {
                match (start != end, start) {
                    (true, _) => self.splice(start, end, ""),
                    (false, 0) => {}
                    (false, at) if word => self.splice(0, at, ""),
                    (false, at) => self.splice(at - 1, at, ""),
                }
                true
            }
            Key::Delete => {
                let len = self.secret.chars().count();
                match (start != end, end) {
                    (true, _) => self.splice(start, end, ""),
                    (false, at) if at == len => {}
                    (false, at) if word => self.splice(at, len, ""),
                    (false, at) => self.splice(at, at + 1, ""),
                }
                true
            }
            Key::Command('c' | 'x' | 'z' | 'y') => true,
            _ => false,
        }
    }

    /// Folds in an edit the editor made itself: the characters that aren't
    /// dots were just inserted and end at the caret. Control characters (a
    /// pasted line's trailing newline) are dropped, as when typing.
    pub fn reconcile(&mut self) {
        let chars: Zeroizing<Vec<char>> = Zeroizing::new(self.mask.text.chars().collect());
        let caret = char_index(&self.mask.text, self.mask.focus);
        let run = chars[..caret]
            .iter()
            .rev()
            .take_while(|c| **c != DOT)
            .count();
        let inserted = &chars[caret - run..caret];
        let old = self.secret.chars().count();
        let kept = chars.len() - run;
        if run == 0 && kept == old {
            return;
        }
        let start = caret - run;
        let removed = old.saturating_sub(kept);
        let with = printable(inserted.iter().copied());
        self.splice(start, (start + removed).min(old), &with);
    }

    /// The selection in characters, ordered.
    fn selection(&self) -> (usize, usize) {
        let a = char_index(&self.mask.text, self.mask.anchor);
        let b = char_index(&self.mask.text, self.mask.focus);
        (a.min(b), a.max(b))
    }

    /// Replaces characters `start..end` of the passphrase with `with`.
    fn splice(&mut self, start: usize, end: usize, with: &str) {
        let byte = |i: usize| {
            self.secret
                .char_indices()
                .nth(i)
                .map_or(self.secret.len(), |(b, _)| b)
        };
        let (from, to) = (byte(start), byte(end));
        let mut next = Zeroizing::new(String::with_capacity(self.secret.len() + with.len()));
        next.push_str(&self.secret[..from]);
        next.push_str(with);
        next.push_str(&self.secret[to..]);
        self.secret = next;
        self.edits += 1;
        self.set_mask(start + with.chars().count());
    }

    /// A fresh mask (no history) with the caret at character `caret`.
    fn set_mask(&mut self, caret: usize) {
        let focused = self.mask.focused;
        self.mask = TextEdit::new(DOT.to_string().repeat(self.secret.chars().count()));
        self.mask.focused = focused;
        self.mask.anchor = caret * DOT.len_utf8();
        self.mask.focus = self.mask.anchor;
    }
}

/// `chars` without control characters, in a buffer sized up front so no
/// partial copy is left behind by a reallocation.
fn printable(chars: impl Iterator<Item = char> + Clone) -> Zeroizing<String> {
    let len = chars.clone().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.extend(chars.filter(|c| !c.is_control()));
    out
}

/// The character index of byte offset `byte` in `text`.
fn char_index(text: &str, byte: usize) -> usize {
    text.char_indices().take_while(|(b, _)| *b < byte).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune::Mods;

    fn key(key: Key) -> KeyEvent {
        KeyEvent {
            key,
            mods: Mods::default(),
        }
    }

    fn typed(s: &str) -> SecretEdit {
        let mut field = SecretEdit::default();
        for c in s.chars() {
            assert!(field.key(&key(Key::Text(c.to_string()))));
        }
        field
    }

    #[test]
    fn shows_dots_and_keeps_the_passphrase() {
        let field = typed("hé llo");
        assert_eq!(field.secret(), "hé llo");
        assert_eq!(field.mask.text, "••••••");
        assert_eq!(field.mask.focus, field.mask.text.len());
    }

    #[test]
    fn deletes_at_the_caret_and_over_selections() {
        let mut field = typed("abcd");
        field.mask.anchor = DOT.len_utf8();
        field.mask.focus = DOT.len_utf8();
        field.key(&key(Key::Backspace));
        assert_eq!(field.secret(), "bcd");
        field.key(&key(Key::Delete));
        assert_eq!(field.secret(), "cd");
        field.mask.anchor = 0;
        field.mask.focus = field.mask.text.len();
        field.key(&key(Key::Text("x".into())));
        assert_eq!(field.secret(), "x");
        assert_eq!(field.mask.text, "•");
    }

    #[test]
    fn copy_cut_and_undo_do_nothing() {
        let mut field = typed("secret");
        for c in ['c', 'x', 'z'] {
            assert!(field.key(&KeyEvent {
                key: Key::Command(c),
                mods: Mods {
                    cmd: true,
                    ..Mods::default()
                }
            }));
        }
        assert_eq!(field.secret(), "secret");
    }

    #[test]
    fn folds_in_pasted_text_at_the_caret() {
        let mut field = typed("ad");
        field.mask.anchor = DOT.len_utf8();
        field.mask.focus = DOT.len_utf8();
        field.mask.paste("bc");
        field.reconcile();
        assert_eq!(field.secret(), "abcd");
        assert_eq!(field.mask.text, "••••");
        assert_eq!(field.mask.focus, 3 * DOT.len_utf8());
    }

    #[test]
    fn pasted_line_breaks_and_controls_are_dropped() {
        let mut field = typed("a");
        field.mask.paste("b\tc\r\n");
        field.reconcile();
        assert_eq!(field.secret(), "abc");
        assert_eq!(field.mask.text, "•••");
    }

    #[test]
    fn edits_count_changes_only() {
        let mut field = typed("ab");
        let edits = field.edits();
        field.key(&key(Key::Command('c')));
        assert_eq!(field.edits(), edits);
        field.key(&key(Key::Backspace));
        assert!(field.edits() > edits);
    }

    #[test]
    fn pasting_over_a_selection_replaces_it() {
        let mut field = typed("abcd");
        field.mask.anchor = DOT.len_utf8();
        field.mask.focus = 3 * DOT.len_utf8();
        field.mask.paste("XY");
        field.reconcile();
        assert_eq!(field.secret(), "aXYd");
    }
}
