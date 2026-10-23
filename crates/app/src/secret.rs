//! Passphrase fields are Rune's secure `TextEdit`: dots on screen, no undo,
//! copy or cut, and the text zeroized when replaced or dropped. Two things
//! it still lets through are handled here: text typed with ⌘ or ⌃ held (the
//! space of an unclaimed ⇧⌘Space) and control characters, which a paste or
//! ⇧Enter put into what is a single line.

use rune::{Key, KeyEvent, TextEdit};
use zeroize::Zeroizing;

/// An empty passphrase field.
pub fn field() -> TextEdit {
    TextEdit::new("").secure()
}

/// Runs before the editor: true when `ev` is a chord that would type text,
/// so it types nothing.
// Rune gap: a TextEdit inserts ⌘/⌃ text chords. Remove when Rune lands `secure-input`.
pub fn chord(ev: &KeyEvent) -> bool {
    matches!(ev.key, Key::Text(_)) && (ev.mods.cmd || ev.mods.ctrl)
}

/// Runs after an edit: drops control characters, keeping the caret where it
/// was among the rest. The buffer is sized up front, so no partial copy is
/// left behind by a reallocation, and the old text is wiped by the swap.
// Rune gap: typing, ⇧⏎ and paste insert control characters. Remove when Rune lands `secure-input`.
pub fn tidy(field: &mut TextEdit) {
    if !field.text.contains(char::is_control) {
        return;
    }
    let printable = |s: &str| {
        s.chars()
            .filter(|c| !c.is_control())
            .map(char::len_utf8)
            .sum()
    };
    let caret: usize = printable(&field.text[..field.focus]);
    let mut clean = String::with_capacity(printable(&field.text));
    clean.extend(field.text.chars().filter(|c| !c.is_control()));
    field.replace_text(clean);
    field.anchor = caret;
    field.focus = caret;
}

/// Takes the passphrase out, leaving the field empty and still focused.
pub fn take(field: &mut TextEdit) -> Zeroizing<String> {
    let secret = Zeroizing::new(std::mem::take(&mut field.text));
    field.clear();
    secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune::Mods;

    #[test]
    fn chords_are_taken_and_plain_typing_is_not() {
        let text = |mods| KeyEvent {
            key: Key::Text(" ".into()),
            mods,
        };
        let cmd_shift = Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        };
        let ctrl = Mods {
            ctrl: true,
            ..Mods::default()
        };
        let alt = Mods {
            alt: true,
            ..Mods::default()
        };
        assert!(chord(&text(cmd_shift)));
        assert!(chord(&text(ctrl)));
        assert!(!chord(&text(alt)), "⌥ types accented letters");
        assert!(!chord(&text(Mods::default())));
        assert!(!chord(&KeyEvent {
            key: Key::Command('v'),
            mods: cmd_shift,
        }));
    }

    #[test]
    fn tidy_drops_controls_and_keeps_the_caret() {
        let mut f = field();
        f.paste("ab\tc\r\nd");
        f.focus = "ab\tc".len();
        f.anchor = f.focus;
        tidy(&mut f);
        assert_eq!(f.text, "abcd");
        assert_eq!(f.focus, "abc".len());
        assert!(f.is_secure());
    }

    #[test]
    fn take_empties_the_field() {
        let mut f = field();
        f.paste("hunter22");
        f.focused = true;
        assert_eq!(take(&mut f).as_str(), "hunter22");
        assert_eq!((f.text.as_str(), f.focus, f.anchor), ("", 0, 0));
        assert!(f.focused && f.is_secure());
    }
}
