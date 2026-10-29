//! Text normalisation shared by clue phrases and page text, so both sides of a
//! match are always reduced the same way.
//!
//! - [`words`]: lowercase, accents folded, every run of anything but letters
//!   and digits turned into one space, padded with a space at each end
//!   (`" sign in "`), so a phrase matches on word boundaries.
//! - [`squash`]: the same without spaces (`"signin"`), the "sanitised" form.
//! - [`code_words`]: [`words`] for developer text, which also splits camelCase
//!   (`loginName` → `" login name "`).
//!
//! Han, kana and Hangul are not separated by spaces in running text, so a
//! phrase in those scripts matches anywhere ([`has_phrase`]). A Latin word
//! glued to CJK text (`Googleでログイン`) is split from it first.

/// Lowercase words separated by single spaces and padded: `" sign in "`.
/// An input with no letters or digits gives `" "`.
pub fn words(text: &str) -> String {
    normalise(text, false)
}

/// [`words`] for ids, names and classes: camelCase boundaries split words too.
pub fn code_words(text: &str) -> String {
    normalise(text, true)
}

/// Removes the spaces of a [`words`] string: `"signin"`.
pub fn squash(words: &str) -> String {
    words.chars().filter(|c| *c != ' ').collect()
}

/// True when `normalized` (a padded [`words`] string) contains `phrase` (an
/// unpadded [`words`] phrase) on word boundaries; CJK phrases match anywhere.
pub fn has_phrase(normalized: &str, phrase: &str) -> bool {
    if phrase.is_empty() {
        return false;
    }
    if phrase.chars().any(is_cjk) {
        normalized.contains(phrase)
    } else {
        normalized.contains(&format!(" {phrase} "))
    }
}

/// Han, Hiragana, Katakana or Hangul.
pub fn is_cjk(c: char) -> bool {
    matches!(c as u32,
        0x1100..=0x11FF       // Hangul Jamo
        | 0x3040..=0x309F     // Hiragana
        | 0x30A0..=0x30FF     // Katakana
        | 0x3130..=0x318F     // Hangul compatibility Jamo
        | 0x31F0..=0x31FF     // Katakana phonetic extensions
        | 0x3400..=0x4DBF     // CJK extension A
        | 0x4E00..=0x9FFF     // CJK unified ideographs
        | 0xAC00..=0xD7AF     // Hangul syllables
        | 0xF900..=0xFAFF     // CJK compatibility ideographs
        | 0xFF66..=0xFF9F     // Halfwidth katakana
        | 0x20000..=0x2FA1F) // CJK extensions B and later
}

fn is_latin_or_digit(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || (c.is_alphabetic() && (c as u32) < 0x0250)
        || matches!(c as u32, 0x1E00..=0x1EFF)
}

fn normalise(text: &str, split_camel: bool) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push(' ');
    let mut prev: Option<char> = None;
    // Whether the last character pushed was a separator (or the leading pad).
    let mut gap = true;
    let mut chars = text.chars().peekable();
    while let Some(raw) = chars.next() {
        let c = fullwidth(raw);
        if c.is_alphanumeric() && !is_mark(c) {
            if let Some(p) = prev
                && !gap
            {
                let script_break =
                    (is_latin_or_digit(p) && is_cjk(c)) || (is_cjk(p) && is_latin_or_digit(c));
                let camel = split_camel
                    && ((p.is_lowercase() && c.is_uppercase())
                        || (p.is_uppercase()
                            && c.is_uppercase()
                            && chars.peek().is_some_and(|n| n.is_lowercase())));
                if script_break || camel {
                    out.push(' ');
                }
            }
            for lower in c.to_lowercase() {
                if is_mark(lower) {
                    continue;
                }
                match fold(lower) {
                    Some(base) => out.push_str(base),
                    None => out.push(lower),
                }
            }
            gap = false;
            prev = Some(c);
        } else if is_mark(c) {
            // Combining accents of decomposed text are dropped, like folded ones.
        } else {
            if !gap {
                out.push(' ');
            }
            gap = true;
            prev = None;
        }
    }
    if !gap {
        out.push(' ');
    }
    out
}

/// Fullwidth ASCII (U+FF01..U+FF5E) to ASCII, as compatibility decomposition would.
fn fullwidth(c: char) -> char {
    match c as u32 {
        0xFF01..=0xFF5E => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
        _ => c,
    }
}

/// Combining diacritical marks.
fn is_mark(c: char) -> bool {
    matches!(c as u32, 0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

/// Base letters of accented Latin lowercase letters, as decomposition plus
/// dropping the marks would give. Letters that don't decompose (ø, ł, ß, æ) stay.
fn fold(c: char) -> Option<&'static str> {
    Some(match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' | 'ǎ' => "a",
        'ç' | 'ć' | 'ĉ' | 'ċ' | 'č' => "c",
        'ď' => "d",
        'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => "e",
        'ĝ' | 'ğ' | 'ġ' | 'ģ' => "g",
        'ĥ' => "h",
        'ì' | 'í' | 'î' | 'ï' | 'ĩ' | 'ī' | 'ĭ' | 'į' | 'ǐ' => "i",
        'ĵ' => "j",
        'ķ' => "k",
        'ĺ' | 'ļ' | 'ľ' | 'ŀ' => "l",
        'ñ' | 'ń' | 'ņ' | 'ň' => "n",
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ō' | 'ŏ' | 'ő' | 'ơ' | 'ǒ' => "o",
        'ŕ' | 'ŗ' | 'ř' => "r",
        'ś' | 'ŝ' | 'ş' | 'š' | 'ș' => "s",
        'ţ' | 'ť' | 'ț' => "t",
        'ù' | 'ú' | 'û' | 'ü' | 'ũ' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' | 'ư' | 'ǔ' => "u",
        'ŵ' => "w",
        'ý' | 'ÿ' | 'ŷ' => "y",
        'ź' | 'ż' | 'ž' => "z",
        // Vietnamese letters with two marks (Latin Extended Additional).
        '\u{1EA1}'..='\u{1EB7}' => "a",
        '\u{1EB9}'..='\u{1EC7}' => "e",
        '\u{1EC9}'..='\u{1ECB}' => "i",
        '\u{1ECD}'..='\u{1EE3}' => "o",
        '\u{1EE5}'..='\u{1EF1}' => "u",
        '\u{1EF3}'..='\u{1EF9}' => "y",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_lowercases_strips_and_pads() {
        assert_eq!(words("Sign In"), " sign in ");
        assert_eq!(words("  Current_Password!! "), " current password ");
        assert_eq!(words("E-mail address"), " e mail address ");
        assert_eq!(words("don't"), " don t ");
        assert_eq!(words("—"), " ");
        assert_eq!(words(""), " ");
    }

    #[test]
    fn folds_accents_both_precomposed_and_decomposed() {
        assert_eq!(words("Contraseña"), " contrasena ");
        assert_eq!(words("Contrasen\u{0303}a"), " contrasena ");
        assert_eq!(words("Mot de passe oublié ?"), " mot de passe oublie ");
        assert_eq!(words("Bestätigungscode"), " bestatigungscode ");
        assert_eq!(words("Đăng nhập"), " đang nhap ");
        assert_eq!(words("ＬＯＧＩＮ"), " login ");
    }

    #[test]
    fn cjk_is_split_from_latin_and_matches_anywhere() {
        assert_eq!(words("Googleでログイン"), " google でログイン ");
        assert!(has_phrase(&words("Googleでログイン"), "ログイン"));
        assert!(has_phrase(
            &words("パスワードを入力"),
            words("パスワード").trim()
        ));
        assert!(has_phrase(&words("사용자 이름"), "사용자 이름"));
    }

    #[test]
    fn latin_phrases_match_on_word_boundaries() {
        let text = words("Your password");
        assert!(has_phrase(&text, "password"));
        assert!(!has_phrase(&text, "pass"));
        assert!(!has_phrase(&words("Passport number"), "pass"));
        assert!(!has_phrase(&text, ""));
    }

    #[test]
    fn code_words_split_camel_case() {
        assert_eq!(code_words("loginName"), " login name ");
        assert_eq!(code_words("txtUserID"), " txt user id ");
        assert_eq!(code_words("HTMLInput"), " html input ");
        assert_eq!(code_words("user_pwd"), " user pwd ");
        assert_eq!(code_words("2faCode"), " 2fa code ");
        assert_eq!(squash(&code_words("signIn-Form")), "signinform");
    }
}
