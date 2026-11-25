//! Hides a route's real secrets should an upstream reflect them (an error
//! page echoing the request, a debug endpoint): each value, its URL
//! encoding (either case of hex) and its base64 become `*`s of the same
//! length, so a response's `Content-Length` stays true. Like
//! [`crate::secrets::Masker`], a value split across reads is held back until
//! the next read settles it.
//!
//! Base64 is matched inside longer encodings too (`base64("Bearer " +
//! token)`, a JSON blob holding the token): a value that starts 0, 1 or 2
//! bytes into a 3-byte group encodes to three different strings, so each
//! phase's characters that only the value's own bytes decide are a pattern,
//! in the standard and the URL-safe alphabets.

use zeroize::Zeroizing;

/// Values shorter than this aren't redacted: they'd match by chance.
const MIN_REDACTED: usize = 8;

/// `text` with each `%XX` escape's hex in lower case.
fn lower_escapes(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    let mut i = 0;
    while i < out.len() {
        if out[i] == b'%' {
            for b in out.iter_mut().skip(i + 1).take(2) {
                b.make_ascii_lowercase();
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

/// The characters of `value`'s encoding, `phase` bytes into a 3-byte group,
/// that only its own bytes decide: whatever comes before or after it in a
/// longer encoded text, these are there.
fn interior(encoding: &data_encoding::Encoding, value: &[u8], phase: usize) -> Zeroizing<Vec<u8>> {
    let mut shifted = Zeroizing::new(vec![0u8; phase]);
    shifted.extend_from_slice(value);
    let encoded = Zeroizing::new(encoding.encode(&shifted).into_bytes());
    // A leading pad byte shares its group's first 2 characters, two share 3.
    let start = [0, 2, 3][phase];
    // A partial last group's last character takes bits of the next byte.
    let end = encoded.len() - usize::from(!shifted.len().is_multiple_of(3));
    Zeroizing::new(encoded.get(start..end).unwrap_or_default().to_vec())
}

#[derive(Clone)]
pub struct Redactor {
    /// Longest first.
    patterns: Vec<Zeroizing<Vec<u8>>>,
    held: Zeroizing<Vec<u8>>,
}

impl Redactor {
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        for value in values {
            if value.len() < MIN_REDACTED {
                continue;
            }
            let url = Zeroizing::new(crate::secrets::url_encoded(value));
            let mut forms = vec![
                Zeroizing::new(value.as_bytes().to_vec()),
                Zeroizing::new(lower_escapes(&url)),
                Zeroizing::new(url.as_bytes().to_vec()),
            ];
            for encoding in [
                &data_encoding::BASE64_NOPAD,
                &data_encoding::BASE64URL_NOPAD,
            ] {
                forms.push(Zeroizing::new(
                    encoding.encode(value.as_bytes()).into_bytes(),
                ));
                forms.extend((0..3).map(|phase| interior(encoding, value.as_bytes(), phase)));
            }
            for form in forms {
                if form.len() >= MIN_REDACTED && !patterns.contains(&form) {
                    patterns.push(form);
                }
            }
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
        Self {
            patterns,
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// What of `chunk` (after what was held) can go out now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(chunk);
        self.scan(false)
    }

    /// The rest, at the end of the body.
    pub fn finish(&mut self) -> Vec<u8> {
        self.scan(true)
    }

    /// `bytes` redacted whole (a header value), or `None` if it held no
    /// secret.
    pub fn redact(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let mut one = self.clone();
        one.held = Zeroizing::new(Vec::new());
        let out = one
            .push(bytes)
            .into_iter()
            .chain(one.finish())
            .collect::<Vec<u8>>();
        (out != bytes).then_some(out)
    }

    fn scan(&mut self, end: bool) -> Vec<u8> {
        let buf = std::mem::replace(&mut self.held, Zeroizing::new(Vec::new()));
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        while i < buf.len() {
            let rest = &buf[i..];
            if !end
                && self
                    .patterns
                    .iter()
                    .any(|p| p.len() > rest.len() && p.starts_with(rest))
            {
                self.held.extend_from_slice(rest);
                break;
            }
            match self.patterns.iter().find(|p| rest.starts_with(p)) {
                Some(p) => {
                    out.resize(out.len() + p.len(), b'*');
                    i += p.len();
                }
                None => {
                    out.push(buf[i]);
                    i += 1;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn through(redactor: &mut Redactor, chunks: &[&str]) -> String {
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(redactor.push(chunk.as_bytes()));
        }
        out.extend(redactor.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn secrets_become_stars_of_the_same_length() {
        let secret = "sk-live-0123456789";
        let text = format!("echo: Bearer {secret}!");
        for at in 0..text.len() {
            let (a, b) = text.split_at(at);
            let mut redactor = Redactor::new([secret]);
            let out = through(&mut redactor, &[a, b]);
            assert_eq!(out.len(), text.len());
            assert_eq!(out, format!("echo: Bearer {}!", "*".repeat(secret.len())));
        }
        let redactor = Redactor::new([secret, "short"]);
        assert_eq!(redactor.redact(b"no secret here"), None);
        assert_eq!(redactor.redact(b"short"), None);
        let b64 = data_encoding::BASE64_NOPAD.encode(secret.as_bytes());
        assert_eq!(
            redactor.redact(b64.as_bytes()).unwrap(),
            "*".repeat(b64.len()).into_bytes()
        );
    }

    #[test]
    fn base64_of_a_secret_inside_a_longer_value_is_starred_at_every_phase() {
        let secret = "sk-real-token-0123456789abcdef";
        let redactor = Redactor::new([secret]);
        for prefix in ["", "B", "Be", "Bearer ", "user:", "{\"token\":\""] {
            for suffix in ["", "x", "xy", "\"}"] {
                let whole = format!("{prefix}{secret}{suffix}");
                for encoding in [&data_encoding::BASE64, &data_encoding::BASE64URL_NOPAD] {
                    let encoded = encoding.encode(whole.as_bytes());
                    let out = redactor
                        .redact(encoded.as_bytes())
                        .unwrap_or_else(|| panic!("{prefix:?}+{suffix:?} not redacted"));
                    assert_eq!(out.len(), encoded.len());
                    // Every character the secret's bits fill, but at most
                    // the two it shares with its neighbours, is starred.
                    let stars = out.iter().filter(|b| **b == b'*').count();
                    assert!(
                        stars >= (secret.len() * 4).div_ceil(3) - 2,
                        "{prefix:?}+{suffix:?}: {}",
                        String::from_utf8_lossy(&out)
                    );
                }
            }
        }
    }

    #[test]
    fn url_encoding_in_either_case_is_starred() {
        let secret = "real/secret+key0123456789";
        let redactor = Redactor::new([secret]);
        for encoded in [
            "real%2Fsecret%2Bkey0123456789",
            "real%2fsecret%2bkey0123456789",
        ] {
            let text = format!("echo={encoded}&x=1");
            let out = redactor.redact(text.as_bytes()).unwrap();
            assert_eq!(
                String::from_utf8(out).unwrap(),
                format!("echo={}&x=1", "*".repeat(encoded.len()))
            );
        }
    }
}
