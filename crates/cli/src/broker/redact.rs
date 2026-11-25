//! Hides a route's real secrets should an upstream reflect them (an error
//! page echoing the request, a debug endpoint): each value, its URL
//! encoding and its base64 become `*`s of the same length, so a
//! response's `Content-Length` stays true. Like [`crate::secrets::Masker`],
//! a value split across reads is held back until the next read settles it.

use zeroize::Zeroizing;

/// Values shorter than this aren't redacted: they'd match by chance.
const MIN_REDACTED: usize = 8;

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
            for form in [
                value.to_string(),
                crate::secrets::url_encoded(value),
                data_encoding::BASE64_NOPAD.encode(value.as_bytes()),
            ] {
                let form = Zeroizing::new(form.into_bytes());
                if !patterns.contains(&form) {
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
}
