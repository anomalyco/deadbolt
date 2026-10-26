//! Time-based one-time passwords (RFC 6238) from the value of an `otp` field.
//!
//! A value is an `otpauth://totp/...` URI, of which only `secret`,
//! `algorithm`, `digits` and `period` matter, or a bare base32 secret
//! (spaces, lowercase and padding are fine) with the usual SHA-1, 6 digits
//! and 30 seconds.

use std::fmt;

use data_encoding::{BASE32_NOPAD, Encoding};
use hmac::{EagerHash, Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Why a value is not a TOTP secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    #[error("no secret")]
    NoSecret,
    #[error("the secret is not base32")]
    NotBase32,
    #[error("not an otpauth://totp URI")]
    NotTotpUri,
    #[error("counter-based (HOTP) codes are not supported")]
    Hotp,
    #[error("unsupported algorithm {0:?}: use SHA1, SHA256 or SHA512")]
    Algorithm(String),
    #[error("unsupported digits {0:?}: use 6 to 8")]
    Digits(String),
    #[error("invalid period {0:?}: use 1 to 3600 seconds")]
    Period(String),
}

/// A parsed TOTP secret. Wiped when dropped; `Debug` leaves the secret out.
#[derive(Clone, PartialEq, Eq)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

impl Totp {
    pub fn parse(value: &str) -> Result<Self, TotpError> {
        let value = value.trim();
        let Some((scheme, rest)) = value.split_once("://") else {
            return Self::new(base32(value)?, Algorithm::Sha1, 6, 30);
        };
        if !scheme.eq_ignore_ascii_case("otpauth") {
            return Err(TotpError::NotTotpUri);
        }
        let (kind, query) = rest.split_once('?').unwrap_or((rest, ""));
        let kind = kind.split('/').next().unwrap_or_default();
        if kind.eq_ignore_ascii_case("hotp") {
            return Err(TotpError::Hotp);
        }
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(TotpError::NotTotpUri);
        }
        let (mut secret, mut algorithm, mut digits, mut period) = (None, Algorithm::Sha1, 6, 30);
        for pair in query.split('&') {
            let (key, raw) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(raw);
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(base32(&value)),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().replace('-', "").as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(TotpError::Algorithm(value.to_string())),
                    }
                }
                "digits" => {
                    digits = value
                        .parse()
                        .ok()
                        .filter(|d| (6..=8).contains(d))
                        .ok_or_else(|| TotpError::Digits(value.to_string()))?;
                }
                "period" => {
                    period = value
                        .parse()
                        .ok()
                        .filter(|p| (1..=3600).contains(p))
                        .ok_or_else(|| TotpError::Period(value.to_string()))?;
                }
                _ => {}
            }
        }
        Self::new(
            secret.ok_or(TotpError::NoSecret)??,
            algorithm,
            digits,
            period,
        )
    }

    fn new(
        secret: Zeroizing<Vec<u8>>,
        algorithm: Algorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self, TotpError> {
        if secret.is_empty() {
            return Err(TotpError::NoSecret);
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
        })
    }

    /// Seconds each code lasts.
    pub fn period(&self) -> u64 {
        self.period
    }

    /// The code for `unix` seconds, zero-padded to the secret's digits.
    pub fn code(&self, unix: u64) -> String {
        let counter = (unix / self.period).to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::Sha1 => sign::<sha1::Sha1>(&self.secret, &counter),
            Algorithm::Sha256 => sign::<sha2::Sha256>(&self.secret, &counter),
            Algorithm::Sha512 => sign::<sha2::Sha512>(&self.secret, &counter),
        };
        let at = usize::from(mac[mac.len() - 1] & 0x0f);
        let bits =
            u32::from_be_bytes([mac[at], mac[at + 1], mac[at + 2], mac[at + 3]]) & 0x7fff_ffff;
        let code = bits % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// When the code for `unix` stops being valid, in unix seconds.
    pub fn valid_until(&self, unix: u64) -> u64 {
        (unix / self.period + 1) * self.period
    }
}

fn sign<D: EagerHash>(key: &[u8], message: &[u8]) -> Vec<u8>
where
    Hmac<D>: KeyInit + Mac,
{
    let mut mac = match <Hmac<D> as KeyInit>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC takes keys of any length"),
    };
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Base32 without padding that also accepts nonzero trailing bits, which
/// some issuers produce.
fn lenient() -> Encoding {
    let mut spec = BASE32_NOPAD.specification();
    spec.check_trailing_bits = false;
    match spec.encoding() {
        Ok(encoding) => encoding,
        Err(_) => unreachable!("a valid base32 specification"),
    }
}

fn base32(value: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let clean: Zeroizing<String> = Zeroizing::new(
        value
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    let trimmed = clean.trim_end_matches('=');
    if trimmed.is_empty() {
        return Err(TotpError::NoSecret);
    }
    lenient()
        .decode(trimmed.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| TotpError::NotBase32)
}

/// Decodes `%XX` escapes (two hex digits) and `+` as a space. Invalid
/// escapes stay as they are.
fn percent_decode(raw: &str) -> Zeroizing<String> {
    let bytes = raw.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        let hex = match bytes.get(i + 1..i + 3) {
            Some(&[a, b]) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => {
                Some(hex_digit(a) << 4 | hex_digit(b))
            }
            _ => None,
        };
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => (c | 0x20) - b'a' + 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(secret: &[u8], algorithm: &str) -> String {
        format!(
            "otpauth://totp/Example:dax?secret={}&algorithm={algorithm}&digits=8&period=30&issuer=Example",
            BASE32_NOPAD.encode(secret)
        )
    }

    /// RFC 6238 appendix B.
    #[test]
    fn rfc_6238_vectors() {
        let sha1 = Totp::parse(&uri(b"12345678901234567890", "SHA1")).unwrap();
        let sha256 = Totp::parse(&uri(b"12345678901234567890123456789012", "SHA256")).unwrap();
        let sha512 = Totp::parse(&uri(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            "SHA512",
        ))
        .unwrap();
        let vectors: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (time, a, b, c) in vectors {
            assert_eq!(sha1.code(time), a, "SHA1 at {time}");
            assert_eq!(sha256.code(time), b, "SHA256 at {time}");
            assert_eq!(sha512.code(time), c, "SHA512 at {time}");
        }
    }

    #[test]
    fn bare_secrets_default_to_six_digits_every_thirty_seconds() {
        let secret = BASE32_NOPAD.encode(b"12345678901234567890");
        let totp = Totp::parse(&secret).unwrap();
        assert_eq!(totp.code(59), "287082");
        assert_eq!(totp.period(), 30);
        assert_eq!(totp.valid_until(59), 60);
        assert_eq!(totp.valid_until(60), 90);
    }

    /// The code the desktop app's scenes show (`fixture_code`).
    #[test]
    fn the_app_scenes_code() {
        let totp = Totp::parse(&BASE32_NOPAD.encode(b"12345678901234567890")).unwrap();
        assert_eq!(totp.code(1_999_999_992), "279037");
        assert_eq!(totp.valid_until(1_999_999_992), 2_000_000_010);
    }

    /// An escape takes exactly two hex digits: "%+f" isn't one.
    #[test]
    fn percent_escapes_need_two_hex_digits() {
        assert_eq!(percent_decode("a%2Bb%2fc").as_str(), "a+b/c");
        for raw in ["%+f", "%-1", "% f", "%zz", "%4"] {
            assert_eq!(percent_decode(raw).as_str(), raw.replace('+', " "));
        }
    }

    #[test]
    fn bare_secrets_tolerate_spaces_lowercase_and_padding() {
        let canonical = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        for variant in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            " jbsw-y3dp-ehpk-3pxp ",
            "JBSWY3DPEHPK3PXP======",
        ] {
            assert_eq!(Totp::parse(variant).unwrap(), canonical, "{variant}");
        }
    }

    #[test]
    fn uris_ignore_label_issuer_and_case() {
        let canonical = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        for variant in [
            "otpauth://totp/GitHub:dax?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            "OTPAUTH://TOTP/x?SECRET=jbswy3dpehpk3pxp&Algorithm=sha1",
            "otpauth://totp/a%20b?issuer=A&secret=JBSW%20Y3DP+EHPK3PXP%3D%3D",
            "otpauth://totp?secret=JBSWY3DPEHPK3PXP&image=https://x.test/a.png",
        ] {
            assert_eq!(Totp::parse(variant).unwrap(), canonical, "{variant}");
        }
        let six = Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6&period=60");
        assert_eq!(six.unwrap().period(), 60);
    }

    #[test]
    fn rejects_malformed_values() {
        let cases = [
            ("", TotpError::NoSecret),
            ("   ", TotpError::NoSecret),
            ("====", TotpError::NoSecret),
            ("123456", TotpError::NotBase32),
            ("JBSWY3DPEHPK3P", TotpError::NotBase32),
            ("not a secret!", TotpError::NotBase32),
            (
                "https://example.com/?secret=JBSWY3DPEHPK3PXP",
                TotpError::NotTotpUri,
            ),
            (
                "otpauth://steam/x?secret=JBSWY3DPEHPK3PXP",
                TotpError::NotTotpUri,
            ),
            (
                "otpauth-migration://offline?data=abc",
                TotpError::NotTotpUri,
            ),
            (
                "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
                TotpError::Hotp,
            ),
            ("otpauth://totp/x?issuer=Example", TotpError::NoSecret),
            ("otpauth://totp/x?secret=", TotpError::NoSecret),
            ("otpauth://totp/x?secret=0189", TotpError::NotBase32),
            (
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
                TotpError::Algorithm("MD5".into()),
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10",
                TotpError::Digits("10".into()),
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=six",
                TotpError::Digits("six".into()),
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
                TotpError::Period("0".into()),
            ),
        ];
        for (value, error) in cases {
            assert_eq!(Totp::parse(value), Err(error), "{value:?}");
        }
    }

    #[test]
    fn debug_leaves_the_secret_out() {
        let debug = format!("{:?}", Totp::parse("JBSWY3DPEHPK3PXP").unwrap());
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("72") && !debug.contains("JBSW"));
    }
}
