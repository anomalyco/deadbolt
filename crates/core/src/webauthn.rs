//! WebAuthn authenticator crypto for passkeys: ES256 (P-256) keys, `none`
//! attestation, client data and the canonical CBOR WebAuthn needs. Only the
//! vault adapters call it; private keys never leave them (see docs/autofill.md).
//!
//! Adapted from Foyer (github.com/R44VC0RP/foyer, bridge/webauthn.ts, by
//! Ryan Vogel): the flags, the zero sign counter, a fixed AAGUID, 16-byte
//! random credential ids and PKCS#8 storage follow it.

use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// COSE algorithm id of ES256, the only one Deadbolt signs with.
pub const ES256: i64 = -7;

/// Identifies passkeys made by Deadbolt (random, chosen once).
pub const AAGUID: [u8; 16] = [
    0x3a, 0x31, 0xec, 0xda, 0xfe, 0xfc, 0xf2, 0x51, 0x1f, 0x3e, 0xa1, 0x1b, 0xfd, 0xc1, 0xde, 0x5f,
];

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

/// The longest challenge taken, in base64url characters.
const MAX_CHALLENGE: usize = 1024;
/// The longest user handle WebAuthn allows, in bytes.
pub const MAX_USER_HANDLE: usize = 64;

pub fn b64(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// Base64url without padding, as WebAuthn JSON writes it; padding is
/// tolerated.
pub fn unb64(text: &str) -> Result<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(text.trim_end_matches('=').as_bytes())
        .map_err(|_| Error::Invalid("not base64url"))
}

/// A WebAuthn challenge as the page gave it: base64url, 16 bytes or more.
pub fn challenge(text: &str) -> Result<&str> {
    if text.len() > MAX_CHALLENGE || unb64(text)?.len() < 16 || text.contains('=') {
        return Err(Error::Invalid(
            "a challenge is 16 or more bytes of base64url",
        ));
    }
    Ok(text)
}

/// A user handle: 1 to 64 bytes of base64url.
pub fn user_handle(text: &str) -> Result<Vec<u8>> {
    if text.len() > MAX_USER_HANDLE.div_ceil(3) * 4 {
        return Err(Error::Invalid("a user handle is 1 to 64 bytes"));
    }
    let bytes = unb64(text)?;
    if bytes.is_empty() || bytes.len() > MAX_USER_HANDLE {
        return Err(Error::Invalid("a user handle is 1 to 64 bytes"));
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Create,
    Get,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    challenge: &'a str,
    origin: &'a str,
    cross_origin: bool,
}

/// `clientDataJSON` for a ceremony on the page at `origin`, in the order
/// and form WebAuthn's own serialization uses. Cross-origin frames are
/// left to the browser, so `crossOrigin` is always false.
pub fn client_data(ceremony: Ceremony, challenge: &str, origin: &str) -> Result<Vec<u8>> {
    let data = ClientData {
        kind: match ceremony {
            Ceremony::Create => "webauthn.create",
            Ceremony::Get => "webauthn.get",
        },
        challenge: self::challenge(challenge)?,
        origin,
        cross_origin: false,
    };
    Ok(serde_json::to_vec(&data)?)
}

/// Flags for authenticator data: user present, backup eligible and backed
/// up (a vault syncs), user verified only if `verified`, attested data on
/// creation.
pub fn flags(verified: bool, attested: bool) -> u8 {
    UP | BE | BS | if verified { UV } else { 0 } | if attested { AT } else { 0 }
}

/// A new passkey's key and credential id.
pub struct NewKey {
    pub credential_id: Vec<u8>,
    /// PKCS#8 DER.
    pub private_key: Zeroizing<Vec<u8>>,
}

pub fn generate() -> Result<NewKey> {
    let key = SigningKey::generate();
    let der = key
        .to_pkcs8_der()
        .map_err(|_| Error::Invalid("encoding a passkey key"))?;
    let mut credential_id = vec![0u8; 16];
    getrandom::fill(&mut credential_id)
        .map_err(|_| Error::Invalid("OS random number generator failed"))?;
    Ok(NewKey {
        credential_id,
        private_key: Zeroizing::new(der.as_bytes().to_vec()),
    })
}

fn signing_key(private_key: &[u8]) -> Result<SigningKey> {
    SigningKey::from_pkcs8_der(private_key)
        .map_err(|_| Error::Invalid("the stored passkey key is unreadable"))
}

/// What a registration returns besides client data.
pub struct Attestation {
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    /// SubjectPublicKeyInfo DER.
    pub public_key: Vec<u8>,
}

/// Authenticator data with attested credential data and a `none`
/// attestation object for a new passkey.
pub fn attest(
    rp_id: &str,
    credential_id: &[u8],
    private_key: &[u8],
    verified: bool,
) -> Result<Attestation> {
    let key = signing_key(private_key)?;
    let public = key.verifying_key();
    let point = public.to_sec1_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(Error::Invalid("a passkey's public key has no coordinates"));
    };
    let cose = cbor::encode(&cbor::Value::Map(vec![
        (cbor::Value::Int(1), cbor::Value::Int(2)),
        (cbor::Value::Int(3), cbor::Value::Int(ES256)),
        (cbor::Value::Int(-1), cbor::Value::Int(1)),
        (cbor::Value::Int(-2), cbor::Value::Bytes(x.to_vec())),
        (cbor::Value::Int(-3), cbor::Value::Bytes(y.to_vec())),
    ]));
    let length =
        u16::try_from(credential_id.len()).map_err(|_| Error::Invalid("credential id too long"))?;
    let mut data = auth_data(rp_id, flags(verified, true));
    data.extend_from_slice(&AAGUID);
    data.extend_from_slice(&length.to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&cose);
    let object = cbor::encode(&cbor::Value::Map(vec![
        (cbor::Value::text("fmt"), cbor::Value::text("none")),
        (cbor::Value::text("attStmt"), cbor::Value::Map(Vec::new())),
        (
            cbor::Value::text("authData"),
            cbor::Value::Bytes(data.clone()),
        ),
    ]));
    let spki = public
        .to_public_key_der()
        .map_err(|_| Error::Invalid("encoding a passkey's public key"))?;
    Ok(Attestation {
        authenticator_data: data,
        attestation_object: object,
        public_key: spki.as_bytes().to_vec(),
    })
}

/// An assertion: authenticator data and the DER ECDSA signature over it
/// and the SHA-256 of `client_data`.
pub fn assert(
    rp_id: &str,
    private_key: &[u8],
    client_data: &[u8],
    verified: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = signing_key(private_key)?;
    let data = auth_data(rp_id, flags(verified, false));
    let mut signed = data.clone();
    signed.extend_from_slice(&Sha256::digest(client_data));
    let signature: DerSignature = key.sign(&signed);
    Ok((data, signature.as_bytes().to_vec()))
}

/// The rpIdHash, flags and a sign counter of zero: a passkey in a synced
/// vault keeps no counter (see docs/autofill.md).
fn auth_data(rp_id: &str, flags: u8) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&[0; 4]);
    data
}

/// The subset of CBOR WebAuthn needs, in the core deterministic encoding of
/// RFC 8949 §4.2.1: shortest heads, map keys sorted by their encoding.
pub mod cbor {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        Int(i64),
        Bytes(Vec<u8>),
        Text(String),
        Map(Vec<(Value, Value)>),
    }

    impl Value {
        pub fn text(s: &str) -> Self {
            Self::Text(s.into())
        }
    }

    fn head(out: &mut Vec<u8>, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..=23 => out.push(major | value as u8),
            24..=0xff => out.extend_from_slice(&[major | 24, value as u8]),
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(major | 26);
                out.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                out.push(major | 27);
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
    }

    fn write(out: &mut Vec<u8>, value: &Value) {
        match value {
            Value::Int(n) if *n >= 0 => head(out, 0, n.unsigned_abs()),
            Value::Int(n) => head(out, 1, (-1 - *n).unsigned_abs()),
            Value::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                head(out, 3, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Map(entries) => {
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (encode(k), encode(v)))
                    .collect();
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                encoded.dedup_by(|a, b| a.0 == b.0);
                head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
        }
    }

    pub fn encode(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut out, value);
        out
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    use super::cbor::{Value, encode};
    use super::*;

    #[test]
    fn cbor_is_canonical() {
        assert_eq!(encode(&Value::Int(0)), [0x00]);
        assert_eq!(encode(&Value::Int(23)), [0x17]);
        assert_eq!(encode(&Value::Int(24)), [0x18, 24]);
        assert_eq!(encode(&Value::Int(256)), [0x19, 1, 0]);
        assert_eq!(encode(&Value::Int(65_536)), [0x1a, 0, 1, 0, 0]);
        assert_eq!(encode(&Value::Int(1 << 32)), [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(encode(&Value::Int(-1)), [0x20]);
        assert_eq!(encode(&Value::Int(-7)), [0x26]);
        assert_eq!(encode(&Value::Int(-25)), [0x38, 24]);
        assert_eq!(encode(&Value::Int(i64::MIN))[0], 0x3b);
        assert_eq!(encode(&Value::text("fmt")), b"\x63fmt");
        assert_eq!(encode(&Value::Bytes(vec![1, 2])), [0x42, 1, 2]);
        // Keys sorted by encoding, so shorter first, then bytewise: 1, 3, -1, -2.
        let map = Value::Map(vec![
            (Value::Int(-2), Value::Int(0)),
            (Value::text("a"), Value::Int(0)),
            (Value::Int(3), Value::Int(0)),
            (Value::Int(-1), Value::Int(0)),
            (Value::Int(1), Value::Int(0)),
        ]);
        assert_eq!(
            encode(&map),
            [0xa5, 0x01, 0, 0x03, 0, 0x20, 0, 0x21, 0, 0x61, b'a', 0]
        );
        // Shorter keys first: fmt, attStmt, authData.
        let none = encode(&Value::Map(vec![
            (Value::text("authData"), Value::Bytes(vec![])),
            (Value::text("fmt"), Value::text("none")),
            (Value::text("attStmt"), Value::Map(vec![])),
        ]));
        assert_eq!(
            none,
            b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x40".to_vec()
        );
    }

    #[test]
    fn client_data_is_built_in_webauthn_order() {
        let challenge = b64(&[7; 32]);
        let data = client_data(Ceremony::Get, &challenge, "https://github.com").unwrap();
        assert_eq!(
            String::from_utf8(data).unwrap(),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://github.com","crossOrigin":false}}"#
            )
        );
        let data = client_data(Ceremony::Create, &challenge, "http://localhost:3000").unwrap();
        assert!(
            String::from_utf8(data)
                .unwrap()
                .starts_with(r#"{"type":"webauthn.create""#)
        );
        for bad in [
            "",
            "AAAA",
            "not base64!",
            &format!("{challenge}=="),
            &"A".repeat(2000),
        ] {
            assert!(
                client_data(Ceremony::Get, bad, "https://github.com").is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn flags_say_verified_only_when_verified() {
        assert_eq!(flags(false, false), 0x19);
        assert_eq!(flags(true, false), 0x1d);
        assert_eq!(flags(false, true), 0x59);
        assert_eq!(flags(true, true), 0x5d);
        assert_eq!(flags(false, true) & UV, 0);
    }

    fn parse_cose(cose: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // a5 01 02 03 26 20 01 21 58 20 <x> 22 58 20 <y>
        assert_eq!(
            &cose[..10],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        (cose[10..42].to_vec(), cose[45..77].to_vec())
    }

    #[test]
    fn registration_carries_the_key_and_assertions_verify() {
        let key = generate().unwrap();
        assert_eq!(key.credential_id.len(), 16);
        let made = attest("github.com", &key.credential_id, &key.private_key, false).unwrap();

        let data = &made.authenticator_data;
        assert_eq!(&data[..32], Sha256::digest(b"github.com").as_slice());
        assert_eq!(data[32], UP | BE | BS | AT);
        assert_eq!(&data[33..37], &[0; 4], "the sign counter is zero");
        assert_eq!(&data[37..53], &AAGUID);
        assert_eq!(&data[53..55], &[0, 16]);
        assert_eq!(&data[55..71], key.credential_id.as_slice());
        let (x, y) = parse_cose(&data[71..]);
        assert_eq!(data.len(), 71 + 77);

        let spki = VerifyingKey::from_public_key_der(&made.public_key).unwrap();
        let point = spki.to_sec1_point(false);
        assert_eq!(point.x().unwrap().as_slice(), x.as_slice());
        assert_eq!(point.y().unwrap().as_slice(), y.as_slice());

        let mut object = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58".to_vec();
        object.push(u8::try_from(data.len()).unwrap());
        object.extend_from_slice(data);
        assert_eq!(made.attestation_object, object);

        let client = client_data(Ceremony::Get, &b64(&[1; 32]), "https://github.com").unwrap();
        let (auth, signature) = assert("github.com", &key.private_key, &client, true).unwrap();
        assert_eq!(auth.len(), 37);
        assert_eq!(auth[32], UP | UV | BE | BS);
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature = Signature::from_der(&signature).unwrap();
        assert!(spki.verify(&signed, &signature).is_ok());
        // Another relying party's data or other client data doesn't verify.
        let mut other = signed.clone();
        other[0] ^= 1;
        assert!(spki.verify(&other, &signature).is_err());
        assert!(assert("github.com", b"not a key", &client, false).is_err());
    }

    #[test]
    fn user_handles_and_base64url() {
        assert_eq!(unb64("AQI").unwrap(), [1, 2]);
        assert_eq!(unb64("AQI=").unwrap(), [1, 2]);
        assert!(unb64("AQ+/").is_err());
        assert!(user_handle("").is_err());
        assert!(user_handle(&b64(&[0; 65])).is_err());
        assert_eq!(user_handle(&b64(&[9; 64])).unwrap().len(), 64);
    }
}
