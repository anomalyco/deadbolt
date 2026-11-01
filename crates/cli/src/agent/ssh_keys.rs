//! SSH key items: generating keys and reading the public key, fingerprint and
//! comment of a private key (`Command::SshGenerate`, `Command::SshInspect`,
//! and the derived fields of an `ssh` item).
//!
//! Private keys parse from OpenSSH PEM (plain or `bcrypt` encrypted), PKCS#8
//! PEM (plain or PBES2 encrypted, as 1Password exports them), PKCS#1 RSA PEM
//! and SEC1 EC PEM.

use anyhow::{Result, anyhow, bail};
use der::Reader as _;
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use ssh_key::getrandom::SysRng;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::RsaPublicKey;
use ssh_key::rand_core::UnwrapErr;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, Mpint, PrivateKey};
use zeroize::Zeroizing;

use super::Agent;
use crate::protocol::{Reply, Secret, SshKeyKind};

/// Key algorithms Deadbolt generates for new `ssh` items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519,
    EcdsaP256,
}

/// A newly generated or normalized SSH key item's fields.
pub struct GeneratedKey {
    /// Unencrypted OpenSSH PEM (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    pub private_key: Zeroizing<String>,
    /// OpenSSH `authorized_keys` line (`<alg> <base64>[ <comment>]`).
    pub public_key: String,
    /// `SHA256:<unpadded-base64>`.
    pub fingerprint: String,
    pub comment: Option<String>,
}

/// A parsed SSH key pair in zeroized memory.
pub struct ParsedKey {
    key: PrivateKey,
}

impl ParsedKey {
    /// Parses a private key in OpenSSH, PKCS#8, PKCS#1 or SEC1 PEM form,
    /// decrypting with `passphrase` when encrypted.
    pub fn parse(pem: &str, passphrase: Option<&str>) -> Result<Self> {
        let trimmed = pem.trim();
        if trimmed.is_empty() {
            bail!("SSH private key is empty");
        }
        let pass = passphrase.filter(|p| !p.is_empty());
        if trimmed.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            return Self::from_openssh_pem(trimmed, pass);
        }
        let (label, body) = decode_pem_block(trimmed)?;
        match label {
            "PRIVATE KEY" => Self::from_pkcs8_der(&body),
            "ENCRYPTED PRIVATE KEY" => {
                let pass = pass.ok_or_else(|| {
                    anyhow!("SSH private key is encrypted; provide its passphrase")
                })?;
                let info: pkcs8::EncryptedPrivateKeyInfo<&der::asn1::OctetStringRef> =
                    der::Decode::from_der(body.as_slice())
                        .map_err(|_| anyhow!("malformed encrypted PKCS#8 private key"))?;
                let decrypted = info
                    .decrypt(pass)
                    .map_err(|_| anyhow!("wrong passphrase for SSH private key"))?;
                Self::from_pkcs8_der(decrypted.as_bytes())
            }
            "RSA PRIVATE KEY" => Self::from_pkcs1_der(&body),
            "EC PRIVATE KEY" => Self::from_sec1_der(&body),
            other => bail!("unsupported SSH private key PEM label {other:?}"),
        }
    }

    fn from_openssh_pem(pem: &str, passphrase: Option<&str>) -> Result<Self> {
        let mut key = PrivateKey::from_openssh(pem.as_bytes())
            .map_err(|_| anyhow!("malformed OpenSSH private key"))?;
        if key.is_encrypted() {
            let pass = passphrase
                .ok_or_else(|| anyhow!("SSH private key is encrypted; provide its passphrase"))?;
            key = key
                .decrypt(pass)
                .map_err(|_| anyhow!("wrong passphrase for SSH private key"))?;
        }
        Ok(Self { key })
    }

    fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        if let Ok(ed) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
            let kp = Ed25519Keypair::from_seed(&ed.to_bytes());
            let key = PrivateKey::new(KeypairData::Ed25519(kp), "")
                .map_err(|e| anyhow!("encoding Ed25519 key: {e}"))?;
            return Ok(Self { key });
        }
        if let Ok(sk) = p256::SecretKey::from_pkcs8_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP256 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-256 key: {e}"))?;
            return Ok(Self { key });
        }
        if let Ok(sk) = p384::SecretKey::from_pkcs8_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP384 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-384 key: {e}"))?;
            return Ok(Self { key });
        }
        if let Ok(sk) = p521::SecretKey::from_pkcs8_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP521 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-521 key: {e}"))?;
            return Ok(Self { key });
        }
        if let Ok(info) = pkcs8::PrivateKeyInfoRef::try_from(der) {
            return Self::from_pkcs1_der(info.private_key.as_bytes());
        }
        bail!("unsupported or malformed PKCS#8 private key")
    }

    fn from_sec1_der(der: &[u8]) -> Result<Self> {
        if let Ok(sk) = p256::SecretKey::from_sec1_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP256 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-256 key: {e}"))?;
            return Ok(Self { key });
        }
        if let Ok(sk) = p384::SecretKey::from_sec1_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP384 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-384 key: {e}"))?;
            return Ok(Self { key });
        }
        if let Ok(sk) = p521::SecretKey::from_sec1_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP521 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-521 key: {e}"))?;
            return Ok(Self { key });
        }
        bail!("unsupported or malformed SEC1 EC private key")
    }

    fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let kp = openssh_rsa_from_pkcs1(der)?;
        let key =
            PrivateKey::new(KeypairData::Rsa(kp), "").map_err(|e| anyhow!("encoding RSA: {e}"))?;
        Ok(Self { key })
    }

    /// OpenSSH `authorized_keys` line (`<alg> <base64>[ <comment>]`).
    pub fn public_openssh(&self, comment_override: Option<&str>) -> Result<String> {
        let mut pubkey = self.key.public_key().clone();
        if let Some(comment) = comment_override {
            pubkey.set_comment(clean_comment(comment));
        }
        pubkey
            .to_openssh()
            .map_err(|e| anyhow!("formatting SSH public key: {e}"))
    }

    /// `SHA256:<unpadded-base64>` fingerprint.
    pub fn fingerprint(&self) -> String {
        self.key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }

    /// Embedded comment from an OpenSSH private key, if non-empty.
    pub fn comment(&self) -> Option<String> {
        let raw = self.key.public_key().comment().as_str_lossy();
        let c = raw.trim();
        (!c.is_empty()).then(|| c.to_string())
    }

    /// Encodes the key as an unencrypted OpenSSH PEM string.
    pub fn to_openssh_pem(&self, comment_override: Option<&str>) -> Result<Zeroizing<String>> {
        let mut key = self.key.clone();
        if let Some(comment) = comment_override {
            key.set_comment(clean_comment(comment));
        }
        key.to_openssh(LineEnding::LF)
            .map_err(|e| anyhow!("encoding OpenSSH private key: {e}"))
    }
}

/// Generates a new SSH key pair of `kind`.
pub fn generate(kind: KeyKind, comment: Option<&str>) -> Result<GeneratedKey> {
    let mut rng = UnwrapErr(SysRng);
    let alg = match kind {
        KeyKind::Ed25519 => Algorithm::Ed25519,
        KeyKind::EcdsaP256 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    };
    let mut key =
        PrivateKey::random(&mut rng, alg).map_err(|e| anyhow!("generating SSH key: {e}"))?;
    let cleaned = comment.map(clean_comment).filter(|c| !c.is_empty());
    if let Some(c) = &cleaned {
        key.set_comment(c.clone());
    }
    let private_key = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow!("encoding generated SSH private key: {e}"))?;
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow!("encoding generated SSH public key: {e}"))?;
    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
    Ok(GeneratedKey {
        private_key,
        public_key,
        fingerprint,
        comment: cleaned,
    })
}

/// Parses an imported key file (decrypting with `passphrase` when needed) and
/// re-encodes it as an unencrypted OpenSSH PEM key with derived metadata.
pub fn normalize_import(
    pem: &str,
    passphrase: Option<&str>,
    comment_override: Option<&str>,
) -> Result<GeneratedKey> {
    let parsed = ParsedKey::parse(pem, passphrase)?;
    let comment = comment_override
        .map(clean_comment)
        .filter(|c| !c.is_empty())
        .or_else(|| parsed.comment());
    let private_key = parsed.to_openssh_pem(comment.as_deref())?;
    let public_key = parsed.public_openssh(comment.as_deref())?;
    let fingerprint = parsed.fingerprint();
    Ok(GeneratedKey {
        private_key,
        public_key,
        fingerprint,
        comment,
    })
}

/// Derives `(public_key, fingerprint, file_comment)` when `private_key` parses
/// as a supported SSH key; `None` for non-PEM or encrypted keys whose
/// passphrase wasn't supplied yet.
pub fn derive_fields(
    private_key: &str,
    passphrase: Option<&str>,
    comment: Option<&str>,
) -> Option<(String, String, Option<String>)> {
    let parsed = ParsedKey::parse(private_key, passphrase).ok()?;
    let file_comment = parsed.comment();
    let effective = comment
        .map(clean_comment)
        .filter(|c| !c.is_empty())
        .or_else(|| file_comment.clone());
    let public_key = parsed.public_openssh(effective.as_deref()).ok()?;
    let fingerprint = parsed.fingerprint();
    Some((public_key, fingerprint, file_comment))
}

fn decode_pem_block(pem: &str) -> Result<(&str, Zeroizing<Vec<u8>>)> {
    let (_, after_begin) = pem
        .split_once("-----BEGIN ")
        .ok_or_else(|| anyhow!("not a PEM-encoded SSH private key"))?;
    let (label, rest) = after_begin
        .split_once("-----")
        .ok_or_else(|| anyhow!("not a PEM-encoded SSH private key"))?;
    let end_marker = format!("-----END {label}-----");
    let (body_lines, _) = rest
        .split_once(&end_marker)
        .ok_or_else(|| anyhow!("unterminated PEM block for {label:?}"))?;
    if body_lines.contains("Proc-Type:") || body_lines.contains("DEK-Info:") {
        bail!("legacy OpenSSL encrypted PEM is not supported; convert with ssh-keygen -p -f <key>");
    }
    let compact: Zeroizing<String> = Zeroizing::new(
        body_lines
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect(),
    );
    let decoded = data_encoding::BASE64
        .decode(compact.as_bytes())
        .map_err(|_| anyhow!("invalid base64 in PEM private key"))?;
    Ok((label, Zeroizing::new(decoded)))
}

fn clean_comment(comment: &str) -> String {
    comment
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Parses RFC 3447 `RSAPrivateKey` ASN.1 DER into `ssh_key::private::RsaKeypair`.
fn openssh_rsa_from_pkcs1(der: &[u8]) -> Result<RsaKeypair> {
    let mut top = der::SliceReader::new(der).map_err(|_| anyhow!("invalid PKCS#1 DER"))?;
    let kp: RsaKeypair = top
        .sequence(|seq| -> der::Result<RsaKeypair> {
            let version: u8 = seq.decode()?;
            if version != 0 {
                return Err(der::Tag::Integer.value_error().into());
            }
            let mpint = |seq: &mut der::SliceReader<'_>| -> der::Result<Mpint> {
                let uint: der::asn1::UintRef<'_> = seq.decode()?;
                Ok(Mpint::from_positive_bytes(uint.as_bytes()))
            };
            let n = mpint(seq)?;
            let e = mpint(seq)?;
            let d = mpint(seq)?;
            let p = mpint(seq)?;
            let q = mpint(seq)?;
            let _dp: der::asn1::UintRef<'_> = seq.decode()?;
            let _dq: der::asn1::UintRef<'_> = seq.decode()?;
            let iqmp = mpint(seq)?;
            let public = RsaPublicKey::new(n, e)
                .map_err(|_| der::Error::from(der::Tag::Integer.value_error()))?;
            let private = RsaPrivateKey::new(d, iqmp, p, q)
                .map_err(|_| der::Error::from(der::Tag::Integer.value_error()))?;
            RsaKeypair::new(public, private)
                .map_err(|_| der::Error::from(der::Tag::Sequence.value_error()))
        })
        .map_err(|_| anyhow!("malformed PKCS#1 RSA private key"))?;
    top.finish()
        .map_err(|_| anyhow!("trailing data in PKCS#1 RSA private key"))?;
    Ok(kp)
}

impl Agent {
    /// Control-socket `Command::SshGenerate`.
    pub(super) fn ssh_generate(&self, kind: SshKeyKind, comment: Option<&str>) -> Result<Reply> {
        let k = match kind {
            SshKeyKind::Ed25519 => KeyKind::Ed25519,
            SshKeyKind::EcdsaP256 => KeyKind::EcdsaP256,
        };
        Ok(generated(generate(k, comment)?))
    }

    /// Control-socket `Command::SshInspect`.
    pub(super) fn ssh_inspect(
        &self,
        private_key: &Secret,
        passphrase: Option<&Secret>,
        comment: Option<&str>,
    ) -> Result<Reply> {
        let made = normalize_import(
            private_key.expose(),
            passphrase.map(Secret::expose),
            comment,
        )?;
        Ok(generated(made))
    }
}

fn generated(made: GeneratedKey) -> Reply {
    Reply::SshGenerated {
        private_key: Secret::new(made.private_key.as_str()),
        public_key: made.public_key,
        fingerprint: made.fingerprint,
        comment: made.comment,
    }
}

#[cfg(test)]
#[path = "ssh_keys_tests.rs"]
mod ssh_keys_tests;
