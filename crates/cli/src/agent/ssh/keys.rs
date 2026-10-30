//! SSH key parsing, generation, normalization, signature verification and
//! signing (`docs/ssh-agent.md`).
//!
//! Supports Ed25519, ECDSA (`nistp256`, `nistp384`, `nistp521`) and RSA
//! (2048-4096 bits via `ring` so `rsa`'s `RUSTSEC-2023-0071` advisory never
//! enters the dependency graph). Private keys parse from OpenSSH PEM (plain
//! or `bcrypt` encrypted), PKCS#8 PEM (plain or PBES2 encrypted, as 1Password
//! exports them), PKCS#1 RSA PEM and SEC1 EC PEM.

use anyhow::{Context, Result, anyhow, bail};
use crypto_bigint::{BoxedUint, NonZero};
use der::Reader as _;
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use ring::rsa::{KeyPair as RingRsaKeyPair, KeyPairComponents, PublicKeyComponents};
use ring::signature::{
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA512,
    RsaPublicKeyComponents,
};
use ssh_key::encoding::Encode as _;
use ssh_key::getrandom::SysRng;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::{KeyData, RsaPublicKey};
use ssh_key::rand_core::UnwrapErr;
use ssh_key::{
    Algorithm, EcdsaCurve, HashAlg, LineEnding, Mpint, PrivateKey, PublicKey, Signature, SshSig,
};
use zeroize::Zeroizing;

/// `draft-ietf-sshm-ssh-agent` §4.5.1 signature flags for RSA SHA-2.
pub const RSA_SHA2_256: u32 = 0x02;
pub const RSA_SHA2_512: u32 = 0x04;

/// Minimum RSA modulus size accepted for signing or verification.
const MIN_RSA_BITS: u32 = 2048;
/// Maximum RSA modulus size `ring::rsa::KeyPair` signs with.
const MAX_RSA_SIGN_BITS: u32 = 4096;

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

enum SignerImpl {
    Ssh(Box<PrivateKey>),
    Rsa {
        openssh: Box<PrivateKey>,
        ring: Box<RingRsaKeyPair>,
    },
}

/// A parsed SSH key pair in zeroized memory, ready to sign or derive public
/// metadata.
pub struct ParsedKey {
    public: PublicKey,
    signer: SignerImpl,
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
        Self::from_private_key(key)
    }

    fn from_private_key(key: PrivateKey) -> Result<Self> {
        let public = key.public_key().clone();
        match key.key_data() {
            KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => Ok(Self {
                public,
                signer: SignerImpl::Ssh(Box::new(key)),
            }),
            KeypairData::Rsa(rsa) => {
                let bits = rsa.key_size();
                if bits < MIN_RSA_BITS {
                    bail!("RSA key is {bits} bits; at least {MIN_RSA_BITS} bits are required");
                }
                if bits > MAX_RSA_SIGN_BITS {
                    bail!("RSA keys over {MAX_RSA_SIGN_BITS} bits are not supported");
                }
                let ring = ring_from_openssh_rsa(rsa)?;
                Ok(Self {
                    public,
                    signer: SignerImpl::Rsa {
                        openssh: Box::new(key),
                        ring: Box::new(ring),
                    },
                })
            }
            KeypairData::Dsa(_) => bail!("DSA (ssh-dss) keys are obsolete and not supported"),
            _ => bail!("unsupported SSH key algorithm {}", key.algorithm()),
        }
    }

    fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        if let Ok(ed) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
            let kp = Ed25519Keypair::from_seed(&ed.to_bytes());
            let key = PrivateKey::new(KeypairData::Ed25519(kp), "")
                .map_err(|e| anyhow!("encoding Ed25519 key: {e}"))?;
            return Self::from_private_key(key);
        }
        if let Ok(sk) = p256::SecretKey::from_pkcs8_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP256 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-256 key: {e}"))?;
            return Self::from_private_key(key);
        }
        if let Ok(sk) = p384::SecretKey::from_pkcs8_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP384 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-384 key: {e}"))?;
            return Self::from_private_key(key);
        }
        if let Ok(sk) = p521::SecretKey::from_pkcs8_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP521 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-521 key: {e}"))?;
            return Self::from_private_key(key);
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
            return Self::from_private_key(key);
        }
        if let Ok(sk) = p384::SecretKey::from_sec1_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP384 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-384 key: {e}"))?;
            return Self::from_private_key(key);
        }
        if let Ok(sk) = p521::SecretKey::from_sec1_der(der) {
            let public = sk.public_key();
            let kp = EcdsaKeypair::NistP521 {
                private: sk.into(),
                public: public.into(),
            };
            let key = PrivateKey::new(KeypairData::Ecdsa(kp), "")
                .map_err(|e| anyhow!("encoding P-521 key: {e}"))?;
            return Self::from_private_key(key);
        }
        bail!("unsupported or malformed SEC1 EC private key")
    }

    fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        let ring = RingRsaKeyPair::from_der(der)
            .map_err(|_| anyhow!("unsupported or malformed RSA private key"))?;
        let kp = openssh_rsa_from_pkcs1(der)?;
        let openssh =
            PrivateKey::new(KeypairData::Rsa(kp), "").map_err(|e| anyhow!("encoding RSA: {e}"))?;
        let public = openssh.public_key().clone();
        Ok(Self {
            public,
            signer: SignerImpl::Rsa {
                openssh: Box::new(openssh),
                ring: Box::new(ring),
            },
        })
    }

    #[cfg(test)]
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Raw SSH wire blob of the public key (`string alg || ...`), without comment.
    pub fn public_blob(&self) -> Result<Vec<u8>> {
        self.public
            .key_data()
            .encode_vec()
            .map_err(|e| anyhow!("encoding SSH public key blob: {e}"))
    }

    /// OpenSSH `authorized_keys` line (`<alg> <base64>[ <comment>]`).
    pub fn public_openssh(&self, comment_override: Option<&str>) -> Result<String> {
        let mut pubkey = self.public.clone();
        if let Some(comment) = comment_override {
            pubkey.set_comment(clean_comment(comment));
        }
        pubkey
            .to_openssh()
            .map_err(|e| anyhow!("formatting SSH public key: {e}"))
    }

    /// `SHA256:<unpadded-base64>` fingerprint.
    pub fn fingerprint(&self) -> String {
        self.public.fingerprint(HashAlg::Sha256).to_string()
    }

    /// Embedded comment from an OpenSSH private key, if non-empty.
    pub fn comment(&self) -> Option<String> {
        let raw = self.public.comment().as_str_lossy();
        let c = raw.trim();
        (!c.is_empty()).then(|| c.to_string())
    }

    /// Encodes the key as an unencrypted OpenSSH PEM string.
    pub fn to_openssh_pem(&self, comment_override: Option<&str>) -> Result<Zeroizing<String>> {
        let mut key = match &self.signer {
            SignerImpl::Ssh(k) => (**k).clone(),
            SignerImpl::Rsa { openssh, .. } => (**openssh).clone(),
        };
        if let Some(comment) = comment_override {
            key.set_comment(clean_comment(comment));
        }
        key.to_openssh(LineEnding::LF)
            .map_err(|e| anyhow!("encoding OpenSSH private key: {e}"))
    }

    /// Signs `data` for `SSH_AGENTC_SIGN_REQUEST` (`13`) with `flags`,
    /// returning the SSH wire-encoded signature blob (`string alg || string sig`).
    pub fn sign_agent(&self, data: &[u8], flags: u32) -> Result<Vec<u8>> {
        let sig = match &self.signer {
            SignerImpl::Ssh(key) => {
                if flags != 0 {
                    bail!(
                        "unexpected signature flags {flags:#x} for {}",
                        key.algorithm()
                    );
                }
                ed25519_dalek::Signer::try_sign(&**key, data)
                    .map_err(|e| anyhow!("signing with {}: {e}", key.algorithm()))?
            }
            SignerImpl::Rsa { ring, .. } => {
                let unknown = flags & !(RSA_SHA2_256 | RSA_SHA2_512);
                if unknown != 0 {
                    bail!("unsupported RSA signature flags {flags:#x}");
                }
                let (hash, alg): (HashAlg, &'static dyn ring::signature::RsaEncoding) =
                    if flags & RSA_SHA2_512 != 0 {
                        (HashAlg::Sha512, &RSA_PKCS1_SHA512)
                    } else if flags & RSA_SHA2_256 != 0 {
                        (HashAlg::Sha256, &RSA_PKCS1_SHA256)
                    } else {
                        bail!("refusing legacy SHA-1 ssh-rsa signature (pass RSA-SHA2 flags)");
                    };
                let mut raw = vec![0u8; ring.public().modulus_len()];
                let rng = ring::rand::SystemRandom::new();
                ring.sign(alg, &rng, data, &mut raw)
                    .map_err(|_| anyhow!("RSA signature failed"))?;
                Signature::new(Algorithm::Rsa { hash: Some(hash) }, raw)
                    .map_err(|e| anyhow!("encoding RSA signature: {e}"))?
            }
        };
        sig.encode_vec()
            .map_err(|e| anyhow!("encoding SSH signature: {e}"))
    }

    /// Signs `msg` in the OpenSSH `SSHSIG` format (`ssh-keygen -Y sign`),
    /// returning the PEM-armored `-----BEGIN SSH SIGNATURE-----` block.
    pub fn sign_sshsig(&self, namespace: &str, msg: &[u8]) -> Result<String> {
        let namespace = namespace.trim();
        if namespace.is_empty() {
            bail!("an SSH signature needs a non-empty namespace");
        }
        let signed_data = SshSig::signed_data(namespace, HashAlg::Sha512, msg)
            .map_err(|e| anyhow!("building SSHSIG payload: {e}"))?;
        let flags = match &self.signer {
            SignerImpl::Ssh(_) => 0,
            SignerImpl::Rsa { .. } => RSA_SHA2_512,
        };
        let encoded_sig = self.sign_agent(&signed_data, flags)?;
        let sig = Signature::try_from(encoded_sig.as_slice())
            .map_err(|e| anyhow!("decoding SSHSIG signature: {e}"))?;
        let sshsig = SshSig::new(
            self.public.key_data().clone(),
            namespace,
            HashAlg::Sha512,
            sig,
        )
        .map_err(|e| anyhow!("building SSHSIG envelope: {e}"))?;
        sshsig
            .to_pem(LineEnding::LF)
            .map_err(|e| anyhow!("encoding SSHSIG PEM: {e}"))
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

/// Parses an OpenSSH public key line (`ssh-ed25519 AAAA...`) or `key::` literal
/// into its raw wire blob (`string alg || ...`) and `SHA256:...` fingerprint.
pub fn parse_public_key_line(line: &str) -> Result<(Vec<u8>, String)> {
    let text = line.trim();
    let text = text.strip_prefix("key::").map_or(text, str::trim);
    let pubkey = PublicKey::from_openssh(text)
        .with_context(|| "not a valid OpenSSH public key (expected ssh-ed25519 ..., ecdsa-sha2-..., or ssh-rsa ...)")?;
    let blob = pubkey
        .key_data()
        .encode_vec()
        .map_err(|e| anyhow!("encoding public key blob: {e}"))?;
    let fingerprint = pubkey.fingerprint(HashAlg::Sha256).to_string();
    Ok((blob, fingerprint))
}

/// Verifies an SSH wire signature (`sig_blob`) over `data` under `pubkey`
/// (used by `session-bind@openssh.com` to verify server KEX host-key
/// signatures).
pub fn verify_signature(pubkey: &PublicKey, data: &[u8], sig_blob: &[u8]) -> Result<()> {
    let sig = Signature::try_from(sig_blob).map_err(|_| anyhow!("malformed SSH signature blob"))?;
    match (pubkey.key_data(), sig.algorithm()) {
        (KeyData::Rsa(rsa), Algorithm::Rsa { hash }) => {
            if rsa.key_size() < MIN_RSA_BITS {
                bail!("RSA host key is smaller than {MIN_RSA_BITS} bits");
            }
            let alg = match hash {
                Some(HashAlg::Sha256) => &RSA_PKCS1_2048_8192_SHA256,
                Some(HashAlg::Sha512) => &RSA_PKCS1_2048_8192_SHA512,
                None => bail!("SHA-1 ssh-rsa signatures are not accepted"),
                Some(other) => bail!("unsupported RSA hash {other:?}"),
            };
            let n = trim_zeros(
                rsa.n()
                    .as_positive_bytes()
                    .ok_or_else(|| anyhow!("negative RSA modulus"))?,
            );
            let e = trim_zeros(
                rsa.e()
                    .as_positive_bytes()
                    .ok_or_else(|| anyhow!("negative RSA exponent"))?,
            );
            RsaPublicKeyComponents { n, e }
                .verify(alg, data, sig.as_bytes())
                .map_err(|_| anyhow!("RSA signature verification failed"))
        }
        (KeyData::Rsa(_), other) => bail!("signature algorithm {other} does not match RSA key"),
        (_, _) => ed25519_dalek::Verifier::verify(pubkey, data, &sig)
            .map_err(|_| anyhow!("SSH signature verification failed")),
    }
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

fn trim_zeros(mut bytes: &[u8]) -> &[u8] {
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    bytes
}

/// Computes `d mod (prime - 1)` in constant time for CRT parameters `dP`/`dQ`.
fn mod_minus_one(d_be: &[u8], prime_be: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let bits = (d_be.len().max(prime_be.len()) as u32)
        .saturating_mul(8)
        .max(MIN_RSA_BITS);
    let d = BoxedUint::from_be_slice(d_be, bits).map_err(|_| anyhow!("invalid RSA exponent"))?;
    let p = BoxedUint::from_be_slice(prime_be, bits).map_err(|_| anyhow!("invalid RSA prime"))?;
    let one = BoxedUint::one_with_precision(bits);
    if p <= one {
        bail!("invalid RSA prime");
    }
    let p_minus_1 = p.wrapping_sub(&one);
    let nz: Option<NonZero<BoxedUint>> = NonZero::new(p_minus_1).into();
    let nz = nz.ok_or_else(|| anyhow!("zero RSA prime modulus"))?;
    let rem = d.rem(&nz);
    let raw = Zeroizing::new(rem.to_be_bytes().into_vec());
    let trimmed = trim_zeros(&raw).to_vec();
    Ok(Zeroizing::new(trimmed))
}

fn pos_mpint<'a>(m: &'a Mpint, what: &str) -> Result<&'a [u8]> {
    Ok(trim_zeros(
        m.as_positive_bytes()
            .ok_or_else(|| anyhow!("invalid RSA {what}"))?,
    ))
}

fn ring_from_openssh_rsa(rsa: &RsaKeypair) -> Result<RingRsaKeyPair> {
    let n = pos_mpint(rsa.public().n(), "n")?;
    let e = pos_mpint(rsa.public().e(), "e")?;
    let d = pos_mpint(rsa.private().d(), "d")?;
    let iqmp = pos_mpint(rsa.private().iqmp(), "iqmp")?;
    let p = pos_mpint(rsa.private().p(), "p")?;
    let q = pos_mpint(rsa.private().q(), "q")?;
    let dp = mod_minus_one(d, p)?;
    let dq = mod_minus_one(d, q)?;
    let components = KeyPairComponents {
        public_key: PublicKeyComponents { n, e },
        d,
        p,
        q,
        dP: dp.as_slice(),
        dQ: dq.as_slice(),
        qInv: iqmp,
    };
    RingRsaKeyPair::from_components(&components)
        .map_err(|_| anyhow!("invalid RSA private key parameters"))
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

#[cfg(test)]
#[path = "keys_tests.rs"]
mod keys_tests;
