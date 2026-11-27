//! Deadbolt v2 cryptographic primitives, key schedule, `X25519Wrap`, and Padmé padding.
//!
//! Pure, deterministic (except explicit OS randomness for nonces/keys),
//! `unsafe_code = "forbid"`, and `wasm32-unknown-unknown`-clean.

use std::fmt;

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use ed25519_dalek::{SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::id::{DeviceId, DeviceSecret, Signature, VaultId};

/// Suite identifier for `X25519Wrap` (X25519 + BLAKE3 KDF + XChaCha20-Poly1305).
pub const SUITE_X25519_WRAP: u8 = 1;
/// Reserved suite identifier for future hybrid post-quantum wrap (X-Wing).
pub const SUITE_XWING_RESERVED: u8 = 2;

/// Byte length of an `X25519Wrap` ciphertext: `pk_e[32] || ct[32] || tag[16]`.
pub const WRAP_LEN: usize = 80;
/// Byte length of an `XChaCha20-Poly1305` nonce.
pub const NONCE_LEN: usize = 24;
/// Byte length of a `Poly1305` authentication tag.
pub const TAG_LEN: usize = 16;
/// Byte length of an encrypted back-link: `nonce[24] || ct[32] || tag[16]`.
pub const BACK_LINK_LEN: usize = NONCE_LEN + 32 + TAG_LEN;
/// Minimum Padmé-padded buffer length (256 bytes).
pub const PADME_FLOOR: usize = 256;

// Domain-separated BLAKE3 derive_key contexts (all literal "deadbolt/v2 " || label).
const CTX_VAULT_ID: &str = "deadbolt/v2 vault id";
const CTX_FRAME_ID: &str = "deadbolt/v2 frame id";
const CTX_RECOVERY_SIGN: &str = "deadbolt/v2 recovery sign";
const CTX_RECOVERY_KEM: &str = "deadbolt/v2 recovery kem";
const CTX_DEVICE_SIGN: &str = "deadbolt/v2 device sign";
const CTX_DEVICE_KEM: &str = "deadbolt/v2 device kem";
const CTX_DEVICE_NET: &str = "deadbolt/v2 device net";
const CTX_EPOCH_DATA: &str = "deadbolt/v2 epoch data";
const CTX_EPOCH_BACK: &str = "deadbolt/v2 epoch back";
const CTX_EPOCH_STATE: &str = "deadbolt/v2 epoch state";
const CTX_EPOCH_COMMIT: &str = "deadbolt/v2 epoch commit";
const CTX_X25519_WRAP: &str = "deadbolt/v2 x25519 wrap";
const CTX_RECOVERY_WRAP_KEM: &str = "deadbolt/v2 recovery wrap kem";

/// Prefix for wrap `info` strings: `"deadbolt/v2 wrap" || vault || author || seq || recipient`.
const WRAP_INFO_PREFIX: &[u8] = b"deadbolt/v2 wrap";

/// Cryptographic errors in `deadbolt_core::v2`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("OS random number generator failed")]
    Rng,
    #[error("unsupported wrap suite {0}")]
    UnsupportedSuite(u8),
    #[error("X25519 public key produced a non-contributory shared secret")]
    NonContributoryKey,
    #[error("wrap info length {0} exceeds u16::MAX")]
    InfoTooLong(usize),
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("AEAD authentication failed")]
    DecryptFailed,
    #[error("invalid Padmé padding")]
    InvalidPadding,
    #[error("plaintext length {0} exceeds maximum")]
    PlaintextTooLarge(usize),
    #[error("device transport key D_net must not equal signing key D_sign")]
    TransportKeyReusesSignKey,
}

fn hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0u8; N];
    crate::rng::fill(&mut out).map_err(|_| CryptoError::Rng)?;
    Ok(out)
}

/// BLAKE3 derive-key over concatenated byte slices, wiping internal hasher state.
pub(crate) fn kdf_bytes(context: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(context));
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// BLAKE3 derive-key returning a zeroized secret key.
pub(crate) fn kdf_secret(context: &str, parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(kdf_bytes(context, parts))
}

/// Derives a v2 `VaultId` from the genesis creator's public key and 32-byte nonce.
pub fn derive_vault_id(creator: &DeviceId, nonce: &[u8; 32]) -> VaultId {
    VaultId::from_bytes(kdf_bytes(CTX_VAULT_ID, &[creator.as_bytes(), nonce]))
}

/// Derives a v2 `FrameId` from the canonical 145-byte header and 32-byte `BLAKE3(body)`.
pub fn derive_frame_id(header_bytes: &[u8; 145], body_hash: &[u8; 32]) -> FrameId {
    FrameId(kdf_bytes(CTX_FRAME_ID, &[header_bytes, body_hash]))
}

macro_rules! v2_bytes_type {
    ($(#[$doc:meta])* $name:ident, $len:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// All-zero sentinel value.
            pub const ZERO: Self = Self([0u8; $len]);

            /// Wraps raw bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Returns the raw bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// True iff all bytes are zero.
            pub fn is_zero(&self) -> bool {
                self.0 == [0u8; $len]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                hex(&self.0, f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                hex(&self.0, f)?;
                write!(f, ")")
            }
        }
    };
}

v2_bytes_type!(
    /// Canonical identifier of a v2 frame: `KDF("frame id", hdr || BLAKE3(body))`.
    FrameId,
    32
);

v2_bytes_type!(
    /// Epoch identifier: exact 1:1 bijection with the minting `Member` frame's `FrameId`.
    EpochId,
    32
);

v2_bytes_type!(
    /// X25519 public key used for epoch key wrapping (`D_kem` or `R_kem`).
    KemPublic,
    32
);

v2_bytes_type!(
    /// Transport Ed25519 public key (`D_net`), strictly separate from `DeviceId` (`D_sign`).
    NetPublic,
    32
);

impl EpochId {
    /// Converts the minting `Member` frame's `FrameId` into its `EpochId`.
    pub const fn from_frame_id(id: FrameId) -> Self {
        Self(id.0)
    }

    /// Returns the underlying minting `FrameId`.
    pub const fn as_frame_id(&self) -> FrameId {
        FrameId(self.0)
    }
}

/// X25519 secret key (`D_kem` or `R_kem`). Zeroized on drop.
pub struct KemSecret(X25519StaticSecret);

impl KemSecret {
    /// Generates a fresh X25519 secret key from OS randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let raw = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self::from_bytes(&raw))
    }

    /// Restores a key from 32 secret bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(X25519StaticSecret::from(*bytes))
    }

    /// Exports the 32-byte secret key.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Returns the matching X25519 public key.
    pub fn public_key(&self) -> KemPublic {
        KemPublic(X25519PublicKey::from(&self.0).to_bytes())
    }

    /// Computes X25519 Diffie-Hellman, rejecting any non-contributory shared secret.
    pub fn diffie_hellman(&self, peer: &KemPublic) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let shared = self.0.diffie_hellman(&X25519PublicKey::from(peer.0));
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributoryKey);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

impl fmt::Debug for KemSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSecret({})", self.public_key())
    }
}

/// Ed25519 transport secret key (`D_net`), strictly separate from `DeviceSecret` (`D_sign`).
pub struct NetSecret(SigningKey);

impl NetSecret {
    /// Generates a fresh transport key from OS randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let raw = Zeroizing::new(random_bytes::<32>()?);
        Ok(Self::from_bytes(&raw))
    }

    /// Restores a transport key from 32 secret bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// Exports the 32-byte secret key.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Returns the public transport key (`D_net`).
    pub fn public_key(&self) -> NetPublic {
        NetPublic(self.0.verifying_key().to_bytes())
    }

    /// Signs `message` with the transport key: proof this device holds it.
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        Signature::from_bytes(self.0.sign(message).to_bytes())
    }
}

impl fmt::Debug for NetSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetSecret({})", self.public_key())
    }
}

/// 32-byte recovery root entropy (`RS`), deriving `R_sign` and `R_kem`.
/// Zeroized on drop.
pub struct RecoverySecret(Zeroizing<[u8; 32]>);

impl RecoverySecret {
    /// Generates a fresh 32-byte recovery secret from OS randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(Zeroizing::new(random_bytes::<32>()?)))
    }

    /// Wraps an existing 32-byte recovery secret.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns the raw 32-byte secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives `R_sign` (Ed25519 signing key).
    pub fn signing_key(&self) -> DeviceSecret {
        let seed = kdf_secret(CTX_RECOVERY_SIGN, &[self.as_bytes()]);
        DeviceSecret::from_bytes(&seed)
    }

    /// Derives `R_kem` (X25519 secret key).
    pub fn kem_secret(&self) -> KemSecret {
        let seed = kdf_secret(CTX_RECOVERY_KEM, &[self.as_bytes()]);
        KemSecret::from_bytes(&seed)
    }

    /// Returns `RecoveryId` (the public key of `R_sign`).
    pub fn recovery_id(&self) -> DeviceId {
        self.signing_key().device_id()
    }

    /// Returns the public key of `R_kem`.
    pub fn kem_public(&self) -> KemPublic {
        self.kem_secret().public_key()
    }
}

impl fmt::Debug for RecoverySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoverySecret({})", self.recovery_id())
    }
}

/// Per-install device keys: separate `D_sign`, `D_kem`, and `D_net`.
pub struct DeviceKeys {
    sign: DeviceSecret,
    kem: KemSecret,
    net: NetSecret,
}

impl DeviceKeys {
    /// Generates three independent per-install keys (`D_sign`, `D_kem`, `D_net`).
    pub fn generate() -> Result<Self, CryptoError> {
        let sign_seed = Zeroizing::new(random_bytes::<32>()?);
        let sign = DeviceSecret::from_bytes(&sign_seed);
        let kem = KemSecret::generate()?;
        let net = NetSecret::generate()?;
        Self::from_parts(sign, kem, net)
    }

    /// Deterministically derives distinct `D_sign`, `D_kem`, and `D_net` from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sign_seed = kdf_secret(CTX_DEVICE_SIGN, &[seed]);
        let kem_seed = kdf_secret(CTX_DEVICE_KEM, &[seed]);
        let net_seed = kdf_secret(CTX_DEVICE_NET, &[seed]);
        Self {
            sign: DeviceSecret::from_bytes(&sign_seed),
            kem: KemSecret::from_bytes(&kem_seed),
            net: NetSecret::from_bytes(&net_seed),
        }
    }

    /// Constructs `DeviceKeys` from explicit parts, rejecting `D_net == D_sign`.
    pub fn from_parts(
        sign: DeviceSecret,
        kem: KemSecret,
        net: NetSecret,
    ) -> Result<Self, CryptoError> {
        if net.public_key().as_bytes() == sign.device_id().as_bytes() {
            return Err(CryptoError::TransportKeyReusesSignKey);
        }
        Ok(Self { sign, kem, net })
    }

    /// Returns `DeviceId` (public key of `D_sign`).
    pub fn device_id(&self) -> DeviceId {
        self.sign.device_id()
    }

    /// Returns the public X25519 key (`D_kem`).
    pub fn kem_public(&self) -> KemPublic {
        self.kem.public_key()
    }

    /// Returns the public transport key (`D_net`).
    pub fn net_public(&self) -> NetPublic {
        self.net.public_key()
    }

    /// Accesses `D_sign`.
    pub fn sign_key(&self) -> &DeviceSecret {
        &self.sign
    }

    /// Accesses `D_kem`.
    pub fn kem_key(&self) -> &KemSecret {
        &self.kem
    }

    /// Accesses `D_net`.
    pub fn net_key(&self) -> &NetSecret {
        &self.net
    }
}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKeys")
            .field("device_id", &self.device_id())
            .field("kem_public", &self.kem_public())
            .field("net_public", &self.net_public())
            .finish()
    }
}

/// 32-byte symmetric epoch key `K_e`. Zeroized on drop.
#[derive(Clone)]
pub struct EpochKey(Zeroizing<[u8; 32]>);

impl EpochKey {
    /// Generates a fresh random 32-byte epoch key.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(Zeroizing::new(random_bytes::<32>()?)))
    }

    /// Wraps raw 32-byte key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns the raw 32-byte key material.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `K_data(e) = KDF("epoch data", K_e || vault || EpochId)`.
    pub fn data_key(&self, vault: &VaultId, epoch: &EpochId) -> Zeroizing<[u8; 32]> {
        kdf_secret(
            CTX_EPOCH_DATA,
            &[self.as_bytes(), vault.as_bytes(), epoch.as_bytes()],
        )
    }

    /// `K_back(e) = KDF("epoch back", K_e || vault || author || seq)`.
    ///
    /// Binds `(vault, author, seq)` rather than `EpochId` (matching `commit`) because
    /// back-links live inside `Rotate` inside the minting `Member` frame body, whose
    /// hash defines `EpochId`.
    pub fn back_key(&self, vault: &VaultId, author: &DeviceId, seq: u64) -> Zeroizing<[u8; 32]> {
        kdf_secret(
            CTX_EPOCH_BACK,
            &[
                self.as_bytes(),
                vault.as_bytes(),
                author.as_bytes(),
                &seq.to_be_bytes(),
            ],
        )
    }

    /// `K_mac(e) = KDF("epoch state", K_e || vault || EpochId)`.
    pub fn mac_key(&self, vault: &VaultId, epoch: &EpochId) -> Zeroizing<[u8; 32]> {
        kdf_secret(
            CTX_EPOCH_STATE,
            &[self.as_bytes(), vault.as_bytes(), epoch.as_bytes()],
        )
    }

    /// `commit = KDF("epoch commit", K_e || vault || author || seq)`.
    pub fn commit(&self, vault: &VaultId, author: &DeviceId, seq: u64) -> [u8; 32] {
        kdf_bytes(
            CTX_EPOCH_COMMIT,
            &[
                self.as_bytes(),
                vault.as_bytes(),
                author.as_bytes(),
                &seq.to_be_bytes(),
            ],
        )
    }

    /// Constant-time check that this key matches an epoch's `commit`.
    pub fn verify_commit(
        &self,
        vault: &VaultId,
        author: &DeviceId,
        seq: u64,
        expected: &[u8; 32],
    ) -> bool {
        let actual = self.commit(vault, author, seq);
        bool::from(actual.ct_eq(expected))
    }
}

impl fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EpochKey(<redacted>)")
    }
}

/// Verifies an Ed25519 signature using strict verification only (rejecting malleable/small-order encodings).
pub fn verify_strict(public_key: &DeviceId, message: &[u8], signature: &Signature) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key.as_bytes()) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    key.verify_strict(message, &sig).is_ok()
}

/// Verifies a transport key's (`D_net`) signature, strictly.
pub fn verify_net(net: &NetPublic, message: &[u8], signature: &Signature) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&net.0) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature.as_bytes());
    key.verify_strict(message, &sig).is_ok()
}

/// Signs `message` with `DeviceSecret`.
pub fn sign(secret: &DeviceSecret, message: &[u8]) -> Signature {
    secret.sign(message)
}

/// Seals `plaintext` with `XChaCha20-Poly1305` under a fresh random 24-byte nonce.
pub fn aead_seal(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ct = aead_seal_with_nonce(key, &nonce, aad, plaintext)?;
    Ok((nonce, ct))
}

fn aead_seal_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    let Ok(tag) = cipher.encrypt_inout_detached(nonce.into(), aad, out.as_mut_slice().into())
    else {
        out.zeroize();
        return Err(CryptoError::EncryptFailed);
    };
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens an `XChaCha20-Poly1305` ciphertext (`ct || tag`).
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if ciphertext.len() < TAG_LEN {
        return Err(CryptoError::DecryptFailed);
    }
    let (ct, tag_slice) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
    let tag: [u8; TAG_LEN] = tag_slice
        .try_into()
        .map_err(|_| CryptoError::DecryptFailed)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut buf = Zeroizing::new(ct.to_vec());
    cipher
        .decrypt_inout_detached(nonce.into(), aad, buf.as_mut_slice().into(), &tag.into())
        .map_err(|_| CryptoError::DecryptFailed)?;
    Ok(buf)
}

/// Seals a 32-byte parent `EpochKey` into a 72-byte back-link (`nonce[24] || ct[32] || tag[16]`).
pub fn seal_back_link(
    k_back: &[u8; 32],
    aad: &[u8],
    parent_key: &EpochKey,
) -> Result<[u8; BACK_LINK_LEN], CryptoError> {
    let (nonce, ct) = aead_seal(k_back, aad, parent_key.as_bytes())?;
    let mut out = [0u8; BACK_LINK_LEN];
    out[..NONCE_LEN].copy_from_slice(&nonce);
    out[NONCE_LEN..].copy_from_slice(&ct);
    Ok(out)
}

/// Opens a 72-byte back-link back into a parent `EpochKey`.
pub fn open_back_link(
    k_back: &[u8; 32],
    aad: &[u8],
    sealed: &[u8; BACK_LINK_LEN],
) -> Result<EpochKey, CryptoError> {
    let nonce: [u8; NONCE_LEN] = sealed[..NONCE_LEN]
        .try_into()
        .map_err(|_| CryptoError::DecryptFailed)?;
    let pt = aead_open(k_back, &nonce, aad, &sealed[NONCE_LEN..])?;
    let key_bytes: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptFailed)?;
    Ok(EpochKey::from_bytes(key_bytes))
}

/// Builds the canonical wrap `info` byte string:
/// `"deadbolt/v2 wrap" || vault[32] || author[32] || seq:u64_be || recipient[32]`.
pub fn wrap_info(vault: &VaultId, author: &DeviceId, seq: u64, recipient: &DeviceId) -> [u8; 120] {
    let mut info = [0u8; 120];
    info[..16].copy_from_slice(WRAP_INFO_PREFIX);
    info[16..48].copy_from_slice(vault.as_bytes());
    info[48..80].copy_from_slice(author.as_bytes());
    info[80..88].copy_from_slice(&seq.to_be_bytes());
    info[88..120].copy_from_slice(recipient.as_bytes());
    info
}

fn derive_x25519_wrap_key(
    dh: &[u8; 32],
    pk_e: &KemPublic,
    pk_r: &KemPublic,
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let info_len = u16::try_from(info.len()).map_err(|_| CryptoError::InfoTooLong(info.len()))?;
    Ok(kdf_secret(
        CTX_X25519_WRAP,
        &[
            dh,
            pk_e.as_bytes(),
            pk_r.as_bytes(),
            &info_len.to_be_bytes(),
            info,
        ],
    ))
}

/// Wraps a 32-byte `EpochKey` to `recipient_pk` using `X25519Wrap` (`suite = 1`).
///
/// Output is 80 bytes: `pk_e[32] || XChaCha20Poly1305(k, [0; 24], aad, K_e)[48]`.
/// The ephemeral scalar is derived from the fresh 256-bit epoch key, info and AAD,
/// making every offer checkable by other key holders. Rejects non-contributory DH
/// and unsupported suites (including reserved `suite = 2`).
pub fn wrap_epoch_key(
    suite: u8,
    recipient_pk: &KemPublic,
    info: &[u8],
    aad: &[u8],
    key: &EpochKey,
) -> Result<[u8; WRAP_LEN], CryptoError> {
    if suite != SUITE_X25519_WRAP {
        return Err(CryptoError::UnsupportedSuite(suite));
    }
    wrap_recovery_epoch_key(suite, recipient_pk, info, aad, key)
}

/// Wraps `K_e` to the recovery root with an ephemeral scalar derived from
/// `KDF("recovery wrap kem", K_e || u16(info.len) || info || aad)` instead of fresh randomness.
///
/// The cold recovery root is offline, so it cannot notice a bad wrap itself. A deterministic
/// wrap lets any online peer that holds the `commit`-verified `K_e` recompute it bit for bit
/// with [`verify_recovery_wrap`], with no access to `R_kem`'s secret.
pub fn wrap_recovery_epoch_key(
    suite: u8,
    recovery_pk: &KemPublic,
    info: &[u8],
    aad: &[u8],
    key: &EpochKey,
) -> Result<[u8; WRAP_LEN], CryptoError> {
    if suite != SUITE_X25519_WRAP {
        return Err(CryptoError::UnsupportedSuite(suite));
    }
    let info_len = u16::try_from(info.len()).map_err(|_| CryptoError::InfoTooLong(info.len()))?;
    let seed = kdf_secret(
        CTX_RECOVERY_WRAP_KEM,
        &[key.as_bytes(), &info_len.to_be_bytes(), info, aad],
    );
    x25519_wrap_with(&KemSecret::from_bytes(&seed), recovery_pk, info, aad, key)
}

/// True iff `wrap` is exactly the deterministic recovery wrap of `k_e` to `recovery_kem`.
/// Needs only the epoch key and public values, never the recovery root's secret.
pub fn verify_recovery_wrap(
    k_e: &EpochKey,
    recovery_kem: &KemPublic,
    info: &[u8],
    aad: &[u8],
    wrap: &[u8; WRAP_LEN],
) -> bool {
    wrap_recovery_epoch_key(SUITE_X25519_WRAP, recovery_kem, info, aad, k_e)
        .is_ok_and(|expected| bool::from(expected.ct_eq(wrap)))
}

fn x25519_wrap_with(
    sk_e: &KemSecret,
    recipient_pk: &KemPublic,
    info: &[u8],
    aad: &[u8],
    key: &EpochKey,
) -> Result<[u8; WRAP_LEN], CryptoError> {
    let pk_e = sk_e.public_key();
    let dh = sk_e.diffie_hellman(recipient_pk)?;
    let wrap_key = derive_x25519_wrap_key(&dh, &pk_e, recipient_pk, info)?;
    // Safe: `wrap_key` seals exactly one plaintext under one `aad`: `sk_e` is
    // derived from this very `K_e`, `info` and `aad`.
    let ct = aead_seal_with_nonce(&wrap_key, &[0u8; NONCE_LEN], aad, key.as_bytes())?;
    let mut out = [0u8; WRAP_LEN];
    out[..32].copy_from_slice(pk_e.as_bytes());
    out[32..].copy_from_slice(&ct);
    Ok(out)
}

/// Unwraps an 80-byte `X25519Wrap` (`suite = 1`) using `recipient_sk`.
///
/// Rejects non-contributory DH, unsupported suites, and authentication failures.
pub fn unwrap_epoch_key(
    suite: u8,
    recipient_sk: &KemSecret,
    info: &[u8],
    aad: &[u8],
    wrapped: &[u8; WRAP_LEN],
) -> Result<EpochKey, CryptoError> {
    if suite != SUITE_X25519_WRAP {
        return Err(CryptoError::UnsupportedSuite(suite));
    }
    let pk_e_bytes: [u8; 32] = wrapped[..32]
        .try_into()
        .map_err(|_| CryptoError::DecryptFailed)?;
    let pk_e = KemPublic::from_bytes(pk_e_bytes);
    let pk_r = recipient_sk.public_key();
    let dh = recipient_sk.diffie_hellman(&pk_e)?;
    let wrap_key = derive_x25519_wrap_key(&dh, &pk_e, &pk_r, info)?;
    let pt = aead_open(&wrap_key, &[0u8; NONCE_LEN], aad, &wrapped[32..])?;
    let key_bytes: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptFailed)?;
    Ok(EpochKey::from_bytes(key_bytes))
}

/// Computes the canonical Padmé padded length for a plaintext of `plaintext_len` bytes
/// (including its 4-byte length prefix), with a 256-byte floor and ≤ 12% overhead above the floor.
pub fn padme_padded_len(plaintext_len: usize) -> Result<usize, CryptoError> {
    let len =
        u32::try_from(plaintext_len).map_err(|_| CryptoError::PlaintextTooLarge(plaintext_len))?;
    let raw = u64::from(len) + 4;
    if raw <= PADME_FLOOR as u64 {
        return Ok(PADME_FLOOR);
    }
    // Standard Padmé (PURBs, USENIX Security 2019), in `u64` so 32-bit (`wasm32`) and 64-bit
    // targets agree bit for bit: e = floor(log2(raw)), s = floor(log2(e)) + 1, last_bits = e - s.
    // `raw > 256` gives `e >= 8` and `s <= e`.
    let e = raw.ilog2();
    let s = e.ilog2() + 1;
    let mask = (1u64 << (e - s)) - 1;
    let padded = (raw + mask) & !mask;
    usize::try_from(padded).map_err(|_| CryptoError::PlaintextTooLarge(plaintext_len))
}

/// Applies canonical Padmé padding: `u32_be(pt.len()) || pt || 0x00*`.
pub fn padme_pad(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let total = padme_padded_len(plaintext.len())?;
    let len_u32 = u32::try_from(plaintext.len())
        .map_err(|_| CryptoError::PlaintextTooLarge(plaintext.len()))?;
    let mut out = Zeroizing::new(vec![0u8; total]);
    out[..4].copy_from_slice(&len_u32.to_be_bytes());
    out[4..4 + plaintext.len()].copy_from_slice(plaintext);
    Ok(out)
}

/// Validates and removes canonical Padmé padding, rejecting wrong lengths and non-zero pad bytes.
pub fn padme_unpad(padded: &[u8]) -> Result<&[u8], CryptoError> {
    if padded.len() < PADME_FLOOR {
        return Err(CryptoError::InvalidPadding);
    }
    let len_bytes: [u8; 4] = padded[..4]
        .try_into()
        .map_err(|_| CryptoError::InvalidPadding)?;
    let pt_len = u32::from_be_bytes(len_bytes) as usize;
    let expected = padme_padded_len(pt_len).map_err(|_| CryptoError::InvalidPadding)?;
    if padded.len() != expected {
        return Err(CryptoError::InvalidPadding);
    }
    let end = 4usize
        .checked_add(pt_len)
        .ok_or(CryptoError::InvalidPadding)?;
    if end > padded.len() {
        return Err(CryptoError::InvalidPadding);
    }
    if padded[end..].iter().any(|&b| b != 0) {
        return Err(CryptoError::InvalidPadding);
    }
    Ok(&padded[4..end])
}
