use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::entry::consent_message;

fn hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).expect("OS random number generator failed");
    bytes
}

macro_rules! bytes_type {
    ($(#[$doc:meta])* $name:ident, $len:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub(crate) [u8; $len]);

        impl $name {
            /// Wraps raw bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
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

bytes_type!(
    /// A device's Ed25519 public key. Equal to its iroh `EndpointId`.
    DeviceId,
    32
);
bytes_type!(
    /// Identifies a vault; derived from its genesis `Create` op.
    VaultId,
    32
);
bytes_type!(
    /// BLAKE3 hash of an entry's canonical encoding (signature excluded).
    Hash,
    32
);
bytes_type!(
    /// An Ed25519 signature.
    Signature,
    64
);
bytes_type!(
    /// Identifies an item within a vault.
    ItemId,
    16
);

impl DeviceId {
    pub(crate) fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature.0))
            .is_ok()
    }
}

impl VaultId {
    const CONTEXT: &str = "deadbolt 2026-10-15 vault id v1";

    pub(crate) fn derive(creator: &DeviceId, nonce: &[u8; 32]) -> Self {
        let mut material = [0; 64];
        material[..32].copy_from_slice(&creator.0);
        material[32..].copy_from_slice(nonce);
        Self(blake3::derive_key(Self::CONTEXT, &material))
    }
}

impl ItemId {
    /// A fresh random item id.
    pub fn random() -> Self {
        Self(random())
    }
}

/// A device's Ed25519 signing key. Zeroized on drop.
pub struct DeviceSecret(SigningKey);

impl DeviceSecret {
    /// Generates a new key from the OS random number generator.
    ///
    /// Panics if the OS random number generator fails.
    pub fn generate() -> Self {
        let bytes = Zeroizing::new(random::<32>());
        Self::from_bytes(&bytes)
    }

    /// Restores a key from its 32-byte secret.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// The 32-byte secret, for encrypted storage.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// The public key / device id.
    pub fn device_id(&self) -> DeviceId {
        DeviceId(self.0.verifying_key().to_bytes())
    }

    /// Signs this device's consent to join `vault`, carried by the `Add` op.
    pub fn join_consent(&self, vault: &VaultId) -> Signature {
        self.sign(&consent_message(vault))
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message).to_bytes())
    }
}

impl fmt::Debug for DeviceSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceSecret({})", self.device_id())
    }
}
