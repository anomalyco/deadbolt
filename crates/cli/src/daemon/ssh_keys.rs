//! SSH keys made and inspected for clients ([`deadbolt_engine::ssh_keys`]).

use anyhow::Result;
use deadbolt_engine::ssh_keys::{GeneratedKey, KeyKind, generate, normalize_import};

use super::Daemon;
use crate::protocol::{Reply, Secret, SshKeyKind};

impl Daemon {
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
