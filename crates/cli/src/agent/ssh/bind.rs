//! `session-bind@openssh.com` verification and connection hop tracking
//! (`PROTOCOL.agent` §1).
//!
//! Verified using only the server's public host key in the message, so
//! bindings succeed while the vault is locked as well as unlocked. Any failed
//! `session-bind` latches `failed = true` and refuses later `SIGN_REQUEST`s on
//! that connection.

use anyhow::{Result, bail};
use ssh_key::{HashAlg, PublicKey};

use super::keys::verify_signature;
use super::wire::{Cursor, SignTarget};

pub const EXT_SESSION_BIND: &str = "session-bind@openssh.com";
const MAX_HOPS: usize = 16;

#[derive(Debug, Clone)]
pub struct BoundHop {
    pub hostkey: PublicKey,
    pub hostkey_blob: Vec<u8>,
    pub fingerprint: String,
    pub session_id: Vec<u8>,
    pub is_forwarding: bool,
}

#[derive(Debug, Default)]
pub struct SessionBind {
    hops: Vec<BoundHop>,
    failed: bool,
}

impl SessionBind {
    /// Parses and verifies a `session-bind@openssh.com` extension payload. On
    /// any failure, latches `failed` so subsequent signing on this connection
    /// fails closed.
    pub fn bind(&mut self, contents: &[u8]) -> Result<()> {
        let outcome = self.try_bind(contents);
        if outcome.is_err() {
            self.failed = true;
        }
        outcome
    }

    fn try_bind(&mut self, contents: &[u8]) -> Result<()> {
        if self.failed {
            bail!("earlier session-bind failed on this connection");
        }
        if self.hops.len() >= MAX_HOPS {
            bail!("too many session-bind hops ({MAX_HOPS})");
        }
        if self.hops.last().is_some_and(|last| !last.is_forwarding) {
            bail!("connection is already bound for authentication");
        }
        let mut r = Cursor(contents);
        let hostkey_blob = r.bytes()?.to_vec();
        let session_id = r.bytes()?.to_vec();
        let signature = r.bytes()?;
        let is_forwarding = match r.u8()? {
            0 => false,
            1 => true,
            other => bail!("invalid session-bind forwarding flag {other}"),
        };
        r.finish()?;

        if session_id.len() < 16 || session_id.len() > 128 {
            bail!("invalid session-bind session identifier length");
        }
        if self.hops.iter().any(|h| h.session_id == session_id) {
            bail!("duplicate session identifier in session-bind");
        }
        let hostkey = PublicKey::from_bytes(&hostkey_blob)
            .map_err(|e| anyhow::anyhow!("malformed session-bind host key: {e}"))?;
        verify_signature(&hostkey, &session_id, signature)?;
        let fingerprint = hostkey.fingerprint(HashAlg::Sha256).to_string();
        self.hops.push(BoundHop {
            hostkey,
            hostkey_blob,
            fingerprint,
            session_id,
            is_forwarding,
        });
        Ok(())
    }

    pub fn has_failed(&self) -> bool {
        self.failed
    }

    /// True when any hop on this connection was bound for agent forwarding
    /// (`ssh -A`).
    pub fn is_forwarded(&self) -> bool {
        self.hops.iter().any(|h| h.is_forwarding)
    }

    /// The destination server hop (the latest bound hop), if any.
    pub fn destination(&self) -> Option<&BoundHop> {
        self.hops.last()
    }

    /// First forwarding hop (`ssh -A` jump box), when forwarded.
    pub fn first_hop(&self) -> Option<&BoundHop> {
        self.hops.first().filter(|h| h.is_forwarding)
    }

    /// Validates `target` against recorded `session-bind` hops before signing.
    pub fn check_sign(
        &self,
        target: &SignTarget,
        allow_forwarding: bool,
    ) -> Result<Option<&BoundHop>> {
        if self.failed {
            bail!("refusing to sign after a failed session-bind on this connection");
        }
        let forwarded = self.is_forwarded();
        if forwarded && !allow_forwarding {
            bail!("SSH agent forwarding is disabled in Deadbolt");
        }
        let Some(dest) = self.hops.last() else {
            return Ok(None);
        };
        match target {
            SignTarget::UserAuth {
                session_id,
                hostkey_blob,
                ..
            } => {
                if session_id != &dest.session_id {
                    bail!("SIGN_REQUEST session_id does not match session-bind");
                }
                match hostkey_blob {
                    Some(blob) if blob != &dest.hostkey_blob => {
                        bail!("SIGN_REQUEST host key does not match session-bind");
                    }
                    // OpenSSH requires hostbound userauth on forwarded hops.
                    None if self.hops.len() > 1 => {
                        bail!("forwarded multi-hop SIGN_REQUEST lacks hostbound host key");
                    }
                    _ => {}
                }
                Ok(Some(dest))
            }
            // A connection bound for `ssh -A` forwarding (`dest.is_forwarding`)
            // may sign an `SSHSIG` (e.g. `git commit` over forwarded agent)
            // when `allow_forwarding` is enabled, whereas an auth-bound local
            // `ssh` connection (`!dest.is_forwarding`) only ever signs userauth.
            SignTarget::SshSig { .. } | SignTarget::Raw { .. } => {
                if !dest.is_forwarding {
                    bail!("non-userauth SIGN_REQUEST on an authentication-bound SSH connection");
                }
                Ok(Some(dest))
            }
        }
    }
}

#[cfg(test)]
#[path = "bind_tests.rs"]
mod bind_tests;
