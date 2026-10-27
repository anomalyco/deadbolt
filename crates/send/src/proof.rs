use hmac::{Hmac, KeyInit, Mac};
use iroh::endpoint::Connection;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const EXPORTER_LABEL: &[u8] = b"EXPORTER-deadbolt-send-v1";
const TRANSCRIPT_LABEL: &[u8] = b"deadbolt/send/1";
const RECEIVER_LABEL: &[u8] = b"receiver-proof";

pub(crate) const PROOF_LEN: usize = 32;

/// `"deadbolt/send/1" || sender id || receiver id || TLS exporter(32)`: unique to
/// this connection, so a proof can't be replayed on another.
pub(crate) fn transcript(
    conn: &Connection,
    sender: &[u8; 32],
    receiver: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut ekm = Zeroizing::new([0u8; 32]);
    conn.export_keying_material(ekm.as_mut(), EXPORTER_LABEL, b"")
        .map_err(|_| Error::Protocol("keying material export failed".into()))?;
    Ok(transcript_bytes(sender, receiver, &ekm))
}

pub(crate) fn transcript_bytes(sender: &[u8; 32], receiver: &[u8; 32], ekm: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(TRANSCRIPT_LABEL.len() + 96);
    t.extend_from_slice(TRANSCRIPT_LABEL);
    t.extend_from_slice(sender);
    t.extend_from_slice(receiver);
    t.extend_from_slice(ekm);
    t
}

#[expect(clippy::expect_used, reason = "HMAC accepts keys of every length")]
fn hmac(secret: &[u8; 32], transcript: &[u8]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("any key length");
    m.update(RECEIVER_LABEL);
    m.update(&[0]);
    m.update(transcript);
    m
}

/// The receiver's proof that it holds `secret`.
pub(crate) fn prove(secret: &[u8; 32], transcript: &[u8]) -> [u8; PROOF_LEN] {
    hmac(secret, transcript).finalize().into_bytes().into()
}

#[cfg_attr(
    all(target_family = "wasm", target_os = "unknown"),
    expect(dead_code, reason = "only senders verify")
)]
/// Constant-time check of a receiver's proof.
pub(crate) fn verify(secret: &[u8; 32], transcript: &[u8], proof: &[u8]) -> bool {
    hmac(secret, transcript).verify_slice(proof).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_are_bound_to_secret_and_transcript() {
        let t = transcript_bytes(&[1; 32], &[2; 32], &[3; 32]);
        let p = prove(&[9; 32], &t);
        assert!(verify(&[9; 32], &t, &p));
        assert!(!verify(&[8; 32], &t, &p), "other secret");
        let swapped = transcript_bytes(&[2; 32], &[1; 32], &[3; 32]);
        assert!(!verify(&[9; 32], &swapped, &p), "other roles");
        let other = transcript_bytes(&[1; 32], &[2; 32], &[4; 32]);
        assert!(!verify(&[9; 32], &other, &p), "other connection");
        assert!(!verify(&[9; 32], &t, &p[..31]), "short");
    }
}
