use super::super::keys::{KeyKind, ParsedKey, generate};
use super::super::wire::put_bytes;
use super::*;

fn make_bind_payload(host: &ParsedKey, session_id: &[u8], forwarding: bool) -> Vec<u8> {
    let sig = host.sign_agent(session_id, 0).unwrap();
    let blob = host.public_blob().unwrap();
    let mut out = Vec::new();
    put_bytes(&mut out, &blob).unwrap();
    put_bytes(&mut out, session_id).unwrap();
    put_bytes(&mut out, &sig).unwrap();
    out.push(u8::from(forwarding));
    out
}

#[test]
fn verifies_session_bind_and_enforces_session_id_and_forwarding_rules() {
    let host1_gen = generate(KeyKind::Ed25519, None).unwrap();
    let host1 = ParsedKey::parse(&host1_gen.private_key, None).unwrap();
    let host2_gen = generate(KeyKind::EcdsaP256, None).unwrap();
    let host2 = ParsedKey::parse(&host2_gen.private_key, None).unwrap();

    let sid1 = [0x11u8; 32];
    let sid2 = [0x22u8; 32];

    // 1. Local auth bind (`forwarding = false`): matches sid1, rejects sid2 and re-bind.
    let mut local = SessionBind::default();
    local
        .bind(&make_bind_payload(&host1, &sid1, false))
        .unwrap();
    assert!(!local.is_forwarded());
    let ok_auth = SignTarget::UserAuth {
        session_id: sid1.to_vec(),
        username: "git".into(),
        hostkey_blob: Some(host1.public_blob().unwrap()),
    };
    assert!(local.check_sign(&ok_auth, false).is_ok());

    let wrong_sid = SignTarget::UserAuth {
        session_id: sid2.to_vec(),
        username: "git".into(),
        hostkey_blob: None,
    };
    assert!(local.check_sign(&wrong_sid, false).is_err());
    // Re-binding after `forwarding = false` fails and latches `failed`.
    assert!(
        local
            .bind(&make_bind_payload(&host2, &sid2, false))
            .is_err()
    );
    assert!(local.has_failed());
    assert!(local.check_sign(&ok_auth, false).is_err());

    // 2. Forwarded hop (`ssh -A` to host1, then `ssh` from host1 to host2).
    let mut fwd = SessionBind::default();
    fwd.bind(&make_bind_payload(&host1, &sid1, true)).unwrap();
    // Duplicate session_id is rejected on a clone:
    let mut dup = SessionBind::default();
    dup.bind(&make_bind_payload(&host1, &sid1, true)).unwrap();
    assert!(dup.bind(&make_bind_payload(&host2, &sid1, false)).is_err());

    fwd.bind(&make_bind_payload(&host2, &sid2, false)).unwrap();
    assert!(fwd.is_forwarded());

    let hop2_auth = SignTarget::UserAuth {
        session_id: sid2.to_vec(),
        username: "deploy".into(),
        hostkey_blob: Some(host2.public_blob().unwrap()),
    };
    // Refused when `allow_forwarding` is false.
    assert!(fwd.check_sign(&hop2_auth, false).is_err());
    // Allowed when `allow_forwarding` is true and hostbound key matches hop2.
    assert!(fwd.check_sign(&hop2_auth, true).is_ok());
    // Unbound userauth on a multi-hop forwarded connection is refused.
    let unbound_hop2 = SignTarget::UserAuth {
        session_id: sid2.to_vec(),
        username: "deploy".into(),
        hostkey_blob: None,
    };
    assert!(fwd.check_sign(&unbound_hop2, true).is_err());
}

#[test]
fn bad_signature_latches_connection_closed_to_signing() {
    let host_gen = generate(KeyKind::Ed25519, None).unwrap();
    let host = ParsedKey::parse(&host_gen.private_key, None).unwrap();
    let mut payload = make_bind_payload(&host, &[0x55; 32], false);
    let last_sig_byte = payload.len() - 2;
    payload[last_sig_byte] ^= 0xff;

    let mut bind = SessionBind::default();
    assert!(bind.bind(&payload).is_err());
    assert!(bind.has_failed());
    assert!(bind.check_sign(&SignTarget::Raw { len: 4 }, true).is_err());
}
