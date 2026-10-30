use proptest::prelude::*;
use ssh_key::{HashAlg, SshSig};

use super::*;

#[tokio::test]
async fn frames_roundtrip_and_reject_zero_or_oversized_lengths() {
    let mut wire = Vec::new();
    let reply = AgentReply::Identities(vec![Identity {
        pubkey_blob: b"blob-1".to_vec(),
        comment: "alice@laptop".into(),
    }]);
    write_reply(&mut wire, &reply).await.unwrap();

    let mut cursor = &wire[..];
    let frame = read_frame(&mut cursor).await.unwrap().unwrap();
    assert_eq!(frame[0], SSH_AGENT_IDENTITIES_ANSWER);
    assert!(read_frame(&mut cursor).await.unwrap().is_none());

    let mut zero = &[0u8, 0, 0, 0][..];
    assert!(read_frame(&mut zero).await.is_err());

    let over = ((MAX_MSG_LEN + 1) as u32).to_be_bytes();
    let mut oversized = &over[..];
    assert!(read_frame(&mut oversized).await.is_err());
}

#[test]
fn decodes_sign_extension_and_unsupported_requests() {
    assert_eq!(
        decode_request(&[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap(),
        AgentRequest::RequestIdentities
    );
    assert!(decode_request(&[SSH_AGENTC_REQUEST_IDENTITIES, 0]).is_err());

    let mut sign = vec![SSH_AGENTC_SIGN_REQUEST];
    put_bytes(&mut sign, b"pk").unwrap();
    put_bytes(&mut sign, b"msg").unwrap();
    sign.extend_from_slice(&0x04u32.to_be_bytes());
    assert_eq!(
        decode_request(&sign).unwrap(),
        AgentRequest::SignRequest {
            pubkey_blob: b"pk".to_vec(),
            data: b"msg".to_vec(),
            flags: 0x04,
        }
    );

    let mut ext = vec![SSH_AGENTC_EXTENSION];
    put_bytes(&mut ext, b"query").unwrap();
    assert_eq!(
        decode_request(&ext).unwrap(),
        AgentRequest::Extension {
            name: "query".into(),
            contents: Vec::new(),
        }
    );

    // Add/remove/lock codes map cleanly to Unsupported for SSH_AGENT_FAILURE.
    for code in [1u8, 17, 18, 19, 22, 23, 25] {
        assert_eq!(
            decode_request(&[code, 1, 2, 3]).unwrap(),
            AgentRequest::Unsupported(code)
        );
    }
}

#[test]
fn parses_userauth_hostbound_sshsig_and_raw_sign_targets() {
    let pk = b"ssh-ed25519-blob";
    let sid = [0x42u8; 32];
    let hostkey = b"server-hostkey-blob";

    let mut hostbound = Vec::new();
    put_bytes(&mut hostbound, &sid).unwrap();
    hostbound.push(50);
    put_bytes(&mut hostbound, b"git").unwrap();
    put_bytes(&mut hostbound, b"ssh-connection").unwrap();
    put_bytes(&mut hostbound, b"publickey-hostbound-v00@openssh.com").unwrap();
    hostbound.push(1);
    put_bytes(&mut hostbound, b"ssh-ed25519").unwrap();
    put_bytes(&mut hostbound, pk).unwrap();
    put_bytes(&mut hostbound, hostkey).unwrap();

    assert_eq!(
        parse_sign_target(&hostbound, pk),
        SignTarget::UserAuth {
            session_id: sid.to_vec(),
            username: "git".into(),
            hostkey_blob: Some(hostkey.to_vec()),
        }
    );
    // Mismatched public key blob falls back to Raw rather than spoofing UserAuth.
    assert_eq!(
        parse_sign_target(&hostbound, b"different-pk"),
        SignTarget::Raw {
            len: hostbound.len()
        }
    );

    let sshsig_bytes = SshSig::signed_data("git", HashAlg::Sha512, b"commit").unwrap();
    assert_eq!(
        parse_sign_target(&sshsig_bytes, pk),
        SignTarget::SshSig {
            namespace: "git".into()
        }
    );
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_decoders(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        drop(decode_request(&bytes));
        drop(parse_sign_target(&bytes, b"pk"));
    }
}
