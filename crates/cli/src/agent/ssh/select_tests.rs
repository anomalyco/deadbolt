use data_encoding::BASE64;
use deadbolt_store::KdfParams;

use super::super::keys::{KeyKind, generate};
use super::*;
use crate::protocol::FieldInput;

fn loaded_store(dir: &Path) -> Loaded {
    let params = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let mut s = Loaded::setup(dir, b"test", "laptop", params).unwrap();
    s.create_vault("personal").unwrap();
    s
}

fn add_ssh(s: &mut Loaded, vault: Option<&str>, name: &str) -> (String, String) {
    let made = generate(KeyKind::Ed25519, Some(name)).unwrap();
    let info = crate::agent::items::create(
        s,
        vault,
        "ssh",
        Some(name.into()),
        vec![FieldInput {
            name: "private-key".into(),
            kind: None,
            value: made.private_key.to_string(),
        }],
    )
    .unwrap();
    (info.id, made.fingerprint)
}

#[test]
fn ranks_last_used_key_first_and_enforces_ssh_toml_host_rules() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded_store(dir.path());
    s.create_vault("work").unwrap();

    // 7 keys in `personal`: without ranking, key #7 would exceed sshd's MaxAuthTries=6.
    let mut fps = Vec::new();
    for i in 1..=7 {
        let (_, fp) = add_ssh(&mut s, Some("personal"), &format!("Key {i}"));
        fps.push(fp);
    }
    let (_, work_fp) = add_ssh(&mut s, Some("work"), "Work Deploy");

    // Default (no ssh.toml): offers only default vault (`personal`), in order.
    let listed = eligible_keys(&s, None, None, None);
    assert_eq!(listed.len(), 7);
    assert_eq!(listed[6].fingerprint, fps[6]);

    // Server hostkey for github.com:
    let host_gen = generate(KeyKind::Ed25519, None).unwrap();
    let host_parsed = ParsedKey::parse(&host_gen.private_key, None).unwrap();
    let hop = BoundHop {
        hostkey: host_parsed.public_key().clone(),
        hostkey_blob: host_parsed.public_blob().unwrap(),
        fingerprint: host_parsed.fingerprint(),
        session_id: vec![0xaa; 32],
        is_forwarding: false,
    };

    // Record that Key 7 signed for this server hostkey -> Key 7 moves to index 0!
    let k7_item = listed[6].item.clone();
    let vid = listed[6].vault_id;
    record_used(&s, &hop.fingerprint, vid, &k7_item, 1_800_000_000).unwrap();

    let ranked = eligible_keys(&s, None, None, Some(&hop));
    assert_eq!(ranked[0].fingerprint, fps[6], "last-used key offered first");
    assert_eq!(ranked.len(), 7);

    // Hashed known_hosts entry (`|1|salt|hash`) for github.com + plain entry for corp.example.com.
    let salt = [0x12u8; 20];
    let mut mac = HmacSha1::new_from_slice(&salt).unwrap();
    mac.update(b"github.com");
    let hash = mac.finalize().into_bytes();
    let pub_str = host_parsed.public_openssh(None).unwrap();
    let known_hosts = format!(
        "|1|{}|{} {pub_str}\n",
        BASE64.encode(&salt),
        BASE64.encode(&hash)
    );
    assert!(hostkey_matches_host(
        &known_hosts,
        host_parsed.public_key(),
        "github.com"
    ));
    assert!(!hostkey_matches_host(
        &known_hosts,
        host_parsed.public_key(),
        "gitlab.com"
    ));

    // ssh.toml scoping Key 3 to gitlab.com (omitted for github.com) and Work Deploy to github.com.
    let cfg: SshToml = toml::from_str(
        r#"
        [[ssh-keys]]
        item = "Key 3"
        vault = "personal"
        hosts = ["gitlab.com"]

        [[ssh-keys]]
        item = "Work Deploy"
        vault = "work"
        hosts = ["github.com"]
        "#,
    )
    .unwrap();
    // Unbound connection omits host-pinned keys (fails closed).
    assert!(eligible_keys(&s, Some(&cfg), Some(&known_hosts), None).is_empty());
    // Bound to github.com offers only Work Deploy.
    let filtered = eligible_keys(&s, Some(&cfg), Some(&known_hosts), Some(&hop));
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].fingerprint, work_fp);
}

#[test]
fn plain_known_hosts_gives_prompt_label_and_revoked_keys_never_match() {
    let host_gen = generate(KeyKind::Ed25519, None).unwrap();
    let host = ParsedKey::parse(&host_gen.private_key, None).unwrap();
    let pub_line = host.public_openssh(None).unwrap();

    let kh = format!("github.com,140.82.112.4 {pub_line}\n");
    assert_eq!(
        known_host_label(&kh, host.public_key()).as_deref(),
        Some("github.com")
    );
    assert!(hostkey_matches_host(&kh, host.public_key(), "github.com"));

    let revoked = format!("{kh}@revoked * {pub_line}\n");
    assert!(!hostkey_matches_host(
        &revoked,
        host.public_key(),
        "github.com"
    ));
    assert_eq!(known_host_label(&revoked, host.public_key()), None);
}
