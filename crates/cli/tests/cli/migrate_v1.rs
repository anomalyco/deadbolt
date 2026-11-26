//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! A genuine v1 `store.redb`, written here from the v1 format (redb tables,
//! Argon2id header, sealed key set, signed entries), moved to v2 by
//! `deadbolt migrate` and by a plain `deadbolt unlock`.

use std::collections::BTreeMap;
use std::path::Path;

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use ed25519_dalek::{Signer, SigningKey};
use redb::TableDefinition;

use super::*;

const HEADER: TableDefinition<&str, &[u8]> = TableDefinition::new("header");
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("log");
const META: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("meta");

/// The test's attachment: every byte value, a few times over.
fn attachment() -> Vec<u8> {
    (0..1000u32).map(|i| (i * 7 % 256) as u8).collect()
}

/// Encodes v1 entry bodies and payloads, big-endian and length-prefixed.
#[derive(Default)]
struct Out(Vec<u8>);

impl Out {
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    fn str(self, v: &str) -> Self {
        self.u32(v.len() as u32).bytes(v.as_bytes())
    }
    fn opt(self, v: Option<&str>) -> Self {
        match v {
            None => self.u8(0),
            Some(v) => self.u8(1).str(v),
        }
    }
}

/// A v1 item create (tag 0, or 3 with a favorite or tags).
fn create(
    kind: &str,
    name: &str,
    fields: &[(&str, &str, &str)],
    favorite: bool,
    tags: &[&str],
) -> Vec<u8> {
    let sorted: BTreeMap<&str, (&str, &str)> =
        fields.iter().map(|(n, t, v)| (*n, (*t, *v))).collect();
    let meta = favorite || !tags.is_empty();
    let mut out = Out::default()
        .u8(if meta { 3 } else { 0 })
        .str(kind)
        .opt(Some(name))
        .u32(sorted.len() as u32);
    for (field, (kind, value)) in sorted {
        out = out.str(field).str(kind).str(value);
    }
    if meta {
        let mut tags = tags.to_vec();
        tags.sort();
        out = out.u8(0).u8(u8::from(favorite)).u32(tags.len() as u32);
        for tag in tags {
            out = out.str(tag);
        }
    }
    out.0
}

fn edit(item: [u8; 16], change: Out) -> Vec<u8> {
    let mut out = Out::default().u8(1).bytes(&item).0;
    out.extend(change.0);
    out
}

fn data(ops: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Out::default().u8(1).u32(ops.len() as u32).0;
    for op in ops {
        out.extend_from_slice(op);
    }
    out
}

fn item_id(entry: &[u8; 32], index: u64) -> [u8; 16] {
    let material = [&entry[..], &index.to_be_bytes()].concat();
    let key = blake3::derive_key("deadbolt 2026-10-15 item id v1", &material);
    key[..16].try_into().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// v1 entries, signed, in the order a v1 store appended them.
struct Log {
    entries: Vec<Vec<u8>>,
}

impl Log {
    /// Signs `payload` as `key`'s entry `seq` in `vault`; returns its hash.
    fn sign(
        &mut self,
        key: &SigningKey,
        vault: [u8; 32],
        seq: u64,
        deps: &[[u8; 32]],
        payload: Vec<u8>,
    ) -> [u8; 32] {
        let mut deps = deps.to_vec();
        deps.sort();
        let mut body = Out::default()
            .bytes(&vault)
            .bytes(&key.verifying_key().to_bytes())
            .u64(seq)
            .u32(deps.len() as u32);
        for dep in &deps {
            body = body.bytes(dep);
        }
        let mut body = body.0;
        body.extend(payload);
        let hash = blake3::derive_key("deadbolt 2026-10-15 entry hash v2", &body);
        let signature = key.sign(&[&b"deadbolt entry signature v1\0"[..], &hash].concat());
        body.extend_from_slice(&signature.to_bytes());
        self.entries.push(body);
        hash
    }
}

fn genesis(key: &SigningKey, nonce: [u8; 32], name: &str) -> ([u8; 32], Vec<u8>) {
    let device = key.verifying_key().to_bytes();
    let vault = blake3::derive_key("deadbolt 2026-10-15 vault id v1", &[device, nonce].concat());
    let payload = Out::default()
        .u8(0)
        .u8(0)
        .bytes(&device)
        .bytes(&nonce)
        .str(name)
        .0;
    (vault, payload)
}

/// What the fixture holds, to check after the move.
struct Fixture {
    github: String,
    team_login: String,
    stranger: String,
}

/// Writes a v1 store with two vaults into `home`:
///
/// - `personal` (the default): GitHub (login with OTP, a custom field, a
///   favorite, tags, an edited password, its date and an ignored finding),
///   a note, an SSH key, a passkey, a document with a binary file, and one
///   item in the trash;
/// - `work`, renamed `team`, shared with a second device that was removed
///   after its first write: that write counts, its next one doesn't.
fn write_v1(home: &Path) -> Fixture {
    let me = SigningKey::from_bytes(&[7; 32]);
    let other = SigningKey::from_bytes(&[9; 32]);
    let mut log = Log {
        entries: Vec::new(),
    };

    let (personal, payload) = genesis(&me, [1; 32], "personal");
    let p0 = log.sign(&me, personal, 0, &[], payload);
    let file = format!("scan.bin\n{}", data_encoding::BASE64.encode(&attachment()));
    let otp = "otpauth://totp/GitHub:kit?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
    let d0 = log.sign(&me, personal, 0, &[p0], data(&[
        create("login", "GitHub", &[
            ("username", "text", "kit"),
            ("password", "secret", "hunter2"),
            ("url", "url", "https://github.com"),
            ("otp", "otp", otp),
            ("recovery-codes", "secret", "aaaa-bbbb"),
        ], true, &["work", "work/dev"]),
        create("note", "Wifi notes", &[("notes", "secret", "the router is in the hall")], false, &[]),
        create("ssh", "Deploy key", &[
            ("private-key", "secret", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"),
            ("public-key", "text", "ssh-ed25519 AAAA deploy"),
            ("passphrase", "secret", "sshpass"),
        ], false, &[]),
        create("passkey", "Example passkey", &[
            ("rp-id", "text", "example.com"),
            ("username", "text", "kit@example.com"),
            ("credential-id", "text", "Y3JlZA"),
            ("user-handle", "text", "dXNlcg"),
            ("private-key", "secret", "cGtjczg"),
        ], false, &[]),
        create("document", "Passport scan", &[("file", "file", &file)], false, &[]),
        create("login", "Old forum", &[("username", "text", "kit"), ("password", "secret", "old")], false, &[]),
    ]));
    let github = item_id(&d0, 0);
    let forum = item_id(&d0, 5);
    let d1 = log.sign(
        &me,
        personal,
        1,
        &[d0],
        data(&[edit(
            github,
            Out::default()
                .u8(0)
                .str("password")
                .str("secret")
                .str("hunter3"),
        )]),
    );
    log.sign(
        &me,
        personal,
        2,
        &[d1],
        data(&[
            edit(github, Out::default().u8(10).str("weak").u8(1).bytes(&d1)),
            edit(github, Out::default().u8(11).opt(Some("2026-10-30"))),
            edit(github, Out::default().u8(9).str("work/dev")),
            edit(forum, Out::default().u8(5).u64(1_790_000_000)),
        ]),
    );

    let (work, payload) = genesis(&me, [2; 32], "work");
    let w0 = log.sign(&me, work, 0, &[], payload);
    let device = other.verifying_key().to_bytes();
    let consent = other.sign(
        &[
            &b"deadbolt join consent v2\0"[..],
            &work,
            &me.verifying_key().to_bytes(),
            &device,
        ]
        .concat(),
    );
    let add = Out::default()
        .u8(0)
        .u8(1)
        .bytes(&device)
        .bytes(&consent.to_bytes())
        .0;
    let w1 = log.sign(&me, work, 1, &[w0], add);
    let rename = Out::default().u8(0).u8(3).str("team").0;
    let w2 = log.sign(&me, work, 2, &[w1], rename);
    let o0 = log.sign(
        &other,
        work,
        0,
        &[w2],
        data(&[create(
            "login",
            "Team login",
            &[
                ("username", "text", "ops"),
                ("password", "secret", "s3cret"),
            ],
            false,
            &[],
        )]),
    );
    let team_login = item_id(&o0, 0);
    // Removed with its first write counted: the edit after never counts.
    let remove = Out::default().u8(0).u8(2).bytes(&device).u8(1).u64(0).0;
    log.sign(&me, work, 3, &[w2], remove);
    log.sign(
        &other,
        work,
        1,
        &[o0],
        data(&[
            edit(
                team_login,
                Out::default()
                    .u8(0)
                    .str("password")
                    .str("secret")
                    .str("stolen"),
            ),
            create(
                "login",
                "Stranger",
                &[("username", "text", "x")],
                false,
                &[],
            ),
        ]),
    );
    let stranger = item_id(&log_last_hash(&log), 1);

    seal_store(home, &me, &log.entries, &hex(&personal));
    Fixture {
        github: hex(&github),
        team_login: hex(&team_login),
        stranger: hex(&stranger),
    }
}

fn log_last_hash(log: &Log) -> [u8; 32] {
    let last = log.entries.last().unwrap();
    blake3::derive_key(
        "deadbolt 2026-10-15 entry hash v2",
        &last[..last.len() - 64],
    )
}

fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).unwrap();
    let mut buf = plain.to_vec();
    let tag = XChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(&nonce.into(), aad, buf.as_mut_slice().into())
        .unwrap();
    [&nonce[..], &buf, &tag[..]].concat()
}

/// The v1 store itself, at the test KDF cost (`DEADBOLT_KDF=fast`).
fn seal_store(home: &Path, me: &SigningKey, entries: &[Vec<u8>], default: &str) {
    std::fs::create_dir_all(home).unwrap();
    let (m, t, p) = (64u32, 1u32, 1u32);
    let kdf = [
        &[1u8][..],
        &m.to_le_bytes(),
        &t.to_le_bytes(),
        &p.to_le_bytes(),
        &[5u8; 16],
    ]
    .concat();
    let params = argon2::Params::new(m, t, p, Some(32)).unwrap();
    let mut unlock = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(PASSPHRASE.as_bytes(), &[5u8; 16], &mut unlock)
        .unwrap();
    let data_key = [3u8; 32];
    let keyset = [&data_key[..], &me.to_bytes()].concat();
    let keyset_aad = [&b"deadbolt-store/v1/keyset"[..], &2u32.to_le_bytes(), &kdf].concat();
    let data = blake3::derive_key("deadbolt-store v1 2026-10-15 data encryption", &data_key);
    let index = blake3::derive_key("deadbolt-store v1 2026-10-15 meta key blinding", &data_key);

    let db = redb::Database::create(home.join("store.redb")).unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut header = txn.open_table(HEADER).unwrap();
        header
            .insert("format", 2u32.to_le_bytes().as_slice())
            .unwrap();
        header.insert("kdf", kdf.as_slice()).unwrap();
        header
            .insert("keyset", seal(&unlock, &keyset_aad, &keyset).as_slice())
            .unwrap();
        let len = (entries.len() as u64).to_le_bytes();
        let sealed = seal(&data, b"deadbolt-store/v1/log-len", &len);
        header.insert("log_len", sealed.as_slice()).unwrap();
        let mut log = txn.open_table(LOG).unwrap();
        for (seq, entry) in entries.iter().enumerate() {
            let aad = [&b"deadbolt-store/v1/log"[..], &(seq as u64).to_be_bytes()].concat();
            log.insert(seq as u64, seal(&data, &aad, entry).as_slice())
                .unwrap();
        }
        let mut meta = txn.open_table(META).unwrap();
        for (name, value) in [
            ("cli/device-name", serde_json::json!("old-laptop")),
            ("cli/default-vault", serde_json::json!(default)),
        ] {
            let blinded: [u8; 32] = blake3::keyed_hash(&index, name.as_bytes()).into();
            let aad = [&b"deadbolt-store/v1/meta"[..], &blinded].concat();
            let value = serde_json::to_vec(&value).unwrap();
            meta.insert(&blinded, seal(&data, &aad, &value).as_slice())
                .unwrap();
        }
    }
    txn.commit().unwrap();
}

/// Files in `home` besides the v1 store: none until a move succeeds.
fn others(home: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(home)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "store.redb")
        .collect();
    names.sort();
    names
}

/// Checks everything the fixture holds, on the v2 store.
fn check_moved(a: &Device, fx: &Fixture) {
    let vaults = a.run(&["vault", "ls"]);
    assert!(vaults.contains("personal"), "{vaults}");
    assert!(vaults.contains("team"), "{vaults}");
    let default = vaults
        .lines()
        .find(|l| l.contains("default"))
        .unwrap_or_default();
    assert!(default.starts_with("personal"), "{vaults}");
    let device = a.run(&["devices"]);
    assert!(device.contains("old-laptop"), "{device}");

    // By name and by the item's v1 id, both as references.
    assert_eq!(a.run(&["get", "github"]).trim_end(), "hunter3");
    let by_id = format!("deadbolt://personal/{}/username", fx.github);
    assert_eq!(a.run(&["read", &by_id]).trim_end(), "kit");
    let custom = format!("deadbolt://personal/{}/recovery-codes", fx.github);
    assert_eq!(a.run(&["read", &custom]).trim_end(), "aaaa-bbbb");
    assert_eq!(
        a.run(&["read", "deadbolt://personal/GitHub/url"])
            .trim_end(),
        "https://github.com"
    );
    let code = a.run(&["code", "github"]);
    assert_eq!(code.trim_end().len(), 6, "{code}");
    let favorites = a.run(&["ls", "--favorites"]);
    assert!(favorites.contains("GitHub"), "{favorites}");
    assert!(a.run(&["ls", "--tag", "work"]).contains("GitHub"));
    assert!(!a.run(&["ls", "--tag", "work/dev"]).contains("GitHub"));

    assert_eq!(
        a.run(&["get", "wifi notes"]).trim_end(),
        "the router is in the hall"
    );
    assert_eq!(
        a.run(&["get", "deploy key", "-f", "passphrase"]).trim_end(),
        "sshpass"
    );
    let key = a.run(&["get", "deploy key", "-f", "private-key"]);
    assert!(key.contains("BEGIN OPENSSH PRIVATE KEY"), "{key}");
    assert_eq!(
        a.run(&["get", "example passkey", "-f", "rp-id"]).trim_end(),
        "example.com"
    );
    let out = a.path("scan.bin");
    a.run(&["get", "passport scan", "--output", out.to_str().unwrap()]);
    assert_eq!(std::fs::read(&out).unwrap(), attachment());
    let deleted = a.run(&["ls", "--deleted"]);
    assert!(deleted.contains("Old forum"), "{deleted}");
    assert!(!a.run(&["ls"]).contains("Old forum"));

    // The removed device's first write counts, its later ones don't.
    let team = format!("deadbolt://team/{}/password", fx.team_login);
    assert_eq!(a.run(&["read", &team]).trim_end(), "s3cret");
    assert!(!a.run(&["--vault", "team", "ls"]).contains("Stranger"));
    let stranger = format!("deadbolt://team/{}/username", fx.stranger);
    assert!(!a.try_run(&["read", &stranger]).status.success());
}

#[test]
fn migrate_moves_a_v1_store_to_v2() {
    let a = Device::new();
    let home = a.path("home");
    let fx = write_v1(&home);
    let v1 = std::fs::read(home.join("store.redb")).unwrap();

    // Nothing sets up a new vault over it.
    let err = a.fail(&["init"]);
    assert!(err.contains("deadbolt migrate"), "{err}");
    assert_eq!(a.state(), "locked");

    // A wrong passphrase changes nothing and leaves nothing behind.
    let mut wrong = a.cmd(&["migrate"]);
    wrong.env("DEADBOLT_PASSPHRASE", "wrong horse");
    let out = a.output(&mut wrong);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong passphrase"));
    assert_eq!(std::fs::read(home.join("store.redb")).unwrap(), v1);
    assert_eq!(others(&home), Vec::<String>::new());

    let out = a.try_run_stdin(
        &["--passphrase-stdin", "migrate", "--json"],
        &format!("{PASSPHRASE}\n"),
    );
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let migrated = json["migrated"].as_array().unwrap();
    assert_eq!(migrated.len(), 2, "{json}");
    assert_eq!(migrated[0]["name"], "personal");
    assert_eq!(migrated[0]["default"], true);
    assert_eq!(migrated[0]["items"], 5);
    assert_eq!(migrated[1]["name"], "team");
    for vault in migrated {
        let kit = vault["recovery_kit"].as_str().unwrap();
        assert_eq!(kit.split(' ').count(), 24, "{kit}");
    }
    assert!(!home.join("store.redb").exists());
    assert_eq!(std::fs::read(home.join("store.redb.v1.bak")).unwrap(), v1);
    assert!(!home.join(".v1-migrate").exists());

    check_moved(&a, &fx);
    // The same passphrase opens the v2 store from now on.
    a.run(&["lock"]);
    a.run(&["unlock"]);
    assert_eq!(a.run(&["get", "github"]).trim_end(), "hunter3");

    let err = a.fail(&["migrate"]);
    assert!(err.contains("already on v2"), "{err}");
}

#[test]
fn unlock_moves_a_v1_store_and_shows_its_kits() {
    let a = Device::new();
    let home = a.path("home");
    let fx = write_v1(&home);
    let out = a.run(&["unlock"]);
    assert!(
        out.contains("Upgraded to Deadbolt v2: moved 2 vaults"),
        "{out}"
    );
    assert!(out.contains("Vault personal (default): 5 items"), "{out}");
    assert!(out.contains("Vault team: 1 item"), "{out}");
    assert_eq!(out.matches("Recovery kit:").count(), 2, "{out}");
    assert!(out.contains(" 24. "), "{out}");
    assert!(out.trim_end().ends_with("unlocked"), "{out}");
    assert!(home.join("store.redb.v1.bak").exists());
    check_moved(&a, &fx);
}
/// The kits `deadbolt migrate --json` printed, in order.
fn migrate_kits(a: &Device) -> Vec<String> {
    let out = a.try_run_stdin(
        &["--passphrase-stdin", "migrate", "--json"],
        &format!("{PASSPHRASE}\n"),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    json["migrated"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["recovery_kit"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_cutover_cut_short_before_its_commit_moves_again() {
    let a = Device::new();
    let home = a.path("home");
    let fx = write_v1(&home);
    let first = migrate_kits(&a);
    a.run(&["debug", "daemon", "stop"]);

    // As a crash just before `store.redb` was renamed leaves it: the moved
    // v2 store, the old one, and the marker. Its kits may never have shown.
    std::fs::rename(home.join("store.redb.v1.bak"), home.join("store.redb")).unwrap();
    std::fs::create_dir(home.join(".v1-migrate")).unwrap();
    std::fs::write(home.join(".v1-migrate/verified"), b"").unwrap();
    let err = a.fail(&["init"]);
    assert!(err.contains("deadbolt migrate"), "{err}");
    assert_eq!(a.state(), "locked");

    let again = migrate_kits(&a);
    assert_eq!(again.len(), 2);
    assert!(again.iter().all(|kit| !first.contains(kit)), "fresh kits");
    assert!(!home.join("store.redb").exists());
    assert!(home.join("store.redb.v1.bak").exists());
    assert!(!home.join(".v1-migrate").exists());
    check_moved(&a, &fx);
}
