use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use super::*;
use crate::protocol::FieldInput;

const OTP: &str = "JBSWY3DPEHPK3PXP";

fn loaded(dir: &std::path::Path) -> Loaded {
    let params = deadbolt_store::KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    let mut loaded = Loaded::setup(dir, b"test", "test", params).unwrap();
    loaded.create_vault("personal").unwrap();
    loaded
}

fn login(s: &mut Loaded, name: &str, fields: &[(&str, &str)]) -> LoginRef {
    let vault = s.resolve(None).unwrap();
    let inputs = fields
        .iter()
        .map(|(name, value)| FieldInput {
            name: (*name).into(),
            kind: None,
            value: (*value).into(),
        })
        .collect();
    let info = super::super::items::create(s, None, "login", Some(name.into()), inputs).unwrap();
    LoginRef {
        vault: hex(vault.as_bytes()),
        item: info.id,
    }
}

fn code(error: &anyhow::Error) -> Option<ErrorCode> {
    error.downcast_ref::<DaemonError>().map(|e| e.code)
}

fn auth(info: &AgentClientInfo, token: &Secret) -> ClientAuth {
    ClientAuth {
        id: info.id.clone(),
        token: token.clone(),
    }
}

fn allow<'a>(client: &'a str, site: &'a str, fields: &'a [Fill]) -> NewGrant<'a> {
    NewGrant {
        client_id: client,
        site: Some(site),
        login: None,
        fields,
        passkeys: false,
        expires_at: None,
    }
}

const NOW: u64 = 1_800_000_000;
const FILL_NOW: Duration = Duration::from_secs(NOW);

#[test]
fn a_paired_client_fills_only_what_is_granted() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let github = login(
        &mut s,
        "GitHub",
        &[
            ("username", "kit"),
            ("password", "hunter2"),
            ("url", "https://github.com/login"),
            ("otp", OTP),
        ],
    );
    let (client, token) = add_client(&s, "browse", NOW).unwrap();
    let me = auth(&client, &token);
    assert_eq!(token.expose().len(), 64);
    // Only the token's hash is stored.
    let stored =
        String::from_utf8(s.store.meta_get(META_CLIENTS).unwrap().unwrap().to_vec()).unwrap();
    assert!(!stored.contains(token.expose()), "{stored}");

    // Nothing granted: not-granted, naming the site and nothing more.
    let error = fill(
        &s,
        &me,
        "https://github.com",
        &github,
        &[Fill::Password],
        FILL_NOW,
    )
    .unwrap_err();
    assert_eq!(code(&error), Some(ErrorCode::NotGranted));
    let detail = error
        .downcast_ref::<DaemonError>()
        .unwrap()
        .grant
        .clone()
        .unwrap();
    assert_eq!((detail.site.as_str(), detail.login), ("github.com", None));
    let (site, granted, listed, _) = logins(&s, &me, "https://github.com", NOW).unwrap();
    assert_eq!(
        (site.as_str(), granted, listed.len()),
        ("github.com", false, 0)
    );

    set_grant(
        &s,
        allow(
            &client.id,
            "www.github.com",
            &[Fill::Username, Fill::Password],
        ),
        NOW,
    )
    .unwrap();
    let (_, granted, listed, _) = logins(&s, &me, "https://github.com", NOW).unwrap();
    assert!(granted);
    assert_eq!(listed[0].fields, [Fill::Username, Fill::Password]);
    assert!(listed[0].has_totp && !listed[0].passkeys);
    let values = fill(
        &s,
        &me,
        "https://github.com",
        &github,
        &[Fill::Username, Fill::Password],
        FILL_NOW,
    )
    .unwrap();
    assert_eq!(values.username.as_deref(), Some("kit"));
    assert_eq!(values.password.unwrap().expose(), "hunter2");
    assert_eq!(list_clients(&s).unwrap()[0].last_used, Some(NOW));

    // The code isn't granted: not-granted names the login.
    let error = fill(
        &s,
        &me,
        "https://github.com",
        &github,
        &[Fill::Totp],
        FILL_NOW,
    )
    .unwrap_err();
    let detail = error
        .downcast_ref::<DaemonError>()
        .unwrap()
        .grant
        .clone()
        .unwrap();
    assert_eq!(detail.login.as_deref(), Some("kit"));

    // Granting the code gives the current one, never the secret.
    let mut grant = allow(&client.id, "github.com", &[Fill::Totp]);
    grant.login = Some("kit");
    set_grant(&s, grant, NOW).unwrap();
    let values = fill(
        &s,
        &me,
        "https://github.com",
        &github,
        &[Fill::Totp],
        FILL_NOW,
    )
    .unwrap();
    let expected = deadbolt_core::totp::Totp::parse(OTP).unwrap().code(NOW);
    assert_eq!(values.totp.unwrap().expose(), expected);
}

#[test]
fn other_origins_tokens_and_removed_clients_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let github = login(
        &mut s,
        "GitHub",
        &[
            ("username", "kit"),
            ("password", "hunter2"),
            ("url", "github.com"),
        ],
    );
    let (client, token) = add_client(&s, "browse", NOW).unwrap();
    let me = auth(&client, &token);
    set_grant(&s, allow(&client.id, "github.com", &[Fill::Password]), NOW).unwrap();

    // Another site's frame gets nothing, whatever it names.
    let error = fill(
        &s,
        &me,
        "https://evil.com",
        &github,
        &[Fill::Password],
        FILL_NOW,
    )
    .unwrap_err();
    assert_eq!(code(&error), Some(ErrorCode::NotGranted));
    // A grant for evil.com doesn't make the GitHub login evil.com's.
    set_grant(&s, allow(&client.id, "evil.com", &[Fill::Password]), NOW).unwrap();
    let error = fill(
        &s,
        &me,
        "https://evil.com",
        &github,
        &[Fill::Password],
        FILL_NOW,
    )
    .unwrap_err();
    assert_eq!(code(&error), Some(ErrorCode::DomainMismatch));
    // An exact-origin grant covers that origin only.
    let (other, other_token) = add_client(&s, "other", NOW).unwrap();
    let them = auth(&other, &other_token);
    set_grant(
        &s,
        allow(&other.id, "https://github.com", &[Fill::Password]),
        NOW,
    )
    .unwrap();
    assert!(
        fill(
            &s,
            &them,
            "https://github.com",
            &github,
            &[Fill::Password],
            FILL_NOW
        )
        .is_ok()
    );
    let error = fill(
        &s,
        &them,
        "https://gist.github.com",
        &github,
        &[Fill::Password],
        FILL_NOW,
    )
    .unwrap_err();
    assert_eq!(code(&error), Some(ErrorCode::NotGranted));

    // A wrong token, or a removed client, is forbidden.
    let wrong = ClientAuth {
        id: client.id.clone(),
        token: Secret::new("0".repeat(64)),
    };
    let error = fill(
        &s,
        &wrong,
        "https://github.com",
        &github,
        &[Fill::Password],
        FILL_NOW,
    )
    .unwrap_err();
    assert_eq!(code(&error), Some(ErrorCode::Forbidden));
    remove_client(&s, &client.id).unwrap();
    let error = fill(
        &s,
        &me,
        "https://github.com",
        &github,
        &[Fill::Password],
        FILL_NOW,
    )
    .unwrap_err();
    assert_eq!(code(&error), Some(ErrorCode::Forbidden));
    // Its grants went with it.
    assert!(
        list_grants(&s, NOW)
            .unwrap()
            .iter()
            .all(|g| g.client_id == other.id)
    );
}

#[test]
fn grants_expire_and_name_sites_and_logins_strictly() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let github = login(
        &mut s,
        "GitHub",
        &[
            ("username", "kit"),
            ("password", "hunter2"),
            ("url", "github.com"),
        ],
    );
    let (client, token) = add_client(&s, "browse", NOW).unwrap();
    let me = auth(&client, &token);
    let mut grant = allow(&client.id, "github.com", &[Fill::Password]);
    grant.expires_at = Some(NOW + 60);
    let made = set_grant(&s, grant, NOW).unwrap();
    assert!(!made.expired);
    assert!(
        fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Password],
            FILL_NOW
        )
        .is_ok()
    );
    let later = Duration::from_secs(NOW + 60);
    let error = fill(
        &s,
        &me,
        "https://github.com",
        &github,
        &[Fill::Password],
        later,
    )
    .unwrap_err();
    assert_eq!(code(&error), Some(ErrorCode::NotGranted));
    assert!(list_grants(&s, NOW + 60).unwrap()[0].expired);

    for bad in ["github.io", "github.com/login", "", "ftp://github.com"] {
        assert!(grant_site(bad).is_err(), "{bad}");
    }
    assert_eq!(grant_site("WWW.GitHub.com").unwrap(), "github.com");
    assert_eq!(
        grant_site("https://App.Example.com/login").unwrap(),
        "https://app.example.com"
    );
    let mut unknown = allow(&client.id, "github.com", &[Fill::Password]);
    unknown.login = Some("someone-else");
    assert_eq!(
        code(&set_grant(&s, unknown, NOW).unwrap_err()),
        Some(ErrorCode::NotFound)
    );
    assert!(set_grant(&s, allow(&client.id, "github.com", &[]), NOW).is_err());
    let mut past = allow(&client.id, "github.com", &[Fill::Password]);
    past.expires_at = Some(NOW);
    assert!(set_grant(&s, past, NOW).is_err());
    // Setting it again replaces it.
    set_grant(&s, allow(&client.id, "github.com", &[Fill::Username]), NOW).unwrap();
    let all = list_grants(&s, NOW).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(
        (all[0].id.as_str(), all[0].fields.as_slice()),
        (made.id.as_str(), &[Fill::Username][..])
    );
    remove_grant(&s, &made.id[..6]).unwrap();
    assert!(list_grants(&s, NOW).unwrap().is_empty());
}

fn register(s: &mut Loaded, origin: &str, rp: Option<&str>, user: &str) -> passkeys::Created {
    let new = passkeys::check_create(
        s,
        origin,
        rp,
        &webauthn::b64(&[5; 32]),
        &webauthn::b64(user.as_bytes()),
        user,
        &[],
    )
    .unwrap();
    let new = passkeys::NewPasskey {
        display_name: passkeys::user_text(&format!("{user} (display)\n")),
        ..new
    };
    passkeys::create_passkey(s, &new, false, 1_798_000_000).unwrap()
}

#[test]
fn passkeys_sign_with_presence_never_verification_and_only_when_granted() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let kit = login(
        &mut s,
        "Example",
        &[
            ("username", "kit"),
            ("password", "pw"),
            ("url", "example.com"),
        ],
    );
    let made = register(&mut s, "https://example.com", None, "kit");
    let (client, token) = add_client(&s, "browse", NOW).unwrap();
    let me = auth(&client, &token);
    let challenge = webauthn::b64(&[9; 32]);
    let request = |uv| PasskeyRequest {
        origin: "https://example.com",
        rp_id: None,
        challenge: &challenge,
        allow_credentials: &[],
        user_verification: uv,
        login: None,
    };
    // A grant for the password doesn't cover the passkey.
    set_grant(&s, allow(&client.id, "example.com", &[Fill::Password]), NOW).unwrap();
    let error = passkey(&s, &me, request(Verify::Preferred), NOW)
        .err()
        .unwrap();
    assert_eq!(code(&error), Some(ErrorCode::NotGranted));

    let mut grant = allow(&client.id, "example.com", &[]);
    grant.passkeys = true;
    grant.login = Some(&kit.item);
    set_grant(&s, grant, NOW).unwrap();
    let (_, _, listed, keys) = logins(&s, &me, "https://example.com", NOW).unwrap();
    assert!(listed[0].has_passkey && listed[0].passkeys);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].username.as_deref(), Some("kit"));
    assert_eq!(keys[0].passkey, made.passkey);
    let signed = passkey(&s, &me, request(Verify::Preferred), NOW).unwrap();
    let data = webauthn::unb64(&signed.authenticator_data).unwrap();
    assert_eq!(data[32] & 0x01, 0x01, "user present");
    assert_eq!(data[32] & 0x04, 0, "never user verified");
    let client_data = webauthn::unb64(&signed.client_data_json).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&client_data).unwrap();
    assert_eq!(parsed["origin"], "https://example.com");
    let key =
        VerifyingKey::from_public_key_der(&webauthn::unb64(&made.public_key).unwrap()).unwrap();
    let mut signed_data = data.clone();
    signed_data.extend_from_slice(&Sha256::digest(&client_data));
    let signature = Signature::from_der(&webauthn::unb64(&signed.signature).unwrap()).unwrap();
    assert!(key.verify(&signed_data, &signature).is_ok());

    // A site that requires verification gets nothing; nor does another
    // relying party, or a credential list naming none here.
    assert!(passkey(&s, &me, request(Verify::Required), NOW).is_err());
    let mut evil = request(Verify::Preferred);
    evil.origin = "https://evil.com";
    assert!(passkey(&s, &me, evil, NOW).is_err());
    let other = [webauthn::b64(&[1; 16])];
    let mut elsewhere = request(Verify::Preferred);
    elsewhere.allow_credentials = &other;
    assert_eq!(
        code(&passkey(&s, &me, elsewhere, NOW).err().unwrap()),
        Some(ErrorCode::NotGranted)
    );
    // A second user's passkey isn't covered by a grant for kit's login.
    let bob = register(&mut s, "https://example.com", None, "bob");
    let only_bob = [bob.credential_id];
    let mut as_bob = request(Verify::Preferred);
    as_bob.allow_credentials = &only_bob;
    assert_eq!(
        code(&passkey(&s, &me, as_bob, NOW).err().unwrap()),
        Some(ErrorCode::NotGranted)
    );
    assert!(passkey(&s, &me, request(Verify::Discouraged), NOW).is_ok());
}

#[test]
fn a_grant_for_every_site_still_fills_each_login_only_on_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let github = login(
        &mut s,
        "GitHub",
        &[
            ("username", "kit"),
            ("password", "hunter2"),
            ("url", "github.com"),
        ],
    );
    let (client, token) = add_client(&s, "browse", NOW).unwrap();
    let me = auth(&client, &token);
    let mut every = allow(
        &client.id,
        "x",
        &[Fill::Username, Fill::Password, Fill::Totp],
    );
    every.site = None;
    every.passkeys = true;
    let made = set_grant(&s, every, NOW).unwrap();
    assert_eq!(made.site, None);
    assert!(
        fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Password],
            FILL_NOW
        )
        .is_ok()
    );
    let (_, granted, listed, _) = logins(&s, &me, "https://example.org", NOW).unwrap();
    assert!(granted && listed.is_empty());
    // Every site, but the GitHub login is still GitHub's.
    let error = fill(
        &s,
        &me,
        "https://evil.com",
        &github,
        &[Fill::Password],
        FILL_NOW,
    )
    .unwrap_err();
    assert_eq!(code(&error), Some(ErrorCode::DomainMismatch));
    // It can't name a login, and it is revoked like any other.
    let mut named = allow(&client.id, "x", &[Fill::Password]);
    named.site = None;
    named.login = Some("kit");
    assert!(set_grant(&s, named, NOW).is_err());
    assert_eq!(remove_grant(&s, &made.id).unwrap(), "every site");
    assert!(
        fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Password],
            FILL_NOW
        )
        .is_err()
    );
}

#[test]
fn several_passkeys_are_chosen_by_ref_within_the_grant() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = loaded(dir.path());
    let kit = register(&mut s, "https://example.com", None, "kit");
    let bob = register(&mut s, "https://example.com", None, "bob");
    let (client, token) = add_client(&s, "browse", NOW).unwrap();
    let me = auth(&client, &token);
    let mut grant = allow(&client.id, "example.com", &[]);
    grant.passkeys = true;
    set_grant(&s, grant, NOW).unwrap();
    let challenge = webauthn::b64(&[9; 32]);
    fn get<'a>(
        challenge: &'a str,
        login: Option<&'a LoginRef>,
        allow: &'a [String],
    ) -> PasskeyRequest<'a> {
        PasskeyRequest {
            origin: "https://example.com",
            rp_id: None,
            challenge,
            allow_credentials: allow,
            user_verification: Verify::Preferred,
            login,
        }
    }
    let request = |login, allow| get(&challenge, login, allow);
    // Both listed, with their user names and refs.
    let (_, _, _, keys) = logins(&s, &me, "https://example.com", NOW).unwrap();
    let mut users: Vec<_> = keys.iter().map(|k| k.username.clone().unwrap()).collect();
    users.sort();
    assert_eq!(users, ["bob", "kit"]);
    assert!(
        keys.iter()
            .any(|k| k.display_name.as_deref() == Some("kit (display)"))
    );

    // Unnamed with two candidates: choose-passkey lists them, no secrets.
    let error = passkey(&s, &me, request(None, &[]), NOW).err().unwrap();
    let refused = error.downcast_ref::<DaemonError>().unwrap();
    assert_eq!(refused.code, ErrorCode::ChoosePasskey);
    let choices = refused.passkeys.clone().unwrap();
    assert_eq!(choices.len(), 2);
    assert!(choices.iter().any(|c| c.passkey == kit.passkey));
    let json = serde_json::to_string(&choices).unwrap();
    assert!(!json.contains("private"), "{json}");

    // The chosen ref is the one that signs.
    let signed = passkey(&s, &me, request(Some(&bob.passkey), &[]), NOW).unwrap();
    assert_eq!(signed.credential_id, bob.credential_id);
    // allowCredentials narrows the candidates to one: no choice needed.
    let only_kit = [kit.credential_id.clone()];
    let signed = passkey(&s, &me, request(None, &only_kit), NOW).unwrap();
    assert_eq!(signed.credential_id, kit.credential_id);
    // A chosen ref outside allowCredentials, or outside the grant, is refused.
    let error = passkey(&s, &me, request(Some(&bob.passkey), &only_kit), NOW)
        .err()
        .unwrap();
    assert_eq!(code(&error), Some(ErrorCode::NotGranted));
    let mut kit_only = allow(&client.id, "example.com", &[]);
    kit_only.passkeys = true;
    let mut s2 = s;
    let kit_login = login(
        &mut s2,
        "Example",
        &[
            ("username", "kit"),
            ("password", "pw"),
            ("url", "example.com"),
        ],
    );
    kit_only.login = Some(&kit_login.item);
    // Replace the site-wide passkey grant with one for kit's login.
    let site_wide = list_grants(&s2, NOW).unwrap()[0].id.clone();
    remove_grant(&s2, &site_wide).unwrap();
    set_grant(&s2, kit_only, NOW).unwrap();
    let error = passkey(&s2, &me, request(Some(&bob.passkey), &[]), NOW)
        .err()
        .unwrap();
    assert_eq!(code(&error), Some(ErrorCode::NotGranted));
    let signed = passkey(&s2, &me, request(None, &[]), NOW).unwrap();
    assert_eq!(signed.credential_id, kit.credential_id);
    // Another relying party's passkey, named by ref, is refused as such.
    let other = register(&mut s2, "https://other.com", None, "kit");
    let error = passkey(&s2, &me, request(Some(&other.passkey), &[]), NOW)
        .err()
        .unwrap();
    assert_eq!(code(&error), Some(ErrorCode::DomainMismatch));
}

mod daemon {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    use super::super::super::passkeys::tests::daemon::{conversation, unlocked};
    use super::*;
    use crate::protocol::{Claim, MAX_LINE, Message, Outcome, PROTOCOL_VERSION, Request};

    fn kit() -> CallerInfo {
        CallerInfo {
            identified: true,
            ..CallerInfo::unverified("Ghostty › zsh › deadbolt")
        }
    }

    fn add(passphrase: Option<&str>) -> Command {
        Command::AgentClientAdd {
            name: "browse".into(),
            passphrase: passphrase.map(|p| Zeroizing::new(p.into())),
        }
    }

    fn code(error: &anyhow::Error) -> Option<ErrorCode> {
        error.downcast_ref::<DaemonError>().map(|e| e.code)
    }

    async fn ask(daemon: &Arc<Daemon>, claimed: Option<Claim>, command: Command) -> Message {
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut line = serde_json::to_vec(&Request {
            v: PROTOCOL_VERSION,
            claimed,
            command,
        })
        .unwrap();
        line.push(b'\n');
        client.write_all(&line).await.unwrap();
        daemon.clone().handle(server, MAX_LINE).await.unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        serde_json::from_str(&reply).unwrap()
    }

    #[tokio::test]
    async fn pairing_needs_the_user_and_never_an_ai() {
        let f = unlocked().await;
        let (conv, _closed) = conversation();
        let taps = Arc::new(AtomicUsize::new(0));
        let (key, seen) = (f.key, taps.clone());
        *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(key))
        }));
        let clients = || f.daemon.with(|s| list_clients(s)).unwrap().len();

        // An AI is refused, passphrase or not, before anyone is asked.
        let mut ai = kit();
        ai.claimed = Some(Claim {
            caller: None,
            opencode_session: Some("ses_1".into()),
        });
        for command in [add(None), add(Some("test"))] {
            let error = f
                .daemon
                .agents_admin(&ai, command, &conv)
                .await
                .unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::Forbidden));
        }
        let mut opencode = kit();
        opencode.ancestry = vec![crate::protocol::Ancestor {
            pid: 9,
            name: "opencode".into(),
            path: None,
        }];
        let grant = Command::AgentGrantSet {
            client_id: "x".into(),
            site: Some("github.com".into()),
            login: None,
            fields: vec![Fill::Password],
            passkeys: false,
            expires_at: None,
            passphrase: Some(Zeroizing::new("test".into())),
        };
        let error = f
            .daemon
            .agents_admin(&opencode, grant, &conv)
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::Forbidden));
        assert_eq!((taps.load(Ordering::SeqCst), clients()), (0, 0));

        // Touch ID, raised by the daemon.
        let reply = f
            .daemon
            .agents_admin(&kit(), add(None), &conv)
            .await
            .unwrap();
        assert!(matches!(reply, Reply::AgentClientAdded { .. }), "{reply:?}");
        assert_eq!((taps.load(Ordering::SeqCst), clients()), (1, 1));
        // Or the passphrase, checked.
        let error = f
            .daemon
            .agents_admin(&kit(), add(Some("wrong")), &conv)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "wrong passphrase");
        f.daemon
            .agents_admin(&kit(), add(Some("test")), &conv)
            .await
            .unwrap();
        assert_eq!((taps.load(Ordering::SeqCst), clients()), (1, 2));
        // Without Touch ID, nothing but the passphrase will do.
        *f.daemon.touch_id_available_override.lock().unwrap() = Some(false);
        let error = f
            .daemon
            .agents_admin(&kit(), add(None), &conv)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("needs your passphrase"),
            "{error}"
        );

        // Over the socket, a claim to be an OpenCode session is refused
        // and recorded as refused.
        let refused = ask(
            &f.daemon,
            Some(Claim {
                caller: None,
                opencode_session: Some("ses_1".into()),
            }),
            add(Some("test")),
        )
        .await;
        assert!(
            matches!(
                refused,
                Message::Error {
                    code: ErrorCode::Forbidden,
                    ..
                }
            ),
            "{refused:?}"
        );
        assert_eq!(clients(), 2);

        // Locked: nothing is asked.
        f.daemon.lock().await;
        let error = f
            .daemon
            .agents_admin(&kit(), add(None), &conv)
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::Locked));
    }

    /// The KDF runs off the session's lock: the vault answers while a
    /// passphrase is checked, and a second check meanwhile is refused.
    #[test]
    fn a_passphrase_check_never_holds_the_vault() {
        use std::future::Future;
        use std::task::Poll;

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                let f = unlocked().await;
                // Occupy the blocking pool so the real KDF queues until
                // released. No assumption about Argon2 speed or when a
                // loaded CI runner will schedule a 20 ms timer.
                let (release, wait) = std::sync::mpsc::channel::<()>();
                let (started, ready) = tokio::sync::oneshot::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    started.send(()).unwrap();
                    // Dropping release also unblocks this on assertion failure.
                    wait.recv().unwrap_or_default();
                });
                ready.await.unwrap();
                let (conv, _closed) = conversation();
                let me = kit();
                let mut checking =
                    std::pin::pin!(f.daemon.agents_admin(&me, add(Some("wrong")), &conv));
                std::future::poll_fn(|cx| {
                    assert!(checking.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                // A regression must fail, not deadlock on the session lock.
                assert!(f.daemon.session.try_lock().is_ok());
                f.daemon.with(|s| list_clients(s)).unwrap();
                let mut second =
                    std::pin::pin!(f.daemon.agents_admin(&me, add(Some("test")), &conv));
                let error = std::future::poll_fn(|cx| {
                    let result = second.as_mut().poll(cx);
                    assert!(
                        result.is_ready(),
                        "a concurrent check must be refused immediately"
                    );
                    result
                })
                .await
                .unwrap_err();
                assert_eq!(code(&error), Some(ErrorCode::RateLimited));
                release.send(()).unwrap();
                blocker.await.unwrap();
                let error = checking.await.unwrap_err();
                assert_eq!(error.to_string(), "wrong passphrase");
            });
    }

    #[tokio::test]
    async fn wrong_passphrases_back_off() {
        let f = unlocked().await;
        *f.daemon.touch_id_available_override.lock().unwrap() = Some(false);
        let (conv, _closed) = conversation();
        let me = kit();
        let try_with = |passphrase| f.daemon.agents_admin(&me, add(Some(passphrase)), &conv);
        for _ in 0..super::super::super::guesses::FREE_FAILURES - 1 {
            assert!(try_with("wrong").await.is_err());
        }
        // A right one resets the count.
        try_with("test").await.unwrap();
        for _ in 0..super::super::super::guesses::FREE_FAILURES {
            let error = try_with("wrong").await.unwrap_err();
            assert_eq!(error.to_string(), "wrong passphrase");
        }
        // Now even the right one waits.
        let error = try_with("test").await.unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::RateLimited), "{error}");
    }

    #[tokio::test]
    async fn a_client_is_rate_limited_locked_out_and_in_activity() {
        let f = unlocked().await;
        let (conv, _closed) = conversation();
        let reply = f
            .daemon
            .agents_admin(&kit(), add(Some("test")), &conv)
            .await
            .unwrap();
        let Reply::AgentClientAdded { client, token } = reply else {
            unreachable!()
        };
        let me = ClientAuth {
            id: client.id.clone(),
            token,
        };
        let logins = || Command::AgentLogins {
            client: me.clone(),
            origin: "https://github.com".into(),
        };
        let reply = ask(&f.daemon, None, logins()).await;
        assert!(matches!(reply, Message::Ok { .. }), "{reply:?}");
        let entries = f
            .daemon
            .with(|s| Ok(s.store.activity_list(0, None, 10)?))
            .unwrap();
        let last: ActivityEntry = serde_json::from_slice(&entries.rows[0].bytes).unwrap();
        assert_eq!(last.command, "agent-logins");
        assert_eq!(last.client.as_deref(), Some("browse"));
        assert_eq!(last.tier, crate::protocol::Tier::Agent);

        let mut answered = 1;
        let limited = loop {
            match f.daemon.agent_client(logins()) {
                Ok(_) => answered += 1,
                Err(error) => break error,
            }
            assert!(answered < 100, "never limited");
        };
        assert_eq!(code(&limited), Some(ErrorCode::RateLimited));
        assert!(answered >= RATE.0, "limited after {answered}");
        // Another client has a budget of its own; a wrong token none.
        let wrong = ClientAuth {
            id: client.id.clone(),
            token: Secret::new("f".repeat(64)),
        };
        let error = f
            .daemon
            .agent_client(Command::AgentLogins {
                client: wrong,
                origin: "https://github.com".into(),
            })
            .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::Forbidden));

        // Locked, every agent request is `locked`, and its entry says so.
        f.daemon.lock().await;
        let reply = ask(&f.daemon, None, logins()).await;
        assert!(
            matches!(
                reply,
                Message::Error {
                    code: ErrorCode::Locked,
                    ..
                }
            ),
            "{reply:?}"
        );
        let held = f.daemon.activity.lock().unwrap().take_held();
        assert_eq!(held.last().map(|e| e.outcome), Some(Outcome::Locked));
    }
}
