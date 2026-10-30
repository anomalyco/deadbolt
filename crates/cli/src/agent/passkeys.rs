//! Passkeys: the agent is the authenticator. A passkey is an item of kind
//! `passkey` found by its relying party id; its private key is read here to
//! sign and is never listed, returned or exported to a client. Every request
//! names the page's origin, which the browser (not the page) reported, and
//! the agent builds the client data from it (see docs/autofill.md).

use std::sync::Arc;

use anyhow::{Result, anyhow};
use deadbolt_core::{Item, ItemId, VaultId, passkeys as shared};
#[cfg(test)]
use zeroize::Zeroizing;

use super::session::{self, Loaded, hex, unhex};
use super::{Agent, Conversation, ErrorCode, biometric, fail};
use crate::config::Config;
use crate::protocol::{Command, LoginRef, Reply, SitePasskey, Verify};
use crate::webauthn;
pub use shared::{NewPasskey, private, user_text};

fn shared_error(error: shared::Error) -> anyhow::Error {
    match error {
        shared::Error::DomainMismatch(_) => fail(ErrorCode::DomainMismatch, error.to_string()),
        shared::Error::Exists => fail(ErrorCode::Exists, error.to_string()),
        shared::Error::NotFound => fail(ErrorCode::NotFound, error.to_string()),
        _ => error.into(),
    }
}

/// The relying party id a page at `origin` asks for, checked.
pub fn rp_id(origin: &str, rp_id: Option<&str>) -> Result<String> {
    if origin == "null" {
        return Err(fail(
            ErrorCode::DomainMismatch,
            "a sandboxed or opaque frame gets no passkeys",
        ));
    }
    crate::site::rp_id(origin, rp_id).map_err(|reason| {
        fail(
            ErrorCode::DomainMismatch,
            format!("{origin}: {reason} ({})", rp_id.unwrap_or("no rp id")),
        )
    })
}

fn value<'a>(item: &'a Item, field: &str) -> Option<&'a str> {
    item.fields
        .get(field)
        .map(|f| f.value.as_str())
        .filter(|v| !v.is_empty())
}

fn passkey_ref(vault: &VaultId, item: &ItemId) -> LoginRef {
    LoginRef {
        vault: hex(vault.as_bytes()),
        item: hex(item.as_bytes()),
    }
}

/// Every passkey for the relying party `rp`, in every vault.
pub(super) fn passkeys<'a>(
    s: &'a Loaded,
    rp: &'a str,
) -> impl Iterator<Item = (VaultId, Item)> + 'a {
    s.vaults.iter().flat_map(move |(id, vault)| {
        vault
            .items()
            .into_iter()
            .filter(|item| shared::matches(item, rp))
            .map(move |item| (*id, item))
    })
}

pub fn list(s: &Loaded, origin: &str, rp: Option<&str>) -> Result<(String, Vec<SitePasskey>)> {
    let rp = rp_id(origin, rp)?;
    let mut found: Vec<SitePasskey> = passkeys(s, &rp)
        .map(|(vault, item)| SitePasskey {
            passkey: passkey_ref(&vault, &item.id),
            vault: s.vault(&vault).name().to_string(),
            credential_id: value(&item, "credential-id").unwrap_or_default().into(),
            username: value(&item, "username").map(str::to_string),
            created: value(&item, "created").map(str::to_string),
        })
        .collect();
    found.sort_by(|a, b| {
        (&a.username, &a.vault, &a.passkey.item).cmp(&(&b.username, &b.vault, &b.passkey.item))
    });
    Ok((rp, found))
}

/// Refuses a registration when the site already has one of `exclude` here.
fn check_excluded(s: &Loaded, rp: &str, exclude: &[String]) -> Result<()> {
    let items: Vec<_> = passkeys(s, rp).map(|(_, item)| item).collect();
    shared::check_excluded(&items, rp, exclude).map_err(shared_error)
}

/// Checks a registration before the user is asked or anything is stored:
/// the relying party, the challenge and user handle, and that the site
/// doesn't already have one of `exclude` here.
pub fn check_create(
    s: &Loaded,
    origin: &str,
    rp: Option<&str>,
    challenge: &str,
    user_id: &str,
    user_name: &str,
    exclude: &[String],
) -> Result<NewPasskey> {
    let rp = rp_id(origin, rp)?;
    let new = shared::check_create(origin, Some(&rp), challenge, user_id, user_name, exclude)
        .map_err(shared_error)?;
    check_excluded(s, &new.rp_id, exclude)?;
    Ok(new)
}

pub struct Created {
    pub passkey: LoginRef,
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub authenticator_data: String,
    pub public_key: String,
}

/// Makes the passkey `new` describes as a new item in the default vault,
/// preserving any existing credential until the user explicitly deletes it.
/// The vault can have changed while the user was asked, so exclusions are
/// checked again here. `now` is Unix seconds, for its creation date.
pub fn create_passkey(
    s: &mut Loaded,
    new: &NewPasskey,
    verified: bool,
    now: i64,
) -> Result<Created> {
    check_excluded(s, &new.rp_id, &new.exclude)?;
    let created = crate::import::onepassword::date(now);
    let made = shared::register(new, verified, &created).map_err(shared_error)?;

    let vault = s.resolve(None)?;
    let entry = s.update(vault, |v, secret| Ok(v.write(secret, vec![made.create])?))?;
    let passkey = passkey_ref(&vault, &ItemId::of_create(&entry.hash(), 0));
    Ok(Created {
        passkey,
        credential_id: made.credential_id,
        client_data_json: made.client_data_json,
        attestation_object: made.attestation_object,
        authenticator_data: made.authenticator_data,
        public_key: made.public_key,
    })
}

/// The passkey `passkey` names, refused unless it's for the relying party
/// `rp`.
pub fn find(s: &Loaded, passkey: &LoginRef, rp: &str) -> Result<(VaultId, Item)> {
    let not_found = || fail(ErrorCode::NotFound, "no such passkey");
    let vault = VaultId::from_bytes(unhex(&passkey.vault).map_err(|_| not_found())?);
    let id = ItemId::from_bytes(unhex(&passkey.item).map_err(|_| not_found())?);
    let item = s
        .vaults
        .get(&vault)
        .and_then(|v| v.item(&id))
        .filter(|item| !item.deleted && item.kind == "passkey")
        .ok_or_else(not_found)?;
    shared::validate(&item, rp).map_err(|error| match error {
        shared::Error::DomainMismatch(_) => fail(
            ErrorCode::DomainMismatch,
            format!("this passkey isn't for {rp}"),
        ),
        other => shared_error(other),
    })?;
    Ok((vault, item))
}

pub use shared::Assertion;

/// Signs `challenge` for the page at `origin` with the passkey `passkey`
/// for the relying party `rp` (checked by [`rp_id`]).
pub fn sign(
    s: &Loaded,
    origin: &str,
    rp: &str,
    passkey: &LoginRef,
    challenge: &str,
    verified: bool,
) -> Result<Assertion> {
    let (_, item) = find(s, passkey, rp)?;
    shared::sign(&item, origin, rp, challenge, verified).map_err(shared_error)
}

impl Agent {
    pub(super) async fn passkey(
        self: Arc<Self>,
        command: Command,
        conv: &Conversation,
    ) -> Result<Reply> {
        match command {
            Command::PasskeyList { origin, rp_id } => {
                let (rp_id, passkeys) = self.with(|s| list(s, &origin, rp_id.as_deref()))?;
                Ok(Reply::Passkeys {
                    rp_id,
                    passkeys,
                    can_verify: self.can_verify(),
                })
            }
            Command::PasskeyCreate {
                origin,
                rp_id,
                challenge,
                user_id,
                user_name,
                user_display_name,
                exclude,
                verify,
            } => {
                let mut new = self.with(|s| {
                    check_create(
                        s,
                        &origin,
                        rp_id.as_deref(),
                        &challenge,
                        &user_id,
                        &user_name,
                        &exclude,
                    )
                })?;
                new.display_name = user_text(&user_display_name);
                let reason = format!("save a passkey for {}", new.rp_id);
                let verified = self.verify_user(conv, verify, &reason).await?;
                let now = i64::try_from(session::now()).unwrap_or(i64::MAX);
                let made = self.with(|s| create_passkey(s, &new, verified, now))?;
                self.sync_now.notify_one();
                Ok(Reply::PasskeyCreated {
                    passkey: made.passkey,
                    credential_id: made.credential_id,
                    client_data_json: made.client_data_json,
                    attestation_object: made.attestation_object,
                    authenticator_data: made.authenticator_data,
                    public_key: made.public_key,
                    verified,
                })
            }
            Command::PasskeyGet {
                origin,
                rp_id,
                passkey,
                challenge,
                verify,
            } => {
                let rp = self::rp_id(&origin, rp_id.as_deref())?;
                webauthn::challenge(&challenge)?;
                self.with(|s| find(s, &passkey, &rp).map(drop))?;
                let reason = format!("sign in to {rp} with a passkey");
                let verified = self.verify_user(conv, verify, &reason).await?;
                let signed =
                    self.with(|s| sign(s, &origin, &rp, &passkey, &challenge, verified))?;
                Ok(Reply::PasskeyAssertion {
                    credential_id: signed.credential_id,
                    client_data_json: signed.client_data_json,
                    authenticator_data: signed.authenticator_data,
                    signature: signed.signature,
                    user_handle: signed.user_handle,
                    verified,
                })
            }
            _ => Err(anyhow!("not a passkey request")),
        }
    }

    /// Whether a ceremony now can verify the user: Touch ID is on, the
    /// Mac has it, and this store has a current enrollment.
    pub(super) fn can_verify(&self) -> bool {
        self.touch_id_on()
            && self
                .with(|s| Ok(s.store.biometric_token()?))
                .ok()
                .flatten()
                .is_some_and(|t| biometric::validate_token(&t, true, session::now()).is_ok())
    }

    fn touch_id_on(&self) -> bool {
        self.is_touch_id_available() && Config::load(&self.paths.config).is_ok_and(|c| c.touch_id())
    }

    /// Verifies the user for a passkey ceremony with Touch ID, as unlock
    /// does: `true` once the Secure Enclave released this store's
    /// biometric key, which it does only for an enrolled finger, and the
    /// key opened the store's biometric key set. `false`, without asking,
    /// when the site discourages it or Touch ID can't verify; an error if
    /// the site requires it then, or the user cancels, or the client hangs
    /// up (which cancels the prompt).
    pub(super) async fn verify_user(
        &self,
        conv: &Conversation,
        verify: Verify,
        reason: &str,
    ) -> Result<bool> {
        if verify == Verify::Discouraged {
            return Ok(false);
        }
        if !self.can_verify() {
            if verify == Verify::Required {
                return Err(anyhow!(
                    "this site requires user verification, and Touch ID is off or not set up"
                ));
            }
            return Ok(false);
        }
        let Some(token) = self.with(|s| Ok(s.store.biometric_token()?))? else {
            return Err(anyhow!("Touch ID is not set up"));
        };
        let cancel = biometric::CancelHandle::new();
        {
            let mut prompt = self
                .passkey_prompt
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if prompt.is_some() {
                return Err(anyhow!("a passkey is already waiting for Touch ID"));
            }
            *prompt = Some(cancel.clone());
        }
        let unseal = {
            let cancel = cancel.clone();
            let reason = reason.to_string();
            #[cfg(test)]
            let hook = self
                .biometric_hook
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                if let Some(hook) = hook {
                    return hook(&cancel);
                }
                biometric::unseal_token(
                    &token,
                    session::now(),
                    &reason,
                    &cancel,
                    biometric::PROMPT_TIMEOUT,
                )
            })
        };
        let unsealed = tokio::select! {
            unsealed = unseal => unsealed,
            () = conv.closed() => {
                cancel.cancel();
                *self.passkey_prompt.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return Err(anyhow!("the request was cancelled"));
            }
        };
        *self
            .passkey_prompt
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        let key = match unsealed? {
            Ok(key) => key,
            Err(biometric::UnlockError::Cancelled) => {
                return Err(anyhow!("Touch ID was cancelled"));
            }
            Err(error) => return Err(anyhow!("Touch ID failed: {error}")),
        };
        if !self.with(|s| Ok(s.store.check_biometric(&key)?))? {
            return Err(anyhow!("Touch ID returned a key this vault doesn't know"));
        }
        Ok(true)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use sha2::{Digest, Sha256};

    use super::*;

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

    fn challenge() -> String {
        webauthn::b64(&[5; 32])
    }

    fn register(s: &mut Loaded, origin: &str, rp: Option<&str>, user: &str) -> Created {
        let new = check_create(
            s,
            origin,
            rp,
            &challenge(),
            &webauthn::b64(user.as_bytes()),
            user,
            &[],
        )
        .unwrap();
        create_passkey(s, &new, false, 1_798_000_000).unwrap()
    }

    fn code(error: &anyhow::Error) -> Option<ErrorCode> {
        error
            .downcast_ref::<crate::client::AgentError>()
            .map(|e| e.code)
    }

    #[test]
    fn a_registered_passkey_signs_for_its_relying_party_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let made = register(
            &mut s,
            "https://login.example.com",
            Some("example.com"),
            "kit",
        );
        let (rp, found) = list(&s, "https://example.com", None).unwrap();
        assert_eq!(rp, "example.com");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].username.as_deref(), Some("kit"));
        assert_eq!(found[0].created.as_deref(), Some("2026-12-23"));
        assert_eq!(found[0].credential_id, made.credential_id);
        // A subdomain page asking for the parent finds it; the subdomain's
        // own relying party doesn't.
        assert_eq!(
            list(&s, "https://www.example.com", Some("example.com"))
                .unwrap()
                .1
                .len(),
            1
        );
        assert!(
            list(&s, "https://www.example.com", None)
                .unwrap()
                .1
                .is_empty()
        );

        let origin = "https://www.example.com";
        let signed = sign(&s, origin, "example.com", &made.passkey, &challenge(), true).unwrap();
        assert_eq!(signed.user_handle, webauthn::b64(b"kit"));
        let client = webauthn::unb64(&signed.client_data_json).unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client).unwrap();
        assert_eq!(client["origin"], origin);
        assert_eq!(client["type"], "webauthn.get");
        let key =
            VerifyingKey::from_public_key_der(&webauthn::unb64(&made.public_key).unwrap()).unwrap();
        let mut signed_data = webauthn::unb64(&signed.authenticator_data).unwrap();
        signed_data.extend_from_slice(&Sha256::digest(
            webauthn::unb64(&signed.client_data_json).unwrap(),
        ));
        let signature = Signature::from_der(&webauthn::unb64(&signed.signature).unwrap()).unwrap();
        assert!(key.verify(&signed_data, &signature).is_ok());

        // Another relying party can't use it.
        let error = sign(
            &s,
            "https://evil.com",
            "evil.com",
            &made.passkey,
            &challenge(),
            false,
        )
        .map(drop)
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::DomainMismatch));
    }

    #[test]
    fn the_private_key_is_never_listed() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let made = register(&mut s, "https://example.com", None, "kit");
        let vault = s.resolve(None).unwrap();
        let listing = super::super::items::Listing::new(s.vault(&vault));
        let item = listing
            .items
            .iter()
            .find(|i| hex(i.id.as_bytes()) == made.passkey.item)
            .unwrap();
        for (reveal, otp) in [(true, false), (true, true)] {
            let info = listing.info(item, reveal, otp);
            assert!(info.fields.iter().all(|f| f.name != "private-key"));
            assert!(info.fields.iter().any(|f| f.name == "rp-id"));
        }
    }

    #[test]
    fn opaque_frames_and_other_sites_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        assert!(list(&s, "null", None).is_err());
        assert!(list(&s, "null", Some("example.com")).is_err());
        for (origin, rp) in [
            ("null", None),
            ("https://example.com", Some("evil.com")),
            ("https://alice.github.io", Some("github.io")),
            ("http://example.com", None),
        ] {
            assert!(
                check_create(&s, origin, rp, &challenge(), "a2l0", "kit", &[]).is_err(),
                "{origin} {rp:?}"
            );
        }
        assert!(s.vault(&s.resolve(None).unwrap()).items().is_empty());

        // Bad challenges and user handles fail before anything is stored.
        for (challenge, user) in [("AAAA", "a2l0"), (challenge().as_str(), "")] {
            assert!(
                check_create(&s, "https://example.com", None, challenge, user, "kit", &[]).is_err()
            );
        }
        let made = register(&mut s, "https://example.com", None, "kit");
        let excluded = check_create(
            &s,
            "https://example.com",
            None,
            &challenge(),
            "Ym9i",
            "bob",
            &[made.credential_id],
        );
        assert_eq!(code(&excluded.err().unwrap()), Some(ErrorCode::Exists));
    }

    /// A passkey the site excluded that appears while the user is asked
    /// (synced from another device, say) is still never replaced.
    #[test]
    fn an_excluded_passkey_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let user = webauthn::b64(b"kit");
        let new = check_create(
            &s,
            "https://example.com",
            None,
            &challenge(),
            &user,
            "kit",
            &[],
        )
        .unwrap();
        let first = register(&mut s, "https://example.com", None, "kit");
        let again = NewPasskey {
            exclude: vec![first.credential_id.clone()],
            ..new
        };
        let error = create_passkey(&mut s, &again, false, 1_798_000_000)
            .err()
            .unwrap();
        assert_eq!(code(&error), Some(ErrorCode::Exists));
        let (_, found) = list(&s, "https://example.com", None).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential_id, first.credential_id);
    }

    #[test]
    fn account_labels_strip_controls_and_bidi_and_bound_unicode_characters() {
        assert_eq!(user_text(" \u{061c}ki\n\u{202e}t\u{2069}\u{200f} "), "kit");
        assert_eq!(
            user_text(&"🔑".repeat(300)),
            "🔑".repeat(shared::MAX_USER_NAME)
        );
        let reason = deadbolt_core::site::rp_id("http://example.com", None).unwrap_err();
        assert_eq!(
            shared::rp_id("http://example.com", None)
                .unwrap_err()
                .to_string(),
            reason
        );
    }

    #[test]
    fn registering_the_same_user_again_preserves_both_passkeys() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let first = register(&mut s, "https://example.com", None, "kit");
        let second = register(&mut s, "https://example.com", None, "kit");
        assert_ne!(first.passkey, second.passkey);
        assert_ne!(first.credential_id, second.credential_id);
        let (_, found) = list(&s, "https://example.com", None).unwrap();
        assert_eq!(found.len(), 2);
        for made in [&first, &second] {
            assert!(
                found
                    .iter()
                    .any(|item| item.credential_id == made.credential_id)
            );
            // Even if the RP discards the second registration, the first key
            // still signs with the public key the RP originally accepted.
            let signed = sign(
                &s,
                "https://example.com",
                "example.com",
                &made.passkey,
                &challenge(),
                false,
            )
            .unwrap();
            let key =
                VerifyingKey::from_public_key_der(&webauthn::unb64(&made.public_key).unwrap())
                    .unwrap();
            let mut data = webauthn::unb64(&signed.authenticator_data).unwrap();
            data.extend_from_slice(&Sha256::digest(
                webauthn::unb64(&signed.client_data_json).unwrap(),
            ));
            let signature =
                Signature::from_der(&webauthn::unb64(&signed.signature).unwrap()).unwrap();
            assert!(key.verify(&data, &signature).is_ok());
        }
        register(&mut s, "https://example.com", None, "bob");
        assert_eq!(list(&s, "https://example.com", None).unwrap().1.len(), 3);
    }

    pub(in crate::agent) mod agent {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use deadbolt_net::{Node, NodeConfig, PeerId};
        use tokio::net::UnixStream;
        use tokio::sync::{mpsc, watch};

        use super::super::super::session::Session;
        use super::super::super::{sync, tests::test_paths};
        use super::*;

        pub(in crate::agent) struct Fixture {
            pub(in crate::agent) agent: Arc<Agent>,
            pub(in crate::agent) key: [u8; 32],
            _dir: tempfile::TempDir,
        }

        pub(in crate::agent) async fn unlocked() -> Fixture {
            unlocked_with(deadbolt_store::KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            })
            .await
        }

        /// An unlocked agent whose passphrase ("test") derives with `fast`.
        pub(in crate::agent) async fn unlocked_with(fast: deadbolt_store::KdfParams) -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let secret = [61; 32];
            drop(deadbolt_store::init_with_params(dir.path(), b"test", secret, fast).unwrap());
            let mut loaded = Loaded::open(dir.path(), b"test").unwrap();
            loaded.create_vault("personal").unwrap();
            let key = deadbolt_store::generate_biometric_key().unwrap();
            let mut token = b"DBSE\x01\x01".to_vec();
            token.extend_from_slice(&session::now().to_le_bytes());
            token.extend_from_slice(b"payload");
            loaded.store.set_biometric(&key, &token).unwrap();
            let agent = Agent::new(test_paths(dir.path()), true, fast);
            *agent.touch_id_available_override.lock().unwrap() = Some(true);
            crate::config::set_touch_id(&agent.paths.config, true).unwrap();
            let node = Node::spawn(
                NodeConfig::local_only(secret),
                Arc::new(|_: &PeerId| false),
                sync::Handler(agent.clone()),
            )
            .await
            .unwrap();
            *agent.session.lock().unwrap() = Some(Session::new(loaded, node));
            Fixture {
                agent,
                key: *key,
                _dir: dir,
            }
        }

        pub(in crate::agent) fn conversation() -> (Conversation, watch::Sender<bool>) {
            let (socket, _client) = UnixStream::pair().unwrap();
            let (_, write) = socket.into_split();
            let (closed, rx) = watch::channel(false);
            let conv = Conversation {
                write: tokio::sync::Mutex::new(write),
                answers: tokio::sync::Mutex::new(mpsc::channel(1).1),
                closed: rx,
            };
            (conv, closed)
        }

        fn create(verify: Verify, user: &str) -> Command {
            Command::PasskeyCreate {
                origin: "https://example.com".into(),
                rp_id: None,
                challenge: webauthn::b64(&[3; 32]),
                user_id: webauthn::b64(user.as_bytes()),
                user_name: user.into(),
                user_display_name: String::new(),
                exclude: Vec::new(),
                verify,
            }
        }

        /// The flags byte of a registration's or assertion's authenticator data.
        fn flags(reply: &Reply) -> (u8, bool) {
            let (data, verified) = match reply {
                Reply::PasskeyCreated {
                    authenticator_data,
                    verified,
                    ..
                }
                | Reply::PasskeyAssertion {
                    authenticator_data,
                    verified,
                    ..
                } => (authenticator_data, *verified),
                other => panic!("{other:?}"),
            };
            (webauthn::unb64(data).unwrap()[32], verified)
        }

        fn count(agent: &Agent) -> usize {
            agent
                .with(|s| Ok(list(s, "https://example.com", None)?.1.len()))
                .unwrap()
        }

        #[tokio::test]
        async fn user_verified_is_set_only_after_touch_id() {
            let f = unlocked().await;
            let (conv, _closed) = conversation();
            let calls = Arc::new(AtomicUsize::new(0));
            let (key, seen) = (f.key, calls.clone());
            *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(Zeroizing::new(key))
            }));

            let made = f
                .agent
                .clone()
                .passkey(create(Verify::Preferred, "kit"), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&made), (0x5d, true), "UV after Touch ID");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let Reply::PasskeyCreated { passkey, .. } = made else {
                unreachable!()
            };
            let get = |verify| Command::PasskeyGet {
                origin: "https://example.com".into(),
                rp_id: Some("example.com".into()),
                passkey: passkey.clone(),
                challenge: webauthn::b64(&[4; 32]),
                verify,
            };
            let signed = f
                .agent
                .clone()
                .passkey(get(Verify::Required), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&signed), (0x1d, true));

            // Discouraged: no prompt and no UV.
            let signed = f
                .agent
                .clone()
                .passkey(get(Verify::Discouraged), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&signed), (0x19, false));
            assert_eq!(calls.load(Ordering::SeqCst), 2);

            // A key that doesn't open this store's Touch ID slot isn't proof.
            *f.agent.biometric_hook.lock().unwrap() =
                Some(Arc::new(|_| Ok(Zeroizing::new([9; 32]))));
            assert!(
                f.agent
                    .clone()
                    .passkey(get(Verify::Preferred), &conv)
                    .await
                    .is_err()
            );

            // Cancelling Touch ID fails the ceremony and stores nothing.
            *f.agent.biometric_hook.lock().unwrap() =
                Some(Arc::new(|_| Err(biometric::UnlockError::Cancelled)));
            let bob = create(Verify::Preferred, "bob");
            assert!(f.agent.clone().passkey(bob, &conv).await.is_err());
            assert_eq!(count(&f.agent), 1);

            // Without Touch ID, `preferred` gets no UV and `required` fails
            // before anything is stored.
            crate::config::set_touch_id(&f.agent.paths.config, false).unwrap();
            *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(|_| unreachable!()));
            let signed = f
                .agent
                .clone()
                .passkey(get(Verify::Preferred), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&signed), (0x19, false));
            assert!(
                f.agent
                    .clone()
                    .passkey(get(Verify::Required), &conv)
                    .await
                    .is_err()
            );
            let bob = |verify| create(verify, "bob");
            assert!(
                f.agent
                    .clone()
                    .passkey(bob(Verify::Required), &conv)
                    .await
                    .is_err()
            );
            assert_eq!(count(&f.agent), 1, "nothing stored");
            let made = f
                .agent
                .clone()
                .passkey(bob(Verify::Preferred), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&made), (0x59, false));
            assert_eq!(count(&f.agent), 2);
        }

        #[tokio::test]
        async fn deleting_a_passkey_requires_native_consent_when_available() {
            let f = unlocked().await;
            let (conv, _closed) = conversation();
            let made = f
                .agent
                .with(|s| Ok(register(s, "https://example.com", None, "kit")))
                .unwrap();
            let remove = || Command::ItemRemove {
                vault: Some(made.passkey.vault.clone()),
                query: vec![made.passkey.item.clone()],
            };
            *f.agent.biometric_hook.lock().unwrap() =
                Some(Arc::new(|_| Err(biometric::UnlockError::Cancelled)));
            assert!(f.agent.clone().run(remove(), &conv).await.is_err());
            assert_eq!(count(&f.agent), 1);
            let key = f.key;
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = calls.clone();
            *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(Zeroizing::new(key))
            }));
            f.agent.clone().run(remove(), &conv).await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(count(&f.agent), 0);
        }

        #[tokio::test]
        async fn deletion_never_retargets_after_touch_id() {
            for vanished in [false, true] {
                let f = unlocked().await;
                let (conv, _closed) = conversation();
                let made = f
                    .agent
                    .with(|s| Ok(register(s, "https://example.com", None, "kit")))
                    .unwrap();
                let vault = VaultId::from_bytes(unhex(&made.passkey.vault).unwrap());
                let id = ItemId::from_bytes(unhex(&made.passkey.item).unwrap());
                let weak = Arc::downgrade(&f.agent);
                let key = f.key;
                *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
                    let agent = weak.upgrade().unwrap();
                    agent
                        .with(|s| {
                            if vanished {
                                super::super::super::items::remove_id(s, vault, id)?;
                            }
                            // Both names collide with the strings the old delete
                            // path would search again after consent.
                            if deadbolt_core::valid_name(&vault.to_string()) {
                                s.create_vault(&vault.to_string())?;
                            }
                            s.update(vault, |v, secret| {
                                Ok(v.create_item(secret, "login", Some(id.to_string()), [])?)
                            })?;
                            Ok(())
                        })
                        .unwrap();
                    Ok(Zeroizing::new(key))
                }));
                let removed = f
                    .agent
                    .clone()
                    .run(
                        Command::ItemRemove {
                            vault: Some(made.passkey.vault),
                            query: vec![made.passkey.item],
                        },
                        &conv,
                    )
                    .await;
                assert_eq!(removed.is_err(), vanished);
                f.agent
                    .with(|s| {
                        let items = s.vault(&vault).items();
                        assert!(items.iter().any(|item| !item.deleted
                            && item.kind == "login"
                            && item.name.as_deref() == Some(id.to_string().as_str())));
                        assert!(s.vault(&vault).item(&id).unwrap().deleted);
                        Ok(())
                    })
                    .unwrap();
            }
        }

        #[tokio::test]
        async fn hanging_up_cancels_the_touch_id_prompt() {
            let f = unlocked().await;
            let (conv, closed) = conversation();
            let cancelled = Arc::new(AtomicUsize::new(0));
            let seen = cancelled.clone();
            *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
                // A prompt nobody cancels gives up, so the test fails rather than hangs.
                for _ in 0..400 {
                    if cancel.is_cancelled() {
                        seen.fetch_add(1, Ordering::SeqCst);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(biometric::UnlockError::Cancelled)
            }));
            let agent = f.agent.clone();
            let request = tokio::spawn(async move {
                let result = agent.passkey(create(Verify::Required, "kit"), &conv).await;
                result.map(drop)
            });
            tokio::time::sleep(Duration::from_millis(30)).await;
            closed.send_replace(true);
            assert!(request.await.unwrap().is_err());
            for _ in 0..100 {
                if cancelled.load(Ordering::SeqCst) == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(cancelled.load(Ordering::SeqCst), 1);
            assert_eq!(count(&f.agent), 0);
            assert!(f.agent.passkey_prompt.lock().unwrap().is_none());
        }
    }
}
