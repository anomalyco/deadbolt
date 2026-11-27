//! Passkey ceremonies for clients: verifying the user, then the engine's
//! authenticator ([`deadbolt_engine::passkeys`]).

use std::sync::Arc;

use anyhow::{Result, anyhow};
#[cfg(test)]
use zeroize::Zeroizing;

pub use deadbolt_engine::passkeys::*;

use super::session;
use super::{Conversation, Daemon, biometric};
use crate::config::Config;
use crate::protocol::{Command, Reply, Verify};
use crate::webauthn;

impl Daemon {
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
    use deadbolt_core::{ItemId, VaultId};
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    use sha2::{Digest, Sha256};

    use deadbolt_core::passkeys as shared;

    use super::super::session::{Loaded, hex, unhex};
    use super::*;
    use crate::protocol::ErrorCode;

    fn loaded(dir: &std::path::Path) -> Loaded {
        let params = crate::disk::KdfParams {
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
            .downcast_ref::<crate::client::DaemonError>()
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
            "alex",
        );
        let (rp, found) = list(&s, "https://example.com", None).unwrap();
        assert_eq!(rp, "example.com");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].username.as_deref(), Some("alex"));
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
        assert_eq!(signed.user_handle, webauthn::b64(b"alex"));
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
        let made = register(&mut s, "https://example.com", None, "alex");
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
                check_create(&s, origin, rp, &challenge(), "YWxleA", "alex", &[]).is_err(),
                "{origin} {rp:?}"
            );
        }
        assert!(s.vault(&s.resolve(None).unwrap()).items().is_empty());

        // Bad challenges and user handles fail before anything is stored.
        for (challenge, user) in [("AAAA", "YWxleA"), (challenge().as_str(), "")] {
            assert!(
                check_create(
                    &s,
                    "https://example.com",
                    None,
                    challenge,
                    user,
                    "alex",
                    &[]
                )
                .is_err()
            );
        }
        let made = register(&mut s, "https://example.com", None, "alex");
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
        let user = webauthn::b64(b"alex");
        let new = check_create(
            &s,
            "https://example.com",
            None,
            &challenge(),
            &user,
            "alex",
            &[],
        )
        .unwrap();
        let first = register(&mut s, "https://example.com", None, "alex");
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
        assert_eq!(
            user_text(" \u{061c}al\n\u{202e}ex\u{2069}\u{200f} "),
            "alex"
        );
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
        let first = register(&mut s, "https://example.com", None, "alex");
        let second = register(&mut s, "https://example.com", None, "alex");
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

    pub(in crate::daemon) mod daemon {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use deadbolt_net::{Node, NodeConfig, PeerId};
        use tokio::net::UnixStream;
        use tokio::sync::{mpsc, watch};

        use super::super::super::session::Session;
        use super::super::super::{sync, tests::test_paths};
        use super::*;

        pub(in crate::daemon) struct Fixture {
            pub(in crate::daemon) daemon: Arc<Daemon>,
            pub(in crate::daemon) key: [u8; 32],
            _dir: tempfile::TempDir,
        }

        pub(in crate::daemon) async fn unlocked() -> Fixture {
            unlocked_with(crate::disk::KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            })
            .await
        }

        /// An unlocked daemon whose passphrase ("test") derives with `fast`.
        pub(in crate::daemon) async fn unlocked_with(fast: crate::disk::KdfParams) -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let secret = [61; 32];
            drop(crate::disk::init_with_params(dir.path(), b"test", &secret, fast).unwrap());
            let mut loaded = Loaded::open(dir.path(), b"test").unwrap();
            loaded.create_vault("personal").unwrap();
            let key = crate::disk::generate_biometric_key().unwrap();
            let mut token = b"DBSE\x01\x01".to_vec();
            token.extend_from_slice(&session::now().to_le_bytes());
            token.extend_from_slice(b"payload");
            loaded.store.set_biometric(&key, &token).unwrap();
            let daemon = Daemon::new(test_paths(dir.path()), true, fast);
            *daemon.biometric_slot.lock().unwrap() = biometric::token_meta(Some(&token));
            daemon
                .biometric_was_enrolled
                .store(true, std::sync::atomic::Ordering::SeqCst);
            *daemon.touch_id_available_override.lock().unwrap() = Some(true);
            crate::config::set_touch_id(&daemon.paths.config, true).unwrap();
            let node = Node::spawn(
                NodeConfig::local_only(secret),
                Arc::new(|_: &PeerId| false),
                sync::Handler(daemon.clone()),
            )
            .await
            .unwrap();
            *daemon.session.lock().unwrap() = Some(Session::new(loaded, node));
            Fixture {
                daemon,
                key: *key,
                _dir: dir,
            }
        }

        pub(in crate::daemon) fn conversation() -> (Conversation, watch::Sender<bool>) {
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

        fn count(daemon: &Daemon) -> usize {
            daemon
                .with(|s| Ok(list(s, "https://example.com", None)?.1.len()))
                .unwrap()
        }

        #[tokio::test]
        async fn user_verified_is_set_only_after_touch_id() {
            let f = unlocked().await;
            let (conv, _closed) = conversation();
            let calls = Arc::new(AtomicUsize::new(0));
            let (key, seen) = (f.key, calls.clone());
            *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(Zeroizing::new(key))
            }));

            let made = f
                .daemon
                .clone()
                .passkey(create(Verify::Preferred, "alex"), &conv)
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
                .daemon
                .clone()
                .passkey(get(Verify::Required), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&signed), (0x1d, true));

            // Discouraged: no prompt and no UV.
            let signed = f
                .daemon
                .clone()
                .passkey(get(Verify::Discouraged), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&signed), (0x19, false));
            assert_eq!(calls.load(Ordering::SeqCst), 2);

            // A key that doesn't open this store's Touch ID slot isn't proof.
            *f.daemon.biometric_hook.lock().unwrap() =
                Some(Arc::new(|_| Ok(Zeroizing::new([9; 32]))));
            assert!(
                f.daemon
                    .clone()
                    .passkey(get(Verify::Preferred), &conv)
                    .await
                    .is_err()
            );

            // Cancelling Touch ID fails the ceremony and stores nothing.
            *f.daemon.biometric_hook.lock().unwrap() =
                Some(Arc::new(|_| Err(biometric::UnlockError::Cancelled)));
            let bob = create(Verify::Preferred, "bob");
            assert!(f.daemon.clone().passkey(bob, &conv).await.is_err());
            assert_eq!(count(&f.daemon), 1);

            // Without Touch ID, `preferred` gets no UV and `required` fails
            // before anything is stored.
            crate::config::set_touch_id(&f.daemon.paths.config, false).unwrap();
            *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(|_| unreachable!()));
            let signed = f
                .daemon
                .clone()
                .passkey(get(Verify::Preferred), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&signed), (0x19, false));
            assert!(
                f.daemon
                    .clone()
                    .passkey(get(Verify::Required), &conv)
                    .await
                    .is_err()
            );
            let bob = |verify| create(verify, "bob");
            assert!(
                f.daemon
                    .clone()
                    .passkey(bob(Verify::Required), &conv)
                    .await
                    .is_err()
            );
            assert_eq!(count(&f.daemon), 1, "nothing stored");
            let made = f
                .daemon
                .clone()
                .passkey(bob(Verify::Preferred), &conv)
                .await
                .unwrap();
            assert_eq!(flags(&made), (0x59, false));
            assert_eq!(count(&f.daemon), 2);
        }

        #[tokio::test]
        async fn deleting_a_passkey_requires_native_consent_when_available() {
            let f = unlocked().await;
            let (conv, _closed) = conversation();
            let made = f
                .daemon
                .with(|s| Ok(register(s, "https://example.com", None, "alex")))
                .unwrap();
            let remove = || Command::ItemRemove {
                vault: Some(made.passkey.vault.clone()),
                query: vec![made.passkey.item.clone()],
            };
            *f.daemon.biometric_hook.lock().unwrap() =
                Some(Arc::new(|_| Err(biometric::UnlockError::Cancelled)));
            assert!(f.daemon.clone().run(remove(), &conv, true).await.is_err());
            assert_eq!(count(&f.daemon), 1);
            let key = f.key;
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = calls.clone();
            *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(Zeroizing::new(key))
            }));
            f.daemon.clone().run(remove(), &conv, true).await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(count(&f.daemon), 0);
        }

        #[tokio::test]
        async fn deletion_never_retargets_after_touch_id() {
            for vanished in [false, true] {
                let f = unlocked().await;
                let (conv, _closed) = conversation();
                let made = f
                    .daemon
                    .with(|s| Ok(register(s, "https://example.com", None, "alex")))
                    .unwrap();
                let vault = VaultId::from_bytes(unhex(&made.passkey.vault).unwrap());
                let id = ItemId::from_bytes(unhex(&made.passkey.item).unwrap());
                let weak = Arc::downgrade(&f.daemon);
                let key = f.key;
                *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
                    let daemon = weak.upgrade().unwrap();
                    daemon
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
                    .daemon
                    .clone()
                    .run(
                        Command::ItemRemove {
                            vault: Some(made.passkey.vault),
                            query: vec![made.passkey.item],
                        },
                        &conv,
                        true,
                    )
                    .await;
                assert_eq!(removed.is_err(), vanished);
                f.daemon
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
            *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |cancel| {
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
            let daemon = f.daemon.clone();
            let request = tokio::spawn(async move {
                let result = daemon
                    .passkey(create(Verify::Required, "alex"), &conv)
                    .await;
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
            assert_eq!(count(&f.daemon), 0);
            assert!(f.daemon.passkey_prompt.lock().unwrap().is_none());
        }
    }
}
