//! Forms: the identities and cards a web form's address, contact and
//! payment fields are filled from (docs/autofill.md, "Forms"). Unlike a
//! login, neither belongs to a site: any page autofill takes may list them,
//! by the same origin rules (https, http only on a local host, never a
//! sandboxed or opaque frame). Listing gives no values; a fill gives only
//! the fields asked for, and a card's number or security code verifies the
//! user first ([`Daemon::form_fill`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use deadbolt_core::{Item, ItemId, VaultId, forms};

use super::autofill::{login_ref, site};
use super::items::label;
use super::session::{Loaded, unhex};
use super::{Conversation, Daemon, ErrorCode, fail};
use crate::protocol::{FormCard, FormIdentity, FormKind, LoginRef, Reply, Secret, Verify};

/// The identities and cards a form on the page at `origin` can be filled
/// from, by title. The shared core owns listing metadata and field rules.
pub fn list(
    s: &Loaded,
    origin: &str,
    kinds: &[FormKind],
) -> Result<(Vec<FormIdentity>, Vec<FormCard>)> {
    site(origin)?;
    let vaults: Vec<_> = s.vaults.values().collect();
    let kinds: Vec<_> = kinds.iter().map(|kind| kind.as_str()).collect();
    let (identities, cards) = forms::list(&vaults, &kinds);
    Ok((
        identities
            .into_iter()
            .map(|i| FormIdentity {
                item: login_ref(&i.item.vault, &i.item.item),
                vault: i.vault,
                title: i.title,
                summary: i.summary,
                fields: i.fields,
            })
            .collect(),
        cards
            .into_iter()
            .map(|c| FormCard {
                item: login_ref(&c.item.vault, &c.item.item),
                vault: c.vault,
                title: c.title,
                brand: c.brand,
                last4: c.last4,
                expiry: c.expiry,
                cardholder: c.cardholder,
                billing: c.billing.map(|r| login_ref(&r.vault, &r.item)),
                fields: c.fields,
            })
            .collect(),
    ))
}

/// The identity or card `target` names, for the page at `origin`, and the
/// fields asked checked against its kind's form fields.
pub fn find(s: &Loaded, origin: &str, target: &LoginRef, fields: &[String]) -> Result<Item> {
    site(origin)?;
    let not_found = || fail(ErrorCode::NotFound, "no such identity or card");
    let vault = VaultId::from_bytes(unhex(&target.vault).map_err(|_| not_found())?);
    let id = ItemId::from_bytes(unhex(&target.item).map_err(|_| not_found())?);
    let item = s
        .vaults
        .get(&vault)
        .and_then(|v| v.item(&id))
        .filter(|item| !item.deleted && matches!(item.kind.as_str(), "identity" | "card"))
        .ok_or_else(not_found)?;
    forms::validate(&item, fields)?;
    Ok(item)
}

/// The values of `fields` that `item` has.
pub fn values(item: &Item, fields: &[String]) -> BTreeMap<String, Secret> {
    forms::values(item, fields)
        .map(|(f, v)| (f.to_string(), Secret::new(v)))
        .collect()
}

impl Daemon {
    pub(super) fn form_items(&self, origin: &str, kinds: &[FormKind]) -> Result<Reply> {
        let (identities, cards) = self.with(|s| list(s, origin, kinds))?;
        Ok(Reply::FormItems {
            identities,
            cards,
            can_verify: self.can_verify(),
        })
    }

    /// Fills a form from an identity or card. A card's number or security
    /// code verifies the user each time: Touch ID when it is on and
    /// enrolled (cancelling it fails the fill), else the pick in the
    /// browser's menu is the user's say. The item is looked up again after
    /// Touch ID, so one deleted meanwhile fills nothing.
    pub(super) async fn form_fill(
        self: Arc<Self>,
        origin: &str,
        target: &LoginRef,
        fields: &[String],
        conv: &Conversation,
    ) -> Result<Reply> {
        let item = self.with(|s| find(s, origin, target, fields))?;
        let verified = if forms::needs_verify(&item, fields) {
            let host = crate::site::url_host(origin).unwrap_or_else(|| origin.to_string());
            let reason = format!("fill {} on {host}", label(&item));
            drop(item);
            self.verify_user(conv, Verify::Preferred, &reason).await?
        } else {
            false
        };
        let item = self.with(|s| find(s, origin, target, fields))?;
        Ok(Reply::FormFill {
            kind: item.kind.clone(),
            title: label(&item),
            values: values(&item, fields),
            verified,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use zeroize::Zeroizing;

    use super::super::biometric;
    use super::super::items::create;
    use super::super::passkeys::tests::daemon::{conversation, unlocked};
    use super::super::session::hex;
    use super::*;
    use crate::protocol::FieldInput;

    fn add(s: &mut Loaded, kind: &str, name: Option<&str>, fields: &[(&str, &str)]) -> LoginRef {
        let inputs = fields
            .iter()
            .map(|(name, value)| FieldInput {
                name: (*name).into(),
                kind: None,
                value: (*value).into(),
            })
            .collect();
        let info = create(s, None, kind, name.map(Into::into), inputs).unwrap();
        LoginRef {
            vault: hex(s.resolve(None).unwrap().as_bytes()),
            item: info.id,
        }
    }

    fn home(s: &mut Loaded) -> LoginRef {
        add(
            s,
            "identity",
            Some("Home"),
            &[
                ("given-name", "Kit"),
                ("family-name", "Langton"),
                ("address-line1", "123 Main St"),
                ("city", "Brooklyn"),
                ("country", "us"),
                ("phone", "+1 718 555 0100"),
                ("passport", "X1234567"),
            ],
        )
    }

    fn visa(s: &mut Loaded, billing: &LoginRef) -> LoginRef {
        add(
            s,
            "card",
            None,
            &[
                ("number", "4242 4242 4242 4242"),
                ("cvv", "123"),
                ("expiry", "08/28"),
                ("brand", "Visa"),
                ("pin", "9876"),
                ("billing", &billing.item),
            ],
        )
    }

    fn code(error: &anyhow::Error) -> Option<ErrorCode> {
        error
            .downcast_ref::<crate::client::DaemonError>()
            .map(|e| e.code)
    }

    fn names(fields: &[&str]) -> Vec<String> {
        fields.iter().map(|f| (*f).to_string()).collect()
    }

    #[tokio::test]
    async fn lists_metadata_and_fills_only_the_fields_asked() {
        let f = unlocked().await;
        let (home, card) = f
            .daemon
            .with(|s| {
                let home = home(s);
                let card = visa(s, &home);
                add(s, "login", None, &[("password", "pw")]);
                Ok((home, card))
            })
            .unwrap();
        let origin = "https://shop.example.com";
        let Reply::FormItems {
            identities, cards, ..
        } = f
            .daemon
            .form_items(origin, &[FormKind::Identity, FormKind::Card])
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].summary, "Kit Langton · 123 Main St, Brooklyn");
        assert!(identities[0].fields.contains(&"country".to_string()));
        assert!(!identities[0].fields.contains(&"passport".to_string()));
        let c = &cards[0];
        assert_eq!(
            (c.brand.as_deref(), c.last4.as_str(), c.expiry.as_deref()),
            (Some("Visa"), "4242", Some("2028-08"))
        );
        assert_eq!(c.billing.as_ref(), Some(&home));
        // No values anywhere in the listing.
        let listed = format!("{identities:?}{cards:?}");
        assert!(!listed.contains("424242424242"));
        let Reply::FormItems { identities, .. } =
            f.daemon.form_items(origin, &[FormKind::Card]).unwrap()
        else {
            unreachable!()
        };
        assert!(identities.is_empty());

        // An identity fills without asking, only what was asked.
        let (conv, _closed) = conversation();
        *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(|_| unreachable!()));
        let reply = f
            .daemon
            .clone()
            .form_fill(
                origin,
                &home,
                &names(&["given-name", "country", "phone", "region"]),
                &conv,
            )
            .await
            .unwrap();
        let Reply::FormFill {
            kind,
            values,
            verified,
            ..
        } = reply
        else {
            unreachable!()
        };
        assert_eq!((kind.as_str(), verified), ("identity", false));
        let values: Vec<(&str, &str)> = values
            .iter()
            .map(|(k, v)| (k.as_str(), v.expose()))
            .collect();
        assert_eq!(
            values,
            [
                ("country", "US"),
                ("given-name", "Kit"),
                ("phone", "+17185550100")
            ]
        );
        // Never its ID numbers, nor a card's PIN, nor a login.
        for (target, field) in [(&home, "passport"), (&card, "pin"), (&card, "notes")] {
            let error = f
                .daemon
                .clone()
                .form_fill(origin, target, &names(&[field]), &conv)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("can't ask"), "{field}");
        }
        // A card's expiry and name need no Touch ID.
        let reply = f
            .daemon
            .clone()
            .form_fill(origin, &card, &names(&["expiry", "brand"]), &conv)
            .await
            .unwrap();
        assert!(matches!(
            reply,
            Reply::FormFill {
                verified: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_card_number_needs_touch_id_each_time_when_it_is_on() {
        let f = unlocked().await;
        let card = f
            .daemon
            .with(|s| {
                let home = home(s);
                Ok(visa(s, &home))
            })
            .unwrap();
        let origin = "https://shop.example.com";
        let (conv, _closed) = conversation();
        let calls = Arc::new(AtomicUsize::new(0));
        let (key, seen) = (f.key, calls.clone());
        *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(key))
        }));
        let fields = names(&["number", "cvv", "expiry"]);
        for n in 1..=2 {
            let reply = f
                .daemon
                .clone()
                .form_fill(origin, &card, &fields, &conv)
                .await
                .unwrap();
            let Reply::FormFill {
                values, verified, ..
            } = reply
            else {
                unreachable!()
            };
            assert!(verified);
            assert_eq!(values["number"].expose(), "4242424242424242");
            assert_eq!(values["cvv"].expose(), "123");
            assert_eq!(calls.load(Ordering::SeqCst), n, "every fill asks");
        }
        // Cancelled: nothing filled.
        *f.daemon.biometric_hook.lock().unwrap() =
            Some(Arc::new(|_| Err(biometric::UnlockError::Cancelled)));
        assert!(
            f.daemon
                .clone()
                .form_fill(origin, &card, &fields, &conv)
                .await
                .is_err()
        );
        // Without Touch ID the pick in the browser is the user's say.
        crate::config::set_touch_id(&f.daemon.paths.config, false).unwrap();
        *f.daemon.biometric_hook.lock().unwrap() = Some(Arc::new(|_| unreachable!()));
        let reply = f
            .daemon
            .clone()
            .form_fill(origin, &card, &fields, &conv)
            .await
            .unwrap();
        assert!(matches!(
            reply,
            Reply::FormFill {
                verified: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn pages_autofill_refuses_get_nothing() {
        let f = unlocked().await;
        let card = f
            .daemon
            .with(|s| {
                let home = home(s);
                Ok(visa(s, &home))
            })
            .unwrap();
        let (conv, _closed) = conversation();
        for origin in [
            "null",
            "http://shop.example.com",
            "file:///tmp/form.html",
            "chrome-extension://abc",
            "",
        ] {
            assert!(
                f.daemon.form_items(origin, &[FormKind::Card]).is_err(),
                "{origin}"
            );
            assert!(
                f.daemon
                    .clone()
                    .form_fill(origin, &card, &names(&["expiry"]), &conv)
                    .await
                    .is_err(),
                "{origin}"
            );
        }
        // http on a local host is a page autofill takes.
        assert!(
            f.daemon
                .form_items("http://localhost:3000", &[FormKind::Card])
                .is_ok()
        );
        let gone = LoginRef {
            vault: card.vault.clone(),
            item: "0".repeat(32),
        };
        let error = f
            .daemon
            .clone()
            .form_fill(
                "https://shop.example.com",
                &gone,
                &names(&["expiry"]),
                &conv,
            )
            .await
            .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::NotFound));
    }
}
