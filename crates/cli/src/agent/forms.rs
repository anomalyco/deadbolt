//! Forms: the identities and cards a web form's address, contact and
//! payment fields are filled from (docs/autofill.md, "Forms"). Unlike a
//! login, neither belongs to a site: any page autofill takes may list them,
//! by the same origin rules (https, http only on a local host, never a
//! sandboxed or opaque frame). Listing gives no values; a fill gives only
//! the fields asked for, and a card's number or security code verifies the
//! user first ([`Agent::form_fill`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use deadbolt_core::{Item, ItemId, VaultId};

use super::autofill::{login_ref, site, value};
use super::items::{label, person};
use super::session::{Loaded, unhex};
use super::{Agent, Conversation, ErrorCode, fail};
use crate::protocol::{
    CARD_FORM_FIELDS, CARD_VERIFIED_FIELDS, FormCard, FormIdentity, FormKind, IDENTITY_FORM_FIELDS,
    LoginRef, Reply, Secret, Verify,
};

/// The form fields of an item of `kind`.
fn form_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "identity" => &IDENTITY_FORM_FIELDS,
        "card" => &CARD_FORM_FIELDS,
        _ => &[],
    }
}

/// The form fields `item` has a value for.
fn present(item: &Item) -> Vec<String> {
    form_fields(&item.kind)
        .iter()
        .filter(|f| value(item, f).is_some())
        .map(|f| (*f).to_string())
        .collect()
}

/// "Kit Langton · 123 Main St, Brooklyn": the person, and the first address
/// line and city. Empty when it has neither.
pub fn summary(item: &Item) -> String {
    let place: Vec<&str> = ["address-line1", "city"]
        .iter()
        .filter_map(|f| value(item, f))
        .collect();
    let place = (!place.is_empty()).then(|| place.join(", "));
    [person(item), place]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ")
}

fn last4(item: &Item) -> String {
    let number = value(item, "number").unwrap_or_default();
    number[number.len().saturating_sub(4)..].to_string()
}

/// Every identity and card of `kinds`, in every vault.
fn items<'a>(s: &'a Loaded, kinds: &'a [FormKind]) -> impl Iterator<Item = (VaultId, Item)> + 'a {
    s.vaults.iter().flat_map(move |(id, vault)| {
        vault
            .items()
            .into_iter()
            .filter(|item| kinds.iter().any(|k| k.as_str() == item.kind))
            .map(move |item| (*id, item))
    })
}

/// The identity `billing` names, if it is in one of the vaults here.
fn billing(s: &Loaded, card: &Item) -> Option<LoginRef> {
    let id = ItemId::from_bytes(unhex(value(card, "billing")?).ok()?);
    s.vaults.iter().find_map(|(vault, v)| {
        v.item(&id)
            .filter(|i| !i.deleted && i.kind == "identity")
            .map(|_| login_ref(vault, &id))
    })
}

/// The identities and cards a form on the page at `origin` can be filled
/// from, by title.
pub fn list(
    s: &Loaded,
    origin: &str,
    kinds: &[FormKind],
) -> Result<(Vec<FormIdentity>, Vec<FormCard>)> {
    site(origin)?;
    let (mut identities, mut cards) = (Vec::new(), Vec::new());
    for (vault, item) in items(s, kinds) {
        let vault_name = s.vault(&vault).name().to_string();
        let item_ref = login_ref(&vault, &item.id);
        if item.kind == "identity" {
            identities.push(FormIdentity {
                item: item_ref,
                vault: vault_name,
                title: label(&item),
                summary: summary(&item),
                fields: present(&item),
            });
        } else {
            cards.push(FormCard {
                item: item_ref,
                vault: vault_name,
                title: label(&item),
                brand: value(&item, "brand").map(str::to_string),
                last4: last4(&item),
                expiry: value(&item, "expiry").map(str::to_string),
                cardholder: value(&item, "cardholder").map(str::to_string),
                billing: billing(s, &item),
                fields: present(&item),
            });
        }
    }
    let order = |title: &str, item: &LoginRef| (title.to_lowercase(), item.item.clone());
    identities.sort_by_key(|i| order(&i.title, &i.item));
    cards.sort_by_key(|c| order(&c.title, &c.item));
    Ok((identities, cards))
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
    if fields.is_empty() {
        return Err(anyhow!("no fields asked for"));
    }
    let allowed = form_fields(&item.kind);
    if let Some(other) = fields.iter().find(|f| !allowed.contains(&f.as_str())) {
        return Err(anyhow!("a form can't ask a {} for {other}", item.kind));
    }
    Ok(item)
}

/// Whether filling `fields` of `item` verifies the user first.
pub fn needs_verify(item: &Item, fields: &[String]) -> bool {
    item.kind == "card"
        && fields
            .iter()
            .any(|f| CARD_VERIFIED_FIELDS.contains(&f.as_str()) && value(item, f).is_some())
}

/// The values of `fields` that `item` has.
pub fn values(item: &Item, fields: &[String]) -> BTreeMap<String, Secret> {
    fields
        .iter()
        .filter_map(|f| value(item, f).map(|v| (f.clone(), Secret::new(v))))
        .collect()
}

impl Agent {
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
        let verified = if needs_verify(&item, fields) {
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
    use super::super::passkeys::tests::agent::{conversation, unlocked};
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
            .downcast_ref::<crate::client::AgentError>()
            .map(|e| e.code)
    }

    fn names(fields: &[&str]) -> Vec<String> {
        fields.iter().map(|f| (*f).to_string()).collect()
    }

    #[tokio::test]
    async fn lists_metadata_and_fills_only_the_fields_asked() {
        let f = unlocked().await;
        let (home, card) = f
            .agent
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
            .agent
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
            f.agent.form_items(origin, &[FormKind::Card]).unwrap()
        else {
            unreachable!()
        };
        assert!(identities.is_empty());

        // An identity fills without asking, only what was asked.
        let (conv, _closed) = conversation();
        *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(|_| unreachable!()));
        let reply = f
            .agent
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
                .agent
                .clone()
                .form_fill(origin, target, &names(&[field]), &conv)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("can't ask"), "{field}");
        }
        // A card's expiry and name need no Touch ID.
        let reply = f
            .agent
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
            .agent
            .with(|s| {
                let home = home(s);
                Ok(visa(s, &home))
            })
            .unwrap();
        let origin = "https://shop.example.com";
        let (conv, _closed) = conversation();
        let calls = Arc::new(AtomicUsize::new(0));
        let (key, seen) = (f.key, calls.clone());
        *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(key))
        }));
        let fields = names(&["number", "cvv", "expiry"]);
        for n in 1..=2 {
            let reply = f
                .agent
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
        *f.agent.biometric_hook.lock().unwrap() =
            Some(Arc::new(|_| Err(biometric::UnlockError::Cancelled)));
        assert!(
            f.agent
                .clone()
                .form_fill(origin, &card, &fields, &conv)
                .await
                .is_err()
        );
        // Without Touch ID the pick in the browser is the user's say.
        crate::config::set_touch_id(&f.agent.paths.config, false).unwrap();
        *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(|_| unreachable!()));
        let reply = f
            .agent
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
            .agent
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
                f.agent.form_items(origin, &[FormKind::Card]).is_err(),
                "{origin}"
            );
            assert!(
                f.agent
                    .clone()
                    .form_fill(origin, &card, &names(&["expiry"]), &conv)
                    .await
                    .is_err(),
                "{origin}"
            );
        }
        // http on a local host is a page autofill takes.
        assert!(
            f.agent
                .form_items("http://localhost:3000", &[FormKind::Card])
                .is_ok()
        );
        let gone = LoginRef {
            vault: card.vault.clone(),
            item: "0".repeat(32),
        };
        let error = f
            .agent
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
