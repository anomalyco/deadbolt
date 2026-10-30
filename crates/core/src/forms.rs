//! Shared identity/card metadata and fill rules. Callers check the page's
//! origin and perform reauthentication before releasing selected values.

use crate::autofill::value;
use crate::{Item, ItemId, Vault, VaultId};

/// An identity's fields a form may ask for: never its ID numbers or notes.
pub const IDENTITY_FORM_FIELDS: [&str; 17] = [
    "honorific",
    "given-name",
    "additional-name",
    "family-name",
    "nickname",
    "organization",
    "job-title",
    "email",
    "phone",
    "address-line1",
    "address-line2",
    "address-line3",
    "city",
    "region",
    "postal-code",
    "country",
    "birthday",
];

/// A card's fields a form may ask for: never its PIN or notes. `number`
/// and `cvv` verify the user ([`CARD_VERIFIED_FIELDS`]).
pub const CARD_FORM_FIELDS: [&str; 5] = ["cardholder", "number", "expiry", "cvv", "brand"];

/// A card's fields whose fill verifies the user.
pub const CARD_VERIFIED_FIELDS: [&str; 2] = ["number", "cvv"];

/// A form item in one of the caller's vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference {
    pub vault: VaultId,
    pub item: ItemId,
}

/// Listing metadata, never identity values beyond the summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub item: Reference,
    pub vault: String,
    pub title: String,
    pub summary: String,
    pub favorite: bool,
    pub fields: Vec<String>,
}

/// Listing metadata, never a card number, security code or PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub item: Reference,
    pub vault: String,
    pub title: String,
    pub brand: Option<String>,
    pub last4: String,
    pub expiry: Option<String>,
    pub cardholder: Option<String>,
    pub billing: Option<Reference>,
    pub favorite: bool,
    pub fields: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("no such identity or card")]
    NotFound,
    #[error("no fields asked for")]
    NoFields,
    #[error("a form can't ask a {kind} for {field}")]
    WrongField { kind: String, field: String },
}

/// The form fields of an item of `kind`.
pub fn form_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "identity" => &IDENTITY_FORM_FIELDS,
        "card" => &CARD_FORM_FIELDS,
        _ => &[],
    }
}

/// The form fields `item` has a value for.
pub fn present(item: &Item) -> Vec<String> {
    form_fields(&item.kind)
        .iter()
        .filter(|f| value(item, f).is_some())
        .map(|f| (*f).to_string())
        .collect()
}

/// An identity's name: given and family name, else its nickname, else the
/// one-line `name` an identity made before names had parts may still have.
pub fn person(item: &Item) -> Option<String> {
    let parts: Vec<&str> = ["given-name", "family-name"]
        .iter()
        .filter_map(|f| item.fields.get(*f).map(|f| f.value.as_str()))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    if !parts.is_empty() {
        return Some(parts.join(" "));
    }
    item.fields
        .get("nickname")
        .map(|f| f.value.as_str())
        .or_else(|| item.fields.get("name").map(|f| f.value.as_str()))
        .map(str::to_string)
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

/// The last four digits of the normalized card number.
pub fn last_four(item: &Item) -> Option<&str> {
    let number = item.fields.get("number")?.value.as_str();
    Some(&number[number.len().saturating_sub(4)..])
}

/// An identity or card's name, else the native label derived from its fields.
pub fn title(item: &Item) -> String {
    if let Some(name) = &item.name {
        return name.clone();
    }
    match item.kind.as_str() {
        "card" => format!(
            "{} •••• {}",
            item.fields
                .get("brand")
                .map_or("card", |f| f.value.as_str()),
            last_four(item).unwrap_or_default()
        ),
        "identity" => person(item)
            .or_else(|| item.fields.get("email").map(|f| f.value.clone()))
            .unwrap_or_else(|| "identity".into()),
        kind => kind.into(),
    }
}

/// The identity `billing` names, if it is in one of the vaults here.
fn billing(vaults: &[&Vault], card: &Item) -> Option<Reference> {
    let bytes = data_encoding::HEXLOWER
        .decode(value(card, "billing")?.as_bytes())
        .ok()?;
    let id = ItemId::from_bytes(bytes.try_into().ok()?);
    vaults.iter().find_map(|vault| {
        vault
            .item(&id)
            .filter(|i| !i.deleted && i.kind == "identity")
            .map(|_| Reference {
                vault: vault.id(),
                item: id,
            })
    })
}

/// Every requested identity and card, ordered by case-insensitive title and id.
/// The caller supplies vaults in its usual iteration order for stable ties.
pub fn list(vaults: &[&Vault], kinds: &[&str]) -> (Vec<Identity>, Vec<Card>) {
    let (mut identities, mut cards) = (Vec::new(), Vec::new());
    for vault in vaults {
        for item in vault
            .items()
            .into_iter()
            .filter(|item| kinds.contains(&item.kind.as_str()))
        {
            let item_ref = Reference {
                vault: vault.id(),
                item: item.id,
            };
            match item.kind.as_str() {
                "identity" => identities.push(Identity {
                    item: item_ref,
                    vault: vault.name().into(),
                    title: title(&item),
                    summary: summary(&item),
                    favorite: item.favorite,
                    fields: present(&item),
                }),
                "card" => cards.push(Card {
                    item: item_ref,
                    vault: vault.name().into(),
                    title: title(&item),
                    brand: value(&item, "brand").map(str::to_string),
                    last4: last_four(&item).unwrap_or_default().into(),
                    expiry: value(&item, "expiry").map(str::to_string),
                    cardholder: value(&item, "cardholder").map(str::to_string),
                    billing: billing(vaults, &item),
                    favorite: item.favorite,
                    fields: present(&item),
                }),
                _ => {}
            }
        }
    }
    identities.sort_by_key(|i| (!i.favorite, i.title.to_lowercase(), i.item.item));
    cards.sort_by_key(|c| (!c.favorite, c.title.to_lowercase(), c.item.item));
    (identities, cards)
}

/// Refuses tombstones, other item kinds, empty requests and non-form fields.
pub fn validate(item: &Item, fields: &[String]) -> Result<(), Error> {
    if item.deleted || !matches!(item.kind.as_str(), "identity" | "card") {
        return Err(Error::NotFound);
    }
    if fields.is_empty() {
        return Err(Error::NoFields);
    }
    let allowed = form_fields(&item.kind);
    if let Some(other) = fields.iter().find(|f| !allowed.contains(&f.as_str())) {
        return Err(Error::WrongField {
            kind: item.kind.clone(),
            field: other.clone(),
        });
    }
    Ok(())
}

/// Whether the native fill asks for user verification: only held card secrets.
pub fn needs_verify(item: &Item, fields: &[String]) -> bool {
    item.kind == "card"
        && fields
            .iter()
            .any(|f| CARD_VERIFIED_FIELDS.contains(&f.as_str()) && value(item, f).is_some())
}

/// Only requested, allowed form values. Call `validate` first to reject the
/// entire request if any field is disallowed; this iterator never leaks one.
pub fn values<'a>(
    item: &'a Item,
    fields: &'a [String],
) -> impl Iterator<Item = (&'a str, &'a str)> {
    fields
        .iter()
        .filter(|f| !item.deleted && form_fields(&item.kind).contains(&f.as_str()))
        .filter_map(|f| value(item, f).map(|v| (f.as_str(), v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataOp, DeviceSecret, Field, FieldType, schema};

    fn add(
        vault: &mut Vault,
        secret: &DeviceSecret,
        kind: &str,
        name: Option<&str>,
        fields: &[(&str, &str)],
    ) -> ItemId {
        let fields = fields.iter().map(|(name, value)| {
            let ty = schema(kind)
                .and_then(|s| s.field(name))
                .map_or(FieldType::Text, |f| f.kind.clone());
            ((*name).into(), Field::new(ty, *value))
        });
        vault
            .create_item(secret, kind, name.map(str::to_string), fields)
            .unwrap()
            .0
    }

    fn names(fields: &[&str]) -> Vec<String> {
        fields.iter().map(|f| (*f).into()).collect()
    }

    #[test]
    fn lists_metadata_and_selects_only_allowed_values() {
        let secret = DeviceSecret::generate();
        let (mut vault, _) = Vault::create(&secret, "personal").unwrap();
        let home = add(
            &mut vault,
            &secret,
            "identity",
            Some("Home"),
            &[
                ("given-name", "Kit"),
                ("family-name", "Langton"),
                ("address-line1", "123 Main St"),
                ("city", "Brooklyn"),
                ("country", "US"),
                ("phone", "+17185550100"),
                ("passport", "X1234567"),
            ],
        );
        let card = add(
            &mut vault,
            &secret,
            "card",
            None,
            &[
                ("number", "4242424242424242"),
                ("cvv", "123"),
                ("expiry", "2028-08"),
                ("brand", "Visa"),
                ("pin", "9876"),
                ("billing", &home.to_string()),
            ],
        );
        add(&mut vault, &secret, "login", None, &[("password", "pw")]);
        let (identities, cards) = list(&[&vault], &["identity", "card", "card"]);
        assert_eq!(identities.len(), 1);
        assert_eq!(cards.len(), 1);
        assert_eq!(identities[0].summary, "Kit Langton · 123 Main St, Brooklyn");
        assert!(!identities[0].fields.contains(&"passport".into()));
        assert_eq!(cards[0].title, "Visa •••• 4242");
        assert_eq!(cards[0].last4, "4242");
        assert_eq!(cards[0].expiry.as_deref(), Some("2028-08"));
        assert_eq!(
            cards[0].billing,
            Some(Reference {
                vault: vault.id(),
                item: home
            })
        );
        let listed = format!("{identities:?}{cards:?}");
        for secret in ["4242424242424242", "X1234567", "9876", "+17185550100"] {
            assert!(!listed.contains(secret));
        }
        assert!(list(&[&vault], &["card"]).0.is_empty());
        let home = vault.item(&home).unwrap();
        let fields = names(&["given-name", "country", "region"]);
        validate(&home, &fields).unwrap();
        assert_eq!(
            values(&home, &fields).collect::<Vec<_>>(),
            [("given-name", "Kit"), ("country", "US")]
        );
        assert!(!needs_verify(&home, &fields));
        let card = vault.item(&card).unwrap();
        assert!(needs_verify(&card, &names(&["number"])));
        assert!(needs_verify(&card, &names(&["cvv"])));
        assert!(!needs_verify(&card, &names(&["expiry"])));
        for (item, field) in [
            (&home, "passport"),
            (&home, "number"),
            (&card, "pin"),
            (&card, "notes"),
            (&card, "email"),
        ] {
            let fields = names(&[field]);
            assert!(matches!(
                validate(item, &fields),
                Err(Error::WrongField { .. })
            ));
            assert_eq!(values(item, &fields).count(), 0);
        }
        assert_eq!(validate(&card, &[]), Err(Error::NoFields));
    }

    #[test]
    fn billing_resolves_across_vaults_but_not_to_tombstones_or_other_kinds() {
        let secret = DeviceSecret::generate();
        let (mut home, _) = Vault::create(&secret, "home").unwrap();
        let (mut work, _) = Vault::create(&secret, "work").unwrap();
        let identity = add(
            &mut home,
            &secret,
            "identity",
            Some("Home"),
            &[("given-name", "Kit")],
        );
        let card = add(
            &mut work,
            &secret,
            "card",
            None,
            &[
                ("number", "4242424242424242"),
                ("billing", &identity.to_string()),
            ],
        );
        assert_eq!(
            list(&[&home, &work], &["card"]).1[0].billing,
            Some(Reference {
                vault: home.id(),
                item: identity
            })
        );
        assert!(list(&[&work], &["card"]).1[0].billing.is_none());
        home.write(&secret, vec![DataOp::delete(identity)]).unwrap();
        assert!(list(&[&home, &work], &["card"]).1[0].billing.is_none());
        assert!(list(&[&home], &["identity"]).0.is_empty());
        assert_eq!(
            validate(&home.item(&identity).unwrap(), &names(&["given-name"])),
            Err(Error::NotFound)
        );
        work.write(
            &secret,
            vec![DataOp::set(
                card,
                "billing",
                Field::new(
                    schema("card")
                        .unwrap()
                        .field("billing")
                        .unwrap()
                        .kind
                        .clone(),
                    card.to_string(),
                ),
            )],
        )
        .unwrap();
        assert!(list(&[&work], &["card"]).1[0].billing.is_none());
        let login = add(&mut home, &secret, "login", None, &[("password", "pw")]);
        assert_eq!(
            validate(&home.item(&login).unwrap(), &names(&["given-name"])),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn labels_keep_legacy_names_and_sort_by_title_then_id() {
        let secret = DeviceSecret::generate();
        let (mut vault, _) = Vault::create(&secret, "personal").unwrap();
        let legacy = add(
            &mut vault,
            &secret,
            "identity",
            None,
            &[("name", "Legacy Name"), ("address", "Old address")],
        );
        let item = vault.item(&legacy).unwrap();
        assert_eq!(title(&item), "Legacy Name");
        assert_eq!(summary(&item), "Legacy Name");
        assert!(present(&item).is_empty());
        let nickname = add(
            &mut vault,
            &secret,
            "identity",
            None,
            &[("nickname", "Kit")],
        );
        assert_eq!(
            person(&vault.item(&nickname).unwrap()).as_deref(),
            Some("Kit")
        );
        let a = add(
            &mut vault,
            &secret,
            "identity",
            Some("a"),
            &[("email", "a@example.com")],
        );
        let b = add(
            &mut vault,
            &secret,
            "identity",
            Some("A"),
            &[("email", "b@example.com")],
        );
        let ids: Vec<_> = list(&[&vault], &["identity"])
            .0
            .into_iter()
            .map(|i| i.item.item)
            .collect();
        let mut first = [a, b];
        first.sort();
        assert_eq!(&ids[..2], &first);
    }
}
