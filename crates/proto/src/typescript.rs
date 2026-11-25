//! The browser protocol's TypeScript bindings, `extension/src/gen/proto.ts`:
//! its constants and every message type, rendered from the Rust types by
//! ts-rs. `gen-ts` writes the file; a test here fails when it's stale.

use std::any::TypeId;
use std::collections::BTreeSet;

use deadbolt_core::forms::{CARD_FORM_FIELDS, IDENTITY_FORM_FIELDS};
use ts_rs::{Config, TS};

use crate::browser::{
    self, Account, Body, Change, Entry, EntrySignIn, ErrorCode, FieldRules, FormCard, FormIdentity,
    HostStatus, Passkey, PasskeyAssertion, PasskeyCancel, PasskeyCreate, PasskeyCreated,
    PasskeyGet, PasskeyList, PasskeyUser, Passkeys, Request,
};
use crate::daemon::{Fill, FormKind, Secret, SignIn, SiteStatus, SiteValues, Verify};

mod format;

/// Where the bindings live, from the repository's root.
pub const PATH: &str = "extension/src/gen/proto.ts";

const HEADER: &str = "\
// Generated from crates/proto (deadbolt-proto) by `bun run gen:proto`. Do not
// edit: change the Rust types and regenerate. CI fails when this file is stale.
//
// The messages between the extension and `deadbolt browser-host`, as
// specified in docs/autofill.md. The browser does the framing (a native-endian
// u32 length, then UTF-8 JSON); this file is the JSON. extension/src/protocol.ts
// adds the TypeScript-only helpers and the checks on what the host sends.
";

/// The whole file.
pub fn bindings() -> String {
    let cfg = Config::new().with_large_int("number");
    let out = format!(
        "{HEADER}
export const NATIVE_HOST = {native_host:?}
export const PROTOCOL = {protocol}

/** An identity's fields a form may ask for, named after the HTML autocomplete tokens (`city` is `address-level2`, `region` `address-level1`). */
export const IDENTITY_FIELDS = {identity} as const
/** A card's fields a form may ask for. `number` and `cvv` raise Touch ID in the daemon when it's on; `expiry` is `YYYY-MM`. */
export const CARD_FIELDS = {card} as const
export type IdentityField = (typeof IDENTITY_FIELDS)[number]
export type CardField = (typeof CARD_FIELDS)[number]
export type FormField = IdentityField | CardField
",
        native_host = browser::NATIVE_HOST,
        protocol = browser::PROTOCOL,
        identity = list(&IDENTITY_FORM_FIELDS),
        card = list(&CARD_FORM_FIELDS),
    );
    let mut types = Types {
        cfg: &cfg,
        out,
        declared: BTreeSet::new(),
        used: BTreeSet::new(),
    };
    types.add::<Secret>();
    types.add::<Fill>();
    types.add::<SiteStatus>();
    types.add::<Verify>();
    types.add::<FormKind>();
    types.add::<HostStatus>();
    types.add::<Change>();
    types.add::<ErrorCode>();
    types.add::<SignIn>();
    types.add::<FieldRules>();
    types.add::<EntrySignIn>();
    types.add::<Entry>();
    types.add::<PasskeyList>();
    types.add::<PasskeyUser>();
    types.add::<PasskeyCreate>();
    types.add::<PasskeyGet>();
    types.add::<PasskeyCancel>();
    types.add::<Request>();
    types.add::<Account>();
    types.add::<SiteValues>();
    types.add::<FormIdentity>();
    types.add::<FormCard>();
    types.add::<Passkey>();
    types.add::<Passkeys>();
    types.add::<PasskeyCreated>();
    types.add::<PasskeyAssertion>();
    types.add::<Body>();
    let missing: Vec<_> = types.used.difference(&types.declared).collect();
    assert!(
        missing.is_empty(),
        "the bindings use types they don't declare: {missing:?}"
    );
    types.out
}

/// `["a", "b"]`, one line.
fn list(items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|i| format!("{i:?}")).collect();
    format!("[{}]", quoted.join(", "))
}

struct Types<'a> {
    cfg: &'a Config,
    out: String,
    declared: BTreeSet<String>,
    used: BTreeSet<String>,
}

impl Types<'_> {
    /// Declares `T`, with its doc comment, after a blank line.
    fn add<T: TS + 'static>(&mut self) {
        self.out.push('\n');
        let docs = T::docs();
        self.out
            .push_str(&format::declaration(docs.as_deref(), &T::decl(self.cfg)));
        self.declared.insert(T::ident(self.cfg));
        self.used.extend(
            T::dependencies(self.cfg)
                .into_iter()
                .filter(|d| d.type_id != TypeId::of::<T>())
                .map(|d| d.ts_name),
        );
    }
}

#[cfg(test)]
mod tests {
    /// The checked-in bindings are what the Rust types say. To fix, run
    /// `bun run gen:proto`.
    #[test]
    fn the_extension_bindings_are_current() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(super::PATH);
        let checked_in = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            checked_in == super::bindings(),
            "{} is stale: run `bun run gen:proto`",
            super::PATH
        );
    }
}
