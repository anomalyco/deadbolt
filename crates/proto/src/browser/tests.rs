//! Golden wire shapes: every request and every message from the host, as
//! the extension sends and reads them (extension/src/gen/proto.ts), both ways.

use std::fmt::Debug;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use super::*;
use crate::daemon::{Fill, FormKind, Secret, SignIn, SiteStatus, SiteValues, Verify};

const REF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// `value` is `wire` on the wire, and `wire` reads back as `value`.
fn golden<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: T, wire: Value) {
    assert_eq!(serde_json::to_value(&value).unwrap(), wire, "{value:?}");
    assert_eq!(serde_json::from_value::<T>(wire).unwrap(), value);
}

fn s(value: &str) -> String {
    value.into()
}

#[test]
fn requests() {
    let origin = || s("https://github.com");
    let rules = FieldRules {
        rules: Some(s("minlength: 12; required: digit;")),
        min_length: Some(12),
        max_length: Some(64),
        allowed: Some(s("a-z0-9")),
    };
    let cases = [
        (Request::Hello, json!({"type": "hello"})),
        (
            Request::List { origin: origin() },
            json!({"type": "list", "origin": "https://github.com"}),
        ),
        (
            Request::Fill {
                origin: origin(),
                login: s(REF),
                want: vec![Fill::Username, Fill::Password, Fill::Totp],
            },
            json!({"type": "fill", "origin": "https://github.com", "ref": REF,
                   "want": ["username", "password", "totp"]}),
        ),
        (
            Request::Generate {
                origin: origin(),
                field: rules.clone(),
            },
            json!({"type": "generate", "origin": "https://github.com",
                   "rules": "minlength: 12; required: digit;", "minLength": 12,
                   "maxLength": 64, "allowed": "a-z0-9"}),
        ),
        (
            Request::GenerateCheck {
                origin: origin(),
                field: FieldRules::default(),
            },
            json!({"type": "generate-check", "origin": "https://github.com"}),
        ),
        (
            Request::GenerateKeep {
                origin: origin(),
                generated: s("g1"),
            },
            json!({"type": "generate-keep", "origin": "https://github.com", "generated": "g1"}),
        ),
        (
            Request::GenerateDrop {
                origin: origin(),
                generated: s("g1"),
            },
            json!({"type": "generate-drop", "origin": "https://github.com", "generated": "g1"}),
        ),
        (
            Request::Check {
                origin: origin(),
                username: Some(s("octocat")),
                password: Some(Secret::new("hunter22")),
                generated: None,
            },
            json!({"type": "check", "origin": "https://github.com", "username": "octocat",
                   "password": "hunter22"}),
        ),
        (
            Request::Check {
                origin: origin(),
                username: None,
                password: None,
                generated: Some(s("g1")),
            },
            json!({"type": "check", "origin": "https://github.com", "generated": "g1"}),
        ),
        (
            Request::Save {
                origin: origin(),
                entry: Entry {
                    title: s("GitHub"),
                    url: s("https://github.com/login"),
                    username: s("octocat"),
                    password: Some(Secret::new("hunter22")),
                    generated: None,
                    sign_in: None,
                },
                login: Some(s(REF)),
            },
            json!({"type": "save", "origin": "https://github.com", "ref": REF,
                   "entry": {"title": "GitHub", "url": "https://github.com/login",
                             "username": "octocat", "password": "hunter22"}}),
        ),
        (
            Request::Save {
                origin: origin(),
                entry: Entry {
                    title: s("GitHub"),
                    url: s("https://github.com/login"),
                    username: String::new(),
                    password: None,
                    generated: None,
                    sign_in: Some(EntrySignIn {
                        provider: s("google"),
                        account: s(REF),
                    }),
                },
                login: None,
            },
            json!({"type": "save", "origin": "https://github.com",
                   "entry": {"title": "GitHub", "url": "https://github.com/login",
                             "signIn": {"provider": "google", "account": REF}}}),
        ),
        (
            Request::Forms {
                origin: origin(),
                kinds: vec![FormKind::Identity, FormKind::Card],
            },
            json!({"type": "forms", "origin": "https://github.com", "kinds": ["identity", "card"]}),
        ),
        (
            Request::FillForm {
                origin: origin(),
                item: s(REF),
                fields: vec![s("given-name"), s("number")],
            },
            json!({"type": "fill-form", "origin": "https://github.com", "ref": REF,
                   "fields": ["given-name", "number"]}),
        ),
        (
            Request::SaveForm {
                origin: origin(),
                kind: FormKind::Card,
                item: Some(s(REF)),
                fields: [(s("expiry"), Secret::new("2030-09"))].into(),
            },
            json!({"type": "save-form", "origin": "https://github.com", "kind": "card",
                   "ref": REF, "fields": {"expiry": "2030-09"}}),
        ),
        (
            Request::PasskeyList(PasskeyList {
                origin: origin(),
                rp_id: Some(s("github.com")),
            }),
            json!({"type": "passkey-list", "origin": "https://github.com", "rpId": "github.com"}),
        ),
        (
            Request::PasskeyCreate(PasskeyCreate {
                origin: origin(),
                rp_id: None,
                challenge: s("Y2hhbGxlbmdl"),
                user: PasskeyUser {
                    id: s("YWxleA"),
                    name: s("alex"),
                    display_name: s("Alex"),
                },
                exclude: vec![s("Y3JlZA")],
                user_verification: Verify::Preferred,
            }),
            json!({"type": "passkey-create", "origin": "https://github.com",
                   "challenge": "Y2hhbGxlbmdl",
                   "user": {"id": "YWxleA", "name": "alex", "displayName": "Alex"},
                   "exclude": ["Y3JlZA"], "userVerification": "preferred"}),
        ),
        (
            Request::PasskeyGet(PasskeyGet {
                origin: origin(),
                rp_id: Some(s("github.com")),
                passkey: s(REF),
                challenge: s("Y2hhbGxlbmdl"),
                user_verification: Verify::Required,
            }),
            json!({"type": "passkey-get", "origin": "https://github.com", "rpId": "github.com",
                   "ref": REF, "challenge": "Y2hhbGxlbmdl", "userVerification": "required"}),
        ),
        (
            Request::PasskeyCancel(PasskeyCancel { request: 7.into() }),
            json!({"type": "passkey-cancel", "request": 7}),
        ),
        (
            Request::Learn {
                session: s("s1"),
                line: json!({"kind": "form", "fields": 3})
                    .as_object()
                    .unwrap()
                    .clone(),
            },
            json!({"type": "learn", "session": "s1", "line": {"kind": "form", "fields": 3}}),
        ),
        (
            Request::LearnRead {
                session: s("s1"),
                offset: Some(4096),
            },
            json!({"type": "learn-read", "session": "s1", "offset": 4096}),
        ),
        (
            Request::LearnDelete { session: s("s1") },
            json!({"type": "learn-delete", "session": "s1"}),
        ),
        (Request::UnlockPrompt, json!({"type": "unlock-prompt"})),
    ];
    for (request, wire) in cases {
        golden(request.clone(), wire.clone());
        // As the host reads it: with the extension's id beside it.
        let mut with_id = wire;
        with_id["id"] = 1.into();
        assert_eq!(serde_json::from_value::<Request>(with_id).unwrap(), request);
    }
}

/// What the extension leaves out, the host reads as empty.
#[test]
fn requests_leave_out_what_is_empty() {
    let request: Request = serde_json::from_value(json!({
        "id": 1, "type": "passkey-create", "origin": "https://github.com",
        "challenge": "Y2hhbGxlbmdl", "user": {"id": "YWxleA"}, "userVerification": "discouraged",
    }))
    .unwrap();
    let Request::PasskeyCreate(create) = request else {
        panic!("{request:?}");
    };
    assert_eq!(
        (create.user.name.as_str(), create.user.display_name.as_str()),
        ("", "")
    );
    assert!(create.exclude.is_empty() && create.rp_id.is_none());
    let read: Request =
        serde_json::from_value(json!({"type": "learn-read", "session": "s1"})).unwrap();
    assert_eq!(
        read,
        Request::LearnRead {
            session: s("s1"),
            offset: None
        }
    );
    // A request this host doesn't know, or a value out of its set, is refused.
    for unknown in [
        json!({"type": "unlock", "passphrase": "x"}),
        json!({"type": "fill", "origin": "o", "ref": REF, "want": ["cvv"]}),
        json!({"type": "passkey-get", "origin": "o", "ref": REF, "challenge": "c", "userVerification": "always"}),
    ] {
        assert!(serde_json::from_value::<Request>(unknown).is_err());
    }
}

#[test]
fn replies() {
    let passkey = Passkey {
        passkey: s(REF),
        vault: s("Personal"),
        credential_id: s("Y3JlZA"),
        username: Some(s("alex")),
        created: None,
    };
    let cases = [
        (
            Body::Hello {
                protocol: PROTOCOL,
                version: s("1.2.3"),
                status: HostStatus::NotSetUp,
                detail: Some(s("Set up Deadbolt")),
                capabilities: CAPABILITIES.map(String::from).to_vec(),
                touch_id_ready: false,
            },
            json!({"type": "hello", "protocol": 3, "version": "1.2.3", "status": "not-set-up",
                   "detail": "Set up Deadbolt", "capabilities": CAPABILITIES}),
        ),
        (
            Body::Hello {
                protocol: PROTOCOL,
                version: s("1.2.3"),
                status: HostStatus::Locked,
                detail: None,
                capabilities: vec![s("unlock-prompt")],
                touch_id_ready: true,
            },
            json!({"type": "hello", "protocol": 3, "version": "1.2.3", "status": "locked",
                   "capabilities": ["unlock-prompt"], "touchIdReady": true}),
        ),
        (
            Body::List {
                site: s("github.com"),
                accounts: vec![Account {
                    login: s(REF),
                    vault: s("Personal"),
                    title: s("GitHub"),
                    username: None,
                    has_password: false,
                    has_totp: true,
                    urls: vec![s("https://github.com")],
                    sign_in: Some(SignIn {
                        provider: s("google"),
                        account: None,
                    }),
                }],
            },
            json!({"type": "list", "site": "github.com", "accounts": [
                {"ref": REF, "vault": "Personal", "title": "GitHub", "hasPassword": false,
                 "hasTotp": true, "urls": ["https://github.com"], "signIn": {"provider": "google"}}
            ]}),
        ),
        (
            Body::Fill {
                values: SiteValues {
                    username: Some(s("octocat")),
                    password: None,
                    totp: Some(Secret::new("123456")),
                },
            },
            json!({"type": "fill", "username": "octocat", "totp": "123456"}),
        ),
        (
            Body::Generate {
                password: Secret::new("Xk3!Xk3!"),
                generated: s("g1"),
            },
            json!({"type": "generate", "password": "Xk3!Xk3!", "generated": "g1"}),
        ),
        (Body::GenerateCheck, json!({"type": "generate-check"})),
        (Body::GenerateKeep, json!({"type": "generate-keep"})),
        (Body::GenerateDrop, json!({"type": "generate-drop"})),
        (
            Body::Check {
                status: SiteStatus::Same,
                matches: vec![s(REF)],
            },
            json!({"type": "check", "status": "same", "matches": [REF]}),
        ),
        (
            Body::Save {
                login: s(REF),
                created: true,
            },
            json!({"type": "save", "ref": REF, "created": true}),
        ),
        (
            Body::Error {
                code: ErrorCode::DomainMismatch,
                message: s("not this site's"),
            },
            json!({"type": "error", "code": "domain_mismatch", "message": "not this site's"}),
        ),
        (
            Body::Changed {
                change: Change::Items,
                touch_id_ready: false,
            },
            json!({"type": "changed", "change": "items"}),
        ),
        (
            Body::Changed {
                change: Change::Locked,
                touch_id_ready: true,
            },
            json!({"type": "changed", "change": "locked", "touchIdReady": true}),
        ),
        (
            Body::Forms {
                identities: vec![FormIdentity {
                    item: s(REF),
                    vault: s("Personal"),
                    title: s("Home"),
                    summary: String::new(),
                    fields: vec![s("given-name")],
                }],
                cards: vec![FormCard {
                    item: s(REF),
                    vault: s("Personal"),
                    title: s("Visa"),
                    brand: Some(s("Visa")),
                    last4: s("4242"),
                    expiry: Some(s("2030-09")),
                    cardholder: None,
                    billing: Some(s(REF)),
                    fields: vec![s("number"), s("expiry")],
                }],
                can_verify: true,
            },
            json!({"type": "forms", "canVerify": true,
                   "identities": [{"ref": REF, "vault": "Personal", "title": "Home",
                                   "summary": "", "fields": ["given-name"]}],
                   "cards": [{"ref": REF, "vault": "Personal", "title": "Visa", "brand": "Visa",
                              "last4": "4242", "expiry": "2030-09", "billing": REF,
                              "fields": ["number", "expiry"]}]}),
        ),
        (
            Body::FillForm {
                values: [(s("number"), Secret::new("4242424242424242"))].into(),
                verified: true,
            },
            json!({"type": "fill-form", "values": {"number": "4242424242424242"}, "verified": true}),
        ),
        (
            Body::SaveForm {
                item: s(REF),
                created: false,
            },
            json!({"type": "save-form", "ref": REF, "created": false}),
        ),
        (
            Body::Passkeys(Passkeys {
                rp_id: s("github.com"),
                can_verify: false,
                passkeys: vec![passkey],
            }),
            json!({"type": "passkeys", "rpId": "github.com", "canVerify": false, "passkeys": [
                {"ref": REF, "vault": "Personal", "credentialId": "Y3JlZA", "username": "alex"}
            ]}),
        ),
        (
            Body::PasskeyCreated(PasskeyCreated {
                passkey: s(REF),
                credential_id: s("Y3JlZA"),
                client_data_json: s("e30"),
                attestation_object: s("YQ"),
                authenticator_data: s("Yg"),
                public_key: s("Yw"),
                verified: true,
            }),
            json!({"type": "passkey-created", "ref": REF, "credentialId": "Y3JlZA",
                   "clientDataJSON": "e30", "attestationObject": "YQ",
                   "authenticatorData": "Yg", "publicKey": "Yw", "verified": true}),
        ),
        (
            Body::PasskeyAssertion(PasskeyAssertion {
                credential_id: s("Y3JlZA"),
                client_data_json: s("e30"),
                authenticator_data: s("Yg"),
                signature: s("c2ln"),
                user_handle: s("YWxleA"),
                verified: false,
            }),
            json!({"type": "passkey-assertion", "credentialId": "Y3JlZA", "clientDataJSON": "e30",
                   "authenticatorData": "Yg", "signature": "c2ln", "userHandle": "YWxleA",
                   "verified": false}),
        ),
        (
            Body::PasskeyCancelled { found: true },
            json!({"type": "passkey-cancelled", "found": true}),
        ),
        (Body::Learned, json!({"type": "learned"})),
        (
            Body::LearnText {
                text: s("{}\n"),
                next: Some(3),
            },
            json!({"type": "learn-text", "text": "{}\n", "next": 3}),
        ),
        (
            Body::LearnText {
                text: String::new(),
                next: None,
            },
            json!({"type": "learn-text", "text": "", "next": null}),
        ),
        (
            Body::LearnDeleted { found: false },
            json!({"type": "learn-deleted", "found": false}),
        ),
        (
            Body::UnlockPrompt { app: true },
            json!({"type": "unlock-prompt", "app": true}),
        ),
    ];
    for (body, wire) in cases {
        golden(body, wire);
    }
}

/// An answer carries its request's id; a pushed change has none.
#[test]
fn envelopes() {
    golden(
        Envelope {
            id: Some("4".into()),
            body: Body::Learned,
        },
        json!({"id": "4", "type": "learned"}),
    );
    // A request whose id couldn't be read is answered with a null one.
    let refused = Envelope {
        id: Some(Value::Null),
        body: Body::Error {
            code: ErrorCode::BadRequest,
            message: s("a request needs an id"),
        },
    };
    assert_eq!(
        serde_json::to_value(&refused).unwrap(),
        json!({"id": null, "type": "error", "code": "bad_request", "message": "a request needs an id"})
    );
    golden(
        Envelope {
            id: None,
            body: Body::Changed {
                change: Change::Started,
                touch_id_ready: false,
            },
        },
        json!({"type": "changed", "change": "started"}),
    );
}

#[test]
fn every_error_code_and_change_has_its_wire_name() {
    let codes = [
        (ErrorCode::Forbidden, "forbidden"),
        (ErrorCode::Locked, "locked"),
        (ErrorCode::NotFound, "not_found"),
        (ErrorCode::DomainMismatch, "domain_mismatch"),
        (ErrorCode::BadRequest, "bad_request"),
        (ErrorCode::RateLimited, "rate_limited"),
        (ErrorCode::Exists, "exists"),
        (ErrorCode::Cancelled, "cancelled"),
        (ErrorCode::Weak, "weak"),
        (ErrorCode::Failed, "failed"),
    ];
    for (code, wire) in codes {
        golden(code, json!(wire));
    }
    for (status, wire) in [
        (HostStatus::Ready, "ready"),
        (HostStatus::Locked, "locked"),
        (HostStatus::NotSetUp, "not-set-up"),
        (HostStatus::Unavailable, "unavailable"),
    ] {
        golden(status, json!(wire));
    }
    for (change, wire) in [
        (Change::Locked, "locked"),
        (Change::Unlocked, "unlocked"),
        (Change::Items, "items"),
        (Change::Stopped, "stopped"),
        (Change::Started, "started"),
    ] {
        golden(change, json!(wire));
    }
}

/// The daemon's changes the extension hears of, and as what.
#[test]
fn daemon_changes_reach_the_extension_as_its_own() {
    use crate::daemon::Change as D;
    let vault = || s("v");
    for (daemon, host) in [
        (D::Locked, Some(Change::Locked)),
        (D::Unlocked, Some(Change::Unlocked)),
        (D::Items { vault: vault() }, Some(Change::Items)),
        (D::Vaults, Some(Change::Items)),
        (D::Resync, Some(Change::Items)),
        (D::Stopping, Some(Change::Stopped)),
        (D::Watching, None),
        (D::Devices { vault: vault() }, None),
        (D::Activity, None),
        (D::Health, None),
        (D::Update, None),
    ] {
        assert_eq!(Change::of(&daemon), host, "{daemon:?}");
    }
}
