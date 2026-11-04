use super::*;
use crate::import::parse;
use crate::import::tests::{fields, lines};

/// The user id in [`EXPORT`]; `op account list` gives it as `user_uuid`.
pub const USER: &str = "USERUSERUSERUSERUSERUSERUS";

/// Shaped like the `export.data` of a 1Password 8 `.1pux`: two vaults.
pub const EXPORT: &str = r#"{
  "accounts": [
    {
      "attrs": {
        "accountName": "Dax",
        "name": "Dax Raad",
        "avatar": "",
        "email": "dax@example.com",
        "uuid": "USERUSERUSERUSERUSERUSERUS",
        "domain": "https://my.1password.com/"
      },
      "vaults": [
        {
          "attrs": { "uuid": "v1v1v1v1v1v1v1v1v1v1v1v1v1", "desc": "", "avatar": "", "name": "Private", "type": "P" },
          "items": [
            {
              "uuid": "item1item1item1item1item1a",
              "favIndex": 1,
              "createdAt": 1700000000,
              "updatedAt": 1710000000,
              "state": "active",
              "categoryUuid": "001",
              "details": {
                "loginFields": [
                  { "value": "dax@example.com", "id": "", "name": "email", "fieldType": "E", "designation": "username" },
                  { "value": "op-github-pw", "id": "", "name": "password", "fieldType": "P", "designation": "password" },
                  { "value": "✓", "id": "remember", "name": "remember_me", "fieldType": "C" },
                  { "value": "", "id": "", "name": "commit", "fieldType": "I" }
                ],
                "notesPlain": "work account\nsecond line",
                "sections": [
                  {
                    "title": "Security",
                    "name": "add more",
                    "fields": [
                      { "title": "one-time password", "id": "TOTP_abc123", "value": { "totp": "otpauth://totp/GitHub:dax?secret=JBSWY3DPEHPK3PXP&issuer=GitHub" }, "guarded": false, "multiline": false },
                      { "title": "Recovery codes", "id": "f1", "value": { "concealed": "op-recovery-111" } },
                      { "title": "", "id": "f2", "value": { "string": "untitled value" } },
                      { "title": "member since", "id": "f3", "value": { "date": 1704067200 } },
                      { "title": "backup email", "id": "f4", "value": { "email": { "email_address": "backup@example.com", "provider": null } } },
                      { "title": "renews", "id": "f5", "value": { "monthYear": 202812 } },
                      { "title": "other login", "id": "f6", "value": { "reference": "item9item9item9item9item9a" } },
                      { "title": "empty", "id": "f7", "value": { "string": "" } },
                      { "title": "blank", "id": "f9", "value": { "concealed": "   " } },
                      { "title": "", "id": "f10", "value": { "file": { "documentId": "doc1doc1doc1doc1doc1doc1d1", "fileName": "recovery.pdf", "decryptedSize": 1024 } } }
                    ]
                  },
                  { "title": "Docs", "name": "docs", "fields": [
                    { "title": "status page", "id": "f8", "value": { "url": "https://www.githubstatus.com" } }
                  ] }
                ],
                "passwordHistory": [ { "value": "op-old-pw", "time": 1690000000 } ]
              },
              "overview": {
                "subtitle": "dax@example.com",
                "urls": [
                  { "label": "", "url": "https://github.com/login" },
                  { "label": "gist", "url": "gist.github.com" }
                ],
                "title": "GitHub",
                "url": "https://github.com/login",
                "ps": 100,
                "tags": ["work", "dev"]
              }
            },
            {
              "uuid": "item2item2item2item2item2a",
              "favIndex": 0,
              "state": "active",
              "categoryUuid": "005",
              "details": { "loginFields": [], "notesPlain": "", "sections": [], "passwordHistory": [], "password": "op-wifi-pw" },
              "overview": { "title": "Garage door", "tags": ["home"] }
            },
            {
              "uuid": "item3item3item3item3item3a",
              "favIndex": 0,
              "state": "active",
              "categoryUuid": "003",
              "details": { "loginFields": [], "notesPlain": "op-note-secret", "sections": [], "passwordHistory": [] },
              "overview": { "title": "A note" }
            },
            {
              "uuid": "item4item4item4item4item4a",
              "favIndex": 0,
              "state": "archived",
              "categoryUuid": "001",
              "details": { "loginFields": [ { "value": "op-archived-pw", "name": "password", "fieldType": "P", "designation": "password" } ] },
              "overview": { "title": "Old site", "url": "https://old.example.com" }
            }
          ]
        },
        {
          "attrs": { "uuid": "v2v2v2v2v2v2v2v2v2v2v2v2v2", "name": "Shared", "type": "U" },
          "items": [
            {
              "uuid": "item5item5item5item5item5a",
              "favIndex": 2,
              "state": "active",
              "categoryUuid": "002",
              "details": {
                "loginFields": [],
                "notesPlain": "",
                "sections": [
                  {
                    "title": "",
                    "name": "",
                    "fields": [
                      { "title": "cardholder name", "id": "cardholder", "value": { "string": "Dax Raad" } },
                      { "title": "type", "id": "type", "value": { "creditCardType": "visa" } },
                      { "title": "number", "id": "ccnum", "value": { "creditCardNumber": "4242 4242 4242 4242" } },
                      { "title": "verification number", "id": "cvv", "value": { "concealed": "321" } },
                      { "title": "website", "id": "site", "value": { "url": "https://bank.example" } },
                      { "title": "expiry date", "id": "expiry", "value": { "monthYear": 202704 } },
                      { "title": "valid from", "id": "validFrom", "value": { "monthYear": 202204 } },
                      { "title": "PIN", "id": "pin", "value": { "concealed": "9876" } }
                    ]
                  },
                  {
                    "title": "Contact Information",
                    "name": "contactInfo",
                    "fields": [
                      { "title": "issuing bank", "id": "bank", "value": { "string": "Example Bank" } },
                      { "title": "phone (intl)", "id": "phoneIntl", "value": { "phone": "+1 555 0100" } },
                      { "title": "address", "id": "addr", "value": { "address": { "street": "1 Main St", "city": "Springfield", "country": "us", "zip": "12345", "state": "" } } }
                    ]
                  }
                ],
                "passwordHistory": []
              },
              "overview": { "title": "Visa", "subtitle": "4242 ****", "url": "bank.example", "urls": [ { "url": "https://bank.example" }, { "url": "https://cards.bank.example" } ] }
            },
            {
              "uuid": "item6item6item6item6item6a",
              "favIndex": 0,
              "state": "active",
              "categoryUuid": "112",
              "details": {
                "sections": [ { "title": "", "fields": [
                  { "title": "username", "id": "username", "value": { "string": "deploy-bot" } },
                  { "title": "credential", "id": "credential", "value": { "concealed": "op-api-key" } },
                  { "title": "hostname", "id": "hostname", "value": { "string": "api.example.com" } }
                ] } ]
              },
              "overview": { "title": "Deploy API" }
            },
            {
              "uuid": "item7item7item7item7item7a",
              "favIndex": 0,
              "state": "active",
              "categoryUuid": "001",
              "details": { "loginFields": [ { "value": "nobody", "name": "username", "fieldType": "T", "designation": "username" } ] },
              "overview": { "title": "No password" }
            },
            {
              "uuid": "item8",
              "state": "active",
              "categoryUuid": "004",
              "details": {
                "notesPlain": "",
                "sections": [
                  { "title": "Identification", "name": "name", "fields": [
                    { "title": "first name", "id": "firstname", "value": { "string": "Dax" } },
                    { "title": "initial", "id": "initial", "value": { "string": "" } },
                    { "title": "last name", "id": "lastname", "value": { "string": "Raad" } },
                    { "title": "birth date", "id": "birthdate", "value": { "date": 636246000 } },
                    { "title": "company", "id": "company", "value": { "string": "Anomaly" } }
                  ] },
                  { "title": "Address", "name": "address", "fields": [
                    { "title": "address", "id": "address", "value": { "address": { "street": "1 Main St", "city": "Springfield", "state": "IL", "zip": "12345", "country": "us" } } },
                    { "title": "default phone", "id": "defphone", "value": { "phone": "+1 555 0100" } }
                  ] },
                  { "title": "Internet Details", "name": "internet", "fields": [
                    { "title": "email", "id": "email", "value": { "email": { "email_address": "not an email", "provider": null } } }
                  ] }
                ]
              },
              "overview": { "title": "Me" }
            },
            {
              "uuid": "itemC",
              "state": "active",
              "categoryUuid": "114",
              "details": {
                "notesPlain": "for CI",
                "sections": [ { "title": "", "name": "", "fields": [
                  { "title": "private key", "id": "private_key", "value": { "sshKey": {
                    "privateKey": "-----BEGIN PRIVATE KEY-----\npkcs8\n-----END PRIVATE KEY-----",
                    "metadata": {
                      "privateKey": "-----BEGIN PRIVATE KEY-----\npkcs8\n-----END PRIVATE KEY-----",
                      "publicKey": "ssh-ed25519 AAAAC3Nz deploy@ci",
                      "fingerprint": "SHA256:abc",
                      "keyType": "ed25519"
                    }
                  } } },
                  { "title": "public key", "id": "public_key", "value": { "string": "ssh-ed25519 AAAAC3Nz deploy@ci" } },
                  { "title": "fingerprint", "id": "fingerprint", "value": { "string": "SHA256:abc" } },
                  { "title": "key type", "id": "key_type", "value": { "string": "ed25519" } }
                ] },
                { "title": "More", "name": "more", "fields": [
                  { "title": "passphrase", "id": "f1", "value": { "concealed": "op-ssh-pass" } },
                  { "title": "comment", "id": "f2", "value": { "string": "deploy@ci" } }
                ] } ]
              },
              "overview": { "title": "CI key" }
            },
            {
              "uuid": "itemE",
              "state": "active",
              "categoryUuid": "114",
              "details": {
                "sections": [ { "title": "", "name": "", "fields": [
                  { "title": "private key", "id": "private_key", "value": { "sshKey": {
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nopenssh\n-----END OPENSSH PRIVATE KEY-----",
                    "metadata": {
                      "privateKey": "-----BEGIN PRIVATE KEY-----\nold\n-----END PRIVATE KEY-----",
                      "publicKey": "ssh-rsa AAAAB3 old",
                      "fingerprint": "SHA256:old",
                      "keyType": "rsa"
                    }
                  } } }
                ] } ]
              },
              "overview": { "title": "Old key" }
            },
            { "uuid": "item9", "state": "active", "categoryUuid": "114", "details": {}, "overview": { "title": "Deploy key" } },
            {
              "uuid": "itemD",
              "state": "active",
              "categoryUuid": "100",
              "details": {
                "notesPlain": "bought 2024",
                "sections": [ { "title": "", "name": "", "fields": [
                  { "title": "license key", "id": "reg_code", "value": { "string": "ABCD-1234" } },
                  { "title": "version", "id": "product_version", "value": { "string": "5" } },
                  { "title": "password", "id": "retail_password", "value": { "concealed": "op-license-pw" } }
                ] } ]
              },
              "overview": { "title": "Editor" }
            },
            {
              "uuid": "itemF",
              "state": "active",
              "categoryUuid": "101",
              "details": { "sections": [ { "title": "", "name": "", "fields": [
                { "title": "bank name", "id": "bankName", "value": { "string": "Example Bank" } },
                { "title": "account number", "id": "accountNo", "value": { "string": "op-account-12345678" } },
                { "title": "IBAN", "id": "iban", "value": { "string": "op-iban-DE00" } },
                { "title": "PIN", "id": "telephonePin", "value": { "concealed": "op-phone-pin" } }
              ] } ] },
              "overview": { "title": "Checking" }
            },
            {
              "uuid": "itemG",
              "state": "active",
              "categoryUuid": "106",
              "details": { "sections": [ { "title": "", "name": "", "fields": [
                { "title": "full name", "id": "fullname", "value": { "string": "Dax Raad" } },
                { "title": "number", "id": "number", "value": { "string": "op-passport-X123" } }
              ] } ] },
              "overview": { "title": "Passport" }
            },
            { "uuid": "itemA", "state": "active", "categoryUuid": "006", "details": { "documentAttributes": { "fileName": "passport.pdf" } }, "overview": { "title": "Scan" } },
            { "uuid": "itemB", "state": "active", "categoryUuid": "999", "details": {}, "overview": { "title": "Future" } }
          ]
        }
      ]
    }
  ]
}"#;

#[test]
fn maps_a_1pux_export() {
    let (items, report) = parse(EXPORT).unwrap();
    assert_eq!(report.source, ImportSource::OnePassword);
    let kinds: Vec<_> = items
        .iter()
        .map(|i| (i.kind, i.name.as_deref().unwrap_or_default()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("login", "GitHub"),
            ("login", "Garage door"),
            ("note", "A note"),
            ("card", "Visa"),
            ("api", "Deploy API"),
            ("login", "No password"),
            ("identity", "Me"),
            ("ssh", "CI key"),
            ("ssh", "Old key"),
            ("license", "Editor"),
            ("bank", "Checking"),
            ("passport", "Passport"),
        ]
    );
    let github = &items[0];
    // Each item records which 1Password item it is, so a sync can take
    // it over. A .1pux names the user, not the account.
    let source = github.source.as_ref().unwrap();
    assert_eq!(
        source.id,
        format!("1password/{USER}/v1v1v1v1v1v1v1v1v1v1v1v1v1/item1item1item1item1item1a")
    );
    let version = MirrorVersion::parse(&source.version).unwrap();
    assert_eq!(
        (version.updated, version.origin),
        (1_710_000_000, Origin::Import)
    );
    assert!(!version.mirrored());
    assert_eq!(
        source_key(&source.id),
        Some((
            USER,
            "v1v1v1v1v1v1v1v1v1v1v1v1v1",
            "item1item1item1item1item1a"
        ))
    );
    assert!(items.iter().all(|i| i.source.is_some()));
    assert_eq!(
        fields(github),
        [
            ("backup-email", "email", "backup@example.com"),
            ("member-since", "date", "2024-01-01"),
            ("notes", "note", "work account\nsecond line"),
            (
                "otp",
                "otp",
                "otpauth://totp/GitHub:dax?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
            ),
            ("password", "secret", "op-github-pw"),
            ("recovery-codes", "secret", "op-recovery-111"),
            ("remember_me", "text", "✓"),
            ("renews", "month", "2028-12"),
            ("security", "text", "untitled value"),
            ("url", "url", "https://github.com/login"),
            ("url-2", "url", "https://gist.github.com"),
            ("url-3", "url", "https://www.githubstatus.com"),
            ("username", "text", "dax@example.com"),
        ]
    );
    assert_eq!(fields(&items[1]), [("password", "secret", "op-wifi-pw")]);
    // A secure note's body is secret.
    assert_eq!(fields(&items[2]), [("notes", "secret", "op-note-secret")]);
    assert_eq!(
        fields(&items[3]),
        [
            ("address", "note", "1 Main St\nSpringfield, 12345\nus"),
            ("brand", "text", "Visa"),
            ("cardholder", "text", "Dax Raad"),
            ("cvv", "secret", "321"),
            ("expiry", "month", "2027-04"),
            ("issuing-bank", "text", "Example Bank"),
            ("number", "secret", "4242424242424242"),
            ("phone-intl", "text", "+1 555 0100"),
            ("pin", "secret", "9876"),
            ("url", "url", "https://bank.example"),
            ("url-2", "url", "https://cards.bank.example"),
            ("valid-from", "month", "2022-04"),
        ]
    );
    // An API credential is a type of its own.
    assert_eq!(
        fields(&items[4]),
        [
            ("credential", "secret", "op-api-key"),
            ("host", "text", "api.example.com"),
            ("username", "text", "deploy-bot"),
        ]
    );
    // A login needs no password.
    assert_eq!(fields(&items[5]), [("username", "text", "nobody")]);
    assert_eq!(
        fields(&items[6]),
        [
            ("address-line1", "text", "1 Main St"),
            ("birthday", "date", "1990-03-01"),
            ("city", "text", "Springfield"),
            ("country", "text", "US"),
            ("email-2", "text", "not an email"),
            ("family-name", "text", "Raad"),
            ("given-name", "text", "Dax"),
            ("organization", "text", "Anomaly"),
            ("phone", "text", "+15550100"),
            ("postal-code", "text", "12345"),
            ("region", "text", "IL"),
        ]
    );
    // A 1Password 8 key: its values from the item's fields, each once.
    assert_eq!(
        fields(&items[7]),
        [
            ("comment", "text", "deploy@ci"),
            ("fingerprint", "text", "SHA256:abc"),
            ("key-type", "text", "ed25519"),
            ("notes", "note", "for CI"),
            ("passphrase", "secret", "op-ssh-pass"),
            (
                "private-key",
                "secret",
                "-----BEGIN PRIVATE KEY-----\npkcs8\n-----END PRIVATE KEY-----"
            ),
            ("public-key", "text", "ssh-ed25519 AAAAC3Nz deploy@ci"),
        ]
    );
    // An older one: the PKCS#8 key and the rest from its metadata.
    assert_eq!(
        fields(&items[8]),
        [
            ("fingerprint", "text", "SHA256:old"),
            (
                "private-key",
                "secret",
                "-----BEGIN PRIVATE KEY-----\nold\n-----END PRIVATE KEY-----"
            ),
            ("public-key", "text", "ssh-rsa AAAAB3 old"),
        ]
    );
    // Licenses, bank accounts and passports have types of their own; a
    // field their type doesn't know stays an extra field. License keys,
    // ID and account numbers are secret, though 1Password exports them
    // as plain strings.
    assert_eq!(
        fields(&items[9]),
        [
            ("license-key", "secret", "ABCD-1234"),
            ("notes", "note", "bought 2024"),
            ("password", "secret", "op-license-pw"),
            ("version", "text", "5"),
        ]
    );
    assert_eq!(
        fields(&items[10]),
        [
            ("account-number", "secret", "op-account-12345678"),
            ("bank", "text", "Example Bank"),
            ("iban", "secret", "op-iban-DE00"),
            ("pin", "secret", "op-phone-pin"),
        ]
    );
    assert_eq!(
        fields(&items[11]),
        [
            ("full-name", "text", "Dax Raad"),
            ("number", "secret", "op-passport-X123"),
        ]
    );
    assert!(github.favorite);
    assert_eq!(github.tags, BTreeSet::from(["dev".into(), "work".into()]));
    assert!(!items[1].favorite);
    assert_eq!(items[1].tags, BTreeSet::from(["home".into()]));
    assert!(items[3].favorite);
    assert_eq!(
        lines(&report),
        [
            "imported 12 from 1Password (logins 3, cards 1, secure notes 1, SSH keys 2, identities 1, API credentials 1, software licenses 1, bank accounts 1, passports 1)",
            "skipped 1 SSH key without a private key",
            "skipped 1 archived item",
            "skipped 1 document whose file is missing from the export",
            "skipped 1 item of unknown type",
            "warning: 1 invalid email address kept as text",
            "dropped: 1 attachment missing from the export, 1 item's password history, 1 linked field",
        ]
    );
}

/// One item of each 1Password category, as `export.data` has them.
const CATEGORIES: &str = r#"{"accounts": [{"attrs": {"uuid": "USER"}, "vaults": [{"attrs": {"uuid": "v1"}, "items": [
      {"uuid": "c001", "categoryUuid": "001", "overview": {"title": "Site", "url": "https://site.example"},
       "details": {"loginFields": [{"value": "pw", "fieldType": "P", "designation": "password"}],
         "sections": [{"title": "", "fields": [
           {"title": "", "id": "f1", "value": {"file": {"fileName": "recovery codes.txt", "documentId": "doc1", "decryptedSize": 5}}},
           {"title": "contract", "id": "f2", "value": {"file": {"fileName": "big.bin", "documentId": "doc9", "decryptedSize": 99}}}]}]}},
      {"uuid": "c002", "categoryUuid": "002", "overview": {"title": "Visa"},
       "details": {"sections": [{"fields": [{"id": "ccnum", "value": {"creditCardNumber": "4242424242424242"}}]}]}},
      {"uuid": "c003", "categoryUuid": "003", "overview": {"title": "Note"}, "details": {"notesPlain": "body"}},
      {"uuid": "c004", "categoryUuid": "004", "overview": {"title": "Me"},
       "details": {"sections": [{"fields": [{"id": "firstname", "value": {"string": "Dax"}}]}]}},
      {"uuid": "c005", "categoryUuid": "005", "overview": {"title": "Door"}, "details": {"password": "door-pw"}},
      {"uuid": "c006", "categoryUuid": "006", "overview": {"title": "Scan"},
       "details": {"notesPlain": "front page", "documentAttributes": {"fileName": "scan.pdf", "documentId": "doc2", "decryptedSize": 4}}},
      {"uuid": "c100", "categoryUuid": "100", "overview": {"title": "Editor"},
       "details": {"sections": [{"fields": [
         {"id": "reg_code", "value": {"string": "KEY-1"}}, {"id": "reg_name", "value": {"string": "Dax"}},
         {"id": "order_date", "value": {"date": 1704067200}}]}]}},
      {"uuid": "c101", "categoryUuid": "101", "overview": {"title": "Checking"},
       "details": {"sections": [{"fields": [
         {"id": "bankName", "value": {"string": "Example Bank"}}, {"id": "accountNo", "value": {"string": "12345678"}},
         {"id": "routingNo", "value": {"string": "021000021"}}]}]}},
      {"uuid": "c102", "categoryUuid": "102", "overview": {"title": "Prod DB"},
       "details": {"sections": [{"fields": [
         {"id": "database_type", "value": {"menu": "postgresql"}}, {"id": "hostname", "value": {"string": "db.example"}},
         {"id": "port", "value": {"string": "5432"}}, {"id": "database", "value": {"string": "app"}},
         {"id": "username", "value": {"string": "app"}}, {"id": "password", "value": {"concealed": "db-pw"}},
         {"id": "sid", "value": {"string": "ORCL"}}]}]}},
      {"uuid": "c103", "categoryUuid": "103", "overview": {"title": "License"},
       "details": {"sections": [{"fields": [
         {"id": "fullname", "value": {"string": "Dax Raad"}}, {"id": "number", "value": {"string": "D123"}},
         {"id": "state", "value": {"string": "IL"}}, {"id": "expiry_date", "value": {"monthYear": 203006}}]}]}},
      {"uuid": "c104", "categoryUuid": "104", "overview": {"title": "Fishing"},
       "details": {"sections": [{"fields": [{"id": "name", "value": {"string": "Dax"}}]}]}},
      {"uuid": "c105", "categoryUuid": "105", "overview": {"title": "Gym"},
       "details": {"sections": [{"fields": [
         {"id": "org_name", "value": {"string": "Gym Co"}}, {"id": "membership_no", "value": {"string": "M-77"}},
         {"id": "member_since", "value": {"monthYear": 202001}}, {"id": "phone", "value": {"phone": "+1 555 0100"}}]}]}},
      {"uuid": "c106", "categoryUuid": "106", "overview": {"title": "Passport"},
       "details": {"sections": [{"fields": [
         {"id": "number", "value": {"string": "X123"}}, {"id": "issuing_country", "value": {"string": "United States"}},
         {"id": "expiry_date", "value": {"date": 1893456000}}]}]}},
      {"uuid": "c107", "categoryUuid": "107", "overview": {"title": "Miles"},
       "details": {"sections": [{"fields": [{"id": "membership_no", "value": {"string": "R-1"}}]}]}},
      {"uuid": "c108", "categoryUuid": "108", "overview": {"title": "SSN"},
       "details": {"sections": [{"fields": [
         {"id": "name", "value": {"string": "Dax Raad"}}, {"id": "number", "value": {"concealed": "078-05-1120"}}]}]}},
      {"uuid": "c109", "categoryUuid": "109", "overview": {"title": "Home Wi-Fi"},
       "details": {"sections": [{"fields": [
         {"id": "network_name", "value": {"string": "Home"}}, {"id": "wireless_password", "value": {"concealed": "wifi-pw"}},
         {"id": "wireless_security", "value": {"menu": "wpa2p"}}, {"id": "password", "value": {"concealed": "router-pw"}}]}]}},
      {"uuid": "c110", "categoryUuid": "110", "overview": {"title": "Box"},
       "details": {"sections": [{"fields": [
         {"id": "url", "value": {"string": "box.example"}}, {"id": "username", "value": {"string": "root"}},
         {"id": "password", "value": {"concealed": "root-pw"}}]}]}},
      {"uuid": "c111", "categoryUuid": "111", "overview": {"title": "Mail"},
       "details": {"sections": [{"fields": [{"id": "pop_username", "value": {"string": "dax"}}]}]}},
      {"uuid": "c112", "categoryUuid": "112", "overview": {"title": "Stripe"},
       "details": {"sections": [{"fields": [
         {"id": "credential", "value": {"concealed": "sk_live_1"}}, {"id": "type", "value": {"menu": "bearer"}},
         {"id": "expires", "value": {"date": 1893456000}}]}]}},
      {"uuid": "c112b", "categoryUuid": "112", "overview": {"title": "Half API"},
       "details": {"sections": [{"fields": [{"id": "username", "value": {"string": "bot"}}]}]}},
      {"uuid": "c113", "categoryUuid": "113", "overview": {"title": "Doctor"},
       "details": {"sections": [{"fields": [{"id": "healthcareprofessional", "value": {"string": "Dr. Who"}}]}]}},
      {"uuid": "c114", "categoryUuid": "114", "overview": {"title": "Key"},
       "details": {"sections": [{"fields": [{"id": "private_key", "value": {"sshKey": {"privateKey": "-----BEGIN-----"}}}]}]}},
      {"uuid": "c115", "categoryUuid": "115", "overview": {"title": "Wallet"},
       "details": {"sections": [{"fields": [
         {"title": "Recovery Phrase", "id": "x1", "value": {"concealed": "abandon ability able"}},
         {"title": "Wallet Address", "id": "x2", "value": {"string": "bc1qxy"}}]}]}},
      {"uuid": "c006b", "categoryUuid": "006", "overview": {"title": "Missing"},
       "details": {"documentAttributes": {"fileName": "gone.pdf", "documentId": "doc404"}}}
    ]}]}]}"#;

#[test]
fn maps_every_category_and_its_files() {
    let files = [
        ExportFile {
            name: "doc1__recovery codes.txt".into(),
            data: "Y29kZXM=".into(),
            too_large: false,
        },
        ExportFile {
            name: "doc2__scan.pdf".into(),
            data: "JVBERg==".into(),
            too_large: false,
        },
        // Left out by the client as over the cap.
        ExportFile {
            name: "doc9__big.bin".into(),
            data: String::new(),
            too_large: true,
        },
    ];
    let (items, report) = crate::import::parse_with(CATEGORIES, &files).unwrap();
    let kinds: Vec<(&str, &str)> = items
        .iter()
        .map(|i| (i.name.as_deref().unwrap(), i.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            ("Site", "login"),
            ("Visa", "card"),
            ("Note", "note"),
            ("Me", "identity"),
            ("Door", "login"),
            ("Scan", "document"),
            ("Editor", "license"),
            ("Checking", "bank"),
            ("Prod DB", "database"),
            ("License", "driver-license"),
            ("Fishing", "note"),
            ("Gym", "membership"),
            ("Passport", "passport"),
            ("Miles", "note"),
            ("SSN", "id-document"),
            ("Home Wi-Fi", "wifi"),
            ("Box", "server"),
            ("Mail", "note"),
            ("Stripe", "api"),
            ("Half API", "note"),
            ("Doctor", "note"),
            ("Key", "ssh"),
            ("Wallet", "crypto"),
        ]
    );
    let by = |name: &str| {
        items
            .iter()
            .find(|i| i.name.as_deref() == Some(name))
            .unwrap()
    };
    // An attachment is a file field, named by its file; one that didn't
    // come is dropped and counted.
    assert_eq!(
        fields(by("Site")),
        [
            ("password", "secret", "pw"),
            ("recovery-codes", "file", "recovery codes.txt\nY29kZXM="),
            ("url", "url", "https://site.example"),
        ]
    );
    assert_eq!(
        fields(by("Scan")),
        [
            ("file", "file", "scan.pdf\nJVBERg=="),
            ("notes", "note", "front page"),
        ]
    );
    assert_eq!(
        fields(by("Editor")),
        [
            ("license-key", "secret", "KEY-1"),
            ("licensed-to", "text", "Dax"),
            ("purchased", "date", "2024-01-01"),
        ]
    );
    assert_eq!(
        fields(by("Checking")),
        [
            ("account-number", "secret", "12345678"),
            ("bank", "text", "Example Bank"),
            ("routing-number", "text", "021000021"),
        ]
    );
    assert_eq!(
        fields(by("Prod DB")),
        [
            ("database", "text", "app"),
            ("host", "text", "db.example"),
            ("password", "secret", "db-pw"),
            ("port", "text", "5432"),
            ("sid", "text", "ORCL"),
            ("type", "text", "postgresql"),
            ("username", "text", "app"),
        ]
    );
    assert_eq!(
        fields(by("License")),
        [
            ("expires", "month", "2030-06"),
            ("full-name", "text", "Dax Raad"),
            ("number", "secret", "D123"),
            ("state", "text", "IL"),
        ]
    );
    assert_eq!(
        fields(by("Gym")),
        [
            ("member-id", "secret", "M-77"),
            ("member-since", "month", "2020-01"),
            ("organization", "text", "Gym Co"),
            ("phone", "text", "+15550100"),
        ]
    );
    assert_eq!(
        fields(by("Passport")),
        [
            ("expires", "date", "2030-01-01"),
            ("issuing-country", "text", "United States"),
            ("number", "secret", "X123"),
        ]
    );
    assert_eq!(
        fields(by("SSN")),
        [
            ("full-name", "text", "Dax Raad"),
            ("number", "secret", "078-05-1120"),
        ]
    );
    assert_eq!(
        fields(by("Home Wi-Fi")),
        [
            ("password", "secret", "wifi-pw"),
            ("password-2", "secret", "router-pw"),
            ("security", "text", "wpa2p"),
            ("ssid", "text", "Home"),
        ]
    );
    assert_eq!(
        fields(by("Box")),
        [
            ("password", "secret", "root-pw"),
            ("url", "url", "https://box.example"),
            ("username", "text", "root"),
        ]
    );
    assert_eq!(
        fields(by("Stripe")),
        [
            ("credential", "secret", "sk_live_1"),
            ("expires", "date", "2030-01-01"),
            ("type", "text", "bearer"),
        ]
    );
    // Without a credential, an API credential is kept as a note.
    assert_eq!(fields(by("Half API")), [("username", "text", "bot")]);
    assert_eq!(
        fields(by("Wallet")),
        [
            ("address", "text", "bc1qxy"),
            ("recovery-phrase", "secret", "abandon ability able"),
        ]
    );
    assert_eq!(
        lines(&report)[1..],
        [
            "skipped 1 document whose file is missing from the export",
            "dropped: 1 attachment over the 10 MiB an item's files hold",
        ]
    );
}

/// An item's files hold at most `MAX_FILE` bytes in all: past that,
/// attachments are dropped, so its create fits in one entry.
#[test]
fn an_items_files_fit_in_one_entry() {
    let data = data_encoding::BASE64.encode(&vec![7; 6 * 1024 * 1024]);
    let export = r#"{"accounts": [{"vaults": [{"items": [{"categoryUuid": "003", "overview": {"title": "Big"},
            "details": {"sections": [{"fields": [
              {"id": "a", "value": {"file": {"fileName": "a.bin", "documentId": "da"}}},
              {"id": "b", "value": {"file": {"fileName": "b.bin", "documentId": "db"}}}]}]}}]}]}]}"#;
    let files = ["da__a.bin", "db__b.bin"].map(|name| ExportFile {
        name: name.into(),
        data: data.clone(),
        too_large: false,
    });
    let (items, report) = crate::import::parse_with(export, &files).unwrap();
    let names: Vec<&str> = items[0].fields.keys().map(String::as_str).collect();
    assert_eq!(names, ["a"]);
    assert_eq!(
        lines(&report)[1..],
        ["dropped: 1 attachment over the 10 MiB an item's files hold"]
    );
}

#[test]
fn addresses_split_as_op_joins_them() {
    let parts = |v: Value| address_parts(&v).unwrap();
    let s = |v: &str| Some(v.to_string());
    assert_eq!(
        parts("1 Main St, Springfield, IL, 12345, us".into()),
        [
            s("1 Main St"),
            s("Springfield"),
            s("IL"),
            s("12345"),
            s("us")
        ]
    );
    assert_eq!(
        parts("1 Main St, Springfield, 12345, us".into()),
        [s("1 Main St"), s("Springfield"), None, s("12345"), s("us")]
    );
    assert_eq!(
        parts("1 Main St, Springfield".into()),
        [s("1 Main St"), s("Springfield"), None, None, None]
    );
    // Two zips, or too many parts: all street, nothing lost.
    for odd in ["1 Main St, Springfield, 12, 34", "a, b, c, d, e, f"] {
        assert_eq!(parts(odd.into()), [s(odd), None, None, None, None]);
    }
}

#[test]
fn dates_and_months() {
    assert_eq!(date(0), "1970-01-01");
    assert_eq!(date(1_704_067_200), "2024-01-01");
    assert_eq!(date(951_782_400), "2000-02-29");
    assert_eq!(date(-86_400), "1969-12-31");
    // 1990-03-01 at midnight in UTC, CET, PST, UTC+11 and UTC-12, and at
    // noon UTC.
    for secs in [
        636_249_600,
        636_249_600 - 3_600,
        636_249_600 + 8 * 3_600,
        636_249_600 - 11 * 3_600,
        636_249_600 + 12 * 3_600,
    ] {
        assert_eq!(date(secs), "1990-03-01", "{secs}");
    }
    assert_eq!(date(636_249_600 + 12 * 3_600 + 1), "1990-03-02");
    assert_eq!(month_year(202_704), "2027-04");
    assert_eq!(month_year(202_713), "202713");
    assert_eq!(month_year(7), "7");
}

#[test]
fn errors_name_no_values() {
    let error =
        parse(r#"{"accounts": [{"vaults": [{"items": [{"details": {"password": "op-s3cret"#)
            .err()
            .unwrap()
            .to_string();
    assert!(!error.contains("op-s3cret"), "{error}");
    assert!(parse(r#"{"accounts": {}}"#).is_err());
}
