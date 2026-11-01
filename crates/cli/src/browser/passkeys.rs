//! The native messaging host's passkey messages (see docs/autofill.md).
//! A registration or sign-in waits on Touch ID, so it runs beside other
//! requests and answers when done; `passkey-cancel` (the page navigated or
//! aborted) stops it, which hangs up on the daemon and dismisses the prompt.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use zeroize::Zeroizing;

use super::host::{
    Body, Bucket, Code, Envelope, Refusal, call, encode, format_ref, parse_ref, unexpected,
};
use crate::paths::Paths;
use crate::protocol::{Command, Reply, Verify};

/// Ceremonies a user starts from Deadbolt's own prompt: a burst, then one a
/// second.
pub const CEREMONIES: (u32, Duration) = (10, Duration::from_secs(1));
/// Ceremonies waiting at once; each holds a Touch ID prompt or is about to.
const MAX_PENDING: usize = 4;
/// Every page's passkey calls list first, before anyone is asked: a burst,
/// then four a second. The extension also limits each page.
pub const LISTS: (u32, Duration) = (20, Duration::from_millis(250));

const MAX_ORIGIN: usize = 2048;
const MAX_RP_ID: usize = 253;
/// Base64url of 1024 bytes.
const MAX_CHALLENGE: usize = 1366;
/// Base64url of 64 bytes.
const MAX_USER_ID: usize = (deadbolt_core::webauthn::MAX_USER_HANDLE * 4).div_ceil(3);
use deadbolt_core::passkeys::MAX_USER_NAME;
/// Base64url of 1023 bytes, WebAuthn's longest credential id.
const MAX_CREDENTIAL_ID: usize = 1364;
const MAX_EXCLUDE: usize = 64;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct List {
    origin: String,
    #[serde(default)]
    rp_id: Option<String>,
}

#[derive(Deserialize)]
pub struct User {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "displayName")]
    display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Create {
    origin: String,
    #[serde(default)]
    rp_id: Option<String>,
    challenge: String,
    user: User,
    #[serde(default)]
    exclude: Vec<String>,
    user_verification: Verify,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Get {
    origin: String,
    #[serde(default)]
    rp_id: Option<String>,
    #[serde(rename = "ref")]
    passkey: String,
    challenge: String,
    user_verification: Verify,
}

#[derive(Deserialize)]
pub struct Cancel {
    /// The id of the `passkey-create` or `passkey-get` to stop.
    request: Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Listed {
    rp_id: String,
    can_verify: bool,
    passkeys: Vec<Passkey>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    #[serde(rename = "ref")]
    passkey: String,
    vault: String,
    credential_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Created {
    #[serde(rename = "ref")]
    passkey: String,
    credential_id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
    authenticator_data: String,
    public_key: String,
    verified: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assertion {
    credential_id: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: String,
    verified: bool,
}

fn at_most(what: &str, value: &str, max: usize) -> Result<(), Refusal> {
    if value.is_empty() || value.len() > max {
        return Err(Refusal::bad(format!("{what} is 1 to {max} bytes")));
    }
    Ok(())
}

fn check_page(origin: &str, rp_id: Option<&str>) -> Result<(), Refusal> {
    at_most("origin", origin, MAX_ORIGIN)?;
    if let Some(rp_id) = rp_id {
        at_most("rpId", rp_id, MAX_RP_ID)?;
    }
    Ok(())
}

pub async fn list(paths: &Paths, list: List) -> Result<Body, Refusal> {
    check_page(&list.origin, list.rp_id.as_deref())?;
    let Reply::Passkeys {
        rp_id,
        passkeys,
        can_verify,
    } = call(
        paths,
        Command::PasskeyList {
            origin: list.origin,
            rp_id: list.rp_id,
        },
    )
    .await?
    else {
        return Err(unexpected());
    };
    Ok(Body::Passkeys(Listed {
        rp_id,
        can_verify,
        passkeys: passkeys
            .into_iter()
            .map(|p| Passkey {
                passkey: format_ref(&p.passkey),
                vault: p.vault,
                credential_id: p.credential_id,
                username: p.username,
                created: p.created,
            })
            .collect(),
    }))
}

pub fn create_command(create: Create) -> Result<Command, Refusal> {
    check_page(&create.origin, create.rp_id.as_deref())?;
    at_most("challenge", &create.challenge, MAX_CHALLENGE)?;
    at_most("user.id", &create.user.id, MAX_USER_ID)?;
    if create.user.name.len() > MAX_USER_NAME * 4 {
        return Err(Refusal::bad("user.name is too long"));
    }
    if create.user.display_name.len() > MAX_USER_NAME * 4 {
        return Err(Refusal::bad("user.displayName is too long"));
    }
    if create.exclude.len() > MAX_EXCLUDE {
        return Err(Refusal::bad(format!(
            "exclude names at most {MAX_EXCLUDE} credentials"
        )));
    }
    for id in &create.exclude {
        at_most("a credential id", id, MAX_CREDENTIAL_ID)?;
    }
    Ok(Command::PasskeyCreate {
        origin: create.origin,
        rp_id: create.rp_id,
        challenge: create.challenge,
        user_id: create.user.id,
        user_name: create.user.name,
        user_display_name: create.user.display_name,
        exclude: create.exclude,
        verify: create.user_verification,
    })
}

pub fn get_command(get: Get) -> Result<Command, Refusal> {
    check_page(&get.origin, get.rp_id.as_deref())?;
    at_most("challenge", &get.challenge, MAX_CHALLENGE)?;
    Ok(Command::PasskeyGet {
        origin: get.origin,
        rp_id: get.rp_id,
        passkey: parse_ref(&get.passkey)?,
        challenge: get.challenge,
        verify: get.user_verification,
    })
}

async fn ceremony(paths: &Paths, command: Command) -> Result<Body, Refusal> {
    match call(paths, command).await? {
        Reply::PasskeyCreated {
            passkey,
            credential_id,
            client_data_json,
            attestation_object,
            authenticator_data,
            public_key,
            verified,
        } => Ok(Body::PasskeyCreated(Created {
            passkey: format_ref(&passkey),
            credential_id,
            client_data_json,
            attestation_object,
            authenticator_data,
            public_key,
            verified,
        })),
        Reply::PasskeyAssertion {
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
            verified,
        } => Ok(Body::PasskeyAssertion(Assertion {
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
            verified,
        })),
        _ => Err(unexpected()),
    }
}

/// The ceremonies running for one connection, by request id.
pub struct Ceremonies {
    running: HashMap<String, AbortHandle>,
    bucket: Bucket,
}

impl Ceremonies {
    pub fn new(now: Instant) -> Self {
        Self {
            running: HashMap::new(),
            bucket: Bucket::new(CEREMONIES, now),
        }
    }

    /// Starts a registration (`create`) or sign-in, answering `id` on
    /// `frames` when it's done; refused at once if it's malformed or too
    /// many run.
    pub fn start(
        &mut self,
        paths: &Paths,
        id: Value,
        request: Result<Command, Refusal>,
        frames: &mpsc::Sender<Zeroizing<Vec<u8>>>,
    ) -> Result<(), Refusal> {
        let command = request?;
        self.running.retain(|_, task| !task.is_finished());
        let key = id.to_string();
        if self.running.contains_key(&key) {
            return Err(Refusal::bad("a passkey request with this id is running"));
        }
        if self.running.len() >= MAX_PENDING || !self.bucket.take(Instant::now()) {
            return Err(Refusal::slow_down());
        }
        let paths = paths.clone();
        let frames = frames.clone();
        let task = tokio::spawn(async move {
            let body = ceremony(&paths, command)
                .await
                .unwrap_or_else(Refusal::body);
            let envelope = Envelope { id: Some(id), body };
            if let Ok(frame) = encode(&envelope) {
                drop(frames.send(frame).await);
            }
        });
        self.running.insert(key, task.abort_handle());
        Ok(())
    }

    /// Stops the ceremony `cancel` names, which then answers that it was
    /// cancelled. Whether one was running.
    pub async fn cancel(
        &mut self,
        cancel: Cancel,
        frames: &mpsc::Sender<Zeroizing<Vec<u8>>>,
    ) -> Body {
        let found = match self.running.remove(&cancel.request.to_string()) {
            Some(task) if !task.is_finished() => {
                task.abort();
                let envelope = Envelope {
                    id: Some(cancel.request),
                    body: Body::Error {
                        code: Code::Cancelled,
                        message: "the passkey request was cancelled".into(),
                    },
                };
                if let Ok(frame) = encode(&envelope) {
                    drop(frames.send(frame).await);
                }
                true
            }
            _ => false,
        };
        Body::PasskeyCancelled { found }
    }
}

impl Drop for Ceremonies {
    fn drop(&mut self) {
        for task in self.running.values() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(json: Value) -> Result<Command, Refusal> {
        create_command(serde_json::from_value(json).unwrap())
    }

    #[test]
    fn requests_are_checked_for_shape() {
        let ok = serde_json::json!({
            "origin": "https://example.com", "rpId": "example.com",
            "challenge": "AAAAAAAAAAAAAAAAAAAAAA", "user": {"id": "a2l0", "name": "kit"},
            "exclude": [], "userVerification": "preferred",
        });
        let Ok(Command::PasskeyCreate { verify, .. }) = create(ok.clone()) else {
            panic!("a valid registration");
        };
        assert_eq!(verify, Verify::Preferred);
        for (field, value) in [
            ("origin", Value::from("")),
            ("rpId", Value::from("a".repeat(300))),
            ("challenge", Value::from("A".repeat(2000))),
            ("exclude", Value::from(vec!["AAAA"; 65])),
        ] {
            let mut bad = ok.clone();
            bad[field] = value;
            assert!(create(bad).is_err(), "{field}");
        }
        let mut bad = ok.clone();
        bad["user"]["id"] = "A".repeat(100).into();
        assert!(create(bad).is_err());
        let mut bad = ok;
        bad["userVerification"] = "always".into();
        assert!(serde_json::from_value::<Create>(bad).is_err());

        let get: Get = serde_json::from_value(serde_json::json!({
            "origin": "https://example.com", "ref": "not a ref",
            "challenge": "AAAAAAAAAAAAAAAAAAAAAA", "userVerification": "required",
        }))
        .unwrap();
        assert!(get_command(get).is_err());
    }
}
