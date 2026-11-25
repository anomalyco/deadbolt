//! The reqwest transport both HTTP backends share: ring TLS, no redirects,
//! bounded timeouts, and status handling.

use std::time::Duration;

use reqwest::{Client, RequestBuilder};

use crate::error::RemoteError;

/// A status and body.
pub(crate) struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The client every backend uses. Redirects are never followed: the next
/// host would receive the `Authorization` header.
pub(crate) fn client(https_only: bool) -> Result<Client, RemoteError> {
    // reqwest takes the process's rustls provider; Deadbolt's is ring.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    Client::builder()
        .user_agent("deadbolt")
        .https_only(https_only)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| RemoteError::Config(format!("HTTP client: {e}")))
}

/// Sends a request and reads the whole reply. A 3xx is refused here, so
/// no verb can be talked into following one.
pub(crate) async fn send(
    request: RequestBuilder,
    verb: &'static str,
    name: &str,
) -> Result<Reply, RemoteError> {
    let transport = |e: reqwest::Error| RemoteError::Transport {
        verb,
        name: name.to_owned(),
        detail: e.without_url().to_string(),
    };
    let response = request.send().await.map_err(transport)?;
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err(RemoteError::Redirect {
            verb,
            name: name.to_owned(),
            status,
        });
    }
    let body = response.bytes().await.map_err(transport)?.to_vec();
    Ok(Reply { status, body })
}

/// An unexpected status.
pub(crate) fn unexpected(verb: &'static str, name: &str, status: u16) -> RemoteError {
    RemoteError::Status {
        verb,
        name: name.to_owned(),
        status,
    }
}

/// The wall clock in Unix seconds, for signing dates.
#[expect(
    clippy::disallowed_methods,
    reason = "the HTTP backends' default clock; tests inject their own"
)]
pub(crate) fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
