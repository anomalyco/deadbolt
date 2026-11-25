//! The reqwest transport both HTTP backends share: ring TLS, no redirects,
//! bounded timeouts, bounded bodies, and status handling.

use std::time::Duration;

use reqwest::{Client, RequestBuilder, Response};

use crate::error::RemoteError;
use crate::store::ByteRange;

/// The most body bytes read from a reply the verb ignores (`PUT`,
/// `DELETE`, `MKCOL`, error statuses).
pub(crate) const SMALL_BODY: u64 = 64 * 1024;
/// The most body bytes read from one `LIST` page or `PROPFIND` reply.
pub(crate) const LIST_BODY: u64 = 16 * 1024 * 1024;
/// The most body bytes one whole-object `GET` reads.
pub(crate) const OBJECT_BODY: u64 = 256 * 1024 * 1024;
/// The longest one request may take, body included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

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
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| RemoteError::Config(format!("HTTP client: {e}")))
}

fn transport(verb: &'static str, name: &str) -> impl Fn(reqwest::Error) -> RemoteError {
    move |e| RemoteError::Transport {
        verb,
        name: name.to_owned(),
        detail: e.without_url().to_string(),
    }
}

fn too_big(verb: &'static str, name: &str, cap: u64) -> RemoteError {
    RemoteError::Protocol(format!("{verb} {name}: reply body over {cap} bytes"))
}

/// Sends a request and returns the response before its body. A 3xx is
/// refused here, so no verb can be talked into following one.
pub(crate) async fn start(
    request: RequestBuilder,
    verb: &'static str,
    name: &str,
) -> Result<Response, RemoteError> {
    let response = request.send().await.map_err(transport(verb, name))?;
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err(RemoteError::Redirect {
            verb,
            name: name.to_owned(),
            status,
        });
    }
    Ok(response)
}

/// Reads a body of at most `cap` bytes, refusing a longer one before
/// buffering it.
pub(crate) async fn body(
    mut response: Response,
    verb: &'static str,
    name: &str,
    cap: u64,
) -> Result<Vec<u8>, RemoteError> {
    if response.content_length().is_some_and(|len| len > cap) {
        return Err(too_big(verb, name, cap));
    }
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport(verb, name))? {
        if (out.len() + chunk.len()) as u64 > cap {
            return Err(too_big(verb, name, cap));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Sends a request and reads a reply of at most `cap` bytes.
pub(crate) async fn send(
    request: RequestBuilder,
    verb: &'static str,
    name: &str,
    cap: u64,
) -> Result<Reply, RemoteError> {
    let response = start(request, verb, name).await?;
    let status = response.status().as_u16();
    let body = body(response, verb, name, cap).await?;
    Ok(Reply { status, body })
}

/// Sends a request whose reply body is ignored: only the status matters.
pub(crate) async fn status(
    request: RequestBuilder,
    verb: &'static str,
    name: &str,
) -> Result<u16, RemoteError> {
    Ok(send(request, verb, name, SMALL_BODY).await?.status)
}

/// A `GET` (with `Range` already set when `range` is given), read with
/// bounds: a whole object up to [`OBJECT_BODY`]; a `206` only if its
/// `Content-Range` is the range asked for, and no longer than it; a `200`
/// to a ranged request streamed, keeping only the range and hanging up
/// once it is read.
pub(crate) async fn get(
    request: RequestBuilder,
    name: &str,
    range: Option<ByteRange>,
) -> Result<Option<Vec<u8>>, RemoteError> {
    const VERB: &str = "GET";
    let response = start(request, VERB, name).await?;
    match (response.status().as_u16(), range) {
        (200, None) => Ok(Some(body(response, VERB, name, OBJECT_BODY).await?)),
        (200, Some(range)) => Ok(Some(slice_of_whole(response, name, range).await?)),
        (206, Some(range)) => {
            let cap = range_len(range);
            let header = response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let (first, last) =
                header
                    .as_deref()
                    .and_then(parse_content_range)
                    .ok_or_else(|| {
                        RemoteError::Protocol(format!(
                            "GET {name}: 206 without a valid Content-Range"
                        ))
                    })?;
            if first != range.start || range.end.is_some_and(|end| last > end) {
                return Err(RemoteError::Protocol(format!(
                    "GET {name}: 206 Content-Range {first}-{last} is not the range asked for"
                )));
            }
            let want = last - first + 1;
            if want > cap {
                return Err(too_big(VERB, name, cap));
            }
            let bytes = body(response, VERB, name, want).await?;
            if bytes.len() as u64 != want {
                return Err(RemoteError::Protocol(format!(
                    "GET {name}: 206 body shorter than its Content-Range"
                )));
            }
            Ok(Some(bytes))
        }
        (206, None) => Err(RemoteError::Protocol(format!(
            "GET {name}: 206 to a request without Range"
        ))),
        (404, _) => Ok(None),
        (416, _) => Ok(Some(Vec::new())),
        (status, _) => Err(unexpected(VERB, name, status)),
    }
}

/// The most bytes a range can select.
fn range_len(range: ByteRange) -> u64 {
    match range.end {
        Some(end) if end < range.start => 0,
        Some(end) => (end - range.start).saturating_add(1).min(OBJECT_BODY),
        None => OBJECT_BODY,
    }
}

/// `bytes first-last/total` (or `/*`) to `(first, last)`.
fn parse_content_range(header: &str) -> Option<(u64, u64)> {
    let spec = header.trim().strip_prefix("bytes ")?;
    let (span, _total) = spec.split_once('/')?;
    let (first, last) = span.split_once('-')?;
    let (first, last) = (first.trim().parse().ok()?, last.trim().parse().ok()?);
    (first <= last).then_some((first, last))
}

/// A store that ignored `Range` sent the whole object: stream it, skip to
/// `range.start`, keep at most the range, and stop reading at its end.
async fn slice_of_whole(
    mut response: Response,
    name: &str,
    range: ByteRange,
) -> Result<Vec<u8>, RemoteError> {
    let want = range_len(range);
    let mut out = Vec::new();
    let mut offset: u64 = 0;
    while (out.len() as u64) < want {
        let Some(chunk) = response.chunk().await.map_err(transport("GET", name))? else {
            break;
        };
        let chunk_start = offset;
        offset += chunk.len() as u64;
        if offset <= range.start {
            continue;
        }
        let skip = usize::try_from(range.start.saturating_sub(chunk_start)).unwrap_or(usize::MAX);
        let room = usize::try_from(want - out.len() as u64).unwrap_or(usize::MAX);
        let rest = chunk.get(skip..).unwrap_or_default();
        out.extend_from_slice(&rest[..rest.len().min(room)]);
    }
    // Dropping the response here closes the connection mid-body.
    Ok(out)
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
