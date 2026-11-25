//! AWS Signature Version 4, header and presigned-URL forms. Pure: the caller
//! passes the time, so it builds for wasm32 and tests against the published
//! vectors.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::path::hex;

/// `x-amz-content-sha256` for a body the signature does not cover.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// The SHA-256 of an empty body.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// An access key. The secret and session token are zeroized on drop and never
/// printed.
#[derive(Clone)]
pub struct Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl Credentials {
    /// A long-lived key pair.
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: Zeroizing::new(secret_access_key.into()),
            session_token: None,
        }
    }

    /// Adds an STS session token (`x-amz-security-token`).
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(Zeroizing::new(token.into()));
        self
    }

    /// The public key id.
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref().map(String::as_str)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A signing time: `YYYYMMDD` and `YYYYMMDDTHHMMSSZ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmzDate {
    date: String,
    stamp: String,
}

impl AmzDate {
    /// The UTC time `unix` seconds after the epoch.
    pub fn from_unix(unix: u64) -> Self {
        let days = unix / 86_400;
        let secs = unix % 86_400;
        let (y, m, d) = civil_from_days(days);
        let date = format!("{y:04}{m:02}{d:02}");
        let stamp = format!(
            "{date}T{:02}{:02}{:02}Z",
            secs / 3600,
            (secs / 60) % 60,
            secs % 60
        );
        Self { date, stamp }
    }

    /// `YYYYMMDD`.
    pub fn date(&self) -> &str {
        &self.date
    }

    /// `YYYYMMDDTHHMMSSZ`.
    pub fn stamp(&self) -> &str {
        &self.stamp
    }
}

/// Howard Hinnant's `civil_from_days` for days since 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// Where a signature is valid: `<date>/<region>/<service>/aws4_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope<'a> {
    pub region: &'a str,
    pub service: &'a str,
}

impl Scope<'_> {
    fn credential_scope(&self, date: &AmzDate) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            date.date, self.region, self.service
        )
    }
}

/// The parts of a request the signature covers.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    /// The canonical URI: already percent-encoded, starting with `/`.
    pub path: &'a str,
    /// Raw (unencoded) query parameters.
    pub query: &'a [(String, String)],
    /// Headers to sign, including `host` and `x-amz-date`.
    pub headers: &'a [(String, String)],
    /// Hex SHA-256 of the body, or [`UNSIGNED_PAYLOAD`].
    pub payload_hash: &'a str,
}

/// A computed signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// `host;x-amz-date;...`
    pub signed_headers: String,
    /// Hex HMAC.
    pub signature: String,
    /// The full `Authorization` header value.
    pub authorization: String,
}

/// RFC 3986 encoding as SigV4 wants it: every byte but `A-Za-z0-9-_.~`
/// becomes `%XX` (uppercase), and `/` too unless `keep_slash`.
pub fn uri_encode(text: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            b'/' if keep_slash => out.push('/'),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(char::from(HEX[usize::from(b >> 4)]));
                out.push(char::from(HEX[usize::from(b & 15)]));
            }
        }
    }
    out
}

/// The canonical query string; also a valid query string to send.
pub fn canonical_query(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| {
            let value = v.split_whitespace().collect::<Vec<_>>().join(" ");
            (k.to_ascii_lowercase(), value)
        })
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut merged: Vec<(String, String)> = Vec::with_capacity(sorted.len());
    for (k, v) in sorted {
        match merged.last_mut() {
            Some((last, value)) if *last == k => {
                value.push(',');
                value.push_str(&v);
            }
            _ => merged.push((k, v)),
        }
    }
    let canonical = merged.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed = merged
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    (canonical, signed)
}

/// The canonical request, with its signed-header list.
pub fn canonical_request(request: &Request<'_>) -> (String, String) {
    let (headers, signed) = canonical_headers(request.headers);
    let text = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        request.path,
        canonical_query(request.query),
        headers,
        signed,
        request.payload_hash
    );
    (text, signed)
}

/// The string to sign.
pub fn string_to_sign(date: &AmzDate, scope: &Scope<'_>, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{}\n{}\n{}",
        date.stamp,
        scope.credential_scope(date),
        sha256_hex(canonical_request.as_bytes())
    )
}

/// Hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[expect(
    clippy::expect_used,
    reason = "HMAC-SHA256 accepts keys of every length"
)]
fn hmac(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// `kSigning`: the HMAC chain over date, region, service and `aws4_request`.
pub fn signing_key(secret: &str, date: &AmzDate, scope: &Scope<'_>) -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new(String::with_capacity(secret.len() + 4));
    seed.push_str("AWS4");
    seed.push_str(secret);
    let k_date = hmac(seed.as_bytes(), date.date.as_bytes());
    let k_region = hmac(&*k_date, scope.region.as_bytes());
    let k_service = hmac(&*k_region, scope.service.as_bytes());
    hmac(&*k_service, b"aws4_request")
}

/// Signs `request` for the `Authorization` header.
pub fn sign(
    credentials: &Credentials,
    date: &AmzDate,
    scope: &Scope<'_>,
    request: &Request<'_>,
) -> Signature {
    let (canonical, signed_headers) = canonical_request(request);
    let to_sign = string_to_sign(date, scope, &canonical);
    let key = signing_key(&credentials.secret_access_key, date, scope);
    let signature = hex(&*hmac(&*key, to_sign.as_bytes()));
    let authorization = format!(
        "{ALGORITHM} Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
        credentials.access_key_id,
        scope.credential_scope(date)
    );
    Signature {
        signed_headers,
        signature,
        authorization,
    }
}

/// The headers every signed S3 request carries besides its own:
/// `host`, `x-amz-content-sha256`, `x-amz-date` and, for STS keys,
/// `x-amz-security-token`.
pub fn base_headers(
    credentials: &Credentials,
    host: &str,
    date: &AmzDate,
    payload_hash: &str,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("host".to_owned(), host.to_owned()),
        ("x-amz-content-sha256".to_owned(), payload_hash.to_owned()),
        ("x-amz-date".to_owned(), date.stamp.clone()),
    ];
    if let Some(token) = credentials.session_token() {
        headers.push(("x-amz-security-token".to_owned(), token.to_owned()));
    }
    headers
}

/// A presigned `GET`: the query string (already canonical, ending in
/// `X-Amz-Signature`) to append to `https://<host><path>?`.
pub fn presign_get_query(
    credentials: &Credentials,
    date: &AmzDate,
    scope: &Scope<'_>,
    host: &str,
    path: &str,
    expires_secs: u32,
) -> String {
    let mut query = vec![
        ("X-Amz-Algorithm".to_owned(), ALGORITHM.to_owned()),
        (
            "X-Amz-Credential".to_owned(),
            format!(
                "{}/{}",
                credentials.access_key_id,
                scope.credential_scope(date)
            ),
        ),
        ("X-Amz-Date".to_owned(), date.stamp.clone()),
        ("X-Amz-Expires".to_owned(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".to_owned(), "host".to_owned()),
    ];
    if let Some(token) = credentials.session_token() {
        query.push(("X-Amz-Security-Token".to_owned(), token.to_owned()));
    }
    let headers = [("host".to_owned(), host.to_owned())];
    let signature = sign(
        credentials,
        date,
        scope,
        &Request {
            method: "GET",
            path,
            query: &query,
            headers: &headers,
            payload_hash: UNSIGNED_PAYLOAD,
        },
    );
    format!(
        "{}&X-Amz-Signature={}",
        canonical_query(&query),
        signature.signature
    )
}
