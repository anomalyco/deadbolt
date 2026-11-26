//! S3-compatible stores (AWS S3, Cloudflare R2, MinIO): configuration and
//! the signed requests for the four verbs, all pure. [`S3ObjStore`] sends
//! them with reqwest behind the `http` feature.

#[cfg(feature = "http")]
mod client;
mod list;

#[cfg(feature = "http")]
pub use client::S3ObjStore;
pub use list::{ListPage, parse_list_objects_v2};

use url::{Host, Url};

use crate::error::RemoteError;
use crate::path::{validate_name, validate_prefix};
use crate::sigv4::{self, AmzDate, Credentials, EMPTY_SHA256, Scope, sha256_hex, uri_encode};
use crate::store::ByteRange;

/// S3's limit on a whole object key, root included.
pub const MAX_KEY_LEN: usize = 1024;

/// How the bucket appears in URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addressing {
    /// `https://endpoint/<bucket>/<key>`: MinIO, R2, and any IP endpoint.
    Path,
    /// `https://<bucket>.endpoint/<key>`: AWS's default. Not for an IP
    /// endpoint, nor for a dotted bucket over `https` (its name would not
    /// match the wildcard certificate).
    VirtualHost,
}

/// An S3 bucket (or a folder in one) and the key that writes to it.
#[derive(Debug, Clone)]
pub struct S3Config {
    endpoint: Url,
    bucket: String,
    region: String,
    root: String,
    addressing: Addressing,
    credentials: Credentials,
}

/// A request ready to send: method, full URL and every header but `host`
/// (which the HTTP client derives from the URL exactly as signed).
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// Never prints the signature, the session token or the URL's query.
impl std::fmt::Debug for SignedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self
            .url
            .split_once('?')
            .map_or(self.url.as_str(), |(path, _)| path);
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| {
                let secret = name.eq_ignore_ascii_case("authorization")
                    || name.eq_ignore_ascii_case("x-amz-security-token");
                (
                    name.as_str(),
                    if secret { "<redacted>" } else { value.as_str() },
                )
            })
            .collect();
        f.debug_struct("SignedRequest")
            .field("method", &self.method)
            .field("url", &url)
            .field("headers", &headers)
            .finish()
    }
}

impl S3Config {
    /// `endpoint` is the service URL without the bucket, such as
    /// `https://<account>.r2.cloudflarestorage.com` (region `auto`) or
    /// `https://s3.eu-west-1.amazonaws.com`. `root` is an optional folder
    /// inside the bucket every object name is placed under.
    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        root: &str,
        addressing: Addressing,
        credentials: Credentials,
    ) -> Result<Self, RemoteError> {
        let endpoint = Url::parse(endpoint).map_err(|e| RemoteError::Config(e.to_string()))?;
        if !matches!(endpoint.scheme(), "https" | "http") || endpoint.host_str().is_none() {
            return Err(RemoteError::Config(
                "endpoint must be an http(s) URL".into(),
            ));
        }
        if endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(RemoteError::Config(
                "endpoint may not carry a query, fragment or credentials".into(),
            ));
        }
        if endpoint.path() != "/" {
            return Err(RemoteError::Config(
                "endpoint may not have a path; set root instead".into(),
            ));
        }
        let bucket_ok = (3..=63).contains(&bucket.len())
            && bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
        if !bucket_ok {
            return Err(RemoteError::Config(
                "bucket name is not a valid S3 bucket name".into(),
            ));
        }
        if region.is_empty()
            || !region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(RemoteError::Config(
                "region must be like us-east-1 or auto".into(),
            ));
        }
        if addressing == Addressing::VirtualHost {
            if matches!(endpoint.host(), Some(Host::Ipv4(_) | Host::Ipv6(_))) {
                return Err(RemoteError::Config(
                    "an IP endpoint needs path-style addressing".into(),
                ));
            }
            if endpoint.scheme() == "https" && bucket.contains('.') {
                return Err(RemoteError::Config(
                    "a dotted bucket over https needs path-style addressing".into(),
                ));
            }
        }
        let root = root.trim_matches('/');
        if !root.is_empty() {
            validate_name(root)?;
        }
        Ok(Self {
            endpoint,
            bucket: bucket.to_owned(),
            region: region.to_owned(),
            root: root.to_owned(),
            addressing,
            credentials,
        })
    }

    /// The endpoint URL.
    pub const fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// True for a plain `http://` endpoint (local MinIO, tests).
    pub fn is_plaintext(&self) -> bool {
        self.endpoint.scheme() == "http"
    }

    fn scope(&self) -> Scope<'_> {
        Scope {
            region: &self.region,
            service: "s3",
        }
    }

    /// `host[:port]` as the HTTP client will send it.
    fn host(&self) -> String {
        let host = self.endpoint.host_str().unwrap_or_default();
        let host = match self.addressing {
            Addressing::Path => host.to_owned(),
            Addressing::VirtualHost => format!("{}.{host}", self.bucket),
        };
        match self.endpoint.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }

    fn origin(&self) -> String {
        format!("{}://{}", self.endpoint.scheme(), self.host())
    }

    /// The object key for a name or prefix: `<root>/<name>`, at most
    /// [`MAX_KEY_LEN`] bytes.
    fn key(&self, name: &str) -> Result<String, RemoteError> {
        let key = if self.root.is_empty() {
            name.to_owned()
        } else {
            format!("{}/{name}", self.root)
        };
        if key.len() > MAX_KEY_LEN {
            return Err(RemoteError::Config(format!(
                "S3 key longer than {MAX_KEY_LEN} bytes; shorten the root"
            )));
        }
        Ok(key)
    }

    /// The name for a listed key, if it lies under the root.
    pub fn name_of_key<'a>(&self, key: &'a str) -> Option<&'a str> {
        if self.root.is_empty() {
            Some(key)
        } else {
            key.strip_prefix(&self.root)?.strip_prefix('/')
        }
    }

    /// The canonical (and sent) path of an object, or of the bucket for `None`.
    fn path(&self, key: Option<&str>) -> String {
        let bucket = match self.addressing {
            Addressing::Path => format!("/{}", uri_encode(&self.bucket, false)),
            Addressing::VirtualHost => String::new(),
        };
        match key {
            Some(key) => format!("{bucket}/{}", uri_encode(key, true)),
            None if bucket.is_empty() => "/".to_owned(),
            None => bucket,
        }
    }

    fn signed(
        &self,
        method: &'static str,
        key: Option<&str>,
        query: &[(String, String)],
        extra: Vec<(String, String)>,
        payload_hash: &str,
        unix_now: u64,
    ) -> SignedRequest {
        let date = AmzDate::from_unix(unix_now);
        let host = self.host();
        let path = self.path(key);
        let mut headers = sigv4::base_headers(&self.credentials, &host, &date, payload_hash);
        headers.extend(extra);
        let signature = sigv4::sign(
            &self.credentials,
            &date,
            &self.scope(),
            &sigv4::Request {
                method,
                path: &path,
                query,
                headers: &headers,
                payload_hash,
            },
        );
        headers.retain(|(k, _)| k != "host");
        headers.push(("authorization".to_owned(), signature.authorization));
        let mut url = format!("{}{path}", self.origin());
        if !query.is_empty() {
            url.push('?');
            url.push_str(&sigv4::canonical_query(query));
        }
        SignedRequest {
            method,
            url,
            headers,
        }
    }

    /// `PUT`, with `If-None-Match: *` when `create_only`.
    pub fn sign_put(
        &self,
        name: &str,
        body: &[u8],
        create_only: bool,
        unix_now: u64,
    ) -> Result<SignedRequest, RemoteError> {
        validate_name(name)?;
        let extra = if create_only {
            vec![("if-none-match".to_owned(), "*".to_owned())]
        } else {
            Vec::new()
        };
        let key = self.key(name)?;
        Ok(self.signed("PUT", Some(&key), &[], extra, &sha256_hex(body), unix_now))
    }

    /// `GET`, with `Range` when given.
    pub fn sign_get(
        &self,
        name: &str,
        range: Option<ByteRange>,
        unix_now: u64,
    ) -> Result<SignedRequest, RemoteError> {
        validate_name(name)?;
        let extra = range
            .map(|r| vec![("range".to_owned(), r.header())])
            .unwrap_or_default();
        let key = self.key(name)?;
        Ok(self.signed("GET", Some(&key), &[], extra, EMPTY_SHA256, unix_now))
    }

    /// One `ListObjectsV2` page, keys URL-encoded. `start_after` is sent
    /// only on the first page: the continuation token carries it after.
    pub fn sign_list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        continuation: Option<&str>,
        unix_now: u64,
    ) -> Result<SignedRequest, RemoteError> {
        validate_prefix(prefix)?;
        let mut query: Vec<(String, String)> = vec![
            ("encoding-type".to_owned(), "url".to_owned()),
            ("list-type".to_owned(), "2".to_owned()),
            ("prefix".to_owned(), self.key(prefix)?),
        ];
        match (continuation, start_after) {
            (Some(token), _) => {
                query.push(("continuation-token".to_owned(), token.to_owned()));
            }
            (None, Some(after)) => {
                validate_prefix(after)?;
                query.push(("start-after".to_owned(), self.key(after)?));
            }
            (None, None) => {}
        }
        Ok(self.signed("GET", None, &query, Vec::new(), EMPTY_SHA256, unix_now))
    }

    /// `DELETE`.
    pub fn sign_delete(&self, name: &str, unix_now: u64) -> Result<SignedRequest, RemoteError> {
        validate_name(name)?;
        let key = self.key(name)?;
        Ok(self.signed(
            "DELETE",
            Some(&key),
            &[],
            Vec::new(),
            EMPTY_SHA256,
            unix_now,
        ))
    }

    /// A presigned `GET` URL valid for `expires_secs` (at most 7 days), for
    /// store-backed Send links that a browser opens with no credentials.
    pub fn presign_get(
        &self,
        name: &str,
        unix_now: u64,
        expires_secs: u32,
    ) -> Result<String, RemoteError> {
        validate_name(name)?;
        if !(1..=604_800).contains(&expires_secs) {
            return Err(RemoteError::Config(
                "presigned URLs last 1 s to 7 days".into(),
            ));
        }
        let path = self.path(Some(&self.key(name)?));
        let query = sigv4::presign_get_query(
            &self.credentials,
            &AmzDate::from_unix(unix_now),
            &self.scope(),
            &self.host(),
            &path,
            expires_secs,
        );
        Ok(format!("{}{path}?{query}", self.origin()))
    }
}
