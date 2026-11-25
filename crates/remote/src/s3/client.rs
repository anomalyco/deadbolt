//! [`S3ObjStore`]: the S3 requests of [`S3Config`] sent with reqwest.

use std::collections::BTreeSet;

use reqwest::{Client, Method, RequestBuilder};

use super::{S3Config, SignedRequest, parse_list_objects_v2};
use crate::error::RemoteError;
use crate::http::{self, LIST_BODY, system_clock, unexpected};
use crate::path::validate_prefix;
use crate::store::{ByteRange, ObjStore, PutOutcome, finish_listing};

/// The most `ListObjectsV2` pages one `list` call follows (1,000 keys each).
const MAX_LIST_PAGES: usize = 10_000;
/// The most keys one `list` call collects.
const MAX_LIST_KEYS: usize = 1_000_000;

/// An S3, R2 or MinIO bucket as an [`ObjStore`].
#[derive(Debug, Clone)]
pub struct S3ObjStore {
    config: S3Config,
    client: Client,
    clock: fn() -> u64,
}

impl S3ObjStore {
    /// A store that signs with the system clock. Refuses redirects; an
    /// `https` endpoint never downgrades.
    pub fn new(config: S3Config) -> Result<Self, RemoteError> {
        let client = http::client(!config.is_plaintext())?;
        Ok(Self {
            config,
            client,
            clock: system_clock,
        })
    }

    /// Replaces the signing clock (Unix seconds).
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    /// The configuration.
    pub const fn config(&self) -> &S3Config {
        &self.config
    }

    fn request(
        &self,
        request: SignedRequest,
        body: Option<&[u8]>,
    ) -> Result<RequestBuilder, RemoteError> {
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|e| RemoteError::Config(e.to_string()))?;
        let mut builder = self.client.request(method, &request.url);
        for (k, v) in &request.headers {
            builder = builder.header(k, v);
        }
        if let Some(body) = body {
            builder = builder.body(body.to_vec());
        }
        Ok(builder)
    }
}

impl ObjStore for S3ObjStore {
    async fn put(
        &self,
        name: &str,
        bytes: &[u8],
        create_only: bool,
    ) -> Result<PutOutcome, RemoteError> {
        let request = self
            .config
            .sign_put(name, bytes, create_only, (self.clock)())?;
        let status = http::status(self.request(request, Some(bytes))?, "PUT", name).await?;
        match status {
            200 | 201 | 204 => Ok(PutOutcome::Created),
            412 if create_only => Ok(PutOutcome::AlreadyExists),
            status => Err(unexpected("PUT", name, status)),
        }
    }

    async fn get(
        &self,
        name: &str,
        range: Option<ByteRange>,
    ) -> Result<Option<Vec<u8>>, RemoteError> {
        let request = self.config.sign_get(name, range, (self.clock)())?;
        http::get(self.request(request, None)?, name, range).await
    }

    async fn list(&self, prefix: &str, after: Option<&str>) -> Result<Vec<String>, RemoteError> {
        validate_prefix(prefix)?;
        if let Some(after) = after {
            validate_prefix(after)?;
        }
        let mut names = Vec::new();
        let mut token: Option<String> = None;
        let mut seen_tokens = BTreeSet::new();
        for _ in 0..MAX_LIST_PAGES {
            let request = self
                .config
                .sign_list(prefix, after, token.as_deref(), (self.clock)())?;
            let reply = http::send(self.request(request, None)?, "LIST", prefix, LIST_BODY).await?;
            if reply.status != 200 {
                return Err(unexpected("LIST", prefix, reply.status));
            }
            let body = String::from_utf8(reply.body)
                .map_err(|_| RemoteError::Protocol("listing is not UTF-8".into()))?;
            let page = parse_list_objects_v2(&body)?;
            names.extend(
                page.keys
                    .iter()
                    .filter_map(|key| self.config.name_of_key(key))
                    // A `<root>/` or `dir/` placeholder is not an object.
                    .filter(|name| !name.is_empty() && !name.ends_with('/'))
                    .map(str::to_owned),
            );
            if names.len() > MAX_LIST_KEYS {
                return Err(RemoteError::Protocol("listing has too many keys".into()));
            }
            match page.next_continuation_token {
                Some(next) if page.is_truncated => {
                    if !seen_tokens.insert(next.clone()) {
                        return Err(RemoteError::Protocol(
                            "listing continuation tokens loop".into(),
                        ));
                    }
                    token = Some(next);
                }
                _ => return Ok(finish_listing(names, prefix, after)),
            }
        }
        Err(RemoteError::Protocol("listing has too many pages".into()))
    }

    async fn delete(&self, name: &str) -> Result<(), RemoteError> {
        let request = self.config.sign_delete(name, (self.clock)())?;
        match http::status(self.request(request, None)?, "DELETE", name).await? {
            200 | 202 | 204 | 404 => Ok(()),
            status => Err(unexpected("DELETE", name, status)),
        }
    }
}
