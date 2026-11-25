//! [`WebDavObjStore`]: the four verbs over WebDAV with reqwest.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use reqwest::{Client, Method, RequestBuilder};

use super::{DavAuth, PROPFIND_BODY, WebDavConfig, parent_dirs, parse_multistatus};
use crate::error::RemoteError;
use crate::http::{self, LIST_BODY, unexpected};
use crate::path::{validate_name, validate_prefix};
use crate::store::{ByteRange, ObjStore, PutOutcome, finish_listing};

/// The most `PROPFIND` requests one `list` call makes.
const MAX_PROPFINDS: usize = 10_000;
/// The deepest collection one `list` call descends into, counted in
/// segments from the base (canonical names sit 3 deep).
const MAX_DEPTH: usize = 8;
/// The most entries one `list` call collects.
const MAX_ENTRIES: usize = 1_000_000;

/// A WebDAV collection as an [`ObjStore`].
///
/// `create_only` sends `If-None-Match: *`. A server that ignores it
/// overwrites; the planner's own-stream check before the first push of a
/// session still catches a self-rollback there.
#[derive(Debug, Clone)]
pub struct WebDavObjStore {
    config: WebDavConfig,
    client: Client,
    /// Directories known to exist, so `MKCOL` runs once per directory.
    made: Arc<Mutex<BTreeSet<String>>>,
}

impl WebDavObjStore {
    /// A store that never follows redirects; an `https` base never downgrades.
    pub fn new(config: WebDavConfig) -> Result<Self, RemoteError> {
        let client = http::client(!config.is_plaintext())?;
        Ok(Self {
            config,
            client,
            made: Arc::default(),
        })
    }

    /// The configuration.
    pub const fn config(&self) -> &WebDavConfig {
        &self.config
    }

    fn made(&self) -> MutexGuard<'_, BTreeSet<String>> {
        self.made.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn request(&self, method: Method, name: &str) -> RequestBuilder {
        let builder = self.client.request(method, self.config.url(name));
        match self.config.auth() {
            DavAuth::None => builder,
            DavAuth::Basic { user, password } => builder.basic_auth(user, Some(password.as_str())),
            DavAuth::Bearer(token) => builder.bearer_auth(token.as_str()),
        }
    }

    async fn put_once(
        &self,
        name: &str,
        bytes: &[u8],
        create_only: bool,
    ) -> Result<u16, RemoteError> {
        let mut builder = self.request(Method::PUT, name).body(bytes.to_vec());
        if create_only {
            builder = builder.header("if-none-match", "*");
        }
        http::status(builder, "PUT", name).await
    }

    /// `MKCOL` every missing parent of `name`, outermost first.
    async fn make_parents(&self, name: &str) -> Result<(), RemoteError> {
        for dir in parent_dirs(name) {
            if self.made().contains(dir) {
                continue;
            }
            let method =
                Method::from_bytes(b"MKCOL").map_err(|e| RemoteError::Config(e.to_string()))?;
            match http::status(self.request(method, dir), "MKCOL", dir).await? {
                // 405: it already exists.
                200 | 201 | 204 | 405 => {
                    self.made().insert(dir.to_owned());
                }
                status => return Err(unexpected("MKCOL", dir, status)),
            }
        }
        Ok(())
    }

    /// One `PROPFIND Depth: 1`: the directory's children, or nothing if it
    /// does not exist.
    async fn children(&self, dir: &str) -> Result<Vec<(String, bool)>, RemoteError> {
        let method =
            Method::from_bytes(b"PROPFIND").map_err(|e| RemoteError::Config(e.to_string()))?;
        let builder = self
            .request(method, dir)
            .header("depth", "1")
            .header("content-type", "application/xml; charset=utf-8")
            .body(PROPFIND_BODY);
        let reply = http::send(builder, "PROPFIND", dir, LIST_BODY).await?;
        match reply.status {
            207 => {}
            404 => return Ok(Vec::new()),
            status => return Err(unexpected("PROPFIND", dir, status)),
        }
        let body = String::from_utf8(reply.body)
            .map_err(|_| RemoteError::Protocol("PROPFIND reply is not UTF-8".into()))?;
        let mut out = Vec::new();
        for entry in parse_multistatus(&body)? {
            for href in &entry.hrefs {
                let Some(rel) = self.config.name_of_href(href) else {
                    continue;
                };
                if rel == dir || rel.trim_end_matches('/') == dir.trim_end_matches('/') {
                    continue;
                }
                let is_dir = entry.is_collection || rel.ends_with('/');
                let rel = if is_dir && !rel.ends_with('/') {
                    format!("{rel}/")
                } else {
                    rel
                };
                out.push((rel, is_dir));
            }
        }
        Ok(out)
    }
}

/// True if a directory can hold a name under `prefix` sorting after `after`.
fn worth_visiting(dir: &str, prefix: &str, after: Option<&str>) -> bool {
    let overlaps = dir.starts_with(prefix) || prefix.starts_with(dir);
    // Every name under `dir` sorts before `after` when `after` is greater
    // than `dir` without extending it.
    let passed = after.is_some_and(|a| a > dir && !a.starts_with(dir));
    overlaps && !passed
}

impl ObjStore for WebDavObjStore {
    async fn put(
        &self,
        name: &str,
        bytes: &[u8],
        create_only: bool,
    ) -> Result<PutOutcome, RemoteError> {
        validate_name(name)?;
        let mut status = self.put_once(name, bytes, create_only).await?;
        if matches!(status, 404 | 409) {
            // A parent is missing, even if this session made it once: the
            // tree was wiped or moved under us. Forget it and make it again.
            {
                let mut made = self.made();
                for dir in parent_dirs(name) {
                    made.remove(dir);
                }
            }
            self.make_parents(name).await?;
            status = self.put_once(name, bytes, create_only).await?;
        }
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
        validate_name(name)?;
        let mut builder = self.request(Method::GET, name);
        if let Some(range) = range {
            builder = builder.header("range", range.header());
        }
        http::get(builder, name, range).await
    }

    async fn list(&self, prefix: &str, after: Option<&str>) -> Result<Vec<String>, RemoteError> {
        validate_prefix(prefix)?;
        if let Some(after) = after {
            validate_prefix(after)?;
        }
        let start = prefix.rfind('/').map_or("", |i| &prefix[..=i]);
        let mut queue = VecDeque::from([start.to_owned()]);
        let mut visited = BTreeSet::from([start.to_owned()]);
        let mut names = Vec::new();
        let mut requests = 0;
        while let Some(dir) = queue.pop_front() {
            requests += 1;
            if requests > MAX_PROPFINDS {
                return Err(RemoteError::Protocol(
                    "listing visits too many collections".into(),
                ));
            }
            for (rel, is_dir) in self.children(&dir).await? {
                if is_dir {
                    if rel.len() > dir.len()
                        && rel.starts_with(&dir)
                        && rel.matches('/').count() <= MAX_DEPTH
                        && worth_visiting(&rel, prefix, after)
                        && visited.insert(rel.clone())
                    {
                        queue.push_back(rel);
                    }
                } else {
                    names.push(rel);
                    if names.len() > MAX_ENTRIES {
                        return Err(RemoteError::Protocol("listing has too many entries".into()));
                    }
                }
            }
        }
        Ok(finish_listing(names, prefix, after))
    }

    async fn delete(&self, name: &str) -> Result<(), RemoteError> {
        validate_name(name)?;
        match http::status(self.request(Method::DELETE, name), "DELETE", name).await? {
            200 | 202 | 204 | 404 => Ok(()),
            status => Err(unexpected("DELETE", name, status)),
        }
    }
}
