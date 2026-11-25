//! WebDAV stores (Nextcloud, Fastmail, SabreDAV, Apache, nginx):
//! configuration, href handling and `PROPFIND` parsing, all pure.
//! [`WebDavObjStore`] speaks to the server behind the `http` feature.

#[cfg(feature = "http")]
mod client;
mod propfind;

#[cfg(feature = "http")]
pub use client::WebDavObjStore;
pub use propfind::{DavEntry, PROPFIND_BODY, parse_multistatus};

use std::fmt;

use url::Url;
use zeroize::Zeroizing;

use crate::error::RemoteError;
use crate::path::validate_name;

/// How requests authenticate. Secrets are zeroized on drop and never printed.
#[derive(Clone)]
pub enum DavAuth {
    /// No `Authorization` header.
    None,
    /// HTTP Basic, usually an app password.
    Basic {
        user: String,
        password: Zeroizing<String>,
    },
    /// `Authorization: Bearer <token>`.
    Bearer(Zeroizing<String>),
}

impl fmt::Debug for DavAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Basic { user, .. } => f
                .debug_struct("Basic")
                .field("user", user)
                .field("password", &"<redacted>")
                .finish(),
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
        }
    }
}

/// A WebDAV collection every object name is placed under.
#[derive(Debug, Clone)]
pub struct WebDavConfig {
    base: Url,
    base_path: String,
    auth: DavAuth,
}

impl WebDavConfig {
    /// `base` is the collection URL, such as
    /// `https://cloud.example.com/remote.php/dav/files/alex/deadbolt/`.
    pub fn new(base: &str, auth: DavAuth) -> Result<Self, RemoteError> {
        let mut base = Url::parse(base).map_err(|e| RemoteError::Config(e.to_string()))?;
        if !matches!(base.scheme(), "https" | "http") || base.host_str().is_none() {
            return Err(RemoteError::Config(
                "WebDAV base must be an http(s) URL".into(),
            ));
        }
        if base.query().is_some()
            || base.fragment().is_some()
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err(RemoteError::Config(
                "WebDAV base may not carry a query, fragment or credentials".into(),
            ));
        }
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        let base_path = percent_decode(base.path())
            .ok_or_else(|| RemoteError::Config("WebDAV base path is not UTF-8".into()))?;
        Ok(Self {
            base,
            base_path,
            auth,
        })
    }

    /// The collection URL, ending in `/`.
    pub const fn base(&self) -> &Url {
        &self.base
    }

    /// The credentials.
    pub const fn auth(&self) -> &DavAuth {
        &self.auth
    }

    /// True for a plain `http://` base (tests, a LAN server).
    pub fn is_plaintext(&self) -> bool {
        self.base.scheme() == "http"
    }

    /// The URL of a name or of a directory (`a/b/`). Canonical names need
    /// no escaping.
    pub fn url(&self, name: &str) -> String {
        format!("{}{name}", self.base)
    }

    /// The name an `href` from a `PROPFIND` reply refers to, relative to
    /// the base; directories keep their trailing `/` and the base itself is
    /// `""`. `None` for anything outside the base or not a valid name.
    pub fn name_of_href(&self, href: &str) -> Option<String> {
        let href = href.trim();
        let absolute = |scheme: &str| {
            href.get(..scheme.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
        };
        let path = if absolute("http://") || absolute("https://") {
            let url = Url::parse(href).ok()?;
            if url.scheme() != self.base.scheme()
                || url.host_str() != self.base.host_str()
                || url.port_or_known_default() != self.base.port_or_known_default()
            {
                return None;
            }
            url.path().to_owned()
        } else if href.starts_with('/') {
            href.split(['?', '#']).next()?.to_owned()
        } else {
            return None;
        };
        let path = percent_decode(&path)?;
        let rel = path
            .strip_prefix(&self.base_path)
            .or_else(|| (path.as_str() == self.base_path.trim_end_matches('/')).then_some(""))?;
        if rel.is_empty() {
            return Some(String::new());
        }
        // One trailing slash marks a collection; `a//` is no name at all.
        validate_name(rel.strip_suffix('/').unwrap_or(rel)).ok()?;
        Some(rel.to_owned())
    }
}

/// Every directory a name sits in, outermost first: `a/b/c` gives `a/`, `a/b/`.
pub fn parent_dirs(name: &str) -> Vec<&str> {
    name.match_indices('/').map(|(i, _)| &name[..=i]).collect()
}

/// Decodes `%XX` escapes; `None` for a bad escape or non-UTF-8 result.
pub(crate) fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = char::from(*bytes.get(i + 1)?).to_digit(16)?;
            let lo = char::from(*bytes.get(i + 2)?).to_digit(16)?;
            out.push(u8::try_from(hi * 16 + lo).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}
