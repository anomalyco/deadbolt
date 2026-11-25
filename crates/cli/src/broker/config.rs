//! What `deadbolt run` hands the broker over its inherited pipe: the run's
//! process, and one route per upstream with the real secrets it injects.

use std::collections::HashSet;
use std::fmt;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use super::hygiene;

/// A request body's limit unless a route sets its own: 10 MiB.
pub const DEFAULT_MAX_BODY: usize = 10 * 1024 * 1024;
/// The methods a route without `methods` allows. `CONNECT` and `TRACE`
/// are never allowed.
pub const DEFAULT_METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// One run's broker.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    /// The `deadbolt run` process: only connections from it and its
    /// descendants are served. `None` serves any local caller (tests).
    #[serde(default)]
    pub root_pid: Option<u32>,
    /// Its start time, so a reused pid isn't taken for it.
    #[serde(default)]
    pub root_start: Option<(u64, u64)>,
    pub routes: Vec<BrokerRoute>,
}

/// `http://127.0.0.1:<port>/<alias>/...` goes to `<upstream>/...`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRoute {
    pub alias: String,
    /// `https://host[:port][/base]`; plain `http` only to a loopback host.
    pub upstream: String,
    pub auth: BrokerAuth,
    /// Allowed methods, upper case; empty allows [`DEFAULT_METHODS`].
    #[serde(default)]
    pub methods: Vec<String>,
    /// Paths (after the alias) allowed with everything under them, on
    /// segment boundaries: `/v1` allows `/v1` and `/v1/models`, not
    /// `/v1x`.
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    /// Paths allowed by glob: `*` within a segment, `**` any segments. With
    /// neither prefixes nor globs, every canonical path is allowed.
    #[serde(default)]
    pub path_globs: Vec<String>,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
}

fn default_max_body() -> usize {
    DEFAULT_MAX_BODY
}

fn authorization() -> String {
    "authorization".to_string()
}

/// How a route's requests are authenticated upstream.
#[derive(Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerAuth {
    /// The caller sends the placeholder in `header_name` (`Authorization:
    /// Bearer <placeholder>`, or the bare placeholder in a custom header
    /// such as `x-api-key`); the broker swaps in the token.
    Bearer {
        placeholder: String,
        token: Zeroizing<String>,
        #[serde(default = "authorization")]
        header_name: String,
    },
    /// The caller signs with the placeholder access key (and any secret);
    /// the broker checks the key id, drops the caller's signature and signs
    /// the request again with the real key.
    AwsSigV4 {
        placeholder_access_key: String,
        access_key: Zeroizing<String>,
        secret_key: Zeroizing<String>,
        #[serde(default)]
        session_token: Option<Zeroizing<String>>,
        region: String,
        service: String,
    },
}

impl BrokerAuth {
    /// The real values, for redaction.
    pub fn secrets(&self) -> Vec<&str> {
        match self {
            Self::Bearer { token, .. } => vec![token.as_str()],
            Self::AwsSigV4 {
                access_key,
                secret_key,
                session_token,
                ..
            } => {
                let mut secrets = vec![access_key.as_str(), secret_key.as_str()];
                secrets.extend(session_token.as_deref().map(String::as_str));
                secrets
            }
        }
    }
}

impl fmt::Debug for BrokerAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer { header_name, .. } => f
                .debug_struct("Bearer")
                .field("header_name", header_name)
                .finish_non_exhaustive(),
            Self::AwsSigV4 {
                region, service, ..
            } => f
                .debug_struct("AwsSigV4")
                .field("region", region)
                .field("service", service)
                .finish_non_exhaustive(),
        }
    }
}

/// `https`, or `http` to a loopback host; no credentials, query or
/// fragment of its own.
pub fn upstream_url(text: &str) -> Result<Url> {
    let url = Url::parse(text).map_err(|e| anyhow::anyhow!("upstream {text:?}: {e}"))?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name == "localhost",
        None => false,
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => bail!("upstream {text:?}: use https (plain http only to this computer)"),
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("upstream {text:?}: credentials belong in the route's secret, not its URL");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("upstream {text:?}: no query or fragment");
    }
    hygiene::check_path(url.path())
        .map_err(|why| anyhow::anyhow!("upstream {text:?}: its path is {why}"))?;
    Ok(url)
}

fn token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

impl BrokerConfig {
    /// Refuses a config the broker can't serve safely.
    pub fn validate(&self) -> Result<()> {
        if self.root_pid.is_none() && self.root_start.is_some() {
            bail!("a root start without a root pid");
        }
        if self.routes.is_empty() {
            bail!("no routes");
        }
        let mut aliases = HashSet::new();
        for route in &self.routes {
            let alias = &route.alias;
            if !token(alias) || alias.len() > 64 || alias.starts_with('.') {
                bail!("route {alias:?}: an alias is letters, digits, '-', '_' and '.'");
            }
            if !aliases.insert(alias.as_str()) {
                bail!("route {alias:?} is named twice");
            }
            upstream_url(&route.upstream)?;
            for method in &route.methods {
                if !method.bytes().all(|b| b.is_ascii_uppercase())
                    || method.is_empty()
                    || method == "CONNECT"
                    || method == "TRACE"
                {
                    bail!("route {alias:?}: {method:?} isn't a method it can allow");
                }
            }
            for path in route.path_prefixes.iter().chain(&route.path_globs) {
                let plain = path.replace('*', "x");
                if hygiene::check_path(&plain).is_err() {
                    bail!("route {alias:?}: {path:?} isn't a canonical path");
                }
            }
            if route.max_body_bytes == 0 {
                bail!("route {alias:?}: max_body_bytes is 0");
            }
            match &route.auth {
                BrokerAuth::Bearer {
                    placeholder,
                    token: secret,
                    header_name,
                } => {
                    if placeholder.len() < 16 || !token(placeholder) {
                        bail!("route {alias:?}: the placeholder is too short or not a token");
                    }
                    if secret.is_empty() || secret.as_str() == placeholder {
                        bail!("route {alias:?}: the token is empty or the placeholder");
                    }
                    let name = header_name.to_ascii_lowercase();
                    if !token(&name) || hygiene::is_reserved(&name) {
                        bail!(
                            "route {alias:?}: the broker can't carry a secret in {header_name:?}"
                        );
                    }
                }
                BrokerAuth::AwsSigV4 {
                    placeholder_access_key,
                    access_key,
                    secret_key,
                    region,
                    service,
                    ..
                } => {
                    if placeholder_access_key.len() < 16 || !token(placeholder_access_key) {
                        bail!("route {alias:?}: the placeholder key is too short or not a token");
                    }
                    if access_key.is_empty()
                        || secret_key.is_empty()
                        || access_key.contains('/')
                        || access_key.as_str() == placeholder_access_key
                    {
                        bail!("route {alias:?}: the access key or secret key isn't usable");
                    }
                    if !token(region) || !token(service) {
                        bail!("route {alias:?}: region and service are like us-east-1 and s3");
                    }
                }
            }
        }
        Ok(())
    }
}
