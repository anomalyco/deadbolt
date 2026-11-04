//! The release service and the npm registry: where an update is read from,
//! and what it reads.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use url::Url;

use super::method::PACKAGE;
use super::protocol::{Target, VERSION};

/// Where the release service lives.
pub(super) const SERVICE: &str = "https://anoma.ly/release/";
/// Overrides [`SERVICE`] in debug builds only, and only with a loopback
/// URL, so tests can serve a fake release and no environment can send a
/// release build anywhere else.
pub(super) const SERVICE_OVERRIDE: &str = "DEADBOLT_RELEASE_URL";
/// The npm registry, which says what npm, pnpm, bun and yarn can install.
const REGISTRY: &str = "https://registry.npmjs.org/";
/// Overrides [`REGISTRY`] as [`SERVICE_OVERRIDE`] does the service.
const REGISTRY_OVERRIDE: &str = "DEADBOLT_NPM_REGISTRY_URL";

/// The largest manifest read.
const MANIFEST_LIMIT: usize = 1 << 20;

pub(super) struct Service {
    base: Url,
    registry: Url,
    client: reqwest::Client,
}

impl Service {
    pub(super) fn new(channel: Option<&str>) -> Result<Self> {
        let env = |name| crate::config::env(name).ok();
        let base = loopback_or(SERVICE, SERVICE_OVERRIDE, env(SERVICE_OVERRIDE).as_deref())?;
        let registry = loopback_or(
            REGISTRY,
            REGISTRY_OVERRIDE,
            env(REGISTRY_OVERRIDE).as_deref(),
        )?;
        // reqwest takes the process's rustls provider; Deadbolt's is ring.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let user_agent = format!("deadbolt/{}/{VERSION}/cli", channel.unwrap_or("source"));
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .https_only(base.scheme() == "https" && registry.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(60))
            .build()
            .context("setting up HTTPS")?;
        Ok(Self {
            base,
            registry,
            client,
        })
    }

    fn manifest_url(&self, artifact: &str, channel: &str) -> Result<Url> {
        Ok(self
            .base
            .join(&format!("deadbolt/{artifact}/{channel}.json"))?)
    }

    /// The manifest's URL and text; `None` when the channel has no release
    /// of `artifact`.
    pub(super) async fn manifest(
        &self,
        artifact: &str,
        channel: &str,
    ) -> Result<Option<(Url, String)>> {
        let url = self.manifest_url(artifact, channel)?;
        Ok(self.small(&url).await?.map(|text| (url, text)))
    }

    /// The version npm serves for `channel` (its dist-tag: `latest` for
    /// stable), which is all npm, pnpm, bun and yarn can install.
    pub(super) async fn npm_version(&self, channel: &str) -> Result<Option<String>> {
        let url = self
            .registry
            .join(&format!("-/package/{PACKAGE}/dist-tags"))?;
        let tag = if channel == "stable" {
            "latest"
        } else {
            channel
        };
        let Some(text) = self.small(&url).await? else {
            return Ok(None);
        };
        let tags: BTreeMap<String, serde_json::Value> =
            serde_json::from_str(&text).with_context(|| format!("reading {url}"))?;
        Ok(tags.get(tag).and_then(|v| v.as_str()).map(str::to_string))
    }

    /// Whether the registry serves `name` at `version`
    /// (`<registry>/<name>/<version>`). Large platform packages show up
    /// minutes after the small `@deadbolt/cli` that needs them.
    pub(super) async fn npm_has(&self, name: &str, version: &str) -> Result<bool> {
        let url = self.registry.join(&format!("{name}/{version}"))?;
        let Some(text) = self.small(&url).await? else {
            return Ok(false);
        };
        let package: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("reading {url}"))?;
        Ok(package.get("version").and_then(|v| v.as_str()) == Some(version))
    }

    /// A small document's text, as manifests are read: `None` on 404.
    async fn small(&self, url: &Url) -> Result<Option<String>> {
        let fetch = async {
            let mut response = self.client.get(url.clone()).send().await?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !response.status().is_success() {
                bail!("the service answered {}", response.status());
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                body.extend_from_slice(&chunk);
                if body.len() > MANIFEST_LIMIT {
                    bail!("it is too large for a manifest");
                }
            }
            Ok(Some(String::from_utf8(body).context("it is not UTF-8")?))
        };
        tokio::time::timeout(Duration::from_secs(30), fetch)
            .await
            .with_context(|| format!("no answer from {url}"))?
            .with_context(|| format!("fetching {url}"))
    }

    /// Downloads `target`, listed in the manifest at `manifest`, to `file`,
    /// failing unless its size and SHA-256 are the manifest's.
    pub(super) async fn download(
        &self,
        manifest: &Url,
        target: &Target,
        file: &Path,
    ) -> Result<()> {
        use std::io::Write;
        let url = file_url(manifest, &target.url)?;
        let fetch = async {
            let mut response = self.client.get(url.clone()).send().await?;
            if !response.status().is_success() {
                bail!("the service answered {}", response.status());
            }
            if response.content_length().is_some_and(|n| n != target.size) {
                bail!("it is not the size the manifest says");
            }
            let mut out = std::fs::File::create(file)
                .with_context(|| format!("creating {}", file.display()))?;
            let mut hash = Sha256::new();
            let mut size = 0u64;
            while let Some(chunk) = response.chunk().await? {
                size += chunk.len() as u64;
                if size > target.size {
                    bail!("it is larger than the manifest says");
                }
                hash.update(&chunk);
                out.write_all(&chunk)?;
            }
            out.sync_all()?;
            if size != target.size {
                bail!(
                    "it is {size} bytes, not the {} the manifest says",
                    target.size
                );
            }
            let sha256 = HEXLOWER.encode(&hash.finalize());
            if sha256 != target.sha256 {
                bail!(
                    "its SHA-256 is {sha256}, not the manifest's {}",
                    target.sha256
                );
            }
            Ok(())
        };
        tokio::time::timeout(Duration::from_secs(30 * 60), fetch)
            .await
            .with_context(|| format!("downloading {url} took too long"))?
            .with_context(|| format!("downloading {url}"))
    }
}

/// A base URL: `default`, or in debug builds `over` (from the variable
/// `var`) on 127.0.0.1 or [::1].
pub(super) fn loopback_or(default: &str, var: &str, over: Option<&str>) -> Result<Url> {
    let Some(over) = over.filter(|o| cfg!(debug_assertions) && !o.is_empty()) else {
        return Ok(Url::parse(default)?);
    };
    let mut url = Url::parse(over).with_context(|| format!("{var} {over}"))?;
    let loopback = matches!(
        url.host(),
        Some(url::Host::Ipv4(ip)) if ip.is_loopback()
    ) || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    if !loopback || !matches!(url.scheme(), "http" | "https") {
        bail!("{var} must be a URL on 127.0.0.1 or [::1]");
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}

/// A target's file URL, resolved against its manifest's URL: only Deadbolt's
/// files on the service that served the manifest.
pub(super) fn file_url(manifest: &Url, reference: &str) -> Result<Url> {
    let url = manifest.join(reference)?;
    let files = manifest.join("../files/")?;
    if url.origin() != manifest.origin()
        || !url.path().starts_with(files.path())
        || url.query().is_some()
    {
        bail!("the manifest points outside Deadbolt's releases: {url}");
    }
    Ok(url)
}
