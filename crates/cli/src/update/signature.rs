//! Release signatures (docs/releasing.md, "Signed releases"): the release
//! workflow signs what it built for each artifact (channel, version and
//! every target's file, size and SHA-256) with an Ed25519 key only its
//! `sign-update` job holds, and publishes the signature as the manifest's
//! [`SIGNATURE_TARGET`]. `update` checks it against the keys pinned in
//! `.github/release/update-keys.txt` before it trusts anything else in the
//! manifest, so the release host alone can't hand out a file Deadbolt's
//! release didn't build.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use data_encoding::BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use url::Url;

use super::protocol::{Target, validated};
use super::service::Service;

/// The manifest target that holds the release's signature.
pub(super) const SIGNATURE_TARGET: &str = "release-signature";
/// The keys a release must be signed with, compiled in.
const PINNED: &str = include_str!("../../../../.github/release/update-keys.txt");
/// Replaces [`PINNED`] in debug builds only, so tests can sign releases with
/// a key of their own.
pub(super) const KEYS_OVERRIDE: &str = "DEADBOLT_UPDATE_KEYS";
/// The largest signature file read.
pub(super) const SIGNATURE_LIMIT: u64 = 64 << 10;

/// The Ed25519 keys a release may be signed with: the current one, and the
/// next during a rotation.
#[derive(Debug)]
pub(super) struct Keys(Vec<VerifyingKey>);

impl Keys {
    /// This build's keys: [`PINNED`], or [`KEYS_OVERRIDE`] in debug builds.
    pub(super) fn pinned() -> Result<Self> {
        match crate::config::test_env(KEYS_OVERRIDE) {
            Some(keys) => Self::parse(&keys.replace(',', "\n")).context(KEYS_OVERRIDE),
            None => Self::parse(PINNED).context("the pinned release keys"),
        }
    }

    /// One base64 Ed25519 public key per line; blank lines and `#` comments
    /// are skipped.
    pub(super) fn parse(text: &str) -> Result<Self> {
        let mut keys = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            keys.push(key(line)?);
        }
        Ok(Self(keys))
    }

    /// Whether no key is pinned: until one is, releases aren't signed and
    /// nothing is checked.
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn key(text: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = BASE64
        .decode(text.as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .with_context(|| format!("{text} is not a base64 Ed25519 public key"))?;
    VerifyingKey::from_bytes(&bytes).with_context(|| format!("{text} is not an Ed25519 public key"))
}

/// The signature file: the statement's exact bytes, and who signed them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: u32,
    /// The signing key, base64, which must be pinned.
    key: String,
    /// The statement, base64: what was signed, byte for byte.
    statement: String,
    /// The Ed25519 signature over the statement's bytes, base64.
    signature: String,
}

/// What the release workflow built and signed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    schema: u32,
    app: String,
    artifact: String,
    channel: String,
    version: String,
    targets: BTreeMap<String, Signed>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Signed {
    file: String,
    size: u64,
    sha256: String,
}

/// Checks `envelope`, a release signature: signed by one of `keys`, for
/// `artifact` on `channel` at `version`, listing exactly `targets` (the
/// manifest's, without its signature), each with its file name, size and
/// SHA-256.
pub(super) fn verify(
    keys: &Keys,
    envelope: &[u8],
    artifact: &str,
    channel: &str,
    version: &str,
    targets: &BTreeMap<String, Target>,
) -> Result<()> {
    let envelope: Envelope =
        serde_json::from_slice(envelope).context("the release signature is malformed")?;
    if envelope.schema != 1 {
        bail!("the release signature has an unknown schema");
    }
    let signer = key(&envelope.key).context("the release signature's key")?;
    if !keys.0.contains(&signer) {
        bail!(
            "the release is signed with {}, which this deadbolt doesn't trust",
            envelope.key
        );
    }
    let decode = |text: &str| BASE64.decode(text.as_bytes()).ok();
    let statement = decode(&envelope.statement).context("the release statement isn't base64")?;
    let signature = decode(&envelope.signature)
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .context("the release signature isn't an Ed25519 signature")?;
    signer
        .verify_strict(&statement, &signature)
        .map_err(|_| anyhow::anyhow!("the release signature doesn't match its statement"))?;

    let signed: Statement =
        serde_json::from_slice(&statement).context("the signed release statement is malformed")?;
    if signed.schema != 1 {
        bail!("the signed release statement has an unknown schema");
    }
    let expected = [
        ("app", signed.app.as_str(), "deadbolt"),
        ("artifact", &signed.artifact, artifact),
        ("channel", &signed.channel, channel),
        ("version", &signed.version, version),
    ];
    for (field, signed, served) in expected {
        if signed != served {
            bail!("the manifest's {field} is {served}, but the signed release's is {signed}");
        }
    }
    let served: BTreeMap<String, Signed> = targets
        .iter()
        .filter(|(name, _)| *name != SIGNATURE_TARGET)
        .map(|(name, target)| {
            let file = target.url.rsplit('/').next().unwrap_or_default();
            let signed = Signed {
                file: file.to_string(),
                size: target.size,
                sha256: target.sha256.clone(),
            };
            (name.clone(), signed)
        })
        .collect();
    if signed.targets != served {
        bail!("the manifest's files aren't the ones the release signed");
    }
    Ok(())
}

/// Checks the manifest `text`, read from `url`, is a release signed with a
/// pinned key, before anything in it (its sequence included) is trusted.
/// Builds that pin no key check nothing.
pub(super) async fn authenticate(
    service: &Service,
    url: &Url,
    text: &str,
    artifact: &str,
    channel: &str,
) -> Result<()> {
    let keys = Keys::pinned()?;
    if keys.is_empty() {
        return Ok(());
    }
    let manifest = validated(artifact, channel, text).map_err(|reason| {
        anyhow::anyhow!("{url} is not a usable {artifact} manifest ({reason})")
    })?;
    let Some(signature) = manifest.target(SIGNATURE_TARGET) else {
        bail!(
            "{url} is not signed (it has no {SIGNATURE_TARGET}); deadbolt installs only \
             releases signed by Deadbolt's release workflow"
        );
    };
    if signature.size > SIGNATURE_LIMIT {
        bail!("{url}'s {SIGNATURE_TARGET} is too large");
    }
    let bytes = service.fetch(url, signature).await?;
    verify(
        &keys,
        &bytes,
        artifact,
        channel,
        manifest.version(),
        manifest.targets(),
    )
    .with_context(|| format!("checking {url}'s release signature"))
}

#[cfg(test)]
#[path = "signature_tests.rs"]
mod signature_tests;
