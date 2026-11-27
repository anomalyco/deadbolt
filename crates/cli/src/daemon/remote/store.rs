//! The configured store: S3 or WebDAV over HTTPS (and, in tests, an
//! in-memory store named by a `mem.test` URL, faults on cue).

use anyhow::{Result, bail};
use deadbolt_proto::daemon::RemoteInput;
use deadbolt_remote::{
    Addressing, ByteRange, DavAuth, ObjStore, PutOutcome, RemoteError, S3Config, S3ObjStore,
    WebDavConfig, WebDavObjStore, sigv4::Credentials,
};

/// One vault's store.
pub(in crate::daemon) enum Remote {
    S3(S3ObjStore),
    Dav(WebDavObjStore),
    #[cfg(test)]
    Mem(deadbolt_remote::FaultyObjStore),
}

impl Remote {
    /// The store `input` names, its credentials moved into the client.
    pub fn open(input: &RemoteInput) -> Result<Self> {
        match input {
            RemoteInput::S3 {
                endpoint,
                bucket,
                region,
                prefix,
                path_style,
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                let mut credentials =
                    Credentials::new(access_key_id.expose(), secret_access_key.expose());
                if let Some(token) = session_token {
                    credentials = credentials.with_session_token(token.expose());
                }
                let addressing = if *path_style {
                    Addressing::Path
                } else {
                    Addressing::VirtualHost
                };
                let config =
                    S3Config::new(endpoint, bucket, region, prefix, addressing, credentials)?;
                if config.is_plaintext() {
                    bail!(
                        "refusing a plaintext http:// endpoint: credentials would cross the network in the clear"
                    );
                }
                Ok(Self::S3(S3ObjStore::new(config)?))
            }
            RemoteInput::Webdav {
                url,
                username,
                password,
            } => {
                #[cfg(test)]
                if let Some(store) = tests::named(url) {
                    return Ok(Self::Mem(store));
                }
                let auth = match (username, password) {
                    (Some(user), Some(password)) => DavAuth::Basic {
                        user: user.clone(),
                        password: zeroize::Zeroizing::new(password.expose().to_owned()),
                    },
                    (None, Some(token)) => {
                        DavAuth::Bearer(zeroize::Zeroizing::new(token.expose().to_owned()))
                    }
                    (Some(_), None) => bail!(
                        "WebDAV username requires a password (set DEADBOLT_WEBDAV_PASSWORD or use --credentials-stdin)"
                    ),
                    (None, None) => DavAuth::None,
                };
                let config = WebDavConfig::new(url, auth)?;
                if config.is_plaintext() {
                    bail!("refusing a plaintext http:// WebDAV URL");
                }
                Ok(Self::Dav(WebDavObjStore::new(config)?))
            }
        }
    }
}

macro_rules! each {
    ($self:ident, $s:ident => $call:expr) => {
        match $self {
            Remote::S3($s) => $call.await,
            Remote::Dav($s) => $call.await,
            #[cfg(test)]
            Remote::Mem($s) => $call.await,
        }
    };
}

impl ObjStore for Remote {
    async fn put(
        &self,
        name: &str,
        bytes: &[u8],
        create_only: bool,
    ) -> Result<PutOutcome, RemoteError> {
        each!(self, s => s.put(name, bytes, create_only))
    }

    async fn get(
        &self,
        name: &str,
        range: Option<ByteRange>,
    ) -> Result<Option<Vec<u8>>, RemoteError> {
        each!(self, s => s.get(name, range))
    }

    async fn list(&self, prefix: &str, after: Option<&str>) -> Result<Vec<String>, RemoteError> {
        each!(self, s => s.list(prefix, after))
    }

    async fn delete(&self, name: &str) -> Result<(), RemoteError> {
        each!(self, s => s.delete(name))
    }
}

#[cfg(test)]
pub(in crate::daemon) mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use deadbolt_remote::FaultyObjStore;

    static STORES: Mutex<BTreeMap<String, FaultyObjStore>> = Mutex::new(BTreeMap::new());

    #[test]
    fn a_webdav_username_requires_a_password() {
        let input = deadbolt_proto::daemon::RemoteInput::Webdav {
            url: "https://example.com/vault/".into(),
            username: Some("alice".into()),
            password: None,
        };
        let error = super::Remote::open(&input).err().expect("missing password");
        assert!(
            error
                .to_string()
                .contains("WebDAV username requires a password")
        );
    }

    /// A WebDAV URL `http://mem.test/<name>/` that opens a shared
    /// in-memory store.
    pub fn url(name: &str) -> String {
        format!("http://mem.test/{name}/")
    }

    /// The store `url(name)` opens, to set its faults.
    pub fn faulty(name: &str) -> FaultyObjStore {
        named(&url(name)).expect("a mem.test URL")
    }

    pub(super) fn named(url: &str) -> Option<FaultyObjStore> {
        url.strip_prefix("http://mem.test/")?;
        let mut stores = STORES.lock().unwrap_or_else(|e| e.into_inner());
        Some(stores.entry(url.to_owned()).or_default().clone())
    }
}
