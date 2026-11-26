//! `deadbolt run --broker`'s side: its `--route`s, the placeholders the
//! command gets in their place, and starting the broker.
//!
//! `--route ALIAS=URL[,KEY=VALUE...]`, keys:
//!
//! | key | meaning |
//! |---|---|
//! | `bearer=REF` | the token; the caller sends `Authorization: Bearer <placeholder>` |
//! | `header=NAME` | carry it in this header, bare (`x-api-key`) |
//! | `env=NAME` | the variable that holds the placeholder (bearer) |
//! | `sigv4=REGION/SERVICE` | AWS SigV4; with `access-key=REF`, `secret-key=REF` and maybe `session-token=REF` |
//! | `base-env=NAME` | the variable that holds `http://127.0.0.1:<port>/<alias>` (SigV4: `AWS_ENDPOINT_URL`) |
//! | `method=M`, `prefix=P`, `glob=G` | the scope, each repeatable |
//! | `max-body=BYTES` | the request body limit (10 MiB) |

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use super::config::{BrokerAuth, BrokerConfig, BrokerRoute, DEFAULT_MAX_BODY, upstream_url};
use crate::protocol::{Reference, ResolvedSecret, SCHEME};
use deadbolt_client::peer::ancestry::{OsProcesses, ProcessFacts};

/// The variable every brokered command gets: `http://127.0.0.1:<port>`.
pub const BROKER_URL: &str = "DEADBOLT_BROKER_URL";
/// How long the broker has to say it's listening.
const READY: Duration = Duration::from_secs(10);

enum Auth {
    Bearer {
        token: String,
        header: Option<String>,
    },
    SigV4 {
        region: String,
        service: String,
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
    },
}

/// One `--route`, with the placeholders the command gets for it.
pub struct RouteSpec {
    alias: String,
    upstream: String,
    auth: Auth,
    env: Option<String>,
    base_env: Option<String>,
    methods: Vec<String>,
    prefixes: Vec<String>,
    globs: Vec<String>,
    max_body: usize,
    placeholder: String,
    /// SigV4: the secret key the caller signs with.
    placeholder_secret: String,
}

/// `db_ph_<32 hex>`, fresh.
pub fn placeholder() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("drawing a placeholder: {e}"))?;
    Ok(format!("db_ph_{}", data_encoding::HEXLOWER.encode(&bytes)))
}

fn reference(key: &str, value: &str) -> Result<String> {
    if !value.trim_start().starts_with(SCHEME) {
        bail!("{key}= takes a deadbolt:// reference");
    }
    Ok(Reference::parse(value)
        .map_err(|e| anyhow!("{key}=: {e}"))?
        .to_string())
}

fn variable(key: &str, name: &str) -> Result<String> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        bail!("{key}={name:?} isn't an environment variable name");
    }
    Ok(name.to_string())
}

impl RouteSpec {
    pub fn parse(text: &str) -> Result<Self> {
        let mut parts = text.split(',');
        let (alias, upstream) = parts
            .next()
            .and_then(|first| first.split_once('='))
            .context("--route takes ALIAS=URL[,KEY=VALUE...]")?;
        upstream_url(upstream)?;
        let (mut bearer, mut header, mut env, mut base_env, mut sigv4) =
            (None, None, None, None, None);
        let (mut access_key, mut secret_key, mut session_token) = (None, None, None);
        let (mut methods, mut prefixes, mut globs) = (Vec::new(), Vec::new(), Vec::new());
        let mut max_body = DEFAULT_MAX_BODY;
        for part in parts {
            let (key, value) = part
                .split_once('=')
                .with_context(|| format!("--route {alias}: {part:?} isn't KEY=VALUE"))?;
            match key {
                "bearer" => bearer = Some(reference(key, value)?),
                "header" => header = Some(value.to_ascii_lowercase()),
                "env" => env = Some(variable(key, value)?),
                "base-env" => base_env = Some(variable(key, value)?),
                "sigv4" => {
                    let (region, service) = value
                        .split_once('/')
                        .context("sigv4= takes REGION/SERVICE, like us-east-1/s3")?;
                    sigv4 = Some((region.to_string(), service.to_string()));
                }
                "access-key" => access_key = Some(reference(key, value)?),
                "secret-key" => secret_key = Some(reference(key, value)?),
                "session-token" => session_token = Some(reference(key, value)?),
                "method" => methods.push(value.to_ascii_uppercase()),
                "prefix" => prefixes.push(value.to_string()),
                "glob" => globs.push(value.to_string()),
                "max-body" => {
                    max_body = value
                        .parse()
                        .with_context(|| format!("--route {alias}: max-body={value:?}"))?;
                }
                _ => bail!("--route {alias}: no key {key:?}"),
            }
        }
        let auth = match (bearer, sigv4) {
            (Some(token), None) => {
                if access_key.is_some() || secret_key.is_some() || session_token.is_some() {
                    bail!(
                        "--route {alias}: access-key, secret-key and session-token go with sigv4="
                    );
                }
                if env.is_none() {
                    bail!("--route {alias}: name the placeholder's variable with env=NAME");
                }
                Auth::Bearer { token, header }
            }
            (None, Some((region, service))) => {
                let (Some(access_key), Some(secret_key)) = (access_key, secret_key) else {
                    bail!("--route {alias}: sigv4= needs access-key=REF and secret-key=REF");
                };
                if header.is_some() || env.is_some() {
                    bail!(
                        "--route {alias}: a sigv4 route sets AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
                    );
                }
                Auth::SigV4 {
                    region,
                    service,
                    access_key,
                    secret_key,
                    session_token,
                }
            }
            _ => bail!("--route {alias}: give one of bearer=REF or sigv4=REGION/SERVICE"),
        };
        let spec = Self {
            alias: alias.to_string(),
            upstream: upstream.to_string(),
            auth,
            env,
            base_env,
            methods,
            prefixes,
            globs,
            max_body,
            placeholder: placeholder()?,
            placeholder_secret: placeholder()?,
        };
        // The broker's own checks, before anything is resolved.
        let mut dry = spec.route(|_| Some(Zeroizing::new("x".repeat(40))))?;
        if let BrokerAuth::AwsSigV4 { access_key, .. } = &mut dry.auth {
            *access_key = Zeroizing::new("AKIDEXAMPLE".to_string());
        }
        BrokerConfig {
            root_pid: None,
            root_start: None,
            routes: vec![dry],
        }
        .validate()?;
        Ok(spec)
    }

    /// The references the route needs resolved.
    pub fn refs(&self) -> Vec<&String> {
        match &self.auth {
            Auth::Bearer { token, .. } => vec![token],
            Auth::SigV4 {
                access_key,
                secret_key,
                session_token,
                ..
            } => [Some(access_key), Some(secret_key), session_token.as_ref()]
                .into_iter()
                .flatten()
                .collect(),
        }
    }

    /// What the command's environment gets before the broker is up: the
    /// placeholders, and for SigV4 a region if it has none.
    pub fn placeholders(&self, has: impl Fn(&str) -> bool) -> Vec<(String, String)> {
        match &self.auth {
            Auth::Bearer { .. } => self
                .env
                .iter()
                .map(|name| (name.clone(), self.placeholder.clone()))
                .collect(),
            Auth::SigV4 { region, .. } => {
                let mut vars = vec![
                    ("AWS_ACCESS_KEY_ID".to_string(), self.placeholder.clone()),
                    (
                        "AWS_SECRET_ACCESS_KEY".to_string(),
                        self.placeholder_secret.clone(),
                    ),
                ];
                for name in ["AWS_REGION", "AWS_DEFAULT_REGION"] {
                    if !has(name) {
                        vars.push((name.to_string(), region.clone()));
                    }
                }
                vars
            }
        }
    }

    /// Variables the command must not inherit: a real session token would
    /// go out signed with the placeholder.
    pub fn unset(&self) -> &'static [&'static str] {
        match self.auth {
            Auth::Bearer { .. } => &[],
            Auth::SigV4 { .. } => &["AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"],
        }
    }

    /// The base URL's variable, once the broker listens on `port`.
    pub fn base_url(&self, port: u16) -> Option<(String, String)> {
        let name = self.base_env.clone().or(match self.auth {
            Auth::SigV4 { .. } => Some("AWS_ENDPOINT_URL".to_string()),
            Auth::Bearer { .. } => None,
        })?;
        Some((name, format!("http://127.0.0.1:{port}/{}", self.alias)))
    }

    /// The broker's route, with each reference's value from `value`.
    fn route(&self, value: impl Fn(&str) -> Option<Zeroizing<String>>) -> Result<BrokerRoute> {
        let get = |reference: &str| {
            value(reference).with_context(|| format!("{reference} wasn't resolved"))
        };
        let auth = match &self.auth {
            Auth::Bearer { token, header } => BrokerAuth::Bearer {
                placeholder: self.placeholder.clone(),
                token: get(token)?,
                header_name: header
                    .clone()
                    .unwrap_or_else(|| "authorization".to_string()),
            },
            Auth::SigV4 {
                region,
                service,
                access_key,
                secret_key,
                session_token,
            } => BrokerAuth::AwsSigV4 {
                placeholder_access_key: self.placeholder.clone(),
                access_key: get(access_key)?,
                secret_key: get(secret_key)?,
                session_token: session_token.as_deref().map(get).transpose()?,
                region: region.clone(),
                service: service.clone(),
            },
        };
        Ok(BrokerRoute {
            alias: self.alias.clone(),
            upstream: self.upstream.clone(),
            auth,
            methods: self.methods.clone(),
            path_prefixes: self.prefixes.clone(),
            path_globs: self.globs.clone(),
            max_body_bytes: self.max_body,
        })
    }
}

/// The broker's config for `specs`, with this process as the run's root.
pub fn config(
    specs: &[RouteSpec],
    values: &HashMap<String, ResolvedSecret>,
) -> Result<BrokerConfig> {
    let root_pid = std::process::id();
    let root_start = OsProcesses
        .facts(root_pid)
        .context("reading this process's start time")?
        .start;
    let value = |reference: &str| {
        values
            .get(reference)
            .filter(|secret| !secret.file)
            .map(|secret| Zeroizing::new(secret.value.expose().to_string()))
    };
    let routes = specs
        .iter()
        .map(|spec| spec.route(value))
        .collect::<Result<Vec<_>>>()?;
    Ok(BrokerConfig {
        root_pid: Some(root_pid),
        root_start: Some(root_start),
        routes,
    })
}

/// A running broker; dropping it kills it.
pub struct Running {
    child: tokio::process::Child,
    pub port: u16,
}

impl Running {
    pub async fn stop(mut self) {
        if let Err(error) = self.child.start_kill() {
            tracing::debug!("stopping the broker: {error}");
        }
        drop(self.child.wait().await);
    }
}

/// Starts `deadbolt broker` with nothing of this environment, hands it
/// `config` on its stdin and waits for its port.
pub async fn launch(config: BrokerConfig) -> Result<Running> {
    let exe = std::env::current_exe().context("finding deadbolt")?;
    let mut child = tokio::process::Command::new(exe)
        .args([super::COMMAND, "--fd", "0"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // Its own group: a terminal's Ctrl-C is for the command, which may
        // still make requests while it handles it.
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .context("starting the broker")?;
    let frame = Zeroizing::new(serde_json::to_vec(&config)?);
    drop(config);
    let mut stdin = child.stdin.take().context("the broker's stdin")?;
    stdin
        .write_all(&frame)
        .await
        .context("handing the broker its config")?;
    drop(stdin);
    drop(frame);
    let stdout = child.stdout.take().context("the broker's stdout")?;
    let mut line = String::new();
    tokio::time::timeout(READY, BufReader::new(stdout).read_line(&mut line))
        .await
        .context("the broker didn't start in time")??;
    #[derive(serde::Deserialize)]
    struct Ready {
        port: u16,
    }
    let ready: Ready = serde_json::from_str(&line).context("the broker didn't start")?;
    Ok(Running {
        child,
        port: ready.port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_parse_into_placeholders_and_scope() {
        let spec = RouteSpec::parse(
            "openai=https://api.openai.com/v1,bearer=deadbolt://AI/OpenAI/key,env=OPENAI_API_KEY,base-env=OPENAI_BASE_URL,method=post,prefix=/chat",
        )
        .unwrap();
        assert_eq!(spec.refs(), ["deadbolt://AI/OpenAI/key"]);
        let vars = spec.placeholders(|_| false);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].0, "OPENAI_API_KEY");
        assert!(vars[0].1.starts_with("db_ph_") && vars[0].1.len() == 38);
        assert_eq!(
            spec.base_url(4000).unwrap(),
            (
                "OPENAI_BASE_URL".to_string(),
                "http://127.0.0.1:4000/openai".to_string()
            )
        );
        assert_eq!(spec.methods, ["POST"]);

        let aws = RouteSpec::parse(
            "s3=https://s3.us-east-1.amazonaws.com,sigv4=us-east-1/s3,access-key=deadbolt://AWS/key,secret-key=deadbolt://AWS/secret",
        )
        .unwrap();
        let vars = aws.placeholders(|name| name == "AWS_REGION");
        let names: Vec<&str> = vars.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_DEFAULT_REGION"
            ]
        );
        assert_eq!(aws.base_url(1).unwrap().0, "AWS_ENDPOINT_URL");
        assert_eq!(aws.unset(), ["AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"]);
    }

    #[test]
    fn bad_routes_are_refused_before_anything_resolves() {
        for bad in [
            "x",
            "x=http://example.com,bearer=deadbolt://a/b,env=T",
            "x=https://user:pw@example.com,bearer=deadbolt://a/b,env=T",
            "x=https://example.com,bearer=literal-secret,env=T",
            "x=https://example.com,bearer=deadbolt://a/b",
            "x=https://example.com,env=T",
            "x=https://example.com,sigv4=us-east-1/s3,access-key=deadbolt://a/b",
            "x=https://example.com,bearer=deadbolt://a/b,env=T,header=host",
            "x=https://example.com,bearer=deadbolt://a/b,env=T,prefix=/../x",
            "x=https://example.com,bearer=deadbolt://a/b,env=T,method=CONNECT",
            "x=https://example.com,bearer=deadbolt://a/b,env=T,wat=1",
            "../x=https://example.com,bearer=deadbolt://a/b,env=T",
        ] {
            assert!(RouteSpec::parse(bad).is_err(), "{bad}");
        }
        assert!(RouteSpec::parse("x=http://127.0.0.1:9,bearer=deadbolt://a/b,env=T").is_ok());
    }
}
