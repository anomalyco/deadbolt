//! The broker's HTTP side: one hyper HTTP/1 server on `127.0.0.1`. Each
//! connection's client is checked against the run's process tree once, on
//! `accept()`, before any request is read; then each request is checked
//! (target, path, query, method, headers, the caller's placeholder), its
//! body read up to the route's limit, its credential swapped, and sent to
//! the route's upstream, never following a redirect. The answer streams
//! back with any real secret it reflects starred out.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use deadbolt_os::net::LoopbackConnection;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use zeroize::Zeroizing;

use super::Lineage;
use super::aws::{SigV4, Target};
use super::config::{BrokerAuth, BrokerConfig, DEFAULT_METHODS, upstream_url};
use super::hygiene;
use super::redact::Redactor;

pub type Body = BoxBody<Bytes, io::Error>;

/// Why a request isn't forwarded. The reason is fixed text: nothing of the
/// request, and never a secret, is echoed.
#[derive(Debug)]
pub struct Refusal {
    pub status: StatusCode,
    pub why: &'static str,
}

impl Refusal {
    pub fn forbidden(why: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            why,
        }
    }

    pub fn bad_request(why: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            why,
        }
    }

    fn response(&self) -> Response<Body> {
        let text = format!("deadbolt broker: {}\n", self.why);
        let mut response = Response::new(
            Full::new(Bytes::from(text))
                .map_err(|never| match never {})
                .boxed(),
        );
        *response.status_mut() = self.status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response
    }
}

enum Auth {
    Bearer {
        header: HeaderName,
        /// The header's value as the caller must send it.
        expected: Zeroizing<String>,
        /// The real value, marked sensitive.
        real: HeaderValue,
    },
    SigV4(SigV4),
}

struct Route {
    alias: String,
    upstream: Url,
    auth: Auth,
    methods: Vec<Method>,
    prefixes: Vec<String>,
    globs: Vec<String>,
    max_body: usize,
    redactor: Redactor,
}

impl Route {
    /// `upstream` + `rest`, the query as the caller sent it.
    fn url(&self, rest: &str, query: Option<&str>) -> Url {
        let mut url = self.upstream.clone();
        let base = self.upstream.path().trim_end_matches('/');
        url.set_path(&format!("{base}{rest}"));
        url.set_query(query);
        url
    }

    fn secret_header(&self) -> Option<&str> {
        match &self.auth {
            Auth::Bearer { header, .. } => Some(header.as_str()),
            Auth::SigV4(_) => None,
        }
    }

    fn check_caller(&self, headers: &HeaderMap, query: Option<&str>) -> Result<(), Refusal> {
        match &self.auth {
            Auth::Bearer {
                header, expected, ..
            } => {
                let sent = headers.get(header).map(HeaderValue::as_bytes);
                if sent.is_some_and(|sent| bool::from(sent.ct_eq(expected.as_bytes()))) {
                    Ok(())
                } else {
                    Err(Refusal::forbidden(
                        "the request doesn't carry this route's placeholder",
                    ))
                }
            }
            Auth::SigV4(sigv4) => sigv4.check_caller(headers, query),
        }
    }

    /// The upstream's answer, streamed through the redactor.
    fn relay(&self, mut response: reqwest::Response) -> Response<Body> {
        let status = response.status();
        let mut headers = std::mem::take(response.headers_mut());
        hygiene::strip_hop_by_hop(&mut headers);
        for value in headers.values_mut() {
            if let Some(clean) = self.redactor.redact(value.as_bytes())
                && let Ok(clean) = HeaderValue::from_bytes(&clean)
            {
                *value = clean;
            }
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        let mut redactor = self.redactor.clone();
        tokio::spawn(async move {
            loop {
                let out = match response.chunk().await {
                    Ok(Some(chunk)) => redactor.push(&chunk),
                    Ok(None) => {
                        let rest = redactor.finish();
                        if !rest.is_empty() {
                            drop(sender.send(Ok(Bytes::from(rest))).await);
                        }
                        return;
                    }
                    Err(_) => {
                        let error = io::Error::other("the upstream's body broke off");
                        drop(sender.send(Err(error)).await);
                        return;
                    }
                };
                if !out.is_empty() && sender.send(Ok(Bytes::from(out))).await.is_err() {
                    return;
                }
            }
        });
        let mut relayed = Response::new(BoxBody::new(Streamed(receiver)));
        *relayed.status_mut() = status;
        *relayed.headers_mut() = headers;
        relayed
    }
}

/// A response body fed by the relay task.
struct Streamed(tokio::sync::mpsc::Receiver<io::Result<Bytes>>);

impl hyper::body::Body for Streamed {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        self.0
            .poll_recv(cx)
            .map(|next| next.map(|chunk| chunk.map(Frame::data)))
    }
}

/// One run's routes and the client that reaches their upstreams.
pub struct Broker {
    routes: Vec<Route>,
    lineage: Option<Lineage>,
    client: reqwest::Client,
}

impl Broker {
    /// Takes the config apart: each secret moves into the one form the
    /// broker uses (a sensitive header value, a SigV4 key), and the rest of
    /// the config, wiped as it drops, is gone.
    pub fn new(config: BrokerConfig) -> Result<Self> {
        config.validate()?;
        let lineage = config.root_pid.map(|root_pid| Lineage {
            root_pid,
            root_start: config.root_start,
        });
        let mut routes = Vec::with_capacity(config.routes.len());
        for route in config.routes {
            let redactor = Redactor::new(route.auth.secrets());
            let auth = match route.auth {
                BrokerAuth::Bearer {
                    placeholder,
                    token,
                    header_name,
                } => {
                    let header =
                        HeaderName::from_bytes(header_name.to_ascii_lowercase().as_bytes())
                            .context("the route's header name")?;
                    let bearer = header == header::AUTHORIZATION;
                    let with_scheme = |value: &str| {
                        Zeroizing::new(if bearer {
                            format!("Bearer {value}")
                        } else {
                            value.to_string()
                        })
                    };
                    let mut real = HeaderValue::from_str(&with_scheme(&token))
                        .ok()
                        .context("the route's token isn't a valid header value")?;
                    real.set_sensitive(true);
                    Auth::Bearer {
                        header,
                        expected: with_scheme(&placeholder),
                        real,
                    }
                }
                BrokerAuth::AwsSigV4 {
                    placeholder_access_key,
                    access_key,
                    secret_key,
                    session_token,
                    region,
                    service,
                } => Auth::SigV4(SigV4::new(
                    &placeholder_access_key,
                    &access_key,
                    &secret_key,
                    session_token.as_deref().map(String::as_str),
                    &region,
                    &service,
                )),
            };
            let methods = if route.methods.is_empty() {
                DEFAULT_METHODS.iter().map(|m| m.to_string()).collect()
            } else {
                route.methods
            };
            routes.push(Route {
                upstream: upstream_url(&route.upstream)?,
                alias: route.alias,
                auth,
                methods: methods
                    .iter()
                    .filter_map(|m| Method::from_bytes(m.as_bytes()).ok())
                    .collect(),
                prefixes: route.path_prefixes,
                globs: route.path_globs,
                max_body: route.max_body_bytes,
                redactor,
            });
        }
        // reqwest takes the process's rustls provider; Deadbolt's is ring.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(15))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .context("setting up the upstream client")?;
        Ok(Self {
            routes,
            lineage,
            client,
        })
    }

    pub fn lineage(&self) -> Option<&Lineage> {
        self.lineage.as_ref()
    }

    /// Serves `listener` until it fails.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        let server_port = listener.local_addr()?.port();
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    // Out of fds, say: wait for some to free up.
                    tracing::debug!("accepting: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            tokio::spawn(self.clone().connection(stream, peer, server_port));
        }
    }

    async fn connection(self: Arc<Self>, stream: TcpStream, peer: SocketAddr, server_port: u16) {
        let allowed = match self.lineage.clone() {
            None => true,
            Some(lineage) => {
                let connection = LoopbackConnection {
                    client_port: peer.port(),
                    server_port,
                };
                peer.ip().is_loopback()
                    && tokio::task::spawn_blocking(move || lineage.allows(connection))
                        .await
                        .unwrap_or(false)
            }
        };
        let service = service_fn(move |request| {
            let broker = self.clone();
            async move { Ok::<_, Infallible>(broker.handle(allowed, request).await) }
        });
        let served = http1::Builder::new()
            .timer(TokioTimer::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
        if let Err(error) = served {
            tracing::debug!("a broker connection ended: {error}");
        }
    }

    async fn handle(&self, allowed: bool, request: Request<Incoming>) -> Response<Body> {
        match self.forward(allowed, request).await {
            Ok(response) => response,
            Err(refusal) => refusal.response(),
        }
    }

    fn route(&self, request: &Request<Incoming>) -> Result<(&Route, String), Refusal> {
        let uri = request.uri();
        if uri.scheme().is_some() || uri.authority().is_some() {
            return Err(Refusal::bad_request("only origin-form request targets"));
        }
        let path = uri.path();
        hygiene::check_path(path).map_err(Refusal::forbidden)?;
        if let Some(query) = uri.query() {
            hygiene::check_query(query).map_err(Refusal::forbidden)?;
        }
        let (alias, rest) =
            hygiene::split_alias(path).ok_or(Refusal::forbidden("no such route"))?;
        let route = self
            .routes
            .iter()
            .find(|route| route.alias == alias)
            .ok_or(Refusal::forbidden("no such route"))?;
        if !route.methods.contains(request.method()) {
            return Err(Refusal::forbidden("the route doesn't allow this method"));
        }
        if !hygiene::path_allowed(&route.prefixes, &route.globs, rest) {
            return Err(Refusal::forbidden("the path is outside the route's scope"));
        }
        hygiene::check_headers(request.headers(), route.secret_header())
            .map_err(Refusal::bad_request)?;
        route.check_caller(request.headers(), uri.query())?;
        Ok((route, rest.to_string()))
    }

    async fn forward(
        &self,
        allowed: bool,
        request: Request<Incoming>,
    ) -> Result<Response<Body>, Refusal> {
        if !allowed {
            return Err(Refusal::forbidden(
                "this process isn't part of the deadbolt run the broker serves",
            ));
        }
        let (route, rest) = self.route(&request)?;
        let too_large = Refusal {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            why: "the request body is over the route's limit",
        };
        let declared = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()?.parse::<u64>().ok());
        if declared.is_some_and(|length| length > route.max_body as u64) {
            return Err(too_large);
        }
        let query = request.uri().query().map(str::to_string);
        let (parts, body) = request.into_parts();
        let body = match Limited::new(body, route.max_body).collect().await {
            Ok(collected) => collected.to_bytes().to_vec(),
            Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
                return Err(too_large);
            }
            Err(_) => return Err(Refusal::bad_request("the request body couldn't be read")),
        };
        let mut headers = parts.headers;
        hygiene::strip_hop_by_hop(&mut headers);
        for name in [header::HOST, header::CONTENT_LENGTH, header::EXPECT] {
            headers.remove(name);
        }
        let (url, body) = match &route.auth {
            Auth::Bearer { header, real, .. } => {
                headers.remove(header::AUTHORIZATION);
                headers.remove(header);
                headers.insert(header.clone(), real.clone());
                (route.url(&rest, query.as_deref()), body)
            }
            Auth::SigV4(sigv4) => sigv4.resign(
                &parts.method,
                Target {
                    upstream: &route.upstream,
                    rest: &rest,
                    query: query.as_deref(),
                },
                &mut headers,
                body,
                crate::config::now(),
            )?,
        };
        let response = self
            .client
            .request(parts.method, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|_| Refusal {
                status: StatusCode::BAD_GATEWAY,
                why: "the upstream couldn't be reached",
            })?;
        let status = response.status();
        if status.is_redirection() && status != StatusCode::NOT_MODIFIED {
            return Err(Refusal {
                status: StatusCode::BAD_GATEWAY,
                why: "the upstream answered with a redirect, which the broker doesn't follow",
            });
        }
        Ok(route.relay(response))
    }
}
