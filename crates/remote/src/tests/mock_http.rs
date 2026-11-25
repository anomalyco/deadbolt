//! A tiny HTTP/1.1 server on loopback for driving the real reqwest backends:
//! one request per connection, `Content-Length` bodies, a handler closure.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::webdav::percent_decode;

#[derive(Debug, Clone)]
pub struct MockRequest {
    pub method: String,
    /// The raw path, as sent.
    pub path: String,
    /// The raw query string, as sent.
    pub query: String,
    /// Lowercase names.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MockRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Decoded query parameters.
    pub fn params(&self) -> Vec<(String, String)> {
        self.query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (percent_decode(k).unwrap(), percent_decode(v).unwrap())
            })
            .collect()
    }

    pub fn param(&self, name: &str) -> Option<String> {
        self.params()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }
}

pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MockResponse {
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn body(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

pub type Log = Arc<Mutex<Vec<MockRequest>>>;

/// Serves `handler` on an ephemeral loopback port until the runtime ends.
pub async fn serve(
    handler: impl Fn(&MockRequest) -> MockResponse + Send + Sync + 'static,
) -> (SocketAddr, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Log = Arc::default();
    let handler = Arc::new(handler);
    let seen = log.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let handler = handler.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                read_request(&mut stream, &handler, &seen).await;
            });
        }
    });
    (addr, log)
}

async fn read_request(
    stream: &mut TcpStream,
    handler: &Arc<impl Fn(&MockRequest) -> MockResponse>,
    log: &Log,
) -> Option<()> {
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let mut chunk = vec![0u8; len - body.len()];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let request = MockRequest {
        method,
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body,
    };
    let response = handler(&request);
    log.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(request);
    let mut out = format!("HTTP/1.1 {} X\r\n", response.status);
    for (k, v) in &response.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        response.body.len()
    ));
    stream.write_all(out.as_bytes()).await.ok()?;
    stream.write_all(&response.body).await.ok()?;
    stream.shutdown().await.ok()?;
    Some(())
}

pub fn requests(log: &Log) -> Vec<MockRequest> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}
