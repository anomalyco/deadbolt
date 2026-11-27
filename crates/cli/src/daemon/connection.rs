//! One control connection: the request line, the conversation events and
//! answers go over, and the handler that turns a request into a reply.

use std::sync::Arc;

use anyhow::{Result, bail};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use super::{AbortOnDrop, Daemon, ErrorCode, IO_TIMEOUT, fail, macos_autofill};
use crate::client::{DaemonError, protocol};
use crate::protocol::{Answer, Command, Event, Message, Reply, Request};

/// Limit each line before buffering it, preserving buffered answers for the next read.
pub(super) async fn request_line(
    read: &mut (impl AsyncBufRead + Unpin),
    max: usize,
) -> Result<Option<Zeroizing<String>>> {
    // Requests carry passphrases and whole exports: the line grows in a
    // buffer that is wiped, also when it is outgrown. Past `max` (plus a
    // `\r`) it stops growing and the rest of the line is skipped.
    let mut line = Zeroizing::new(Vec::new());
    let mut read_any = false;
    let mut too_large = false;
    loop {
        let bytes = read.fill_buf().await?;
        if bytes.is_empty() {
            break;
        }
        read_any = true;
        let newline = bytes.iter().position(|b| *b == b'\n');
        let end = newline.unwrap_or(bytes.len());
        if !too_large && line.len() + end > max + 1 {
            too_large = true;
            line = Zeroizing::new(Vec::new());
        }
        if !too_large {
            deadbolt_client::append(&mut line, &bytes[..end], max + 1);
        }
        read.consume(newline.map_or(end, |i| i + 1));
        if newline.is_some() {
            break;
        }
    }
    if !read_any {
        return Ok(None);
    }
    if line.ends_with(b"\r") {
        line.pop();
    }
    if too_large || line.len() > max {
        return Err(fail(ErrorCode::Failed, "request too large"));
    }
    match String::from_utf8(std::mem::take(&mut *line)) {
        Ok(line) => Ok(Some(Zeroizing::new(line))),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            Err(fail(ErrorCode::Failed, "invalid request: not UTF-8"))
        }
    }
}

/// Why a request isn't valid, by position only: serde's messages can
/// quote the values in it.
pub(super) fn invalid_request(error: &serde_json::Error) -> anyhow::Error {
    let what = match error.classify() {
        serde_json::error::Category::Io => "unreadable",
        serde_json::error::Category::Syntax => "not valid JSON",
        serde_json::error::Category::Data => "not a request this daemon knows",
        serde_json::error::Category::Eof => "cut short",
    };
    fail(
        ErrorCode::Failed,
        format!(
            "invalid request: {what} (line {} column {})",
            error.line(),
            error.column()
        ),
    )
}

/// One control connection: sends events and reads answers.
pub struct Conversation {
    pub(super) write: tokio::sync::Mutex<OwnedWriteHalf>,
    pub(super) answers: tokio::sync::Mutex<mpsc::Receiver<Answer>>,
    pub(super) closed: watch::Receiver<bool>,
}

impl Conversation {
    pub(super) async fn send(&self, message: &Message) -> Result<()> {
        // Replies carry secrets.
        let body = deadbolt_client::encode_json(b"", message, b"\n")?;
        tokio::time::timeout(IO_TIMEOUT, async {
            self.write.lock().await.write_all(&body).await
        })
        .await??;
        Ok(())
    }

    pub async fn event(&self, event: Event) -> Result<()> {
        self.send(&Message::Event { event }).await
    }

    /// Sends an event and waits for the client's answer; `None` if it hangs up.
    pub async fn ask(&self, event: Event) -> Option<Answer> {
        self.event(event).await.ok()?;
        self.answers.lock().await.recv().await
    }

    /// Resolves once the client hangs up.
    pub async fn closed(&self) {
        let mut closed = self.closed.clone();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a dropped sender also means the connection closed"
        )]
        let _ = closed.wait_for(|closed| *closed).await;
    }
}

impl Daemon {
    pub(super) async fn handle(self: Arc<Self>, stream: UnixStream, max_line: usize) -> Result<()> {
        self.handle_on(stream, max_line, macos_autofill::SocketKind::Control)
            .await
    }

    pub(super) async fn handle_on(
        self: Arc<Self>,
        stream: UnixStream,
        max_line: usize,
        socket: macos_autofill::SocketKind,
    ) -> Result<()> {
        // The socket's directory keeps other users out; this holds even if
        // it didn't. (macOS keeps a peer's uid, but not its audit token, once
        // it hangs up.)
        match deadbolt_client::peer::uid(&stream) {
            Ok(uid) if uid == rustix::process::getuid().as_raw() => {}
            Ok(uid) => bail!("refused a connection from uid {uid}: not this user"),
            Err(error) => bail!("refused a connection: reading its credentials: {error}"),
        }
        let peer = deadbolt_client::peer::Peer::of(&stream);
        let (read, write) = stream.into_split();
        let mut read = BufReader::new(read);
        let request =
            match tokio::time::timeout(IO_TIMEOUT, request_line(&mut read, max_line)).await? {
                Ok(Some(line)) => {
                    serde_json::from_str::<Request>(&line).map_err(|e| invalid_request(&e))
                }
                Ok(None) => return Ok(()),
                Err(error) => Err(error),
            };
        let (answers_tx, answers) = mpsc::channel(4);
        let (closed_tx, closed) = watch::channel(false);
        let _reader = AbortOnDrop(tokio::spawn(async move {
            while let Ok(Some(line)) = request_line(&mut read, max_line).await {
                let Ok(answer) = serde_json::from_str::<Answer>(&line) else {
                    break;
                };
                if answers_tx.send(answer).await.is_err() {
                    break;
                }
            }
            closed_tx.send_replace(true);
        }));
        let conversation = Conversation {
            write: tokio::sync::Mutex::new(write),
            answers: tokio::sync::Mutex::new(answers),
            closed,
        };
        let mut stop = false;
        // The protocol first, then (in `answer`) the socket's access rules,
        // and only then a run's screen: a request either of them refuses
        // never reaches a run's capability, so it can't use one up.
        let result = match request {
            Err(error) => Err(error),
            Ok(request)
                if request.v != protocol()
                    && !matches!(request.command, Command::Status | Command::Stop) =>
            {
                Err(fail(
                    ErrorCode::Version,
                    format!(
                        "the daemon speaks protocol {}, not {}; run `deadbolt debug daemon stop`",
                        protocol(),
                        request.v
                    ),
                ))
            }
            Ok(Request {
                command: Command::Watch { app },
                ..
            }) if socket == macos_autofill::SocketKind::Control => {
                let kernel = peer.as_ref().ok().copied();
                let daemon = self.clone();
                let caller = tokio::task::spawn_blocking(move || daemon.callers.identify(peer))
                    .await
                    .unwrap_or_else(|_| super::caller::nobody());
                let screened =
                    match macos_autofill::check_access(socket, &caller, &Command::Watch { app }) {
                        Err(error) => Some(Err(error)),
                        Ok(()) => self.screen(kernel.as_ref(), &Command::Watch { app }),
                    };
                match screened {
                    Some(screened) => screened,
                    None => return self.watch(&conversation, app).await,
                }
            }
            Ok(request) => {
                let asked_stop = matches!(request.command, Command::Stop);
                let (result, entry) = self
                    .clone()
                    .answer(socket, peer, request, &conversation)
                    .await;
                // Recorded before the reply goes: a client that never
                // reads it, or the daemon stopping, can't lose the entry.
                if let Some(entry) = entry {
                    self.record(entry);
                }
                stop = asked_stop && result.is_ok();
                result
            }
        };
        let delivered_kits =
            matches!(&result, Ok(Reply::Unlocked { migrated }) if !migrated.is_empty());
        let message = match result {
            Ok(reply) => Message::Ok { reply },
            Err(error) => match error.downcast::<DaemonError>() {
                Ok(error) => Message::Error {
                    code: error.code,
                    message: error.message,
                },
                Err(error) => Message::Error {
                    code: ErrorCode::Failed,
                    message: format!("{error:#}"),
                },
            },
        };
        let sent = async {
            conversation.send(&message).await?;
            conversation.write.lock().await.shutdown().await?;
            Ok(())
        }
        .await;
        if delivered_kits && sent.is_err() {
            self.lock().await;
        }
        if sent.is_ok() && delivered_kits {
            self.with(|s| {
                super::session::set_json(
                    s.store(),
                    super::upgrade::PENDING_KITS,
                    &Vec::<crate::protocol::MigratedVault>::new(),
                )
            })?;
        }
        if stop {
            self.shutdown.notify_one();
        }
        sent
    }
}
