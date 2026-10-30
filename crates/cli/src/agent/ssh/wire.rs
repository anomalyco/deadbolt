//! Binary wire framing and payload parsers for `draft-ietf-sshm-ssh-agent`
//! and OpenSSH's `PROTOCOL.agent` / `PROTOCOL.sshsig`.

use anyhow::{Result, anyhow, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// OpenSSH `ssh-agent`'s `MAX_MSG_LEN` (`256 KiB`).
pub const MAX_MSG_LEN: usize = 256 * 1024;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
pub const SSH_AGENT_EXTENSION_RESPONSE: u8 = 29;

const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRequest {
    RequestIdentities,
    SignRequest {
        pubkey_blob: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    Extension {
        name: String,
        contents: Vec<u8>,
    },
    /// Any other request code (SSHv1 `1..=9`, `ADD_IDENTITY`, `REMOVE_*`,
    /// `LOCK`/`UNLOCK`, unknown codes), which the agent refuses with `5`.
    Unsupported(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub pubkey_blob: Vec<u8>,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentReply {
    Failure,
    Success,
    ExtensionFailure,
    Identities(Vec<Identity>),
    SignResponse(Vec<u8>),
    QueryExtensions(Vec<&'static str>),
}

/// What the bytes inside `SignRequest.data` represent, so Touch ID prompts
/// and `session-bind` checks see the real protocol intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignTarget {
    UserAuth {
        session_id: Vec<u8>,
        username: String,
        hostkey_blob: Option<Vec<u8>>,
    },
    SshSig {
        namespace: String,
    },
    Raw {
        len: usize,
    },
}

/// Reads one length-prefixed frame (`u32 BE len` + `len` bytes). Returns
/// `Ok(None)` on clean EOF before the first length byte, and errors on
/// truncated frames, `len == 0` or `len > MAX_MSG_LEN`.
pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    match reader.read(&mut head[..1]).await? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!(),
    }
    reader.read_exact(&mut head[1..]).await?;
    let len = u32::from_be_bytes(head) as usize;
    if len == 0 || len > MAX_MSG_LEN {
        bail!("invalid SSH agent frame length {len}");
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Writes one length-prefixed reply frame and flushes.
pub async fn write_reply(writer: &mut (impl AsyncWrite + Unpin), reply: &AgentReply) -> Result<()> {
    let body = encode_reply(reply)?;
    let len = u32::try_from(body.len()).map_err(|_| anyhow!("SSH agent reply too large"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

pub fn decode_request(frame: &[u8]) -> Result<AgentRequest> {
    let mut r = Cursor(frame);
    let kind = r.u8()?;
    match kind {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            r.finish()?;
            Ok(AgentRequest::RequestIdentities)
        }
        SSH_AGENTC_SIGN_REQUEST => {
            let pubkey_blob = r.bytes()?.to_vec();
            let data = r.bytes()?.to_vec();
            let flags = r.u32()?;
            r.finish()?;
            Ok(AgentRequest::SignRequest {
                pubkey_blob,
                data,
                flags,
            })
        }
        SSH_AGENTC_EXTENSION => {
            let name = r.string()?;
            let contents = r.rest().to_vec();
            Ok(AgentRequest::Extension { name, contents })
        }
        other => Ok(AgentRequest::Unsupported(other)),
    }
}

pub fn encode_reply(reply: &AgentReply) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match reply {
        AgentReply::Failure => out.push(SSH_AGENT_FAILURE),
        AgentReply::Success => out.push(SSH_AGENT_SUCCESS),
        AgentReply::ExtensionFailure => out.push(SSH_AGENT_EXTENSION_FAILURE),
        AgentReply::Identities(list) => {
            out.push(SSH_AGENT_IDENTITIES_ANSWER);
            let count =
                u32::try_from(list.len()).map_err(|_| anyhow!("too many SSH identities"))?;
            out.extend_from_slice(&count.to_be_bytes());
            for id in list {
                put_bytes(&mut out, &id.pubkey_blob)?;
                put_bytes(&mut out, id.comment.as_bytes())?;
            }
        }
        AgentReply::SignResponse(sig) => {
            out.push(SSH_AGENT_SIGN_RESPONSE);
            put_bytes(&mut out, sig)?;
        }
        AgentReply::QueryExtensions(names) => {
            out.push(SSH_AGENT_EXTENSION_RESPONSE);
            put_bytes(&mut out, b"query")?;
            for name in names {
                put_bytes(&mut out, name.as_bytes())?;
            }
        }
    }
    Ok(out)
}

/// Inspects `data` from `SSH_AGENTC_SIGN_REQUEST` to tell an RFC 4252 /
/// OpenSSH hostbound `USERAUTH_REQUEST` or an `SSHSIG` message from raw bytes.
pub fn parse_sign_target(data: &[u8], expected_pubkey_blob: &[u8]) -> SignTarget {
    if let Some(auth) = try_parse_userauth(data, expected_pubkey_blob) {
        return auth;
    }
    if let Some(sig) = try_parse_sshsig(data) {
        return sig;
    }
    SignTarget::Raw { len: data.len() }
}

fn try_parse_userauth(data: &[u8], expected_pubkey_blob: &[u8]) -> Option<SignTarget> {
    let mut r = Cursor(data);
    let session_id = r.bytes().ok()?;
    if session_id.len() < 16 || session_id.len() > 128 {
        return None;
    }
    if r.u8().ok()? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    let username = clean_label(&r.string().ok()?);
    let service = r.string().ok()?;
    if service != "ssh-connection" {
        return None;
    }
    let method = r.string().ok()?;
    let has_sig = r.u8().ok()?;
    if has_sig != 1 {
        return None;
    }
    let _alg = r.string().ok()?;
    let pubkey_blob = r.bytes().ok()?;
    if pubkey_blob != expected_pubkey_blob {
        return None;
    }
    let hostkey_blob = match method.as_str() {
        "publickey" => None,
        "publickey-hostbound-v00@openssh.com" => Some(r.bytes().ok()?.to_vec()),
        _ => return None,
    };
    r.finish().ok()?;
    Some(SignTarget::UserAuth {
        session_id: session_id.to_vec(),
        username,
        hostkey_blob,
    })
}

fn try_parse_sshsig(data: &[u8]) -> Option<SignTarget> {
    let rest = data.strip_prefix(SSHSIG_MAGIC)?;
    let mut r = Cursor(rest);
    let namespace = clean_label(&r.string().ok()?);
    if namespace.is_empty() {
        return None;
    }
    let _reserved = r.bytes().ok()?;
    let hash_alg = r.string().ok()?;
    let hash = r.bytes().ok()?;
    let expected_len = match hash_alg.as_str() {
        "sha256" => 32,
        "sha512" => 64,
        _ => return None,
    };
    if hash.len() != expected_len {
        return None;
    }
    r.finish().ok()?;
    Some(SignTarget::SshSig { namespace })
}

pub(crate) fn clean_label(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect::<String>()
        .trim()
        .replace(['"', '\u{201c}', '\u{201d}'], "'")
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow!("SSH string too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub(crate) struct Cursor<'a>(pub(crate) &'a [u8]);

impl<'a> Cursor<'a> {
    pub(crate) fn u8(&mut self) -> Result<u8> {
        let (&b, rest) = self.0.split_first().ok_or_else(|| anyhow!("truncated"))?;
        self.0 = rest;
        Ok(b)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        if self.0.len() < 4 {
            bail!("truncated u32");
        }
        let (head, rest) = self.0.split_at(4);
        self.0 = rest;
        Ok(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if self.0.len() < len {
            bail!("truncated string of {len} bytes");
        }
        let (body, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(body)
    }

    pub(crate) fn string(&mut self) -> Result<String> {
        let bytes = self.bytes()?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| anyhow!("non-UTF-8 SSH string"))
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.0
    }

    pub(crate) fn finish(&self) -> Result<()> {
        if !self.0.is_empty() {
            bail!("{} trailing bytes in SSH message", self.0.len());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod wire_tests;
