//! Deadbolt's SSH agent (`ssh.sock`) and `Command::Ssh*` handlers
//! (`docs/ssh-agent.md`).

pub(crate) mod bind;
pub(crate) mod keys;
pub(crate) mod policy;
pub(crate) mod select;
pub(crate) mod wire;

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use data_encoding::BASE64;
use deadbolt_client::peer::Peer;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::activity::ledger;
use super::{AbortOnDrop, Agent, DRAIN_TIMEOUT, ErrorCode, IO_TIMEOUT, caller, fail, session};
use crate::config::{Config, set_ssh_agent};
use crate::protocol::{
    ActivityEntry, ActivityItem, CallerInfo, Outcome, Reply, Secret, SshKeyKind, Tier,
};
use bind::{BoundHop, EXT_SESSION_BIND, SessionBind};
use keys::{KeyKind, ParsedKey};
use policy::{PolicyState, SignContext, UnlockTicket};
use select::{SshToml, eligible_keys, read_known_hosts, record_used, to_identities};
use wire::{AgentReply, AgentRequest, SignTarget, decode_request, parse_sign_target};

struct RunningListener {
    _task: AbortOnDrop,
    stop: watch::Sender<bool>,
    socket: PathBuf,
    link: Option<PathBuf>,
}

impl RunningListener {
    fn stop_and_clean(self) {
        self.stop.send_replace(true);
        drop(self._task);
        remove_if_exists(&self.socket);
        if let Some(link) = &self.link {
            remove_symlink_if_ours(link, &self.socket);
        }
    }
}

#[derive(Default)]
pub struct SshState {
    pub(super) policy: PolicyState,
    listener: Mutex<Option<RunningListener>>,
}

impl SshState {
    pub fn clear_on_lock(&self) {
        self.policy.clear_on_lock();
    }

    pub fn shutdown(&self) {
        self.policy.cancel_prompt();
        if let Some(running) = self
            .listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            running.stop_and_clean();
        }
    }

    pub fn is_listening(&self) -> bool {
        self.listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }
}

impl Agent {
    /// Starts `ssh.sock` at agent startup if `ssh_agent = true` in `config.toml`.
    pub(super) fn start_ssh_if_enabled(self: &Arc<Self>) {
        let enabled = Config::load(&self.paths.config)
            .map(|c| c.ssh_agent())
            .unwrap_or(false);
        if enabled && let Err(err) = self.bind_ssh_listener() {
            warn!("starting SSH agent socket failed: {err:#}");
        }
    }

    /// Enables or disables the SSH agent in `config.toml` and binds or drops
    /// `ssh.sock` immediately.
    pub(super) fn set_ssh_agent(self: &Arc<Self>, enabled: bool) -> Result<()> {
        let home = self
            .paths
            .ssh_link()
            .and_then(|p| p.parent().and_then(Path::parent).map(Path::to_path_buf));
        if enabled {
            self.bind_ssh_listener()?;
            set_ssh_agent(&self.paths.config, true).context("updating config.toml")?;
            if let Some(home) = &home
                && let Err(err) = install_login_unit(home)
            {
                warn!("installing SSH agent login unit: {err:#}");
            }
        } else {
            set_ssh_agent(&self.paths.config, false).context("updating config.toml")?;
            if let Some(running) = self
                .ssh
                .listener
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                running.stop_and_clean();
            }
            if let Some(home) = &home
                && let Err(err) = remove_login_unit(home)
            {
                warn!("removing SSH agent login unit: {err:#}");
            }
        }
        Ok(())
    }

    fn bind_ssh_listener(self: &Arc<Self>) -> Result<()> {
        let mut guard = self.ssh.listener.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(());
        }
        let socket = self.paths.ssh_socket();
        let runtime = socket.parent().context("ssh.sock has no parent")?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(runtime)
            .with_context(|| format!("creating {}", runtime.display()))?;
        deadbolt_client::paths::secure_dir(runtime)
            .with_context(|| format!("checking {}", runtime.display()))?;

        remove_if_exists(&socket);
        let listener =
            UnixListener::bind(&socket).with_context(|| format!("binding {}", socket.display()))?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;

        let link = self.paths.ssh_link();
        if let Some(link_path) = &link
            && let Err(err) = install_symlink(link_path, &socket)
        {
            warn!("updating {}: {err:#}", link_path.display());
        }

        let (stop_tx, mut stop_rx) = watch::channel(false);
        let agent = self.clone();
        let bound_path = socket.clone();
        let task = tokio::spawn(async move {
            info!(socket = %bound_path.display(), "SSH agent listening");
            let mut conns = JoinSet::new();
            loop {
                let stop_conn = stop_rx.clone();
                tokio::select! {
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let a = agent.clone();
                                conns.spawn(async move {
                                    if let Err(err) = a.handle_ssh_stream(stream, stop_conn).await {
                                        tracing::debug!("SSH connection ended: {err:#}");
                                    }
                                });
                            }
                            Err(err) => {
                                warn!("accepting SSH connection: {err}");
                                break;
                            }
                        }
                    }
                    Some(_) = conns.join_next(), if !conns.is_empty() => {}
                    _ = stop_rx.wait_for(|s| *s) => break,
                }
            }
            drop(listener);
            let drain = async { while conns.join_next().await.is_some() {} };
            if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
                conns.shutdown().await;
            }
        });

        *guard = Some(RunningListener {
            _task: AbortOnDrop(task),
            stop: stop_tx,
            socket,
            link,
        });
        Ok(())
    }

    async fn handle_ssh_stream(
        self: Arc<Self>,
        stream: UnixStream,
        mut stopping: watch::Receiver<bool>,
    ) -> Result<()> {
        match deadbolt_client::peer::uid(&stream) {
            Ok(uid) if uid == rustix::process::getuid().as_raw() => {}
            Ok(uid) => bail!("refused SSH connection from uid {uid}: not this user"),
            Err(err) => bail!("refused SSH connection: reading credentials: {err}"),
        }
        let peer = Peer::of(&stream);
        let caller = {
            let a = self.clone();
            let mut info = tokio::task::spawn_blocking(move || a.callers.identify(peer, None))
                .await
                .unwrap_or_else(|_| caller::nobody());
            ledger::bound_caller(&mut info);
            info
        };

        let (mut read_half, mut write_half) = stream.into_split();
        let mut session_bind = SessionBind::default();
        let mut unlock_ticket: Option<UnlockTicket> = None;

        loop {
            let frame = tokio::select! {
                res = wire::read_frame(&mut read_half) => match res? {
                    Some(f) => f,
                    None => return Ok(()),
                },
                _ = stopping.wait_for(|s| *s) => return Ok(()),
            };
            let request = match decode_request(&frame) {
                Ok(req) => req,
                Err(_) => {
                    wire::write_reply(&mut write_half, &AgentReply::Failure).await?;
                    continue;
                }
            };
            let reply = self
                .dispatch_ssh_request(
                    &caller,
                    request,
                    &mut session_bind,
                    &mut unlock_ticket,
                    stopping.clone(),
                )
                .await;
            tokio::time::timeout(IO_TIMEOUT, wire::write_reply(&mut write_half, &reply))
                .await
                .context("writing SSH agent reply timed out")??;
        }
    }

    async fn dispatch_ssh_request(
        self: &Arc<Self>,
        caller: &CallerInfo,
        request: AgentRequest,
        session_bind: &mut SessionBind,
        unlock_ticket: &mut Option<UnlockTicket>,
        stopping: watch::Receiver<bool>,
    ) -> AgentReply {
        match request {
            AgentRequest::Extension { name, contents } => match name.as_str() {
                "query" if contents.is_empty() => {
                    AgentReply::QueryExtensions(vec![EXT_SESSION_BIND])
                }
                "query" => AgentReply::ExtensionFailure,
                EXT_SESSION_BIND => match session_bind.bind(&contents) {
                    Ok(()) => AgentReply::Success,
                    Err(_) => AgentReply::ExtensionFailure,
                },
                // Unknown extensions return generic FAILURE (5) per draft-ietf-sshm-ssh-agent.
                _ => AgentReply::Failure,
            },
            AgentRequest::RequestIdentities => {
                if self.ssh.policy.check_look_rate(caller).is_err() {
                    return AgentReply::Identities(Vec::new());
                }
                let known_hosts = read_known_hosts();
                if !self.status().unlocked {
                    match self
                        .unlock_for_ssh(caller, session_bind.destination(), known_hosts.as_deref())
                        .await
                    {
                        Ok(ticket) => *unlock_ticket = ticket,
                        Err(_) => return AgentReply::Identities(Vec::new()),
                    }
                }
                if session_bind.has_failed() {
                    return AgentReply::Identities(Vec::new());
                }
                let ssh_toml = SshToml::load(&self.paths.ssh_config()).ok().flatten();
                let global_fwd = Config::load(&self.paths.config)
                    .map(|c| c.ssh_allow_forwarding())
                    .unwrap_or(false);
                let allow_fwd = ssh_toml
                    .as_ref()
                    .and_then(|t| t.allow_forwarding)
                    .unwrap_or(global_fwd);
                if session_bind.is_forwarded() && !allow_fwd {
                    return AgentReply::Identities(Vec::new());
                }
                let identities = self
                    .with(|s| {
                        let mut keys = eligible_keys(
                            s,
                            ssh_toml.as_ref(),
                            known_hosts.as_deref(),
                            session_bind.destination(),
                        );
                        if session_bind.is_forwarded() {
                            keys.retain(|k| k.allow_forwarding.unwrap_or(allow_fwd));
                        }
                        Ok(to_identities(&keys))
                    })
                    .unwrap_or_default();
                AgentReply::Identities(identities)
            }
            AgentRequest::SignRequest {
                pubkey_blob,
                data,
                flags,
            } => {
                match self
                    .handle_ssh_sign_request(
                        caller,
                        &pubkey_blob,
                        &data,
                        flags,
                        session_bind,
                        unlock_ticket,
                        stopping,
                    )
                    .await
                {
                    Ok(sig) => AgentReply::SignResponse(sig),
                    Err(_) => AgentReply::Failure,
                }
            }
            AgentRequest::Unsupported(_) => AgentReply::Failure,
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "combines wire fields, connection bind state, and cancellation"
    )]
    async fn handle_ssh_sign_request(
        self: &Arc<Self>,
        caller: &CallerInfo,
        pubkey_blob: &[u8],
        data: &[u8],
        flags: u32,
        session_bind: &SessionBind,
        unlock_ticket: &mut Option<UnlockTicket>,
        stopping: watch::Receiver<bool>,
    ) -> Result<Vec<u8>> {
        let target = parse_sign_target(data, pubkey_blob);
        let target_label = target_summary(&target, session_bind.destination());
        let known_hosts = read_known_hosts();

        if !self.status().unlocked {
            let outcome = if self.status().touch_id_ready {
                self.unlock_for_ssh(caller, session_bind.destination(), known_hosts.as_deref())
                    .await
                    .map(|t| *unlock_ticket = t)
            } else {
                Err(fail(ErrorCode::Locked, "locked"))
            };
            if let Err(err) = outcome {
                self.record_ssh_activity(caller, None, &target_label, &err);
                return Err(err);
            }
        }

        let ssh_toml = SshToml::load(&self.paths.ssh_config()).ok().flatten();
        let global_fwd = Config::load(&self.paths.config)
            .map(|c| c.ssh_allow_forwarding())
            .unwrap_or(false);
        let default_fwd = ssh_toml
            .as_ref()
            .and_then(|t| t.allow_forwarding)
            .unwrap_or(global_fwd);

        let found = self.with(|s| {
            let keys = eligible_keys(
                s,
                ssh_toml.as_ref(),
                known_hosts.as_deref(),
                session_bind.destination(),
            );
            keys.into_iter()
                .find(|k| k.pubkey_blob == pubkey_blob)
                .ok_or_else(|| fail(ErrorCode::NotFound, "no matching SSH key in Deadbolt"))
        });
        let key = match found {
            Ok(k) => k,
            Err(err) => {
                self.record_ssh_activity(caller, None, &target_label, &err);
                return Err(err);
            }
        };

        let item_ref = ActivityItem {
            vault: Some(key.vault_name.clone()),
            id: Some(key.item.id.to_string()),
            title: key.title.clone(),
        };
        let allow_fwd = key.allow_forwarding.unwrap_or(default_fwd);
        let dest_hop = match session_bind.check_sign(&target, allow_fwd) {
            Ok(hop) => hop,
            Err(err) => {
                let err = fail(ErrorCode::Forbidden, err.to_string());
                self.record_ssh_activity(caller, Some(item_ref), &target_label, &err);
                return Err(err);
            }
        };

        let ctx = SignContext {
            caller,
            vault_id: key.vault_id,
            vault_name: &key.vault_name,
            item_id: &key.item.id.to_string(),
            item_title: &key.title,
            target: &target,
            dest_hop,
            first_hop: session_bind.first_hop(),
            forwarded: session_bind.is_forwarded(),
            known_hosts: known_hosts.as_deref(),
        };
        if let Err(err) = self
            .approve_ssh_sign(&ctx, Some(unlock_ticket), stopping)
            .await
        {
            self.record_ssh_activity(caller, Some(item_ref), &target_label, &err);
            return Err(err);
        }

        let signed = self.with(|s| {
            let current = s
                .held(&key.vault_id)
                .and_then(|v| v.item(&key.item.id))
                .filter(|i| !i.deleted && i.kind == "ssh")
                .ok_or_else(|| fail(ErrorCode::NotFound, "SSH key was removed"))?;
            let priv_pem = current
                .fields
                .get("private-key")
                .map(|f| f.value.as_str())
                .ok_or_else(|| anyhow!("SSH key has no private-key"))?;
            let pass = current.fields.get("passphrase").map(|f| f.value.as_str());
            let parsed = ParsedKey::parse(priv_pem, pass)?;
            let sig = parsed.sign_agent(data, flags)?;
            if let Some(hop) = dest_hop {
                drop(record_used(
                    s,
                    &hop.fingerprint,
                    key.vault_id,
                    &current,
                    session::now(),
                ));
            }
            Ok(sig)
        });
        match &signed {
            Ok(_) => self.record(ActivityEntry {
                id: 0,
                time: session::now(),
                caller: caller.clone(),
                tier: Tier::Use,
                command: "ssh-sign".into(),
                items: vec![item_ref],
                fields: vec![target_label],
                outcome: Outcome::Allowed,
                more: 0,
                client: None,
            }),
            Err(err) => self.record_ssh_activity(caller, Some(item_ref), &target_label, err),
        }
        signed
    }

    fn record_ssh_activity(
        &self,
        caller: &CallerInfo,
        item: Option<ActivityItem>,
        target: &str,
        error: &anyhow::Error,
    ) {
        let outcome = match crate::client::code(error) {
            Some(ErrorCode::Locked) => Outcome::Locked,
            Some(ErrorCode::Forbidden | ErrorCode::NotGranted | ErrorCode::RateLimited) => {
                Outcome::Refused
            }
            _ => Outcome::Failed,
        };
        self.record(ActivityEntry {
            id: 0,
            time: session::now(),
            caller: caller.clone(),
            tier: Tier::Use,
            command: "ssh-sign".into(),
            items: item.into_iter().collect(),
            fields: vec![target.to_owned()],
            outcome,
            more: 0,
            client: None,
        });
    }

    /// Control-socket `Command::SshGenerate` and `Command::SshInspect`.
    pub(super) fn ssh_generate(&self, kind: SshKeyKind, comment: Option<&str>) -> Result<Reply> {
        let k = match kind {
            SshKeyKind::Ed25519 => KeyKind::Ed25519,
            SshKeyKind::EcdsaP256 => KeyKind::EcdsaP256,
        };
        let made = keys::generate(k, comment)?;
        Ok(Reply::SshGenerated {
            private_key: Secret::new(made.private_key.as_str()),
            public_key: made.public_key,
            fingerprint: made.fingerprint,
            comment: made.comment,
        })
    }

    pub(super) fn ssh_inspect(
        &self,
        private_key: &Secret,
        passphrase: Option<&Secret>,
        comment: Option<&str>,
    ) -> Result<Reply> {
        let made = keys::normalize_import(
            private_key.expose(),
            passphrase.map(Secret::expose),
            comment,
        )?;
        Ok(Reply::SshGenerated {
            private_key: Secret::new(made.private_key.as_str()),
            public_key: made.public_key,
            fingerprint: made.fingerprint,
            comment: made.comment,
        })
    }

    /// Control-socket `Command::SshSign` (`deadbolt ssh-sign`, `gpg.ssh.program`):
    /// single-tap unlock + sign when locked with `touch_id_ready`.
    pub(super) async fn ssh_sign_command(
        self: &Arc<Self>,
        caller: &CallerInfo,
        public_key: &str,
        namespace: &str,
        data_b64: &str,
        closed: watch::Receiver<bool>,
    ) -> Result<Reply> {
        let (pubkey_blob, pub_fp) = keys::parse_public_key_line(public_key)?;
        let raw = BASE64
            .decode(data_b64.trim().as_bytes())
            .context("invalid base64 payload in ssh-sign")?;
        let ns = namespace.trim();
        if ns.is_empty() {
            bail!("ssh-sign requires a non-empty namespace");
        }

        let mut unlocked_and_approved = false;
        if !self.status().unlocked && self.status().touch_id_ready {
            let anchor_key = super::activity::anchor(caller);
            self.ssh
                .policy
                .check_cooldown(&anchor_key, session::now())?;
            self.ssh.policy.check_look_rate(caller)?;
            let reason = format!(
                "unlock Deadbolt and sign a \"{}\" message with SSH key {pub_fp} ({})",
                wire::clean_label(ns),
                wire::clean_label(&caller.label)
            );
            let _busy = self.busy();
            unlocked_and_approved = self.unlock_biometric_with_reason(None, &reason).await?;
        }

        let (vault_id, vault_name, item, title) = self.with(|s| {
            for (vid, v) in &s.vaults {
                for item in v.items() {
                    if item.deleted || item.kind != "ssh" {
                        continue;
                    }
                    let Some(pk) = item.fields.get("private-key") else {
                        continue;
                    };
                    let pass = item.fields.get("passphrase").map(|f| f.value.as_str());
                    if let Ok(parsed) = ParsedKey::parse(&pk.value, pass)
                        && parsed.public_blob().ok().as_deref() == Some(pubkey_blob.as_slice())
                    {
                        let title = deadbolt_core::listing::label(&item);
                        return Ok((*vid, v.name().to_owned(), item, title));
                    }
                }
            }
            Err(fail(
                ErrorCode::NotFound,
                format!("no SSH key with fingerprint {pub_fp} in Deadbolt"),
            ))
        })?;

        if !unlocked_and_approved {
            let target = SignTarget::SshSig {
                namespace: ns.to_owned(),
            };
            let ctx = SignContext {
                caller,
                vault_id,
                vault_name: &vault_name,
                item_id: &item.id.to_string(),
                item_title: &title,
                target: &target,
                dest_hop: None,
                first_hop: None,
                forwarded: false,
                known_hosts: None,
            };
            self.approve_ssh_sign(&ctx, None, closed).await?;
        }

        let signature = self.with(|s| {
            let current = s
                .held(&vault_id)
                .and_then(|v| v.item(&item.id))
                .filter(|i| !i.deleted && i.kind == "ssh")
                .ok_or_else(|| fail(ErrorCode::NotFound, "SSH key was removed"))?;
            let priv_pem = current
                .fields
                .get("private-key")
                .map(|f| f.value.as_str())
                .ok_or_else(|| anyhow!("SSH key has no private-key"))?;
            let pass = current.fields.get("passphrase").map(|f| f.value.as_str());
            ParsedKey::parse(priv_pem, pass)?.sign_sshsig(ns, &raw)
        })?;

        Ok(Reply::SshSignature { signature })
    }
}

fn target_summary(target: &SignTarget, dest_hop: Option<&BoundHop>) -> String {
    match target {
        SignTarget::UserAuth { username, .. } => match dest_hop {
            Some(hop) => format!("ssh:{username}@{}", hop.fingerprint),
            None => format!("ssh:{username}"),
        },
        SignTarget::SshSig { namespace } => format!("sshsig:{namespace}"),
        SignTarget::Raw { len } => format!("raw:{len}B"),
    }
}

fn remove_if_exists(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => warn!("removing {}: {err}", path.display()),
    }
}

fn install_symlink(link: &Path, target: &Path) -> Result<()> {
    let dir = link.parent().context("ssh link has no parent")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    deadbolt_client::paths::secure_dir(dir)
        .with_context(|| format!("checking {}", dir.display()))?;
    let tmp = dir.join(format!(".ssh.sock.{}", std::process::id()));
    remove_if_exists(&tmp);
    std::os::unix::fs::symlink(target, &tmp)
        .with_context(|| format!("creating symlink {}", tmp.display()))?;
    fs::rename(&tmp, link)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), link.display()))
}

fn remove_symlink_if_ours(link: &Path, expected_target: &Path) {
    if fs::read_link(link).ok().as_deref() == Some(expected_target) {
        remove_if_exists(link);
    }
}

fn install_login_unit(home: &Path) -> Result<()> {
    let exe = crate::caller::own_exe()?;
    #[cfg(target_os = "macos")]
    {
        let dir = home.join("Library/LaunchAgents");
        fs::create_dir_all(&dir)?;
        let plist = dir.join("pw.deadbolt.agent.plist");
        let escaped = exe
            .display()
            .to_string()
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>pw.deadbolt.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{escaped}</string>
        <string>agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#
        );
        fs::write(&plist, body)?;
    }
    #[cfg(target_os = "linux")]
    {
        let dir = home.join(".config/systemd/user");
        fs::create_dir_all(&dir)?;
        let unit = dir.join("deadbolt-agent.service");
        let body = format!(
            "[Unit]\nDescription=Deadbolt background agent\n\n[Service]\nExecStart=\"{}\" agent\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n",
            exe.display()
        );
        fs::write(&unit, body)?;
    }
    Ok(())
}

fn remove_login_unit(home: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let plist = home.join("Library/LaunchAgents/pw.deadbolt.agent.plist");
        if plist.exists() {
            fs::remove_file(plist)?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        let unit = home.join(".config/systemd/user/deadbolt-agent.service");
        if unit.exists() {
            fs::remove_file(unit)?;
        }
    }
    Ok(())
}
