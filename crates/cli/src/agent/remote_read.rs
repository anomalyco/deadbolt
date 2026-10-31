//! Opt-in single-read remote approval; no caller ever receives an approval token.
use anyhow::{Result, anyhow};
use deadbolt_core::{DeviceId, VaultId};
use deadbolt_net::approval::ReadScope;
use tokio::sync::watch;
use zeroize::Zeroizing;

use super::{
    Agent, Conversation, caller, fail, secrets,
    session::{self, Session},
};
use crate::protocol::{CallerClass, CallerInfo, Check, ErrorCode, Reference, Reply};

pub(super) struct Designation {
    pub(super) device: DeviceId,
    lifetime: watch::Sender<()>,
}
fn forbidden(msg: &str) -> anyhow::Error {
    fail(ErrorCode::Forbidden, msg)
}
fn members(s: &Session, vault: VaultId, device: DeviceId) -> Result<()> {
    if device == s.id
        || !s
            .vaults
            .get(&vault)
            .is_some_and(|v| v.is_member(&s.id) && v.is_member(&device))
    {
        return Err(forbidden(
            "read approval needs two current members of the named vault",
        ));
    }
    Ok(())
}
fn verified_caller(info: &CallerInfo) -> Result<String> {
    let err = || {
        forbidden(
            "experimental mobile read requires the Mac agent to verify the socket caller's code signature and audit token",
        )
    };
    if info.check != Check::Signature || info.class != CallerClass::Caller || info.pid == 0 {
        return Err(err());
    }
    let sig = info
        .signature
        .as_ref()
        .filter(|s| s.valid)
        .ok_or_else(err)?;
    let path = info
        .program
        .as_ref()
        .filter(|p| std::path::Path::new(p).is_absolute() && !p.ends_with("…(cut)"))
        .ok_or_else(err)?;
    let hash = sig
        .cdhash
        .as_ref()
        .filter(|h| h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(err)?;
    let version = info.pid_version.ok_or_else(err)?;
    // Process ancestry is an AI *hint*. A CLI caller's claimed OpenCode session,
    // even if set, is not a verified OpenCode identity. Don't display it as one.
    let context = caller::ai_host(info).map_or_else(
        || "AI session claimed (not verified)".into(),
        |name| format!("{name} (ancestry hint)"),
    );
    Ok(format!(
        "{path:?} · pid {}:{version} · cdhash {hash} · {context}",
        info.pid
    ))
}
fn scope(s: &Session, found: &secrets::Found, who: &str) -> Result<ReadScope> {
    if found.ssh_secret {
        return Err(forbidden(
            "SSH private-key export cannot be approved remotely",
        ));
    }
    if found.secret.file {
        return Err(forbidden("file fields cannot be released by read"));
    }
    Ok(ReadScope {
        vault: found.vault_id.clone(),
        item: found.secret.item.clone(),
        field: found.secret.field.clone(),
        title: found.secret.title.clone(),
        caller: who.into(),
        origin_name: s.meta.device_name.clone(),
    })
}
impl Agent {
    /// Only called from `agents_admin` after its caller gate. `off` or replacement
    /// drops the old sender, cancelling every outstanding use of that designation.
    pub(super) async fn experimental_approver_set(
        &self,
        vault: Option<&str>,
        device: Option<&str>,
        passphrase: Option<Zeroizing<String>>,
        conv: &Conversation,
    ) -> Result<Reply> {
        let interrupted = self.interrupts.subscribe();
        let device = device
            .map(session::unhex)
            .transpose()?
            .map(DeviceId::from_bytes);
        let vault = self.with_data(|s| {
            let id = s.resolve(vault)?;
            if let Some(d) = device {
                members(s, id, d)?;
            }
            Ok(id)
        })?;
        let reason = match device {
            Some(d) => format!(
                "let device {d} approve individual AI reads of vault {vault} until this Mac locks"
            ),
            None => format!("disable remote read approval for vault {vault}"),
        };
        let _busy = self.busy();
        self.prove_user(conv, passphrase, &reason).await?;
        self.with_data(|s| {
            if interrupted.has_changed().unwrap_or(true) {
                return Err(forbidden(
                    "session changed during read-approver designation",
                ));
            }
            match device {
                Some(d) => {
                    members(s, vault, d)?;
                    s.approvers.insert(
                        vault,
                        Designation {
                            device: d,
                            lifetime: watch::channel(()).0,
                        },
                    );
                }
                None => {
                    s.approvers.remove(&vault);
                }
            }
            Ok(Reply::Done)
        })
    }
    pub(super) async fn experimental_mobile_read(
        &self,
        caller: &CallerInfo,
        refs: &[String],
        conv: &Conversation,
    ) -> Result<(Reply, DeviceId)> {
        let [reference] = refs else {
            return Err(forbidden(
                "experimental mobile read covers exactly one field",
            ));
        };
        if !caller::is_ai(caller) {
            return Err(forbidden("experimental mobile read is only for AI callers"));
        }
        self.ai_rate(caller)?;
        let who = verified_caller(caller)?;
        let reference = Reference::parse(reference).map_err(|e| anyhow!(e))?;
        let mut interrupts = self.interrupts.subscribe();
        let (node, peer, expected, vault, mut lifetime) = self.with_data(|s| {
            let found = secrets::find(s, &reference, crate::config::wall_clock())?;
            let vault = VaultId::from_bytes(session::unhex(&found.vault_id)?);
            let cap = s.approvers.get(&vault).ok_or_else(|| {
                forbidden("no experimental read approver designated for this vault in this unlocked session")
            })?;
            members(s, vault, cap.device)?;
            Ok((
                s.node.clone(), s.addr_of(&cap.device), scope(s, &found, &who)?,
                vault, cap.lifetime.subscribe(),
            ))
        })?;
        let device = DeviceId::from_bytes(peer.id);
        let witness = lifetime.clone();
        let exact = |s: &Session| -> Result<()> {
            members(s, vault, device)?;
            if !s.approvers.get(&vault).is_some_and(|c| {
                c.device == device && c.lifetime.subscribe().same_channel(&witness)
            }) {
                return Err(forbidden("read approver designation changed"));
            }
            Ok(())
        };
        // Unlike local Touch ID, an unattended network wait does not extend
        // idle unlock: a lock cancels the request and its designation.
        let request = node.request_read_approval(peer, expected.clone(), || {
            self.with_data(|s| exact(s)).is_ok()
        });
        let approved = tokio::select! {
            _ = conv.closed() => return Err(forbidden("requesting socket closed")),
            _ = interrupts.changed() => return Err(forbidden("session changed during approval")),
            _ = lifetime.changed() => return Err(forbidden("read approver designation changed")),
            result = request => result.map_err(|e| fail(ErrorCode::Forbidden, format!("remote read not approved: {e}")))?,
        };
        // Never re-resolve the title, prefix or default vault after consent. Re-read
        // the exact item and recheck its display metadata, membership and designation
        // atomically in the unlocked session; keep no reusable grant or value cache.
        self.with_data(|s| {
            if interrupts.has_changed().unwrap_or(true) || *conv.closed.borrow() {
                return Err(forbidden("request no longer outstanding"));
            }
            exact(s)?;
            let reference = Reference {
                vault: Some(expected.vault.clone()),
                item: expected.item.clone(),
                field: expected.field.clone(),
            };
            let found = secrets::find(s, &reference, crate::config::wall_clock())?;
            approved
                .consume(&scope(s, &found, &who)?, device.as_bytes())
                .map_err(|_| forbidden("approved read no longer matches"))?;
            Ok((
                Reply::Secrets {
                    secrets: vec![found.secret],
                },
                device,
            ))
        })
    }
}
