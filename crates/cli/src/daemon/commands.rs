//! Command dispatch: what each control request runs once the connection has
//! authenticated it, and the change stream a watcher follows.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, bail};
use deadbolt_net::PeerId;
use tokio::io::AsyncWriteExt;

use super::connection::Conversation;
use super::session::Session;
use super::{
    Daemon, ErrorCode, INTERRUPTED, autofill, fail, generate, grants, items, macos_autofill,
    mirror, pairing, secrets, session, sync, watchers,
};
use crate::protocol::{CallerInfo, Change, Command, Message, Reply};

impl Daemon {
    pub(super) async fn dispatch(
        self: Arc<Self>,
        caller: &CallerInfo,
        command: Command,
        conv: &Conversation,
    ) -> Result<Reply> {
        if matches!(command, Command::Status | Command::Stop) {
            return self.run(command, conv).await;
        }
        self.ai_gate(caller, &command, conv).await?;
        // A one-time code isn't use: a client showing one asks every period,
        // which would otherwise hold the vault open for as long as it shows.
        // Nor is a browser looking at a page: it asks for every page loaded.
        // Nor are sends, which never touch the vault, nor SSH key generation.
        // Nor is bringing the app forward.
        let send = matches!(
            command,
            Command::SendCreate { .. }
                | Command::SendList
                | Command::SendShow { .. }
                | Command::SendRevoke { .. }
                | Command::SendWait { .. }
                | Command::SshGenerate { .. }
                | Command::SshInspect { .. }
        );
        let used = !send
            && !matches!(
                command,
                Command::ItemCode { .. }
                    | Command::SiteLogins { .. }
                    | Command::SiteCheck { .. }
                    | Command::FormItems { .. }
                    | Command::PasskeyList { .. }
                    | Command::SiteGenerateCheck { .. }
                    | Command::SiteGenerateDrop { .. }
                    | Command::AppActivate { .. }
                    // An AI signing in unattended mustn't hold the vault open.
                    | Command::AgentLogins { .. }
                    | Command::AgentFill { .. }
                    | Command::AgentPasskeyGet { .. }
                    // macOS AutoFill lookups run in the background without use.
                    | Command::AutofillStatus
                    | Command::AutofillIdentities
                    | Command::AutofillList { .. }
            );
        // Nor does a sync from 1Password hold the vault open: `op` may hang,
        // and a lock stops it before it writes anything. Nor does waiting
        // for a send to be picked up, or for an app to start.
        let busy = !matches!(
            command,
            Command::SyncOnePassword { .. }
                | Command::SendWait { .. }
                | Command::AppActivate { .. }
        );
        if busy {
            self.busy.fetch_add(1, Ordering::SeqCst);
        }
        if used {
            self.touch();
        }
        let result = self.clone().run(command, conv).await;
        if used {
            self.touch();
        }
        if busy {
            self.busy.fetch_sub(1, Ordering::SeqCst);
        }
        result
    }

    pub(super) async fn run(
        self: Arc<Self>,
        command: Command,
        conv: &Conversation,
    ) -> Result<Reply> {
        match command {
            Command::Status => Ok(Reply::Status(Box::new(self.status()))),
            Command::Stop => {
                self.cancel_biometric_prompt();
                Ok(Reply::Done)
            }
            Command::Setup {
                passphrase,
                device_name,
            } => {
                self.setup(passphrase, device_name).await?;
                Ok(Reply::Done)
            }
            Command::Unlock {
                passphrase,
                timeout_secs,
            } => {
                self.unlock(passphrase, timeout_secs).await?;
                Ok(Reply::Done)
            }
            Command::UnlockBiometric { timeout_secs } => {
                let outcome = tokio::select! {
                    res = self.unlock_biometric(timeout_secs) => res,
                    () = conv.closed() => return Err(fail(ErrorCode::Cancelled, "the request was cancelled")),
                };
                match outcome {
                    Ok(()) => Ok(Reply::Done),
                    Err(error) if macos_autofill::is_biometric_cancelled(&error) => {
                        Err(fail(ErrorCode::Cancelled, error.to_string()))
                    }
                    Err(error) => Err(error),
                }
            }
            Command::TouchIdSet { enabled } => {
                self.set_touch_id(enabled).await?;
                Ok(Reply::Done)
            }
            Command::Lock => {
                self.lock().await;
                Ok(Reply::Done)
            }
            Command::Watch { .. } => bail!("watch streams on a connection of its own"),
            Command::AppActivate { token } => Ok(if self.watchers.activate(token).await {
                Reply::Activated
            } else {
                Reply::NoApp
            }),
            Command::ActivityReport { .. } => bail!("reports are answered as they arrive"),
            Command::ActivityList {
                since,
                limit,
                before,
            } => self.activity_list(since, limit, before),
            Command::VaultCreate { name } => {
                let vault = self.with(|s| {
                    let id = s.create_vault(&name)?;
                    Ok(s.vault_info(&id))
                })?;
                Ok(Reply::Vault { vault })
            }
            Command::VaultList => Ok(Reply::Vaults {
                vaults: self.with(|s| Ok(s.vault_infos()))?,
            }),
            Command::VaultRename { vault, name } => {
                let vault = self.with(|s| {
                    let id = s.resolve(Some(&vault))?;
                    if s.name_taken(&name, Some(id)) {
                        bail!("a vault named {name} already exists");
                    }
                    s.update(id, |v, secret| {
                        v.rename(secret, name.clone()).context("renaming")
                    })?;
                    Ok(s.vault_info(&id))
                })?;
                self.sync_now.notify_one();
                Ok(Reply::Vault { vault })
            }
            Command::VaultDefault { vault } => {
                let vault = self.with(|s| {
                    let id = s.resolve(Some(&vault))?;
                    s.meta.default_vault = Some(id);
                    s.save_meta()?;
                    Ok(s.vault_info(&id))
                })?;
                Ok(Reply::Vault { vault })
            }
            Command::Devices { vault } => {
                let devices = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let connected: HashSet<PeerId> = s.node.connected_peers().into_iter().collect();
                    let mut devices: Vec<_> = s
                        .vault(&id)
                        .members()
                        .map(|member| s.device_info(&member, &connected))
                        .collect();
                    devices
                        .sort_by(|a, b| (!a.this, &a.name, &a.id).cmp(&(!b.this, &b.name, &b.id)));
                    Ok(devices)
                })?;
                Ok(Reply::Devices { devices })
            }
            Command::DeviceRemove { vault, device } => {
                let (vault, device) = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let target = s.resolve_device(&id, &device)?;
                    if target == s.id {
                        bail!("cannot remove this device; remove it from another device");
                    }
                    let info = s.device_info(&target, &HashSet::new());
                    s.update(id, |v, secret| {
                        v.remove(secret, target).context("removing device")
                    })?;
                    self.refresh(s);
                    Ok((s.vault_info(&id), info))
                })?;
                self.sync_now.notify_one();
                Ok(Reply::Device { vault, device })
            }
            Command::Sync { vault } => {
                let only =
                    self.with(|s| vault.as_deref().map(|v| s.resolve(Some(v))).transpose())?;
                self.wait_ready().await?;
                Ok(Reply::Sync {
                    peers: sync::sync_all(&self, only).await?,
                })
            }
            Command::Join {
                device_name,
                passphrase,
            } => pairing::join(&self, conv, device_name, passphrase).await,
            Command::Pair { code, vault } => pairing::pair(&self, conv, code, vault).await,
            Command::ItemGet {
                vault,
                query,
                otp,
                ssh_private,
                files,
                deleted,
            } => Ok(Reply::Item {
                item: self.with(|s| {
                    items::get(
                        s,
                        vault.as_deref(),
                        &query,
                        otp,
                        ssh_private,
                        &files,
                        deleted,
                    )
                })?,
            }),
            Command::ItemCode { vault, query } => Ok(Reply::Code {
                code: self.with(|s| {
                    items::code(s, vault.as_deref(), &query, crate::config::wall_clock())
                })?,
            }),
            Command::ItemList {
                vault,
                query,
                kind,
                deleted,
                tags,
                favorites,
            } => Ok(Reply::Items {
                items: self.with(|s| {
                    items::list_filtered(
                        s,
                        vault.as_deref(),
                        &query,
                        kind.as_deref(),
                        deleted,
                        &tags,
                        favorites,
                    )
                })?,
            }),
            Command::TagList { vault } => Ok(Reply::Tags {
                tags: self.with(|s| items::tags(s, vault.as_deref()))?,
            }),
            Command::ItemNew {
                vault,
                kind,
                name,
                fields,
                favorite,
                tags,
            } => self.item_write(|s| {
                items::create_with(s, vault.as_deref(), &kind, name, fields, favorite, tags)
            }),
            Command::ItemSet {
                vault,
                query,
                fields,
                name,
                unset,
                favorite,
                add_tags,
                remove_tags,
            } => self.item_write(|s| {
                items::set_with(
                    s,
                    vault.as_deref(),
                    &query,
                    fields,
                    name,
                    &unset,
                    favorite,
                    &add_tags,
                    &remove_tags,
                )
            }),
            Command::ItemUnset {
                vault,
                query,
                field,
            } => self.item_write(|s| items::unset(s, vault.as_deref(), &query, &field)),
            Command::ItemRemove { vault, query } => {
                // Resolve once before consent: a renamed item, default-vault
                // change or sync during Touch ID must not retarget the delete.
                let (vault, id, passkey) = self.with(|s| {
                    let vault = s.resolve(vault.as_deref())?;
                    let item = items::find_live(s.vault(&vault), &query)?;
                    Ok((vault, item.id, item.kind == "passkey"))
                })?;
                if passkey {
                    self.verify_user(
                        conv,
                        crate::protocol::Verify::Preferred,
                        "delete a saved passkey",
                    )
                    .await?;
                }
                self.item_write(|s| items::remove_id(s, vault, id))
            }
            Command::ItemRestore { vault, query } => {
                self.item_write(|s| items::restore(s, vault.as_deref(), &query))
            }
            Command::Import {
                vault,
                export,
                files,
                apply,
            } => {
                // Mapping needs no session: it runs before taking the lock.
                let parsed = crate::import::parse_with(&export, &files)?;
                drop((export, files));
                let report = self.with(|s| items::import(s, vault.as_deref(), parsed, apply))?;
                if apply {
                    self.sync_now.notify_one();
                }
                Ok(Reply::Import { report })
            }
            Command::SyncOnePassword {
                vault,
                account,
                op_vaults,
                dry_run,
            } => {
                let Ok(_syncing) = self.syncing_op.try_lock() else {
                    bail!("already syncing from 1Password: try again when it finishes");
                };
                let mut interrupts = self.interrupts.subscribe();
                // Locked fails here, before 1Password is asked anything. `op`
                // runs outside the lock: it may wait on 1Password's prompt.
                let known = self.with(|s| mirror::known(s, vault.as_deref()))?;
                let fetch = mirror::fetch(self.op(), account.as_deref(), &op_vaults, &known);
                // Dropping the fetch kills `op`.
                let fetched = tokio::select! {
                    fetched = fetch => fetched?,
                    _ = interrupts.changed() => return Err(fail(ErrorCode::Locked, INTERRUPTED)),
                    () = conv.closed() => bail!("the sync from 1Password was cancelled"),
                };
                let report = self.with(|s| {
                    // A lock bumps `interrupts` before it lets go of the vault.
                    if interrupts.has_changed().unwrap_or(true) {
                        return Err(fail(ErrorCode::Locked, INTERRUPTED));
                    }
                    mirror::apply(s, &known, fetched, !dry_run)
                })?;
                if report.applied && report.changed() {
                    self.sync_now.notify_one();
                }
                Ok(Reply::Mirror { report })
            }
            Command::SendCreate {
                secret,
                sealed,
                opens,
                ttl_secs,
                label,
            } => {
                self.send_create(secret, sealed, opens, ttl_secs, label)
                    .await
            }
            Command::SendList => Ok(self.send_list().await),
            Command::SendShow { id } => self.send_show(&id).await,
            Command::SendRevoke { id } => self.send_revoke(&id).await,
            Command::SendWait { id } => self.send_wait(&id, conv).await,
            Command::Generate {
                length,
                symbols,
                url,
            } => Ok(Reply::Password {
                password: deadbolt_core::site_password::generate_for_url(
                    url.as_deref(),
                    length,
                    symbols,
                )?,
            }),
            Command::SiteLogins { origin } => {
                let (site, logins) = self.with(|s| autofill::list(s, &origin))?;
                Ok(Reply::SiteLogins { site, logins })
            }
            Command::SiteFill {
                origin,
                login,
                want,
            } => Ok(Reply::SiteFill {
                values: self.with(|s| {
                    autofill::fill(s, &origin, &login, &want, crate::config::wall_clock())
                })?,
            }),
            Command::SiteGenerateCheck { origin, field } => {
                generate::check(&origin, &generate::field_rules(&field))?;
                Ok(Reply::Done)
            }
            Command::SiteGenerate { origin, field } => {
                let password = crate::protocol::Secret::new(
                    generate::generate(&origin, &generate::field_rules(&field))?.as_str(),
                );
                let id = self.with(|s| {
                    s.generated
                        .offer(&origin, password.clone(), std::time::Instant::now())
                })?;
                Ok(Reply::SiteGenerated { password, id })
            }
            Command::SiteGenerateKeep { origin, id } => {
                self.with(|s| s.generated.keep(&origin, &id, std::time::Instant::now()))?;
                Ok(Reply::Done)
            }
            Command::SiteGenerateDrop { origin, id } => {
                self.with(|s| {
                    s.generated.drop_candidate(&origin, &id);
                    Ok(())
                })?;
                Ok(Reply::Done)
            }
            Command::SiteCheck {
                origin,
                username,
                password,
            } => {
                let (status, matches) = self.with(|s| {
                    let password =
                        s.generated
                            .resolve(&origin, &password, std::time::Instant::now())?;
                    autofill::check(s, &origin, username.as_deref(), &password)
                })?;
                Ok(Reply::SiteCheck { status, matches })
            }
            Command::SiteSave {
                origin,
                login,
                title,
                url,
                username,
                password,
            } => {
                let (login, created) = self.with(|s| {
                    let secret =
                        s.generated
                            .resolve(&origin, &password, std::time::Instant::now())?;
                    let saved = autofill::save(
                        s,
                        autofill::Save {
                            origin: &origin,
                            login: login.as_ref(),
                            title: &title,
                            url: &url,
                            username: &username,
                            password: &secret,
                        },
                    )?;
                    s.generated.saved(&password);
                    Ok(saved)
                })?;
                self.sync_now.notify_one();
                Ok(Reply::SiteSaved { login, created })
            }
            Command::SiteLink {
                origin,
                title,
                url,
                provider,
                account,
            } => {
                let (login, created) = self.with(|s| {
                    autofill::link(
                        s,
                        autofill::Link {
                            origin: &origin,
                            title: &title,
                            url: &url,
                            provider: &provider,
                            account: &account,
                        },
                    )
                })?;
                if created {
                    self.sync_now.notify_one();
                }
                Ok(Reply::SiteSaved { login, created })
            }
            Command::FormItems { origin, kinds } => self.form_items(&origin, &kinds),
            Command::FormFill {
                origin,
                item,
                fields,
            } => self.form_fill(&origin, &item, &fields, conv).await,
            command @ (Command::PasskeyList { .. }
            | Command::PasskeyCreate { .. }
            | Command::PasskeyGet { .. }) => self.passkey(command, conv).await,
            Command::AgentClientAdd { .. }
            | Command::AgentGrantSet { .. }
            | Command::SecretGrantSet { .. }
            | Command::Resolve { .. }
            | Command::Health { .. }
            | Command::HealthIgnore { .. }
            | Command::BreachChecksSet { .. } => {
                bail!("pairing, grants, references and health are answered with the caller")
            }
            Command::AgentClientList => Ok(Reply::AgentClients {
                clients: self.with(|s| grants::list_clients(s))?,
            }),
            Command::AgentClientRemove { id } => {
                let (id, _) = self.with(|s| grants::remove_client(s, &id))?;
                self.forget_agent_client(&id);
                Ok(Reply::Done)
            }
            Command::AgentGrantList => Ok(Reply::AgentGrants {
                grants: self.with(|s| grants::list_grants(s, session::now()))?,
            }),
            Command::AgentGrantRemove { id } => {
                // Either kind of grant: a sign-in grant, else a secret grant.
                self.with(|s| match grants::remove_grant(s, &id) {
                    Err(error) if crate::client::code(&error) == Some(ErrorCode::NotFound) => {
                        secrets::remove_grant(s, &id)
                    }
                    removed => removed.map(drop),
                })?;
                Ok(Reply::Done)
            }
            Command::SecretGrantList => Ok(Reply::SecretGrants {
                grants: self.with(|s| secrets::list_grants(s, session::now()))?,
            }),
            Command::SshGenerate { kind, comment } => self.ssh_generate(kind, comment.as_deref()),
            Command::SshInspect {
                private_key,
                passphrase,
                comment,
            } => self.ssh_inspect(&private_key, passphrase.as_ref(), comment.as_deref()),
            command @ (Command::AgentLogins { .. }
            | Command::AgentFill { .. }
            | Command::AgentPasskeyGet { .. }) => self.agent_client(command),
            command @ (Command::AutofillStatus
            | Command::AutofillIdentities
            | Command::AutofillList { .. }
            | Command::AutofillFill { .. }
            | Command::AutofillPasskeyGet { .. }
            | Command::AutofillPasskeyCreate { .. }) => self.macos_autofill(command, conv).await,
        }
    }

    /// Runs a local item write, then syncs it out right away.
    pub(super) fn item_write(
        &self,
        f: impl FnOnce(&mut Session) -> Result<crate::protocol::ItemInfo>,
    ) -> Result<Reply> {
        let item = self.with(f)?;
        self.sync_now.notify_one();
        Ok(Reply::Item { item })
    }

    /// Streams changes to one watcher until it hangs up or the daemon stops.
    /// A watcher that stops reading is dropped after [`watchers::SEND_TIMEOUT`];
    /// publishing never waits for it.
    pub(super) async fn watch(&self, conv: &Conversation, app: bool) -> Result<()> {
        let subscription = self.watchers.subscribe(app);
        let send = |change| async move {
            tokio::time::timeout(
                watchers::SEND_TIMEOUT,
                conv.send(&Message::Change { change }),
            )
            .await
            .context("the watcher stopped reading")?
        };
        send(Change::Watching).await?;
        loop {
            let changes = tokio::select! {
                changes = subscription.next() => changes,
                () = conv.closed() => return Ok(()),
            };
            for change in changes {
                let stopping = change == Change::Stopping;
                send(change).await?;
                if stopping {
                    conv.send(&Message::Ok { reply: Reply::Done }).await?;
                    conv.write.lock().await.shutdown().await?;
                    return Ok(());
                }
            }
        }
    }
}
