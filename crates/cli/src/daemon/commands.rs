//! Command dispatch: what each control request runs once the connection has
//! authenticated it, and the change stream a watcher follows.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, bail};
use deadbolt_client::telemetry::Span;
use deadbolt_core::DeviceId;
use tokio::io::AsyncWriteExt;

use super::connection::Conversation;
use super::session::Session;
use super::{
    Daemon, ErrorCode, autofill, fail, generate, items, macos_autofill, pairing, sync, watchers,
};
use crate::protocol::{Change, Command, Message, Reply};

impl Daemon {
    /// Runs `command` in a `daemon.command` span when telemetry is on. The
    /// span names the command and the outcome, and an error's code, never
    /// what the request carried or the error's message.
    pub(super) async fn dispatch(
        self: Arc<Self>,
        command: Command,
        conv: &Conversation,
        can_show_kits: bool,
    ) -> Result<Reply> {
        let mut span = Span::root("daemon.command").attr("command", command.name());
        let result = self.dispatch_command(command, conv, can_show_kits).await;
        match &result {
            Ok(_) => span.ok(),
            Err(error) => span.fail(crate::client::code(error).map(ErrorCode::name)),
        }
        span.end();
        result
    }

    async fn dispatch_command(
        self: Arc<Self>,
        command: Command,
        conv: &Conversation,
        can_show_kits: bool,
    ) -> Result<Reply> {
        // Whether it is use and holds the daemon busy: `Command::policy`.
        let policy = command.policy();
        let (used, busy) = (policy.keepalive, policy.busy);
        if busy {
            self.busy.fetch_add(1, Ordering::SeqCst);
        }
        if used {
            self.touch();
        }
        let result = self.clone().run(command, conv, can_show_kits).await;
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
        can_show_kits: bool,
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
                let migrated = self
                    .unlock_for(passphrase, timeout_secs, can_show_kits)
                    .await?;
                // DELETABLE(v1-migrate): back to `Reply::Done` alone.
                Ok(if migrated.is_empty() {
                    Reply::Done
                } else {
                    Reply::Unlocked { migrated }
                })
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
                let (vault, words) = self.with(|s| {
                    let (id, words) = s.create_vault_with_kit(&name)?;
                    Ok((s.vault_info(&id), words))
                })?;
                Ok(Reply::VaultCreated {
                    vault,
                    recovery_kit: crate::protocol::Secret::new(words.as_str()),
                })
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
                    let connected: HashSet<DeviceId> =
                        s.connected_devices(s.node.connected_peers());
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
            command @ (Command::DeviceRemoveStolen { .. }
            | Command::VaultConfirmReinstated { .. }
            | Command::VaultStatus { .. }
            | Command::RecoveryRotate { .. }) => self.recovery_command(command),
            command @ (Command::RemoteSet { .. }
            | Command::RemoteShow { .. }
            | Command::RemoteSync { .. }
            | Command::RemoteRemove { .. }
            | Command::Recover { .. }) => self.remote_command(command).await,
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
                let report =
                    self.with(|s| super::import::import(s, vault.as_deref(), parsed, apply))?;
                if apply {
                    self.sync_now.notify_one();
                }
                Ok(Reply::Import { report })
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
                )?
                .into(),
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
                let id =
                    self.with(|s| s.generated.offer(&origin, password.clone(), s.elapsed()))?;
                Ok(Reply::SiteGenerated { password, id })
            }
            Command::SiteGenerateKeep { origin, id } => {
                self.with(|s| s.generated.keep(&origin, &id, s.elapsed()))?;
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
                    let password = s.generated.resolve(&origin, &password, s.elapsed())?;
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
                    let secret = s.generated.resolve(&origin, &password, s.elapsed())?;
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
                            test_hosts: crate::config::test_env("DEADBOLT_TEST_PROVIDER_HOSTS")
                                .as_deref()
                                == Some("1"),
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
            Command::RunTaint | Command::RunUntaint { .. } => {
                bail!("runs are answered with the caller")
            }
            Command::Resolve { .. }
            | Command::Health { .. }
            | Command::HealthIgnore { .. }
            | Command::BreachChecksSet { .. } => {
                bail!("references and health are answered with the caller")
            }
            Command::SshGenerate { kind, comment } => self.ssh_generate(kind, comment.as_deref()),
            Command::SshInspect {
                private_key,
                passphrase,
                comment,
            } => self.ssh_inspect(&private_key, passphrase.as_ref(), comment.as_deref()),
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
