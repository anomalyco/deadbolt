//! The background worker and watch threads that speak the daemon's socket
//! protocol, posting replies into the UI's inbox and waking the window.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadbolt_client::export;
use deadbolt_client::protocol::{
    Change, Code, Command, ItemInfo, Reply, Secret, Status, code_field,
};
use deadbolt_client::{Error, Launch, Paths};
use rune::Waker;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::{Done, Failure, ImportFailure, Imported, Job, Values, next_jobs};

/// The first wait before watching again after the daemon went away.
const RECONNECT_FIRST: Duration = Duration::from_millis(100);
/// The longest wait between attempts while no daemon is running.
const RECONNECT_MAX: Duration = Duration::from_secs(2);

/// Posts to the UI's inbox and wakes the window.
#[derive(Clone)]
pub(super) struct Post {
    pub(super) results: Sender<Done>,
    pub(super) waker: Arc<Mutex<Option<Waker>>>,
}

impl Post {
    /// False once the app is gone.
    fn send(&self, done: Done) -> bool {
        if self.results.send(done).is_err() {
            return false;
        }
        let wake = self.waker.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(wake) = wake {
            wake();
        }
        true
    }
}

/// Keeps a watch stream open until `stop` fires or the app is gone, as the
/// app's main window when `app`. It never starts the daemon: that's the
/// worker's `Connect` and `Unlock`.
pub(super) fn watch(paths: Paths, app: bool, post: Post, mut stop: oneshot::Receiver<()>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    runtime.block_on(async {
        let mut delay = RECONNECT_FIRST;
        loop {
            tokio::select! {
                gone = follow(&paths, app, &post, &mut delay) => if gone { return },
                _ = &mut stop => return,
            }
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                _ = &mut stop => return,
            }
            delay = (delay * 2).min(RECONNECT_MAX);
        }
    });
}

/// Follows one watch stream to its end. True once the app is gone.
async fn follow(paths: &Paths, app: bool, post: &Post, delay: &mut Duration) -> bool {
    let Ok(mut stream) = deadbolt_client::watch(paths, app).await else {
        return false;
    };
    loop {
        match stream.next().await {
            Ok(Some(change)) => {
                // Only a daemon that accepted the watch resets the backoff; one
                // that refuses it (an older protocol) keeps it growing.
                if change == Change::Watching {
                    *delay = RECONNECT_FIRST;
                }
                if !post.send(Done::Changed(change)) {
                    return true;
                }
            }
            // The daemon said `stopping` before ending the stream.
            Ok(None) => return false,
            Err(_) => return !post.send(Done::WatchLost),
        }
    }
}

pub(super) fn work(paths: Paths, launch: Launch, requests: Receiver<Job>, main: Post) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let failure = Failure {
                code: None,
                message: format!("starting the daemon thread: {error}"),
            };
            main.send(Done::Connected(Err(failure)));
            return;
        }
    };
    let mut queue = VecDeque::new();
    loop {
        if queue.is_empty() {
            match requests.recv() {
                Ok(job) => queue.push_back(job),
                Err(_) => return,
            }
        }
        queue.extend(requests.try_iter());
        let mut jobs = next_jobs(&mut queue);
        if jobs.len() > 1 {
            if !all(
                &runtime,
                jobs,
                |job| run(&paths, &launch, job),
                |done| main.send(done),
            ) {
                return;
            }
            continue;
        }
        let Some(job) = jobs.pop() else {
            continue;
        };
        if let Job::SyncOnePassword { seq } = job {
            let failed = move |error: std::io::Error| Done::Mirrored {
                seq,
                result: Err(Failure {
                    code: None,
                    message: format!("starting the sync: {error}"),
                }),
            };
            let paths = paths.clone();
            let thread = main.clone();
            let spawned = std::thread::Builder::new()
                .name("deadbolt-1password".into())
                .spawn(move || {
                    let done = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime.block_on(mirror(&paths, seq)),
                        Err(error) => failed(error),
                    };
                    thread.send(done);
                });
            if let Err(error) = spawned
                && !main.send(failed(error))
            {
                return;
            }
            continue;
        }
        if !main.send(runtime.block_on(run(&paths, &launch, job))) {
            return;
        }
    }
}

/// Runs `jobs` at once, posting each reply as it comes; false once the app
/// has gone.
fn all<'a, F: Future<Output = Done> + 'a>(
    runtime: &tokio::runtime::Runtime,
    jobs: Vec<Job>,
    run: impl Fn(Job) -> F,
    mut post: impl FnMut(Done) -> bool,
) -> bool {
    let mut running: Vec<_> = jobs.into_iter().map(|job| Box::pin(run(job))).collect();
    let mut live = true;
    runtime.block_on(std::future::poll_fn(|cx| {
        running.retain_mut(|f| match f.as_mut().poll(cx) {
            std::task::Poll::Ready(done) => {
                live &= post(done);
                false
            }
            std::task::Poll::Pending => true,
        });
        if running.is_empty() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }));
    live
}

async fn run(paths: &Paths, launch: &Launch, job: Job) -> Done {
    match job {
        Job::Connect => Done::Connected(
            deadbolt_client::ensure_running(paths, launch)
                .await
                .map_err(Failure::from),
        ),
        Job::Status => Done::Status(deadbolt_client::status(paths).await),
        // The daemon may have stopped while the unlock screen was up.
        Job::Unlock(passphrase) => {
            let command = Command::Unlock {
                passphrase,
                timeout_secs: None,
            };
            Done::Unlocked(
                status_after(paths, Some(launch), command, false)
                    .await
                    .map_err(|(f, _)| f),
            )
        }
        Job::UnlockBiometric => {
            let command = Command::UnlockBiometric { timeout_secs: None };
            Done::UnlockedBiometric(status_after(paths, Some(launch), command, true).await)
        }
        Job::TouchIdSet(enabled) => Done::TouchIdSet {
            enabled,
            result: status_after(paths, None, Command::TouchIdSet { enabled }, true).await,
        },
        Job::Lock => Done::Locked(
            deadbolt_client::simple(paths, Command::Lock)
                .await
                .map(drop)
                .map_err(Failure::from),
        ),
        Job::List { generation } => {
            let command = Command::ItemList {
                vault: None,
                query: Vec::new(),
                kind: None,
                deleted: false,
                tags: Vec::new(),
                favorites: false,
            };
            let result = call(paths, command, |r| match r {
                Reply::Items { items } => Some(items),
                _ => None,
            })
            .await;
            Done::Items { generation, result }
        }
        Job::Get { id, seq, .. } => Done::Item {
            seq,
            result: values(paths, id, true).await,
        },
        Job::Peek { id, epoch, .. } => Done::Peeked {
            id: id.clone(),
            epoch,
            result: values(paths, id, false).await,
        },
        Job::Code { id, seq } => Done::Code {
            seq,
            result: code(paths, id).await,
        },
        Job::Import { path, apply, seq } => {
            let mut applied = false;
            let result = import(paths, &path, apply, &mut applied).await;
            Done::Imported {
                seq,
                applied,
                result,
            }
        }
        Job::SyncOnePassword { seq } => mirror(paths, seq).await,
        Job::Activity { seq } => crate::activity::list(paths, seq).await,
        Job::Report {
            action,
            item,
            title,
            field,
        } => crate::activity::report(paths, action, item, title, field).await,
        Job::Agents { seq, revoke } => crate::agents::run(paths, seq, revoke).await,
        Job::Trash { seq, restore } => crate::trash::run(paths, seq, restore).await,
        Job::TrashItem { id, seq } => crate::trash::item(paths, id, seq).await,
        Job::Health { seq, online } => crate::health::load(paths, seq, online).await,
        Job::HealthIgnore {
            id,
            kind,
            ignored,
            seq,
        } => crate::health::set_ignored(paths, id, kind, ignored, seq).await,
        Job::BreachChecksSet { enabled, seq } => {
            crate::health::set_breach_checks(paths, enabled, seq).await
        }
        Job::Create {
            kind,
            name,
            fields,
            favorite,
            tags,
            seq,
        } => {
            let command = Command::ItemNew {
                vault: None,
                kind,
                name,
                fields,
                favorite,
                tags,
            };
            Done::Saved {
                seq,
                result: item(paths, command).await,
            }
        }
        Job::Save {
            id,
            name,
            fields,
            unset,
            favorite,
            add_tags,
            remove_tags,
            seq,
        } => {
            let command = Command::ItemSet {
                vault: None,
                query: vec![id],
                fields,
                name,
                unset,
                favorite,
                add_tags,
                remove_tags,
            };
            Done::Saved {
                seq,
                result: item(paths, command).await,
            }
        }
        Job::Favorite { id, favorite, seq } => {
            let command = Command::ItemSet {
                vault: None,
                query: vec![id],
                fields: Vec::new(),
                name: None,
                unset: Vec::new(),
                favorite: Some(favorite),
                add_tags: Vec::new(),
                remove_tags: Vec::new(),
            };
            Done::Favorited {
                seq,
                result: item(paths, command).await,
            }
        }
        Job::SaveFile { id, field, path } => {
            Done::FileSaved(save_file(paths, id, &field, &path).await)
        }
        Job::Remove { id, seq } => {
            let command = Command::ItemRemove {
                vault: None,
                query: vec![id],
            };
            Done::Removed {
                seq,
                result: item(paths, command).await,
            }
        }
        Job::Generate {
            length,
            symbols,
            url,
            seq,
        } => {
            let command = Command::Generate {
                length,
                symbols,
                url,
            };
            let result = call(paths, command, |r| match r {
                Reply::Password { password } => Some(password),
                _ => None,
            })
            .await;
            Done::Generated { seq, result }
        }
        Job::SshGenerate { kind, comment, seq } => {
            let command = Command::SshGenerate { kind, comment };
            let result = call(paths, command, |r| match r {
                Reply::SshGenerated {
                    private_key,
                    public_key,
                    fingerprint,
                    comment,
                } => Some(crate::ssh::SshGeneratedKey {
                    private_key: Zeroizing::new(private_key.expose().to_owned()),
                    public_key,
                    fingerprint,
                    comment,
                }),
                _ => None,
            })
            .await;
            Done::SshGenerated { seq, result }
        }
        Job::SshImportFile { path, comment, seq } => {
            let result = async {
                let raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| Failure {
                    code: None,
                    message: e.to_string(),
                })?);
                let command = Command::SshInspect {
                    private_key: Secret::new(raw.as_str()),
                    passphrase: None,
                    comment,
                };
                call(paths, command, |r| match r {
                    Reply::SshGenerated {
                        private_key,
                        public_key,
                        fingerprint,
                        comment,
                    } => Some(crate::ssh::SshGeneratedKey {
                        private_key: Zeroizing::new(private_key.expose().to_owned()),
                        public_key,
                        fingerprint,
                        comment,
                    }),
                    _ => None,
                })
                .await
            }
            .await;
            Done::SshGenerated { seq, result }
        }
    }
}

/// Runs `command` (starting the daemon first when `launch` is given) and reads
/// back the fresh `Status`. When `status_on_err` is set, a failure still reads
/// `Status` so Touch ID sees whether its biometric slot was reset.
async fn status_after(
    paths: &Paths,
    launch: Option<&Launch>,
    command: Command,
    status_on_err: bool,
) -> Result<Status, (Failure, Option<Box<Status>>)> {
    let result = async {
        if let Some(launch) = launch {
            deadbolt_client::ensure_running(paths, launch).await?;
        }
        deadbolt_client::simple(paths, command).await?;
        Ok::<_, Error>(deadbolt_client::status(paths).await)
    }
    .await
    .map_err(Failure::from)
    .and_then(|status| {
        status.ok_or_else(|| Failure {
            code: None,
            message: "The daemon stopped.".into(),
        })
    });
    match result {
        Ok(status) => Ok(status),
        Err(failure) => {
            let status = if status_on_err {
                deadbolt_client::status(paths).await.map(Box::new)
            } else {
                None
            };
            Err((failure, status))
        }
    }
}

/// Sends `command` and extracts the expected `Reply` variant.
pub(crate) async fn call<T>(
    paths: &Paths,
    command: Command,
    take: impl FnOnce(Reply) -> Option<T>,
) -> Result<T, Failure> {
    let reply = deadbolt_client::simple(paths, command).await?;
    take(reply).ok_or_else(unexpected)
}

/// One item with its values, and its one-time code if it has one.
async fn values(paths: &Paths, id: String, ssh_private: bool) -> Result<Values, Failure> {
    let command = Command::ItemGet {
        vault: None,
        query: vec![id.clone()],
        otp: false,
        ssh_private,
        files: Vec::new(),
        deleted: false,
    };
    let got = item(paths, command).await?;
    if code_field(&got.fields).is_some() {
        Ok(Values::with_code(got, code(paths, id).await))
    } else {
        Ok(Values::new(got))
    }
}

/// Writes the item's file field `field` to `path`, and says its name.
async fn save_file(paths: &Paths, id: String, field: &str, path: &Path) -> Result<String, Failure> {
    let command = Command::ItemGet {
        vault: None,
        query: vec![id],
        otp: false,
        ssh_private: false,
        files: vec![field.to_owned()],
        deleted: false,
    };
    let mut got = item(paths, command).await?;
    let file = got
        .fields
        .iter()
        .find(|f| f.name == field && f.kind == "file")
        .ok_or_else(|| Failure {
            code: None,
            message: format!("{} has no file {field}", got.label),
        })?;
    let written = deadbolt_client::file::write(&file.value, path).map_err(|e| Failure {
        code: None,
        message: crate::daemon::error_chain(&e),
    });
    let name = deadbolt_client::file::name(&file.value).to_owned();
    crate::model::forget(&mut got);
    written.map(|()| name)
}

/// A write or read that replies with `Reply::Item`.
async fn item(paths: &Paths, command: Command) -> Result<ItemInfo, Failure> {
    call(paths, command, |r| match r {
        Reply::Item { item } => Some(item),
        _ => None,
    })
    .await
}

/// The export's text goes into the request, and with it is wiped once sent.
/// An import goes ahead only if the file still reads as it was previewed;
/// otherwise this previews it again.
async fn import(
    paths: &Paths,
    path: &Path,
    apply: Option<blake3::Hash>,
    applied: &mut bool,
) -> Result<Imported, ImportFailure> {
    let export = export::read(path)?;
    let digest = export.digest();
    let changed = apply.is_some_and(|previewed| previewed != digest);
    *applied = apply.is_some() && !changed;
    let command = Command::Import {
        vault: None,
        export: export.text,
        files: export.files,
        apply: *applied,
    };
    let report = call(paths, command, |r| match r {
        Reply::Import { report } => Some(report),
        _ => None,
    })
    .await
    .map_err(ImportFailure::Daemon)?;
    Ok(if *applied {
        Imported::Done(report)
    } else {
        Imported::Preview {
            report,
            digest,
            changed,
        }
    })
}

async fn mirror(paths: &Paths, seq: u64) -> Done {
    let command = Command::SyncOnePassword {
        vault: None,
        account: None,
        op_vaults: Vec::new(),
        dry_run: false,
    };
    let result = call(paths, command, |r| match r {
        Reply::Mirror { report } => Some(report),
        _ => None,
    })
    .await;
    Done::Mirrored { seq, result }
}

async fn code(paths: &Paths, id: String) -> Result<Code, Failure> {
    let command = Command::ItemCode {
        vault: None,
        query: vec![id],
    };
    call(paths, command, |r| match r {
        Reply::Code { code } => Some(code),
        _ => None,
    })
    .await
}

fn unexpected() -> Failure {
    Failure {
        code: None,
        message: "unexpected reply from the daemon".into(),
    }
}
