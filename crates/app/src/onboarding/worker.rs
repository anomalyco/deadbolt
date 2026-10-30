//! First-run requests: creating a vault and joining one. Each runs on its own
//! thread with its own connection, beside the app's request worker, because a
//! join holds its connection open for minutes and waits on the person at the
//! screen. Progress lands in an inbox the UI drains each frame; the thread
//! wakes the window when it sends.

use std::thread::JoinHandle;

use deadbolt_client::protocol::{Answer, Command, DeviceInfo, Event, Reply, Status, VaultInfo};
use deadbolt_client::{Launch, Paths};
use rune::Waker;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::agent::Failure;
use crate::worker::{Inbox, Poster};

/// What a request is doing now. Sent as each slow part starts, so progress is
/// only ever what really happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Starting,
    /// Deriving the store key from the passphrase (Argon2): the slow part.
    Protecting,
    CreatingVault,
    /// Making a code and publishing where the other device can find it.
    MakingCode,
}

#[derive(Debug)]
pub enum Progress {
    Stage(Stage),
    /// This device is set up; `set_up` says whether this request did it.
    DeviceReady {
        set_up: bool,
    },
    /// The code to type on the other device.
    Code(Zeroizing<String>),
    /// The other device paired this one into `vault`.
    Paired {
        vault: String,
        inviter: DeviceInfo,
    },
    Created(Result<VaultInfo, Failure>),
    Joined(Result<VaultInfo, Failure>),
    /// What this computer calls itself, to suggest as the device's name.
    DeviceName(String),
}

/// This device's name and passphrase, when it isn't set up yet.
pub struct NewDevice {
    pub name: String,
    pub passphrase: Zeroizing<String>,
}

pub struct Worker {
    agent: Option<(Paths, Launch)>,
    inbox: Inbox<Progress>,
    cancel: Option<oneshot::Sender<()>>,
    /// The running request's thread, so one runs at a time and close can wait for it.
    thread: Option<JoinHandle<()>>,
    /// Progress to deliver at set times, for scenes (no agent).
    script: Vec<(f64, Progress)>,
    /// The device name lookup has started.
    naming: bool,
}

impl Worker {
    pub fn new(paths: Paths, launch: Launch) -> Worker {
        Worker {
            agent: Some((paths, launch)),
            ..Worker::offline()
        }
    }

    /// No agent: requests go nowhere, for scenes and snapshots.
    pub fn offline() -> Worker {
        Worker {
            agent: None,
            inbox: Inbox::new(),
            cancel: None,
            thread: None,
            script: Vec::new(),
            naming: false,
        }
    }

    /// No agent; `script` arrives at the given seconds on the app's clock.
    pub fn scripted(mut script: Vec<(f64, Progress)>) -> Worker {
        script.sort_by(|a, b| a.0.total_cmp(&b.0));
        Worker {
            script,
            ..Worker::offline()
        }
    }

    pub fn set_waker(&self, waker: Waker) {
        self.inbox.set_waker(waker);
    }

    /// Progress so far, and the time of the next scripted delivery.
    pub fn drain(&mut self, now: f64) -> (Vec<Progress>, Option<f64>) {
        let mut out = self.inbox.drain();
        let due = self.script.iter().take_while(|(at, _)| *at <= now).count();
        out.extend(self.script.drain(..due).map(|(_, p)| p));
        (out, self.script.first().map(|(at, _)| *at))
    }

    /// Looks up what this computer calls itself on a thread (`scutil` can
    /// take tens of milliseconds) and posts it as `Progress::DeviceName`.
    /// Once per worker, and not offline: scenes name their devices.
    pub fn name_device(&mut self) {
        if self.agent.is_none() || self.naming {
            return;
        }
        self.naming = true;
        // No thread, no suggestion: the field keeps its placeholder.
        self.inbox
            .poster()
            .spawn("deadbolt-device-name", |post| {
                post.send(Progress::DeviceName(super::default_device_name()));
            })
            .ok();
    }

    /// Sets up this device if `device` is given, then creates `vault`.
    pub fn create(&mut self, device: Option<NewDevice>, vault: String) {
        self.start(Progress::Created, move |paths, launch, post| async move {
            let result = create(&paths, &launch, device, vault, &post).await;
            post.send(Progress::Created(result));
        });
    }

    /// Sets up this device if `device` is given, then shows a code and waits
    /// for another device to pair.
    pub fn join(&mut self, device: Option<NewDevice>) {
        let (cancel, cancelled) = oneshot::channel();
        self.cancel = Some(cancel);
        self.start(Progress::Joined, move |paths, launch, post| async move {
            let result = join(&paths, &launch, device, cancelled, &post).await;
            post.send(Progress::Joined(result));
        });
    }

    /// Hangs up a pending join. A device setup already sent finishes first:
    /// the agent completes it either way, so the join stops after it.
    pub fn cancel(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.send(()).ok();
        }
    }

    /// Cancels, then waits for the request's thread to end (the window is closing).
    pub fn stop(&mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }

    /// Runs `run` on its own thread; `done` reports a thread that couldn't start.
    fn start<F, Fut>(&mut self, done: fn(Result<VaultInfo, Failure>) -> Progress, run: F)
    where
        F: FnOnce(Paths, Launch, Poster<Progress>) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let Some((paths, launch)) = self.agent.clone() else {
            return;
        };
        // The screen starts a request only once the last one has reported, after
        // which its thread just exits.
        if let Some(previous) = self.thread.take() {
            previous.join().ok();
        }
        let fail = move |error| {
            done(Err(Failure {
                code: None,
                message: format!("starting the request thread: {error}"),
            }))
        };
        let post = self.inbox.poster();
        let spawned = post.clone().spawn("deadbolt-onboarding", move |post| {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(run(paths, launch, post)),
                Err(error) => post.send(fail(error)),
            }
        });
        match spawned {
            Ok(thread) => self.thread = Some(thread),
            Err(error) => post.send(fail(error)),
        }
    }
}

/// The agent's refusal when a device is set up twice; the app says the same.
pub const ALREADY_SET_UP: &str = "this device is already set up";

/// Starts the agent and reads its status.
async fn start(paths: &Paths, launch: &Launch, post: &Poster<Progress>) -> Result<Status, Failure> {
    post.send(Progress::Stage(Stage::Starting));
    Ok(deadbolt_client::ensure_running(paths, launch).await?)
}

/// Sets this device up with `device`, which the screen sends only while it
/// believes the device isn't set up. If it is after all (set up elsewhere
/// meanwhile), the passphrase just typed would not be the one protecting it,
/// so this refuses rather than carry on with the old one.
async fn set_up(
    paths: &Paths,
    status: &Status,
    device: Option<NewDevice>,
    post: &Poster<Progress>,
) -> Result<(), Failure> {
    let set_up = !status.initialized;
    match (status.initialized, device) {
        (true, None) => {}
        (true, Some(_)) => {
            return Err(Failure {
                code: None,
                message: ALREADY_SET_UP.into(),
            });
        }
        (false, None) => {
            return Err(Failure {
                code: None,
                message: "This device isn't set up yet.".into(),
            });
        }
        (false, Some(device)) => {
            post.send(Progress::Stage(Stage::Protecting));
            let command = Command::Setup {
                passphrase: device.passphrase,
                device_name: device.name,
            };
            deadbolt_client::simple(paths, command).await?;
        }
    }
    post.send(Progress::DeviceReady { set_up });
    Ok(())
}

async fn create(
    paths: &Paths,
    launch: &Launch,
    device: Option<NewDevice>,
    vault: String,
    post: &Poster<Progress>,
) -> Result<VaultInfo, Failure> {
    let status = start(paths, launch, post).await?;
    set_up(paths, &status, device, post).await?;
    post.send(Progress::Stage(Stage::CreatingVault));
    match deadbolt_client::simple(paths, Command::VaultCreate { name: vault }).await? {
        Reply::Vault { vault } => Ok(vault),
        _ => Err(unexpected()),
    }
}

/// Sets up the device if needed, then joins until the other device finishes
/// or `cancelled` fires (or its sender drops). A cancel during setup waits for
/// it: the agent finishes a setup it has started even if this hangs up, and
/// the screen must know the device is set up.
async fn join(
    paths: &Paths,
    launch: &Launch,
    device: Option<NewDevice>,
    mut cancelled: oneshot::Receiver<()>,
    post: &Poster<Progress>,
) -> Result<VaultInfo, Failure> {
    let cancel = || Failure {
        code: None,
        message: "cancelled".into(),
    };
    let status = tokio::select! {
        status = start(paths, launch, post) => status?,
        _ = &mut cancelled => return Err(cancel()),
    };
    set_up(paths, &status, device, post).await?;
    tokio::select! {
        biased;
        // Dropping the request hangs up, which cancels the join in the agent.
        _ = &mut cancelled => Err(cancel()),
        result = pair(paths, post) => result,
    }
}

/// Shows a code and receives the vault once the other device pairs. The
/// device is set up already, so the agent never asks for a passphrase.
async fn pair(paths: &Paths, post: &Poster<Progress>) -> Result<VaultInfo, Failure> {
    post.send(Progress::Stage(Stage::MakingCode));
    let command = Command::Join {
        device_name: None,
        passphrase: None,
    };
    let reply = deadbolt_client::call(paths, command, |event| {
        Ok::<_, std::convert::Infallible>(match event {
            Event::Code { code } => {
                post.send(Progress::Code(Zeroizing::new(code)));
                None
            }
            Event::Joined {
                vault,
                inviter,
                passphrase,
            } => {
                post.send(Progress::Paired { vault, inviter });
                // Set up elsewhere and then reset under us: never send one blind.
                passphrase.then(Answer::no)
            }
        })
    })
    .await?;
    match reply {
        Reply::Vault { vault } => Ok(vault),
        _ => Err(unexpected()),
    }
}

fn unexpected() -> Failure {
    Failure {
        code: None,
        message: "unexpected reply from the agent".into(),
    }
}
