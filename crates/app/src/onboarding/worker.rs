//! First-run requests: creating a vault and joining one. Each runs on its own
//! thread with its own connection, beside the app's request worker, because a
//! join holds its connection open for minutes and waits on the person at the
//! screen. Progress lands in an inbox the UI drains each frame; the thread
//! wakes the window when it sends.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use deadbolt_client::protocol::{Command, DeviceInfo, Event, Reply, VaultInfo};
use deadbolt_client::{Launch, Paths};
use rune::Waker;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::agent::Failure;

/// What a request is doing now. Sent as each slow part starts, so progress is
/// only ever what really happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Starting,
    /// Deriving the store key from the passphrase (Argon2): the slow part.
    Protecting,
    CreatingVault,
    /// Waiting for a relay, so the ticket carries an address.
    MakingTicket,
    /// Codes confirmed; receiving the vault.
    Joining,
}

#[derive(Debug)]
pub enum Progress {
    Stage(Stage),
    /// This device's pairing ticket.
    Ticket(String),
    /// The confirmation code; waits for [`Worker::answer`].
    Code {
        code: String,
        vault: String,
        inviter: DeviceInfo,
    },
    Created(Result<VaultInfo, Failure>),
    Joined(Result<VaultInfo, Failure>),
}

/// This device's name and passphrase, when it isn't set up yet.
pub struct NewDevice {
    pub name: String,
    pub passphrase: Zeroizing<String>,
}

pub struct Worker {
    agent: Option<(Paths, Launch)>,
    sender: Sender<Progress>,
    inbox: Receiver<Progress>,
    waker: Arc<Mutex<Option<Waker>>>,
    answer: Option<mpsc::UnboundedSender<bool>>,
    cancel: Option<oneshot::Sender<()>>,
    /// Progress to deliver at set times, for scenes (no agent).
    script: Vec<(f64, Progress)>,
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
        let (sender, inbox) = channel();
        Worker {
            agent: None,
            sender,
            inbox,
            waker: Arc::default(),
            answer: None,
            cancel: None,
            script: Vec::new(),
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
        *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(waker);
    }

    /// Progress so far, and the time of the next scripted delivery.
    pub fn drain(&mut self, now: f64) -> (Vec<Progress>, Option<f64>) {
        let mut out: Vec<Progress> = self.inbox.try_iter().collect();
        let due = self.script.iter().take_while(|(at, _)| *at <= now).count();
        out.extend(self.script.drain(..due).map(|(_, p)| p));
        (out, self.script.first().map(|(at, _)| *at))
    }

    /// Sets up this device if `device` is given, then creates `vault`.
    pub fn create(&mut self, device: Option<NewDevice>, vault: String) {
        self.start(Progress::Created, move |paths, launch, report| async move {
            let result = create(&paths, &launch, device, vault, &report).await;
            report(Progress::Created(result));
        });
    }

    /// Sets up this device if `device` is given, then shows a ticket and waits
    /// for another device to pair.
    pub fn join(&mut self, device: Option<NewDevice>) {
        let (answer, answers) = mpsc::unbounded_channel();
        let (cancel, cancelled) = oneshot::channel();
        self.answer = Some(answer);
        self.cancel = Some(cancel);
        self.start(Progress::Joined, move |paths, launch, report| async move {
            let result = tokio::select! {
                result = join(&paths, &launch, device, answers, &report) => result,
                // Dropping the request hangs up, which cancels the join in the agent.
                _ = cancelled => Err(Failure { code: None, message: "cancelled".into() }),
            };
            report(Progress::Joined(result));
        });
    }

    /// The person's answer to the confirmation code.
    pub fn answer(&mut self, matches: bool) {
        if let Some(answer) = &self.answer {
            answer.send(matches).ok();
        }
    }

    /// Hangs up a pending join.
    pub fn cancel(&mut self) {
        self.answer = None;
        if let Some(cancel) = self.cancel.take() {
            cancel.send(()).ok();
        }
    }

    /// Runs `run` on its own thread; `done` reports a thread that couldn't start.
    fn start<F, Fut>(&mut self, done: fn(Result<VaultInfo, Failure>) -> Progress, run: F)
    where
        F: FnOnce(Paths, Launch, Report) -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let Some((paths, launch)) = self.agent.clone() else {
            return;
        };
        let sender = self.sender.clone();
        let waker = self.waker.clone();
        let report: Report = Arc::new(move |progress| {
            if sender.send(progress).is_ok() {
                let wake = waker.lock().unwrap_or_else(|e| e.into_inner()).clone();
                if let Some(wake) = wake {
                    wake();
                }
            }
        });
        let failed = report.clone();
        let spawned = std::thread::Builder::new()
            .name("deadbolt-onboarding".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(run(paths, launch, report)),
                    Err(error) => report(done(Err(Failure {
                        code: None,
                        message: format!("starting the request thread: {error}"),
                    }))),
                }
            });
        if let Err(error) = spawned {
            failed(done(Err(Failure {
                code: None,
                message: format!("starting the request thread: {error}"),
            })));
        }
    }
}

type Report = Arc<dyn Fn(Progress) + Send + Sync>;

/// Starts the agent and sets up this device if needed.
async fn prepare(
    paths: &Paths,
    launch: &Launch,
    device: Option<NewDevice>,
    report: &Report,
) -> Result<(), Failure> {
    report(Progress::Stage(Stage::Starting));
    let status = deadbolt_client::ensure_running(paths, launch).await?;
    if status.initialized {
        return Ok(());
    }
    let Some(device) = device else {
        return Err(Failure {
            code: None,
            message: "This device isn't set up yet.".into(),
        });
    };
    report(Progress::Stage(Stage::Protecting));
    let command = Command::Setup {
        passphrase: device.passphrase,
        device_name: device.name,
    };
    deadbolt_client::simple(paths, command).await?;
    Ok(())
}

async fn create(
    paths: &Paths,
    launch: &Launch,
    device: Option<NewDevice>,
    vault: String,
    report: &Report,
) -> Result<VaultInfo, Failure> {
    prepare(paths, launch, device, report).await?;
    report(Progress::Stage(Stage::CreatingVault));
    match deadbolt_client::simple(paths, Command::VaultCreate { name: vault }).await? {
        Reply::Vault { vault } => Ok(vault),
        _ => Err(unexpected()),
    }
}

async fn join(
    paths: &Paths,
    launch: &Launch,
    device: Option<NewDevice>,
    answers: mpsc::UnboundedReceiver<bool>,
    report: &Report,
) -> Result<VaultInfo, Failure> {
    prepare(paths, launch, device, report).await?;
    report(Progress::Stage(Stage::MakingTicket));
    let answers = Arc::new(tokio::sync::Mutex::new(answers));
    let reply = deadbolt_client::converse(paths, Command::Join { confirm: true }, |event| {
        let answers = answers.clone();
        let report = report.clone();
        async move {
            Ok::<_, std::convert::Infallible>(match event {
                Event::Ticket { ticket } => {
                    report(Progress::Ticket(ticket));
                    None
                }
                Event::Joining {
                    code,
                    vault,
                    inviter,
                } => {
                    report(Progress::Code {
                        code,
                        vault,
                        inviter,
                    });
                    let matches = answers.lock().await.recv().await.unwrap_or(false);
                    if matches {
                        report(Progress::Stage(Stage::Joining));
                    }
                    Some(matches)
                }
                // Only the inviting side sees `pairing`.
                Event::Pairing { .. } => None,
            })
        }
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
