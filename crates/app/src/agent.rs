//! The connection to the agent: requests run in order on one worker thread
//! (each is one socket connection, like the CLI's) and their results land in
//! an inbox the UI drains each frame. The worker wakes the window when a
//! result arrives; nothing polls.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use deadbolt_client::protocol::{Command, ErrorCode, ItemInfo, Reply, Status};
use deadbolt_client::{Error, Launch, Paths};
use rune::Waker;
use zeroize::Zeroizing;

pub enum Job {
    /// Start the agent if needed and read its status.
    Connect,
    Status,
    Unlock(Zeroizing<String>),
    Lock,
    List,
    /// One item with its values; `seq` tells a stale reply from the current one.
    Get {
        id: String,
        seq: u64,
    },
}

pub enum Done {
    Connected(Result<Status, Failure>),
    Status(Option<Status>),
    Unlocked(Result<(), Failure>),
    Locked(Result<(), Failure>),
    Items(Result<Vec<ItemInfo>, Failure>),
    Item {
        seq: u64,
        result: Result<ItemInfo, Failure>,
    },
}

/// A request that failed: the agent's code if it refused, and a message for people.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub code: Option<ErrorCode>,
    pub message: String,
}

impl Failure {
    pub fn locked(&self) -> bool {
        self.code == Some(ErrorCode::Locked)
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        let message = match &error {
            Error::Spawn(e) if e.kind() == std::io::ErrorKind::NotFound => {
                "Couldn't find the deadbolt command. Install it, or set DEADBOLT_BIN to its path."
                    .into()
            }
            _ => error_chain(&error),
        };
        Failure {
            code: error.code(),
            message,
        }
    }
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(e) = source {
        message.push_str(": ");
        message.push_str(&e.to_string());
        source = e.source();
    }
    message
}

pub struct Agent {
    jobs: Option<Sender<Job>>,
    inbox: Receiver<Done>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl Agent {
    /// Starts the worker. Nothing is sent until the first job.
    #[expect(
        clippy::expect_used,
        reason = "the app can't run without its agent thread"
    )]
    pub fn spawn(paths: Paths, launch: Launch) -> Agent {
        let (jobs, requests) = channel::<Job>();
        let (results, inbox) = channel();
        let waker: Arc<Mutex<Option<Waker>>> = Arc::default();
        let wake = waker.clone();
        std::thread::Builder::new()
            .name("deadbolt-agent".into())
            .spawn(move || work(paths, launch, requests, results, wake))
            .expect("spawning the agent thread");
        Agent {
            jobs: Some(jobs),
            inbox,
            waker,
        }
    }

    /// A connection that never answers, for scenes and snapshots.
    pub fn offline() -> Agent {
        let (_, inbox) = channel();
        Agent {
            jobs: None,
            inbox,
            waker: Arc::default(),
        }
    }

    pub fn send(&self, job: Job) {
        if let Some(jobs) = &self.jobs {
            // The worker only stops when this sender drops, so sending cannot fail while
            // `self` lives.
            jobs.send(job).ok();
        }
    }

    pub fn set_waker(&self, waker: Waker) {
        *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(waker);
    }

    pub fn drain(&self) -> Vec<Done> {
        self.inbox.try_iter().collect()
    }
}

fn work(
    paths: Paths,
    launch: Launch,
    requests: Receiver<Job>,
    results: Sender<Done>,
    waker: Arc<Mutex<Option<Waker>>>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let failure = Failure {
                code: None,
                message: format!("starting the agent thread: {error}"),
            };
            results.send(Done::Connected(Err(failure))).ok();
            return;
        }
    };
    for job in requests {
        let done = runtime.block_on(run(&paths, &launch, job));
        if results.send(done).is_err() {
            return;
        }
        let wake = waker.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(wake) = wake {
            wake();
        }
    }
}

async fn run(paths: &Paths, launch: &Launch, job: Job) -> Done {
    match job {
        Job::Connect => Done::Connected(
            deadbolt_client::ensure_running(paths, launch)
                .await
                .map_err(Failure::from),
        ),
        Job::Status => Done::Status(deadbolt_client::status(paths).await),
        Job::Unlock(passphrase) => {
            let command = Command::Unlock {
                passphrase: passphrase.to_string(),
                timeout_secs: None,
            };
            Done::Unlocked(
                deadbolt_client::simple(paths, command)
                    .await
                    .map(drop)
                    .map_err(Failure::from),
            )
        }
        Job::Lock => Done::Locked(
            deadbolt_client::simple(paths, Command::Lock)
                .await
                .map(drop)
                .map_err(Failure::from),
        ),
        Job::List => {
            let command = Command::ItemList {
                vault: None,
                query: Vec::new(),
                kind: None,
            };
            Done::Items(match deadbolt_client::simple(paths, command).await {
                Ok(Reply::Items { items }) => Ok(items),
                Ok(_) => Err(unexpected()),
                Err(error) => Err(error.into()),
            })
        }
        Job::Get { id, seq } => {
            let command = Command::ItemGet {
                vault: None,
                query: vec![id],
            };
            let result = match deadbolt_client::simple(paths, command).await {
                Ok(Reply::Item { item }) => Ok(item),
                Ok(_) => Err(unexpected()),
                Err(error) => Err(error.into()),
            };
            Done::Item { seq, result }
        }
    }
}

fn unexpected() -> Failure {
    Failure {
        code: None,
        message: "unexpected reply from the agent".into(),
    }
}

/// The `deadbolt` binary that runs the agent: `DEADBOLT_BIN`, else one next to
/// this app, else the usual install locations, else `deadbolt` on `PATH`.
/// Apps opened from the Finder get a minimal `PATH`, hence the fixed places.
pub fn launch() -> Launch {
    let mut candidates = std::env::var_os("DEADBOLT_BIN")
        .map(PathBuf::from)
        .into_iter()
        .chain(
            std::env::current_exe()
                .ok()
                .and_then(|exe| Some(exe.parent()?.join("deadbolt"))),
        )
        .chain(["/opt/homebrew/bin/deadbolt", "/usr/local/bin/deadbolt"].map(PathBuf::from))
        .chain(
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/bin/deadbolt")),
        );
    let program = candidates
        .find(|p| p.is_file())
        .unwrap_or_else(|| "deadbolt".into());
    Launch {
        program,
        version: None,
    }
}
