//! The connection to the agent: requests run in order on one worker thread
//! (each is one socket connection, like the CLI's) and their results land in
//! an inbox the UI drains each frame. A second thread holds a `watch` stream
//! open, reconnecting with backoff, and posts each change to the same inbox.
//! Both wake the window when something lands; nothing polls.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadbolt_client::export::{self, ExportError};
use deadbolt_client::protocol::{
    Change, Command, ErrorCode, ImportReport, ItemInfo, Reply, Status,
};
use deadbolt_client::{Error, Launch, Paths};
use rune::{FileDialogOptions, FileDialogs, Waker};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// The first wait before watching again after the agent went away.
const RECONNECT_FIRST: Duration = Duration::from_millis(100);
/// The longest wait between attempts while no agent is running.
const RECONNECT_MAX: Duration = Duration::from_secs(2);

pub enum Job {
    /// Start the agent if needed and read its status.
    Connect,
    Status,
    Unlock(Zeroizing<String>),
    Lock,
    /// The list; `generation` tells a reply from before a lock from a current one.
    List {
        generation: u64,
    },
    /// One item with its values; `seq` tells a stale reply from the current one.
    Get {
        id: String,
        seq: u64,
    },
    /// Reads an export and has the agent import it into the default vault,
    /// or only say what it would import. The text never leaves this thread.
    Import {
        path: PathBuf,
        apply: bool,
        seq: u64,
    },
}

pub enum Done {
    Connected(Result<Status, Failure>),
    Status(Option<Status>),
    /// The status right after unlocking.
    Unlocked(Result<Status, Failure>),
    Locked(Result<(), Failure>),
    Items {
        generation: u64,
        result: Result<Vec<ItemInfo>, Failure>,
    },
    Item {
        seq: u64,
        result: Result<Values, Failure>,
    },
    Imported {
        seq: u64,
        apply: bool,
        result: Result<ImportReport, ImportFailure>,
    },
    /// The file Choose File… picked; `None` if it was cancelled.
    Chosen {
        seq: u64,
        result: Result<Option<PathBuf>, String>,
    },
    /// From the watch stream.
    Changed(Change),
    /// The watch stream broke without the agent saying it was stopping.
    WatchLost,
}

/// An item with its values, wiped when dropped, so a reply nobody takes (a
/// stale one, or one left in a hidden window's inbox) doesn't keep them.
pub struct Values(ItemInfo);

impl Values {
    pub fn new(item: ItemInfo) -> Values {
        Values(item)
    }

    /// The item, for the taker to wipe (`model::forget`).
    pub fn take(mut self) -> ItemInfo {
        let fields = std::mem::take(&mut self.0.fields);
        ItemInfo {
            fields,
            ..self.0.clone()
        }
    }
}

impl Drop for Values {
    fn drop(&mut self) {
        crate::model::forget(&mut self.0);
    }
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
            Error::Spawn(program, e) if e.kind() == std::io::ErrorKind::NotFound => {
                if crate::binary::is_helper(program) {
                    "Deadbolt is damaged: its deadbolt helper is missing. Reinstall Deadbolt."
                        .into()
                } else {
                    "Couldn't find the deadbolt command. Install it, or set DEADBOLT_BIN to its path."
                        .into()
                }
            }
            _ => error_chain(&error),
        };
        Failure {
            code: error.code(),
            message,
        }
    }
}

/// Why an export wasn't read or imported.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportFailure {
    /// The file isn't an export Deadbolt reads: not text, empty, too large.
    NotExport(String),
    /// The file couldn't be read.
    Read(String),
    Agent(Failure),
}

impl From<ExportError> for ImportFailure {
    fn from(error: ExportError) -> Self {
        match error {
            // The path is on screen already; say only what went wrong.
            ExportError::Read(_, e) | ExportError::Io(e) => ImportFailure::Read(e.to_string()),
            e => ImportFailure::NotExport(error_chain(&e)),
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
    /// For file dialogs, which answer on threads of their own.
    post: Post,
    /// Dropping it ends the watch thread.
    _watching: Option<oneshot::Sender<()>>,
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
        let (watching, stop) = oneshot::channel();
        let post = Post {
            results: results.clone(),
            waker: waker.clone(),
        };
        let watch_post = post.clone();
        let watch_paths = paths.clone();
        std::thread::Builder::new()
            .name("deadbolt-watch".into())
            .spawn(move || watch(watch_paths, watch_post, stop))
            .expect("spawning the watch thread");
        let wake = waker.clone();
        std::thread::Builder::new()
            .name("deadbolt-agent".into())
            .spawn(move || work(paths, launch, requests, results, wake))
            .expect("spawning the agent thread");
        Agent {
            jobs: Some(jobs),
            inbox,
            post,
            waker,
            _watching: Some(watching),
        }
    }

    /// A connection that never answers, for scenes and snapshots.
    pub fn offline() -> Agent {
        let (results, inbox) = channel();
        let waker: Arc<Mutex<Option<Waker>>> = Arc::default();
        Agent {
            jobs: None,
            inbox,
            post: Post {
                results,
                waker: waker.clone(),
            },
            waker,
            _watching: None,
        }
    }

    /// A connection the caller answers for, in tests: it reads the jobs and
    /// posts the replies.
    pub fn scripted() -> (Agent, Receiver<Job>, Sender<Done>) {
        let (jobs, requests) = channel();
        let (results, inbox) = channel();
        let waker: Arc<Mutex<Option<Waker>>> = Arc::default();
        let agent = Agent {
            jobs: Some(jobs),
            inbox,
            post: Post {
                results: results.clone(),
                waker: waker.clone(),
            },
            waker,
            _watching: None,
        };
        (agent, requests, results)
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

    /// Shows Choose File…'s Open dialog on a thread of its own, which waits
    /// for it (a native one is presented on the main thread's run loop, which
    /// must not wait), and posts `Done::Chosen`.
    pub fn choose_file(&self, dialogs: FileDialogs, options: FileDialogOptions, seq: u64) {
        let post = self.post.clone();
        let spawned = std::thread::Builder::new()
            .name("deadbolt-file-dialog".into())
            .spawn(move || {
                let result = match tokio::runtime::Builder::new_current_thread().build() {
                    Ok(runtime) => runtime
                        .block_on(dialogs.open(options))
                        .map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                post.send(Done::Chosen { seq, result });
            });
        if let Err(e) = spawned {
            self.post.send(Done::Chosen {
                seq,
                result: Err(e.to_string()),
            });
        }
    }
}

/// Posts to the UI's inbox and wakes the window.
#[derive(Clone)]
struct Post {
    results: Sender<Done>,
    waker: Arc<Mutex<Option<Waker>>>,
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

/// Keeps a watch stream open until `stop` fires or the app is gone. It never
/// starts the agent: that's the worker's `Connect` and `Unlock`.
fn watch(paths: Paths, post: Post, mut stop: oneshot::Receiver<()>) {
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
                gone = follow(&paths, &post, &mut delay) => if gone { return },
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
async fn follow(paths: &Paths, post: &Post, delay: &mut Duration) -> bool {
    let Ok(mut stream) = deadbolt_client::watch(paths).await else {
        return false;
    };
    loop {
        match stream.next().await {
            Ok(Some(change)) => {
                // Only an agent that accepted the watch resets the backoff; one
                // that refuses it (an older protocol) keeps it growing.
                if change == Change::Watching {
                    *delay = RECONNECT_FIRST;
                }
                if !post.send(Done::Changed(change)) {
                    return true;
                }
            }
            // The agent said `stopping` before ending the stream.
            Ok(None) => return false,
            Err(_) => return !post.send(Done::WatchLost),
        }
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
        // The agent may have stopped while the unlock screen was up.
        Job::Unlock(passphrase) => Done::Unlocked(
            async {
                deadbolt_client::ensure_running(paths, launch).await?;
                let command = Command::Unlock {
                    passphrase,
                    timeout_secs: None,
                };
                deadbolt_client::simple(paths, command).await?;
                Ok::<_, Error>(deadbolt_client::status(paths).await)
            }
            .await
            .map_err(Failure::from)
            .and_then(|status| {
                status.ok_or_else(|| Failure {
                    code: None,
                    message: "The agent stopped.".into(),
                })
            }),
        ),
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
            };
            let result = match deadbolt_client::simple(paths, command).await {
                Ok(Reply::Items { items }) => Ok(items),
                Ok(_) => Err(unexpected()),
                Err(error) => Err(error.into()),
            };
            Done::Items { generation, result }
        }
        Job::Get { id, seq } => {
            let command = Command::ItemGet {
                vault: None,
                query: vec![id],
            };
            let result = match deadbolt_client::simple(paths, command).await {
                Ok(Reply::Item { item }) => Ok(Values::new(item)),
                Ok(_) => Err(unexpected()),
                Err(error) => Err(error.into()),
            };
            Done::Item { seq, result }
        }
        Job::Import { path, apply, seq } => Done::Imported {
            seq,
            apply,
            result: import(paths, &path, apply).await,
        },
    }
}

/// The export's text goes into the request, and with it is wiped once sent.
async fn import(paths: &Paths, path: &Path, apply: bool) -> Result<ImportReport, ImportFailure> {
    let export = export::read(path)?;
    let command = Command::Import {
        vault: None,
        export,
        apply,
    };
    match deadbolt_client::simple(paths, command).await {
        Ok(Reply::Import { report }) => Ok(report),
        Ok(_) => Err(ImportFailure::Agent(unexpected())),
        Err(error) => Err(ImportFailure::Agent(error.into())),
    }
}

fn unexpected() -> Failure {
    Failure {
        code: None,
        message: "unexpected reply from the agent".into(),
    }
}

/// Bundles always launch their own helper. Development runs allow an override.
pub fn launch() -> Launch {
    let program = crate::binary::discover(
        std::env::current_exe().ok().as_deref(),
        std::env::var_os("DEADBOLT_BIN").as_deref(),
        &std::env::var_os("PATH").unwrap_or_default(),
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
    );
    Launch { program }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_helper_means_a_damaged_app_not_a_missing_command() {
        let missing = || std::io::Error::from(std::io::ErrorKind::NotFound);
        let helper = "/Applications/Deadbolt.app/Contents/Helpers/deadbolt";
        let failure = Failure::from(Error::Spawn(helper.into(), missing()));
        assert!(
            failure.message.contains("Reinstall Deadbolt"),
            "{failure:?}"
        );
        assert!(!failure.message.contains("DEADBOLT_BIN"));
        let failure = Failure::from(Error::Spawn("deadbolt".into(), missing()));
        assert!(failure.message.contains("DEADBOLT_BIN"), "{failure:?}");
    }
}
