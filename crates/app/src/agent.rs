//! The connection to the agent: requests run in order on one worker thread
//! (each is one socket connection, like the CLI's) and their results land in
//! an inbox the UI drains each frame. A second thread holds a `watch` stream
//! open, reconnecting with backoff, and posts each change to the same inbox.
//! Both wake the window when something lands; nothing polls. The main
//! window's stream watches as the app, so another launch brings it forward.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadbolt_client::export::{self, ExportError};
use deadbolt_client::protocol::{
    ActivityEntry, AppAction, Change, Code, Command, ErrorCode, FieldInput, ImportReport, ItemInfo,
    MirrorReport, Reply, Status, code_field,
};
use deadbolt_client::{Error, Launch, Paths};
use rune::Waker;
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

/// The first wait before watching again after the agent went away.
const RECONNECT_FIRST: Duration = Duration::from_millis(100);
/// The longest wait between attempts while no agent is running.
const RECONNECT_MAX: Duration = Duration::from_secs(2);

/// Whose connection this is. The main window's watch is the app's, which a
/// second launch brings forward (`app-activate`); the quick panel's isn't.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    Main,
    Panel,
}

pub enum Job {
    /// Start the agent if needed and read its status.
    Connect,
    Status,
    Unlock(Zeroizing<String>),
    UnlockBiometric,
    TouchIdSet(bool),
    Lock,
    /// The list; `generation` tells a reply from before a lock from a current one.
    List {
        generation: u64,
    },
    /// One item with its values, and its one-time code if it has one (the
    /// agent leaves otp secrets out); `seq` tells a stale reply from the
    /// current one. `cached` when its page already shows from the cache:
    /// then the reads ahead (`Peek`) go first.
    Get {
        id: String,
        seq: u64,
        cached: bool,
    },
    /// An item's values for the page cache (`cache::Cache`), read ahead of
    /// the selection. Only when nothing else waits: the worker runs these
    /// last, and drops a batch once a newer one comes (`next_jobs`). `epoch`
    /// tells a reply from before the cache was cleared.
    Peek {
        id: String,
        epoch: u64,
        batch: u64,
    },
    /// The item's current one-time code, tagged like `Get`.
    Code {
        id: String,
        seq: u64,
    },
    /// Reads an export and has the agent import it into the default vault,
    /// or only say what it would import. The text never leaves this thread.
    Import {
        path: PathBuf,
        /// The digest of the export as previewed, to import it; `None` to
        /// preview. The file imports only if it still has that digest.
        apply: Option<blake3::Hash>,
        seq: u64,
    },
    /// Mirrors 1Password into the default vault. It runs beside the other
    /// jobs, since 1Password may wait on its approval prompt. `seq` tells
    /// the sync it's for (`mirror::Mirror`).
    SyncOnePassword {
        seq: u64,
    },
    /// Adds an item to the default vault. `seq` tells the edit it's for (`edit::Edit`).
    Create {
        kind: String,
        name: Option<String>,
        fields: Vec<FieldInput>,
        seq: u64,
    },
    /// Changes an item in one entry: sets `fields`, removes `unset` and
    /// renames it (`Some("")` clears the name).
    Save {
        id: String,
        name: Option<String>,
        fields: Vec<FieldInput>,
        unset: Vec<String>,
        seq: u64,
    },
    Remove {
        id: String,
        seq: u64,
    },
    /// A password from the agent's generator.
    Generate {
        length: usize,
        symbols: bool,
        seq: u64,
    },
    /// The newest Activity entries (`activity::Activity`).
    Activity {
        seq: u64,
    },
    /// The agent clients and grants, after revoking one if asked
    /// (`agents::Agents`).
    Agents {
        seq: u64,
        revoke: Option<crate::agents::Revoke>,
    },
    /// Tells the agent the app showed or copied a field, for Activity.
    Report {
        action: AppAction,
        item: String,
        title: String,
        field: String,
    },
}

pub enum Done {
    Connected(Result<Status, Failure>),
    Status(Option<Status>),
    /// The status right after unlocking.
    Unlocked(Result<Status, Failure>),
    /// The outcome of a Touch ID unlock attempt, plus the fresh status when it
    /// failed so the lock screen sees if the biometric slot was reset.
    UnlockedBiometric(Result<Status, (Failure, Option<Box<Status>>)>),
    TouchIdSet {
        enabled: bool,
        result: Result<Status, (Failure, Option<Box<Status>>)>,
    },
    Locked(Result<(), Failure>),
    Items {
        generation: u64,
        result: Result<Vec<ItemInfo>, Failure>,
    },
    Item {
        seq: u64,
        result: Result<Values, Failure>,
    },
    /// A `Peek`'s values, for `id`.
    Peeked {
        id: String,
        epoch: u64,
        result: Result<Values, Failure>,
    },
    Code {
        seq: u64,
        result: Result<Code, Failure>,
    },
    Imported {
        seq: u64,
        /// An import was attempted: false for a preview, or for an import
        /// that turned into one because the file changed.
        applied: bool,
        result: Result<Imported, ImportFailure>,
    },
    Mirrored {
        seq: u64,
        result: Result<MirrorReport, Failure>,
    },
    /// An item added or changed, without its values.
    Saved {
        seq: u64,
        result: Result<ItemInfo, Failure>,
    },
    Removed {
        seq: u64,
        result: Result<ItemInfo, Failure>,
    },
    Generated {
        seq: u64,
        result: Result<Zeroizing<String>, Failure>,
    },
    Activity {
        seq: u64,
        result: Result<Vec<ActivityEntry>, Failure>,
    },
    Agents {
        seq: u64,
        result: Result<crate::agents::Listing, Failure>,
    },
    /// A report went, or didn't: nothing waits on it.
    Reported,
    /// From the watch stream.
    Changed(Change),
    /// The watch stream broke without the agent saying it was stopping.
    WatchLost,
}

/// An item with its values, and its one-time code if it has one, wiped when
/// dropped, so a reply nobody takes (a stale one, or one left in a hidden
/// window's inbox) doesn't keep them.
pub struct Values(ItemInfo, Option<Result<Code, Failure>>);

impl Values {
    pub fn new(item: ItemInfo) -> Values {
        Values(without_otp(item), None)
    }

    pub fn with_code(item: ItemInfo, code: Result<Code, Failure>) -> Values {
        Values(without_otp(item), Some(code))
    }

    /// The item, for the taker to wipe (`model::forget`), and its code.
    pub fn take(mut self) -> (ItemInfo, Option<Result<Code, Failure>>) {
        let item = ItemInfo {
            id: std::mem::take(&mut self.0.id),
            short: std::mem::take(&mut self.0.short),
            kind: std::mem::take(&mut self.0.kind),
            label: std::mem::take(&mut self.0.label),
            detail: self.0.detail.take(),
            fields: std::mem::take(&mut self.0.fields),
            source: self.0.source.take(),
        };
        (item, self.1.take())
    }
}

/// Wipes any one-time password secret on arrival, should one have come.
fn without_otp(mut item: ItemInfo) -> ItemInfo {
    for field in item.fields.iter_mut().filter(|f| f.kind == "otp") {
        field.value.zeroize();
    }
    item
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

/// What the agent did with an export.
#[derive(Debug, Clone, PartialEq)]
pub enum Imported {
    /// What it would import. `changed` when this was to be an import but the
    /// file no longer had the digest previewed, so nothing was imported.
    Preview {
        report: ImportReport,
        digest: blake3::Hash,
        changed: bool,
    },
    Done(ImportReport),
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

pub struct Agent(Mode);

enum Mode {
    Offline,
    /// A worker on this thread, on the app's clock, for scenes and tests.
    Loopback(RefCell<Loopback>),
    Channel {
        jobs: Sender<Job>,
        inbox: Receiver<Done>,
        waker: Arc<Mutex<Option<Waker>>>,
        /// Dropping it ends the watch thread.
        _watching: Option<oneshot::Sender<()>>,
    },
}

/// Item reads (`Get`, `Peek`) the worker runs at once, each on its own
/// connection, so a selection the cache missed still reads ahead.
pub const LANES: usize = 3;

/// Picks the worker's next jobs from what's waiting (`prune`, then the
/// first of the highest rank, with up to `LANES` item reads together):
/// `Peek`s run only when nothing else waits but a `cached` `Get`, so while
/// an arrow is held, reading ahead keeps the pages coming.
pub fn next_jobs(queue: &mut VecDeque<Job>) -> Vec<Job> {
    prune(queue, |j| j);
    take_next(queue, queue.len(), |j| j)
}

/// `next_jobs` among the first `seen` waiting, unpruned.
fn take_next<T>(queue: &mut VecDeque<T>, seen: usize, job: impl Fn(&T) -> &Job) -> Vec<T> {
    let read = |j: &Job| matches!(j, Job::Get { .. } | Job::Peek { .. });
    let Some(first) = pick(queue.iter().take(seen).map(&job)).and_then(|at| queue.remove(at))
    else {
        return Vec::new();
    };
    let mut jobs = vec![first];
    // Anything but a read runs alone, in order.
    while jobs.len() < LANES && read(job(&jobs[0])) {
        match pick(queue.iter().take(seen - jobs.len()).map(&job)) {
            Some(at) if read(job(&queue[at])) => jobs.extend(queue.remove(at)),
            _ => break,
        }
    }
    jobs
}

/// Drops what waits that nobody needs any more: every list, item or code
/// request but the newest (an older one's reply would be dropped as stale),
/// a `cached` `Get` when the same was hurried (a copy waiting), and every
/// `Peek` but the newest batch's.
pub fn prune<T>(queue: &mut VecDeque<T>, job: impl Fn(&T) -> &Job) {
    let keep_get = queue
        .iter()
        .enumerate()
        .filter_map(|(i, item)| match job(item) {
            Job::Get { seq, cached, .. } => Some(((*seq, !*cached), std::cmp::Reverse(i), i)),
            _ => None,
        })
        .max()
        .map(|(_, _, i)| i);
    let keep_list = queue
        .iter()
        .enumerate()
        .filter_map(|(i, item)| match job(item) {
            Job::List { generation } => Some((*generation, std::cmp::Reverse(i), i)),
            _ => None,
        })
        .max()
        .map(|(_, _, i)| i);
    let newest_seq = queue
        .iter()
        .filter_map(|item| match job(item) {
            Job::Get { seq, .. } | Job::Code { seq, .. } => Some(*seq),
            _ => None,
        })
        .max();
    let keep_code = queue
        .iter()
        .enumerate()
        .filter_map(|(i, item)| match job(item) {
            Job::Code { seq, .. } if newest_seq.is_none_or(|n| *seq >= n) => {
                Some((*seq, std::cmp::Reverse(i), i))
            }
            _ => None,
        })
        .max()
        .map(|(_, _, i)| i);
    let newest_batch = queue
        .iter()
        .filter_map(|item| match job(item) {
            Job::Peek { batch, .. } => Some(*batch),
            _ => None,
        })
        .max();
    let mut i = 0;
    queue.retain(|item| {
        let at = i;
        i += 1;
        match job(item) {
            Job::Get { .. } => keep_get == Some(at),
            Job::List { .. } => keep_list == Some(at),
            Job::Code { .. } => keep_code == Some(at),
            Job::Peek { batch, .. } => newest_batch.is_none_or(|n| *batch >= n),
            _ => true,
        }
    });
}

/// Where the next job to run is among `jobs`.
fn pick<'a>(jobs: impl Iterator<Item = &'a Job>) -> Option<usize> {
    let rank = |j: &Job| match j {
        Job::Peek { .. } => 1,
        Job::Get { cached: true, .. } => 2,
        _ => 0,
    };
    jobs.enumerate()
        .min_by_key(|(_, j)| rank(j))
        .map(|(i, _)| i)
}

/// An agent answered on the UI thread by `answer`: each round of requests
/// takes `cost` seconds of the app's clock, picked as the worker picks them
/// (`next_jobs`).
struct Loopback {
    /// What waits, with when it was sent, pruned as the worker would.
    queue: VecDeque<(f64, Job)>,
    answer: fn(Job) -> Option<Done>,
    cost: f64,
    /// When the worker is next free.
    free_at: f64,
    /// The clock at the last drain: what's sent since was sent then.
    last: f64,
    /// The most requests ever waiting at once.
    most: usize,
}

impl Agent {
    /// Starts the worker. Nothing is sent until the first job.
    #[expect(
        clippy::expect_used,
        reason = "the app can't run without its agent thread"
    )]
    pub fn spawn(paths: Paths, launch: Launch, window: Window) -> Agent {
        let (jobs, requests) = channel::<Job>();
        let (results, inbox) = channel();
        let waker: Arc<Mutex<Option<Waker>>> = Arc::default();
        let (watching, stop) = oneshot::channel();
        let post = Post {
            results,
            waker: waker.clone(),
        };
        let watch_post = post.clone();
        let watch_paths = paths.clone();
        std::thread::Builder::new()
            .name("deadbolt-watch".into())
            .spawn(move || watch(watch_paths, window == Window::Main, watch_post, stop))
            .expect("spawning the watch thread");
        std::thread::Builder::new()
            .name("deadbolt-agent".into())
            .spawn(move || work(paths, launch, requests, post))
            .expect("spawning the agent thread");
        Agent(Mode::Channel {
            jobs,
            inbox,
            waker,
            _watching: Some(watching),
        })
    }

    /// A connection that never answers, for scenes and snapshots.
    pub fn offline() -> Agent {
        Agent(Mode::Offline)
    }

    /// An agent `answer` answers, each request taking `cost` seconds of the
    /// app's clock, for scenes and tests that need replies without a socket.
    pub fn loopback(answer: fn(Job) -> Option<Done>, cost: f64) -> Agent {
        Agent(Mode::Loopback(RefCell::new(Loopback {
            queue: VecDeque::new(),
            answer,
            cost,
            free_at: 0.0,
            last: 0.0,
            most: 0,
        })))
    }

    /// A loopback's requests still waiting, and the most that ever were.
    pub fn backlog(&self) -> Option<(usize, usize)> {
        match &self.0 {
            Mode::Loopback(lb) => {
                let lb = lb.borrow();
                Some((lb.queue.len(), lb.most))
            }
            _ => None,
        }
    }

    /// A connection the caller answers for, in tests: it reads the jobs and
    /// posts the replies.
    pub fn scripted() -> (Agent, Receiver<Job>, Sender<Done>) {
        let (jobs, requests) = channel();
        let (results, inbox) = channel();
        let agent = Agent(Mode::Channel {
            jobs,
            inbox,
            waker: Arc::default(),
            _watching: None,
        });
        (agent, requests, results)
    }

    pub fn is_live(&self) -> bool {
        !matches!(self.0, Mode::Offline)
    }

    pub fn send(&self, job: Job) {
        match &self.0 {
            Mode::Offline => {}
            Mode::Loopback(lb) => {
                let mut lb = lb.borrow_mut();
                let at = lb.last;
                lb.queue.push_back((at, job));
                prune(&mut lb.queue, |(_, j)| j);
                lb.most = lb.most.max(lb.queue.len());
            }
            Mode::Channel { jobs, .. } => {
                // The worker only stops when this sender drops, so sending cannot fail while
                // `self` lives.
                jobs.send(job).ok();
            }
        }
    }

    pub fn set_waker(&self, waker: Waker) {
        if let Mode::Channel { waker: slot, .. } = &self.0 {
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(waker);
        }
    }

    /// What's landed by `now`, on the app's clock.
    pub fn drain(&self, now: f64) -> Vec<Done> {
        match &self.0 {
            Mode::Offline => Vec::new(),
            Mode::Channel { inbox, .. } => inbox.try_iter().collect(),
            Mode::Loopback(lb) => {
                let lb = &mut *lb.borrow_mut();
                let mut done = Vec::new();
                let mut at = lb.free_at;
                while let Some((sent, _)) = lb.queue.front() {
                    at = at.max(*sent);
                    if at + lb.cost > now + 1e-9 {
                        break;
                    }
                    // What was sent by the time the worker's free: sent times only grow.
                    let seen = lb.queue.iter().take_while(|(sent, _)| *sent <= at).count();
                    let jobs = take_next(&mut lb.queue, seen, |(_, j)| j);
                    if jobs.is_empty() {
                        break;
                    }
                    at += lb.cost;
                    done.extend(jobs.into_iter().filter_map(|(_, job)| (lb.answer)(job)));
                }
                lb.free_at = at;
                lb.last = now;
                done
            }
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

/// Keeps a watch stream open until `stop` fires or the app is gone, as the
/// app's main window when `app`. It never starts the agent: that's the
/// worker's `Connect` and `Unlock`.
fn watch(paths: Paths, app: bool, post: Post, mut stop: oneshot::Receiver<()>) {
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

fn work(paths: Paths, launch: Launch, requests: Receiver<Job>, main: Post) {
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
        // The agent may have stopped while the unlock screen was up.
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
            result: values(paths, id).await,
        },
        Job::Peek { id, epoch, .. } => Done::Peeked {
            id: id.clone(),
            epoch,
            result: values(paths, id).await,
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
        Job::Create {
            kind,
            name,
            fields,
            seq,
        } => {
            let command = Command::ItemNew {
                vault: None,
                kind,
                name,
                fields,
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
            seq,
        } => {
            let command = Command::ItemSet {
                vault: None,
                query: vec![id],
                fields,
                name,
                unset,
            };
            Done::Saved {
                seq,
                result: item(paths, command).await,
            }
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
            seq,
        } => {
            let command = Command::Generate { length, symbols };
            let result = call(paths, command, |r| match r {
                Reply::Password { password } => Some(password),
                _ => None,
            })
            .await;
            Done::Generated { seq, result }
        }
    }
}

/// Runs `command` (starting the agent first when `launch` is given) and reads
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
            message: "The agent stopped.".into(),
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
async fn values(paths: &Paths, id: String) -> Result<Values, Failure> {
    let command = Command::ItemGet {
        vault: None,
        query: vec![id.clone()],
        otp: false,
    };
    let got = item(paths, command).await?;
    if code_field(&got.fields).is_some() {
        Ok(Values::with_code(got, code(paths, id).await))
    } else {
        Ok(Values::new(got))
    }
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
    let digest = blake3::hash(export.as_bytes());
    let changed = apply.is_some_and(|previewed| previewed != digest);
    *applied = apply.is_some() && !changed;
    let command = Command::Import {
        vault: None,
        export,
        apply: *applied,
    };
    let report = call(paths, command, |r| match r {
        Reply::Import { report } => Some(report),
        _ => None,
    })
    .await
    .map_err(ImportFailure::Agent)?;
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
        message: "unexpected reply from the agent".into(),
    }
}

/// Bundles always launch their own helper. Development runs allow an override.
/// A passphrase goes only to an agent running that program, as the
/// `deadbolt-enclave` beside it sees the agent's code signature, and only once
/// that helper is the one this build pinned (macOS).
pub fn launch() -> Launch {
    let exe = std::env::current_exe().ok().map(crate::binary::resolved);
    let program = crate::binary::discover(
        exe.as_deref(),
        std::env::var_os("DEADBOLT_BIN").as_deref(),
        &std::env::var_os("PATH").unwrap_or_default(),
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
    );
    let expected = std::fs::canonicalize(&program).unwrap_or_else(|_| program.clone());
    deadbolt_client::set_agent_check(Box::new(move |socket| {
        let helper = expected.with_file_name("deadbolt-enclave");
        crate::enclave::verify(&helper)?;
        deadbolt_client::peer::check(&socket, &helper, &expected)
    }));
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
