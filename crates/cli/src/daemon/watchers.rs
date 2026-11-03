//! `watch` subscriptions. Publishing marks what changed in each watcher's
//! pending set and wakes it; it never waits on a watcher. Each watcher's
//! connection drains its set after a short window, so bursts coalesce, and a
//! set that grows past [`MAX_PENDING`] collapses to one `resync`.
//!
//! The desktop app's main window watches as the app. `app-activate` marks
//! the most recent app watcher's set with `activate`; with none it reserves
//! [`STARTING`] for the app its caller now starts, so a second launch in that
//! window waits for that app instead of starting another.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadbolt_core::VaultId;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::session::Changes;
use crate::protocol::Change;

/// How long a woken watcher gathers changes before sending them.
pub const COALESCE: Duration = Duration::from_millis(25);
/// How long one change may take to reach a watcher before it is dropped.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Most vaults a watcher holds as pending before it gets `resync` instead.
const MAX_PENDING: usize = 64;
/// How long a `no-app` reply holds the place of the app its caller starts.
pub const STARTING: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct Watchers {
    /// In the order they subscribed.
    list: Mutex<Vec<Arc<Watcher>>>,
    /// Set under `list`'s lock, so a late subscriber still hears `stopping`.
    stopped: AtomicBool,
    /// Until when an app being started holds its place; cleared, under
    /// `list`'s lock, when an app watcher subscribes.
    starting: Mutex<Option<Instant>>,
    /// Woken when an app watcher subscribes.
    attached: Notify,
}

#[derive(Default)]
struct Watcher {
    /// The desktop app's main window.
    app: bool,
    pending: Mutex<Pending>,
    wake: Notify,
}

/// What a watcher hasn't been told yet.
#[derive(Debug, Default)]
struct Pending {
    /// The store locked since the last drain.
    locked: bool,
    /// The store unlocked after the last lock.
    unlocked: bool,
    vaults: bool,
    items: BTreeSet<VaultId>,
    devices: BTreeSet<VaultId>,
    /// New Activity entries were stored.
    activity: bool,
    /// Password health memo or breach-check state changed.
    health: bool,
    /// Whether an update is available changed.
    update: bool,
    resync: bool,
    stopping: bool,
    /// Another launch asked for the window, with the latest token.
    activate: Option<Option<String>>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        !(self.locked
            || self.unlocked
            || self.vaults
            || self.activity
            || self.health
            || self.update
            || self.resync
            || self.stopping)
            && self.items.is_empty()
            && self.devices.is_empty()
            && self.activate.is_none()
    }

    fn changed(&mut self, changes: &Changes) {
        self.vaults |= changes.vaults;
        self.items.extend(&changes.items);
        self.devices.extend(&changes.devices);
        if self.items.len() + self.devices.len() > MAX_PENDING {
            self.resync = true;
            self.vaults = false;
            self.items.clear();
            self.devices.clear();
        }
    }

    /// Everything pending, in order, leaving it empty.
    fn take(&mut self) -> Vec<Change> {
        let pending = std::mem::take(self);
        let mut out = Vec::new();
        if pending.resync {
            out.push(Change::Resync);
        } else {
            if pending.locked {
                out.push(Change::Locked);
            }
            if pending.unlocked {
                out.push(Change::Unlocked);
            }
            if pending.vaults {
                out.push(Change::Vaults);
            }
            out.extend(pending.devices.iter().map(|v| Change::Devices {
                vault: v.to_string(),
            }));
            out.extend(pending.items.iter().map(|v| Change::Items {
                vault: v.to_string(),
            }));
            if pending.activity {
                out.push(Change::Activity);
            }
            if pending.health {
                out.push(Change::Health);
            }
            if pending.update {
                out.push(Change::Update);
            }
        }
        if let Some(token) = pending.activate {
            out.push(Change::Activate { token });
        }
        if pending.stopping {
            out.push(Change::Stopping);
        }
        out
    }
}

impl Watchers {
    /// A new watcher; `app` for the desktop app's main window.
    pub fn subscribe(&self, app: bool) -> Subscription<'_> {
        let watcher = Arc::new(Watcher {
            app,
            ..Watcher::default()
        });
        let mut list = self.list.lock().unwrap_or_else(|e| e.into_inner());
        if self.stopped.load(Ordering::SeqCst) {
            watcher
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .stopping = true;
            watcher.wake.notify_one();
        }
        list.push(watcher.clone());
        if app {
            *self.starting.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
        drop(list);
        if app {
            self.attached.notify_waiters();
        }
        Subscription {
            watchers: self,
            watcher,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.list.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn publish(&self, mark: impl Fn(&mut Pending)) {
        mark_all(&self.list.lock().unwrap_or_else(|e| e.into_inner()), mark);
    }

    pub fn changed(&self, changes: &Changes) {
        if !changes.is_empty() {
            self.publish(|p| p.changed(changes));
        }
    }

    pub fn locked(&self) {
        self.publish(|p| {
            // What changed before the lock is moot; clients refetch on unlock.
            *p = Pending {
                locked: true,
                resync: p.resync,
                update: p.update,
                stopping: p.stopping,
                activate: p.activate.take(),
                ..Pending::default()
            };
        });
    }

    pub fn unlocked(&self) {
        self.publish(|p| p.unlocked = true);
    }

    pub fn activity(&self) {
        self.publish(|p| p.activity = true);
    }

    pub fn health(&self) {
        self.publish(|p| p.health = true);
    }

    pub fn update(&self) {
        self.publish(|p| p.update = true);
    }

    /// Asks the most recent app watcher to bring its window forward, true
    /// once asked. With none, an app being started (a reservation from an
    /// earlier call) is waited for until its reservation runs out; with no
    /// reservation either, this call takes one for the app its caller will
    /// start, and is false.
    pub async fn activate(&self, token: Option<String>) -> bool {
        loop {
            let attached = self.attached.notified();
            tokio::pin!(attached);
            // Before looking, so an app subscribing after the look still wakes it.
            attached.as_mut().enable();
            let until = {
                let list = self.list.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(app) = list.iter().rev().find(|w| w.app) {
                    app.pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .activate = Some(token);
                    app.wake.notify_one();
                    return true;
                }
                let mut starting = self.starting.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                match *starting {
                    Some(until) if until > now => until,
                    _ => {
                        *starting = Some(now + STARTING);
                        return false;
                    }
                }
            };
            // Woken by an app subscribing, or the reservation ran out: look again.
            tokio::select! {
                () = &mut attached => {}
                () = tokio::time::sleep_until(until) => {}
            }
        }
    }

    pub fn stopping(&self) {
        let list = self.list.lock().unwrap_or_else(|e| e.into_inner());
        self.stopped.store(true, Ordering::SeqCst);
        mark_all(&list, |p| p.stopping = true);
    }
}

fn mark_all(list: &[Arc<Watcher>], mark: impl Fn(&mut Pending)) {
    for watcher in list {
        mark(&mut watcher.pending.lock().unwrap_or_else(|e| e.into_inner()));
        watcher.wake.notify_one();
    }
}

/// One watcher, removed when dropped.
pub struct Subscription<'a> {
    watchers: &'a Watchers,
    watcher: Arc<Watcher>,
}

impl Subscription<'_> {
    /// Waits for changes, gathers them for [`COALESCE`] and returns them.
    /// Cancel-safe: the pending set, not the wake-up, says whether to send,
    /// and it is only taken at the end.
    pub async fn next(&self) -> Vec<Change> {
        loop {
            let idle = self.pending().is_empty();
            if idle {
                self.watcher.wake.notified().await;
                continue;
            }
            tokio::time::sleep(COALESCE).await;
            let changes = self.pending().take();
            if !changes.is_empty() {
                return changes;
            }
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.watcher
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Subscription<'_> {
    fn drop(&mut self) {
        self.watchers
            .list
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|w| !Arc::ptr_eq(w, &self.watcher));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(n: u8) -> VaultId {
        VaultId::from_bytes([n; 32])
    }

    fn items(vaults: impl IntoIterator<Item = u8>) -> Changes {
        Changes {
            items: vaults.into_iter().map(vault).collect(),
            ..Changes::default()
        }
    }

    #[test]
    fn bursts_coalesce_per_vault_and_a_lock_drops_what_came_before() {
        let watchers = Watchers::default();
        let sub = watchers.subscribe(false);
        let take = || sub.watcher.pending.lock().unwrap().take();
        for _ in 0..100 {
            watchers.changed(&items([1, 2]));
        }
        assert_eq!(
            take(),
            [
                Change::Items {
                    vault: vault(1).to_string()
                },
                Change::Items {
                    vault: vault(2).to_string()
                }
            ]
        );
        watchers.changed(&items([1]));
        watchers.locked();
        assert_eq!(take(), [Change::Locked]);
        watchers.locked();
        watchers.unlocked();
        watchers.changed(&items([3]));
        assert_eq!(
            take(),
            [
                Change::Locked,
                Change::Unlocked,
                Change::Items {
                    vault: vault(3).to_string()
                }
            ]
        );
        watchers.unlocked();
        watchers.locked();
        assert_eq!(take(), [Change::Locked]);
        watchers.stopping();
        assert_eq!(take(), [Change::Stopping]);
        assert!(take().is_empty());
        let late = watchers.subscribe(false);
        assert_eq!(
            late.watcher.pending.lock().unwrap().take(),
            [Change::Stopping]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_next_keeps_the_wake_up() {
        let watchers = Watchers::default();
        let sub = watchers.subscribe(false);
        watchers.changed(&items([1]));
        // Cancelled mid-coalesce, after it took the wake-up.
        let cancelled = tokio::time::timeout(COALESCE / 2, sub.next()).await;
        assert!(cancelled.is_err());
        let changes = tokio::time::timeout(COALESCE * 2, sub.next()).await;
        assert_eq!(
            changes.ok(),
            Some(vec![Change::Items {
                vault: vault(1).to_string()
            }])
        );
        // Nothing pending: it waits.
        assert!(
            tokio::time::timeout(COALESCE * 4, sub.next())
                .await
                .is_err()
        );
    }

    #[test]
    fn a_watcher_that_falls_behind_gets_one_resync_and_unsubscribes_on_drop() {
        let watchers = Watchers::default();
        let sub = watchers.subscribe(false);
        for n in 0..=MAX_PENDING as u8 {
            watchers.changed(&items([n]));
        }
        watchers.changed(&items([1]));
        watchers.locked();
        watchers.stopping();
        let changes = sub.watcher.pending.lock().unwrap().take();
        assert_eq!(changes, [Change::Resync, Change::Stopping]);
        assert_eq!(watchers.len(), 1);
        drop(sub);
        assert_eq!(watchers.len(), 0);
    }

    fn activation(sub: &Subscription<'_>) -> Option<Option<String>> {
        sub.watcher.pending.lock().unwrap().activate.clone()
    }

    #[tokio::test(start_paused = true)]
    async fn activation_waits_out_a_reservation_then_takes_its_own() {
        let watchers = Arc::new(Watchers::default());
        let _other = watchers.subscribe(false);
        assert!(
            !watchers.activate(Some("a".into())).await,
            "no app: start one"
        );
        let start = Instant::now();
        // The app never watches: the second launch waits out the
        // reservation, then is told to start one, and holds its own.
        assert!(!watchers.activate(Some("b".into())).await);
        assert_eq!(start.elapsed(), STARTING);
        let third = tokio::spawn({
            let watchers = watchers.clone();
            async move { watchers.activate(Some("c".into())).await }
        });
        tokio::time::sleep(STARTING / 2).await;
        assert!(!third.is_finished());
        let app = watchers.subscribe(true);
        assert!(third.await.unwrap());
        assert_eq!(activation(&app), Some(Some("c".into())));
        assert_eq!(start.elapsed(), STARTING + STARTING / 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_app_watching_clears_the_reservation_and_a_lock_keeps_its_activation() {
        let watchers = Watchers::default();
        assert!(!watchers.activate(None).await);
        let app = watchers.subscribe(true);
        drop(app);
        // That app quit: the next launch starts one straight away.
        let start = Instant::now();
        assert!(!watchers.activate(None).await);
        assert_eq!(start.elapsed(), Duration::ZERO);

        let app = watchers.subscribe(true);
        assert!(watchers.activate(Some("t".into())).await);
        watchers.locked();
        assert_eq!(
            app.pending().take(),
            [
                Change::Locked,
                Change::Activate {
                    token: Some("t".into())
                }
            ]
        );
    }
}
