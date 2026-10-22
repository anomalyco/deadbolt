#![allow(dead_code)]
#![cfg(test)]

use std::{
    collections::HashSet,
    future::Future,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use deadbolt_net::{HandlerError, Membership, Node, NodeConfig, PeerId, SyncHandler};
use tokio::sync::Notify;

pub const T: Duration = Duration::from_secs(10);

pub async fn within<F: Future>(fut: F) -> F::Output {
    tokio::time::timeout(T, fut).await.expect("timed out")
}

pub fn key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).unwrap();
    k
}

#[derive(Default)]
pub struct Members(RwLock<HashSet<PeerId>>);

impl Members {
    pub fn add(&self, id: PeerId) {
        self.0.write().unwrap().insert(id);
    }
    pub fn remove(&self, id: &PeerId) {
        self.0.write().unwrap().remove(id);
    }
}

impl Membership for Members {
    fn is_member(&self, id: &[u8; 32]) -> bool {
        self.0.read().unwrap().contains(id)
    }
}

/// Entries are short byte strings; heads are the newline-joined entry set.
#[derive(Default)]
pub struct Store {
    pub entries: Mutex<Vec<Vec<u8>>>,
    pub received: Mutex<Vec<Vec<Vec<u8>>>>,
    pub calls: AtomicUsize,
    /// When set, `missing_for` signals `entered` and waits for `release`.
    pub block: Option<(Arc<Notify>, Arc<Notify>)>,
}

impl Store {
    pub fn with(entries: &[&str]) -> Arc<Self> {
        let s = Self::default();
        *s.entries.lock().unwrap() = entries.iter().map(|e| e.as_bytes().to_vec()).collect();
        Arc::new(s)
    }

    pub fn sorted(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| String::from_utf8(e.clone()).unwrap())
            .collect();
        v.sort();
        v
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SyncHandler for Store {
    async fn heads(&self, _peer: PeerId) -> Result<Vec<u8>, HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.entries.lock().unwrap().join(&b'\n'))
    }

    async fn missing_for(
        &self,
        _peer: PeerId,
        peer_heads: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some((entered, release)) = &self.block {
            entered.notify_one();
            release.notified().await;
        }
        let theirs: HashSet<&[u8]> = peer_heads.split(|b| *b == b'\n').collect();
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| !theirs.contains(e.as_slice()))
            .cloned()
            .collect())
    }

    async fn receive(&self, _peer: PeerId, entries: Vec<Vec<u8>>) -> Result<(), HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.received.lock().unwrap().push(entries.clone());
        self.entries.lock().unwrap().extend(entries);
        Ok(())
    }
}

pub struct TestNode {
    pub node: Node,
    pub members: Arc<Members>,
    pub store: Arc<Store>,
}

impl TestNode {
    pub async fn new(store: Arc<Store>) -> Self {
        let members = Arc::new(Members::default());
        let node = Node::spawn(
            NodeConfig::local_only(key()),
            members.clone(),
            store.clone(),
        )
        .await
        .unwrap();
        Self {
            node,
            members,
            store,
        }
    }

    pub fn id(&self) -> PeerId {
        self.node.id()
    }
}

/// Two nodes that are members of each other.
pub async fn pair_of_members(a: &[&str], b: &[&str]) -> (TestNode, TestNode) {
    let a = TestNode::new(Store::with(a)).await;
    let b = TestNode::new(Store::with(b)).await;
    a.members.add(b.id());
    b.members.add(a.id());
    (a, b)
}
