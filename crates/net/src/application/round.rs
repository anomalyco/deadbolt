//! Membership startup barrier, extracted from the browser device adapter.
use super::Addr;
use crate::{Node, PeerAddr, PeerId};
use n0_future::time::{Instant, sleep, timeout};
use std::{collections::BTreeSet, time::Duration};

/// Synchronous snapshots only; never hold the device's state lock over I/O.
pub trait RoundState {
    type Error;
    fn ready(&self) -> Result<bool, Self::Error>;
    fn targets(&self) -> Result<Vec<PeerAddr>, Self::Error>;
    fn saw(&self, peer: PeerId) -> Result<(), Self::Error>;
    fn publish_ready(&self, addr: Addr) -> Result<(), Self::Error>;
}

/// The native/browser 30-second best-effort refresh, followed by a full data
/// round. Dial failures count as unreachable, not post-connect failures or
/// admission-limit refusals. New members learned during refresh are contacted.
pub async fn sync_round<S: RoundState>(node: &Node, state: &S) -> Result<(), S::Error> {
    let mut ready = state.ready()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attempts = BTreeSet::new();
    loop {
        let targets = state
            .targets()?
            .into_iter()
            .filter(|peer| ready || !attempts.contains(&peer.id))
            .collect();
        let completed = super::contact_round(
            targets,
            (!ready).then_some(deadline),
            |peer, budget| async move {
                let id = peer.id;
                let until = Instant::now() + budget;
                let complete = match timeout(budget, node.connect(peer)).await {
                    Ok(Ok(conn)) => {
                        let result =
                            timeout(until.saturating_duration_since(Instant::now()), conn.sync())
                                .await;
                        conn.close();
                        match result {
                            Ok(Ok(_)) => {
                                state.saw(id)?;
                                true
                            }
                            Ok(Err(crate::Error::MembershipRejected(_))) => true,
                            Ok(Err(_)) | Err(_) => false,
                        }
                    }
                    Ok(Err(crate::Error::Rejected(_))) => false,
                    Ok(Err(_)) | Err(_) => true,
                };
                Ok(complete)
            },
        )
        .await?;
        attempts.extend(completed);
        let complete = state
            .targets()?
            .iter()
            .all(|peer| attempts.contains(&peer.id));
        if ready || complete || Instant::now() >= deadline {
            state.publish_ready(Addr::from_peer(node.addr()))?;
            if !ready {
                ready = true;
                attempts.clear();
                continue;
            }
            break;
        }
        sleep(Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now()))).await;
    }
    Ok(())
}
