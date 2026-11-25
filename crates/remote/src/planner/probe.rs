//! [`confirm_missing`]: direct GETs that tell a lagging LIST from a store
//! that lost a frame.

use deadbolt_core::VaultId;
use deadbolt_core::v2::{FrameKind, LogKind};

use super::verify::verify_named;
use super::{Observed, RemoteAnomaly};
use crate::error::RemoteError;
use crate::path::RemotePath;
use crate::store::ObjStore;

/// Keeps only the [`RemoteAnomaly::RemoteRegressed`] alarms whose anchored
/// frame a direct GET cannot find either. An eventually consistent or
/// caching LIST can lag a PUT the store already acknowledged, so a frame
/// missing from a LIST is gone only when GET agrees. A GET that finds another
/// valid frame under the name turns the alarm into [`Observed::Different`].
/// Every other anomaly passes through unchanged.
pub async fn confirm_missing<S: ObjStore>(
    store: &S,
    vault: &VaultId,
    anomalies: Vec<RemoteAnomaly>,
) -> Result<Vec<RemoteAnomaly>, RemoteError> {
    let mut out = Vec::with_capacity(anomalies.len());
    for anomaly in anomalies {
        let RemoteAnomaly::RemoteRegressed {
            log,
            author,
            expected_seq,
            expected_id,
            observed: Observed::Missing { .. },
        } = anomaly
        else {
            out.push(anomaly);
            continue;
        };
        let kinds: &[FrameKind] = match log {
            LogKind::Member => &[FrameKind::Member],
            LogKind::Data => &[FrameKind::Data, FrameKind::Checkpoint],
        };
        let mut other = None;
        let mut present = false;
        for &kind in kinds {
            let path = RemotePath::frame(*vault, kind, author, expected_seq);
            let Some(bytes) = store.get(&path.to_name(), None).await? else {
                continue;
            };
            if let Ok(frame) = verify_named(&path, &bytes) {
                if frame.id() == expected_id {
                    present = true;
                    break;
                }
                other = Some(frame.id());
            }
        }
        if present {
            continue;
        }
        out.push(match other {
            Some(id) => RemoteAnomaly::RemoteRegressed {
                log,
                author,
                expected_seq,
                expected_id,
                observed: Observed::Different(id),
            },
            None => anomaly,
        });
    }
    Ok(out)
}
