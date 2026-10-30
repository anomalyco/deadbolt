//! Reload the standalone browser's single persisted vault without rewriting it.
//! Kept outside the wasm adapter so the production storage seam is host-tested.
use deadbolt_core::{Entry, Vault, VaultId};
use deadbolt_store::Unlocked;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Store(#[from] deadbolt_store::Error),
    #[error(transparent)]
    Decode(#[from] deadbolt_core::DecodeError),
    #[error(
        "Vault {id} is unavailable: {reason}. Its encrypted entries are retained. Do not reset browser storage."
    )]
    Unavailable {
        id: VaultId,
        reason: deadbolt_core::Error,
    },
    #[error(
        "This browser expects one vault, but storage contains {0}. No vault was selected or replaced; encrypted entries are retained."
    )]
    VaultCount(usize),
}

pub(crate) fn load(store: &Unlocked) -> Result<Vault, Error> {
    let mut grouped: BTreeMap<VaultId, Vec<Entry>> = BTreeMap::new();
    for bytes in store.iter_all()? {
        let entry = Entry::decode(&bytes?)?;
        grouped.entry(entry.vault()).or_default().push(entry);
    }
    // Unlike the CLI, this browser's UI and wire adapter only support a single
    // vault. Never silently select a different one when a history fails.
    if grouped.len() != 1 {
        return Err(Error::VaultCount(grouped.len()));
    }
    let (id, entries) = grouped.pop_first().ok_or(Error::VaultCount(0))?;
    Vault::load(entries).map_err(|reason| Error::Unavailable { id, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadbolt_core::{DeviceSecret, MAX_MEMBERSHIP_ENTRIES, MembershipOp, Payload};
    use deadbolt_store::KdfParams;

    #[test]
    fn over_budget_browser_history_is_reported_without_changing_storage() {
        let key = DeviceSecret::from_bytes(&[7; 32]);
        let store = deadbolt_store::init_with_backend(
            redb::backends::InMemoryBackend::new(),
            b"test",
            *key.to_bytes(),
            KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let (vault, genesis) = Vault::create(&key, "browser").unwrap();
        let mut prev = genesis.hash();
        let mut entries = vec![genesis.encode()];
        for seq in 1..=MAX_MEMBERSHIP_ENTRIES {
            let entry = Entry::sign(
                &key,
                vault.id(),
                seq,
                [prev],
                Payload::Membership(MembershipOp::Rename {
                    name: "flood".into(),
                }),
            );
            prev = entry.hash();
            entries.push(entry.encode());
        }
        store
            .append_batch(entries.iter().map(|entry| entry.as_slice()))
            .unwrap();
        let error = match load(&store) {
            Ok(_) => panic!("accepted an over-budget history"),
            Err(error) => error,
        };
        assert!(
            matches!(error, Error::Unavailable { id, reason: deadbolt_core::Error::MembershipLimit { .. } } if id == vault.id())
        );
        assert!(error.to_string().contains("encrypted entries are retained"));
        assert_eq!(
            store
                .iter_all()
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>(),
            entries
        );

        // A second history cannot hide the first or become a silent default.
        let (_, other) = Vault::create(&key, "other").unwrap();
        store.append_batch([other.encode().as_slice()]).unwrap();
        assert!(matches!(load(&store), Err(Error::VaultCount(2))));
        assert_eq!(store.iter_all().unwrap().count(), entries.len() + 1);
    }

    #[test]
    fn valid_browser_history_still_loads() {
        let key = DeviceSecret::from_bytes(&[8; 32]);
        let store = deadbolt_store::init_with_backend(
            redb::backends::InMemoryBackend::new(),
            b"test",
            *key.to_bytes(),
            KdfParams {
                m_cost_kib: 64,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap();
        let (vault, genesis) = Vault::create(&key, "browser").unwrap();
        store.append_batch([genesis.encode().as_slice()]).unwrap();
        assert_eq!(load(&store).unwrap().heads(), vault.heads());
    }
}
