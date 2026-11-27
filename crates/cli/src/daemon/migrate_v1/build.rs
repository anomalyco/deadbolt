//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! Writes replayed v1 vaults into a fresh v2 store, then reopens it and
//! checks every vault and item against what was replayed.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use deadbolt_core::{Change, DataOp, ItemId, VaultId};
use zeroize::Zeroizing;

use super::replay::V1Vault;
use crate::daemon::session::Loaded;
use crate::disk::KdfParams;

/// A vault as it was moved: its new id, how many items it holds, and the
/// 24-word kit of its new recovery root, sealed until the unlock reply succeeds.
pub(crate) struct Moved {
    pub vault: VaultId,
    pub items: usize,
    pub recovery_kit: Zeroizing<String>,
}

/// What the v2 store must hold once built.
pub(super) struct Plan<'a> {
    pub device_name: &'a str,
    /// The default vault's v1 id.
    pub default: Option<[u8; 32]>,
    pub vaults: &'a [V1Vault],
}

/// Builds the v2 store in `dir` (empty) under `passphrase`, and checks it.
pub(super) fn build(
    dir: &Path,
    passphrase: &[u8],
    params: KdfParams,
    plan: &Plan<'_>,
) -> Result<Vec<Moved>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut_slice())?;
    let mut loaded = Loaded::setup_with(dir, passphrase, plan.device_name, params, &seed)?;
    let mut moved = Vec::with_capacity(plan.vaults.len());
    let mut default = None;
    for vault in plan.vaults {
        let name = free_name(&loaded, &vault.name);
        let (id, recovery_kit) = loaded
            .create_vault_with_kit(&name)
            .with_context(|| format!("creating vault {name}"))?;
        write_items(&mut loaded, id, vault).with_context(|| format!("moving vault {name}"))?;
        if plan.default == Some(vault.id) {
            default = Some(id);
        }
        moved.push(Moved {
            vault: id,
            items: vault.items.values().filter(|i| i.deleted.is_none()).count(),
            recovery_kit,
        });
    }
    // A v1 store with no default, or one naming a vault it doesn't hold,
    // keeps v2's own pick: the first vault made.
    let default = default.or(loaded.meta.default_vault);
    loaded.meta.default_vault = default;
    loaded.save_meta()?;
    let pending: Vec<_> = moved
        .iter()
        .map(|m| crate::protocol::MigratedVault {
            vault: loaded.vault_info(&m.vault),
            items: m.items,
            recovery_kit: m.recovery_kit.clone().into(),
        })
        .collect();
    crate::daemon::session::set_json(
        loaded.store(),
        super::super::upgrade::PENDING_KITS,
        &pending,
    )?;
    drop(loaded);
    verify(dir, passphrase, plan, &moved, default)?;
    Ok(moved)
}

/// `name`, or `name-2`, `name-3`… if a vault moved earlier took it (two
/// v1 vaults renamed alike on different devices).
fn free_name(loaded: &Loaded, name: &str) -> String {
    let mut candidate = name.to_owned();
    let mut n = 2;
    while loaded.name_taken(&candidate, None) {
        let suffix = format!("-{n}");
        let keep = name.len().min(64 - suffix.len());
        candidate = format!("{}{suffix}", &name[..keep]);
        n += 1;
    }
    candidate
}

/// Every item under its v1 id, deleted ones too, in one transaction.
fn write_items(loaded: &mut Loaded, id: VaultId, vault: &V1Vault) -> Result<()> {
    if vault.items.is_empty() {
        return Ok(());
    }
    loaded.update(id, |w, author| {
        let mut creates = Vec::new();
        let mut fields = Vec::new();
        for (id, item) in &vault.items {
            let (create, edits) = super::fit::operations(*id, item);
            creates.push((*id, create));
            fields.extend(edits);
        }
        w.create_items_as(author, creates)?;
        if !fields.is_empty() {
            w.write(author, fields)?;
        }
        // What a create doesn't carry. A password finding ignored for the
        // v1 entry that wrote the current password follows it to the v2
        // frame that wrote it now.
        let mut edits = Vec::new();
        for (iid, item) in &vault.items {
            if let Some(date) = &item.password_changed {
                edits.push(DataOp::password_changed(*iid, Some(date.clone())));
            }
            for (kind, at) in &item.ignored {
                let at = match item.password_entry {
                    Some(entry) if entry == *at => w
                        .item(iid)
                        .and_then(|now| now.password_entry)
                        .unwrap_or(*at),
                    _ => *at,
                };
                edits.push(DataOp::ignore(*iid, kind.clone(), Some(at)));
            }
        }
        if !edits.is_empty() {
            w.write(author, edits)?;
        }
        // Deletes last, in a frame of their own, so no edit above revives them.
        let deletes: Vec<DataOp> = vault
            .items
            .iter()
            .filter_map(|(iid, item)| {
                let at = item.deleted?;
                Some(DataOp::Edit {
                    item: *iid,
                    change: Change::Delete { at },
                })
            })
            .collect();
        if !deletes.is_empty() {
            w.write(author, deletes)?;
        }
        Ok(())
    })
}

/// Reopens `dir` as an unlock would and checks it holds exactly the plan.
fn verify(
    dir: &Path,
    passphrase: &[u8],
    plan: &Plan<'_>,
    moved: &[Moved],
    default: Option<VaultId>,
) -> Result<()> {
    let loaded = Loaded::open(dir, passphrase).context("reopening the new v2 store")?;
    ensure!(
        loaded.meta.device_name == plan.device_name,
        "the new store lost the device name"
    );
    ensure!(
        loaded.meta.default_vault == default,
        "the new store lost the default vault"
    );
    ensure!(
        loaded.vaults.len() == plan.vaults.len(),
        "the new store holds {} vaults, not {}",
        loaded.vaults.len(),
        plan.vaults.len()
    );
    for (v1, moved) in plan.vaults.iter().zip(moved) {
        let Some(vault) = loaded.held(&moved.vault) else {
            bail!("the new store lost vault {}", v1.name);
        };
        let held: Vec<ItemId> = vault
            .items()
            .into_iter()
            .map(|i| i.id)
            .chain(vault.deleted().into_iter().map(|d| d.item.id))
            .collect();
        ensure!(
            held.len() == v1.items.len(),
            "vault {} holds {} items, not {}",
            v1.name,
            held.len(),
            v1.items.len()
        );
        for (iid, want) in &v1.items {
            let Some(got) = vault.item(iid) else {
                bail!("vault {} lost item {iid}", v1.name);
            };
            let same = got.kind == want.kind
                && got.name == want.name
                && got.fields == want.fields
                && got.source == want.source
                && got.favorite == want.favorite
                && got.tags == want.tags
                && got.password_changed == want.password_changed
                && got.ignored.keys().eq(want.ignored.keys())
                && got.deleted == want.deleted.is_some();
            ensure!(same, "vault {} item {iid} differs after the move", v1.name);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    fn vault(id: u8, name: &str) -> V1Vault {
        V1Vault {
            id: [id; 32],
            name: name.into(),
            items: Default::default(),
        }
    }

    /// The default the built store holds, by the moved vault's position.
    fn default_after(default: Option<[u8; 32]>) -> usize {
        let dir = tempfile::tempdir().unwrap();
        let vaults = [vault(1, "personal"), vault(2, "work")];
        let plan = Plan {
            device_name: "laptop",
            default,
            vaults: &vaults,
        };
        let store = dir.path().join("store");
        let moved = build(&store, b"pass", FAST, &plan).unwrap();
        let loaded = Loaded::open(&store, b"pass").unwrap();
        let held = loaded.meta.default_vault.expect("a default vault");
        moved.iter().position(|m| m.vault == held).unwrap()
    }

    #[test]
    fn the_v1_default_carries_over() {
        assert_eq!(default_after(Some([2; 32])), 1);
    }

    #[test]
    fn no_default_or_a_stale_one_falls_back_to_the_first_vault() {
        assert_eq!(default_after(None), 0);
        assert_eq!(default_after(Some([9; 32])), 0);
    }
}
