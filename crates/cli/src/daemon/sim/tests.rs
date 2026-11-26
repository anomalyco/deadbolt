use super::*;
use deadbolt_core::v2::{LogKind, MemberOp};
use deadbolt_net::{Inviter, PairingContext, SyncHandler};

fn actions(seed: u64) -> Vec<Action> {
    let mut rng = Rng(seed);
    let mut actions = vec![Action::Pair(1), Action::Pair(2), Action::Pair(3)];
    for _ in 0..48 {
        let i = (rng.next() % DEVICES as u64) as usize;
        let j = (rng.next() % DEVICES as u64) as usize;
        let value = rng.next();
        if rng.next().is_multiple_of(24) {
            actions.push(Action::RemoveBy(i, j));
            continue;
        }
        actions.push(match rng.next() % 19 {
            0 => Action::Add(i, value),
            1 => Action::Edit(i, value),
            2 => Action::Delete(i),
            3 => Action::Pair(i),
            4 => Action::Remove(i),
            5 => Action::Lock(i),
            6 => Action::Unlock(i),
            7 => Action::Crash(i),
            8 => Action::Partition(i, j),
            9 => Action::Heal,
            10 => Action::Sync(i, j, value, Some((value % 500) as usize)),
            11 => Action::Attach(i, value),
            12 => Action::WriteFailure(i),
            13 => Action::RevokeDuringSync(i, value, (value % 400) as usize),
            14 => Action::Startup(i),
            15 => Action::Restore(i),
            16 => Action::Favorite(i, value & 1 == 0),
            17 => Action::Tag(i, value),
            18 => Action::Untag(i),
            _ => Action::Sync(i, j, value, None),
        });
    }
    actions
}

fn replay(actions: &[Action]) -> Result<String> {
    let timing = std::env::var_os("DEADBOLT_SIM_TIMING").is_some();
    let start = std::time::Instant::now();
    let mut world = World::new()?;
    if timing {
        eprintln!("init {:?}", start.elapsed());
    }
    for (i, action) in actions.iter().enumerate() {
        let start = std::time::Instant::now();
        world
            .step(action)
            .with_context(|| format!("step {i} {action:?}"))?;
        if timing {
            eprintln!("{action:?}: {:?}", start.elapsed());
        }
    }
    let start = std::time::Instant::now();
    world.converge()?;
    if timing {
        eprintln!("converge {:?}", start.elapsed());
    }
    Ok(world.digest.finalize().to_hex().to_string())
}

/// Delta debugging removes contiguous chunks, then individual actions. Every
/// candidate starts with fresh encrypted stores and the same deterministic keys.
fn shrink(mut actions: Vec<Action>, mut fails: impl FnMut(&[Action]) -> bool) -> Vec<Action> {
    let mut width = (actions.len() / 2).max(1);
    while width > 0 {
        let mut start = 0;
        while start + width <= actions.len() {
            let mut candidate = actions.clone();
            candidate.drain(start..start + width);
            if fails(&candidate) {
                actions = candidate;
                start = 0;
            } else {
                start += 1;
            }
        }
        width /= 2;
    }
    actions
}

/// Two members cut off from each other each remove the other, offline and
/// concurrently, while a third writes. Once healed every device agrees on
/// who is left, and replay is byte for byte.
#[test]
fn concurrent_offline_removals_converge_and_replay() {
    let actions = [
        Action::Pair(1),
        Action::Pair(2),
        Action::Pair(3),
        Action::Add(0, 1),
        Action::Sync(0, 1, 3, None),
        Action::Sync(0, 2, 4, None),
        Action::Partition(1, 2),
        Action::Partition(0, 2),
        Action::RemoveBy(1, 2),
        Action::RemoveBy(2, 1),
        Action::Add(2, 5),
        Action::Crash(1),
        Action::Add(3, 6),
        Action::Heal,
        Action::Startup(1),
    ];
    assert_eq!(replay(&actions).unwrap(), replay(&actions).unwrap());
}

/// A removal made while its target is unreachable, then a crash on both
/// sides before they meet again.
#[test]
fn a_removal_across_a_partition_survives_crashes() {
    replay(&[
        Action::Pair(1),
        Action::Pair(2),
        Action::Partition(0, 1),
        Action::Remove(1),
        Action::Add(1, 9),
        Action::Crash(0),
        Action::Crash(1),
        Action::Heal,
        Action::Startup(0),
        Action::Startup(1),
        Action::Add(0, 10),
    ])
    .unwrap();
}

#[test]
fn exploration() {
    let count = crate::config::env("DEADBOLT_SIM_SEEDS")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(2);
    let first = crate::config::env("DEADBOLT_SIM_SEED")
        .map(|s| s.parse::<u64>().unwrap())
        .unwrap_or(0);
    if let Ok(trace) = crate::config::env("DEADBOLT_SIM_TRACE") {
        replay(&serde_json::from_str::<Vec<Action>>(&trace).unwrap()).unwrap();
        return;
    }
    for seed in first..first + count {
        let actions = actions(seed);
        if let Err(error) = replay(&actions) {
            let failure = error.root_cause().to_string();
            let reduced = shrink(actions.clone(), |candidate| {
                replay(candidate).is_err_and(|e| e.root_cause().to_string() == failure)
            });
            panic!(
                "seed {seed}: {error:#}\nactions={}\nshrunk={}\nreplay with DEADBOLT_SIM_SEED={seed} DEADBOLT_SIM_SEEDS=1, or DEADBOLT_SIM_TRACE='<shrunk JSON>'",
                serde_json::to_string(&actions).unwrap(),
                serde_json::to_string(&reduced).unwrap()
            );
        }
    }
}

#[tokio::test]
async fn pairing_offer_rejects_a_removed_inviter() {
    let mut world = World::new().unwrap();
    world.pair(1).unwrap();
    let peer = DeviceId::from_bytes(world.devices[1].id);
    let removal = world.devices[0]
        .with(|s| {
            let id = s.update(world.vault, |v, a| Ok(v.remove(a, peer)?))?;
            Ok(s.vault(&world.vault).frame(&id).unwrap().clone())
        })
        .unwrap();
    world.devices[1]
        .with(|s| {
            s.update(world.vault, |v, a| {
                Ok(v.apply(a.keys().kem_key(), vec![removal])?)
            })
        })
        .unwrap();
    let invite = Invitation {
        device: &world.devices[1],
        vault: world.vault,
    };
    let ctx = PairingContext {
        local: world.devices[1].id,
        remote: world.devices[2].id,
    };
    let error = invite.offer(&ctx).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "this device is no longer a member of sim"
    );
    world.check().unwrap();
}

#[tokio::test]
async fn pairing_offer_rejects_a_removed_joiner() {
    let mut world = World::new().unwrap();
    world.pair(1).unwrap();
    world.step(&Action::Remove(1)).unwrap();
    let invite = Invitation {
        device: &world.devices[0],
        vault: world.vault,
    };
    let ctx = PairingContext {
        local: world.devices[0].id,
        remote: world.devices[1].id,
    };
    // Exercise the offer adapter directly: World::pair skips removed peers.
    let error = invite.offer(&ctx).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "that device was removed from sim and can't rejoin it"
    );
    let fresh = PairingContext {
        remote: world.devices[2].id,
        ..ctx
    };
    invite.offer(&fresh).await.unwrap();
    world.check().unwrap();
}

#[test]
fn pairing_cuts_preserve_committed_state() {
    for cut in [1, 20, 60, 120, 240] {
        let mut world = World::new().unwrap();
        world.pair_with_cut(1, Some(cut)).unwrap();
        world.check().unwrap();
        world.step(&Action::Crash(0)).unwrap();
        world.step(&Action::Crash(1)).unwrap();
    }
}

/// A cut after the inviter committed the `Add` leaves a member that never got
/// its welcome. Pairing it again completes without a second `Add`, and the
/// devices converge.
#[test]
fn pairing_again_after_a_cut_finishes_the_join() {
    for cut in [1, 20, 60, 120, 240] {
        let mut world = World::new().unwrap();
        world.pair_with_cut(1, Some(cut)).unwrap();
        world.step(&Action::Startup(0)).unwrap();
        world.step(&Action::Pair(1)).unwrap();
        assert!(
            world.devices[1]
                .with(|s| Ok(s.vaults.contains_key(&world.vault)))
                .unwrap()
        );
        let adds = world.devices[0]
            .with(|s| {
                Ok(s.vault(&world.vault)
                    .frames()
                    .filter(|f| {
                        f.member_body()
                            .is_some_and(|b| matches!(b.op, Some(MemberOp::Add { .. })))
                    })
                    .count())
            })
            .unwrap();
        // Genesis adds the creator; pairing adds one more.
        assert_eq!(adds, 2, "cut {cut}");
        world.step(&Action::Add(1, 7)).unwrap();
        world.converge().unwrap();
    }
}

#[test]
fn startup_reopens_pairing_and_existing_handlers_observe_readiness() {
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Crash(0)).unwrap();
    let handler = world.devices[0].handler();
    assert!(!handler.ready.load(Ordering::SeqCst));
    world.step(&Action::Pair(2)).unwrap();
    assert!(!world.can_write(2));
    world.step(&Action::Startup(0)).unwrap();
    assert!(handler.ready.load(Ordering::SeqCst));
    world.step(&Action::Pair(2)).unwrap();
    assert!(world.can_write(2));
    world.step(&Action::Add(2, 42)).unwrap();
    world.converge().unwrap();
}

/// Two devices that can't see each other both delete an item, and one
/// restores it: the restore never saw the other delete, so once healed
/// every device has the item back.
#[test]
fn restore_beats_a_delete_it_never_saw() {
    let mut world = World::new().unwrap();
    for action in [
        Action::Pair(1),
        Action::Add(0, 1),
        Action::Sync(0, 1, 10, None),
        Action::Partition(0, 1),
        Action::Delete(0),
        Action::Delete(1),
        Action::Restore(0),
    ] {
        world.step(&action).unwrap();
    }
    let deleted = |world: &World, i: usize| {
        world.devices[i]
            .with(|s| Ok(s.vault(&world.vault).deleted().len()))
            .unwrap()
    };
    assert_eq!((deleted(&world, 0), deleted(&world, 1)), (0, 1));
    world.converge().unwrap();
    for i in 0..2 {
        assert_eq!(deleted(&world, i), 0);
        let items = world.devices[i]
            .with(|s| Ok(s.vault(&world.vault).items().len()))
            .unwrap();
        assert_eq!(items, 1);
    }
}

#[test]
fn replay_has_identical_wire_schedule() {
    let trace = vec![
        Action::Pair(1),
        Action::Add(0, 19),
        Action::Sync(0, 1, 47, Some(200)),
        Action::Crash(0),
        Action::Sync(1, 0, 63, None),
    ];
    assert_eq!(replay(&trace).unwrap(), replay(&trace).unwrap());
}

#[test]
fn removal_blocks_causal_data_via_a_stale_peer() {
    replay(&[
        Action::Pair(1),
        Action::Pair(2),
        Action::Add(0, 1),
        Action::Sync(0, 1, 10, None),
        Action::Partition(0, 1),
        Action::Remove(1),
        Action::Add(0, 2),
        Action::Sync(0, 2, 12, None),
        Action::Sync(2, 1, 13, None),
        Action::Heal,
        Action::Sync(0, 1, 14, None),
    ])
    .unwrap();
}

#[test]
fn shrinking_keeps_only_the_failure_dependencies() {
    let trace = vec![
        Action::Heal,
        Action::Pair(1),
        Action::Heal,
        Action::Remove(1),
        Action::Heal,
    ];
    let reduced = shrink(trace, |candidate| {
        candidate.iter().any(|a| matches!(a, Action::Pair(1)))
            && candidate.iter().any(|a| matches!(a, Action::Remove(1)))
    });
    assert!(matches!(
        reduced.as_slice(),
        [Action::Pair(1), Action::Remove(1)]
    ));
}

#[test]
fn offline_unlock_keeps_local_items_available_and_failed_dials_finish_startup() {
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Add(0, 10)).unwrap();
    world.step(&Action::Lock(1)).unwrap();
    world.step(&Action::Crash(0)).unwrap();
    assert!(!world.devices[0].ready.load(Ordering::SeqCst));
    assert!(world.can_write(0));
    world.step(&Action::Add(0, 11)).unwrap();
    world.devices[0]
        .with(|s| {
            assert_eq!(s.vault(&world.vault).items().len(), 2);
            Ok(())
        })
        .unwrap();
    let result = world.sync(0, 1, 10, None, None).unwrap();
    assert_eq!(result, sync::Attempt::Unreachable);
    world.step(&Action::Startup(0)).unwrap();
    assert!(world.devices[0].ready.load(Ordering::SeqCst));
    world.converge().unwrap();
}

/// Cut identical short sessions before DONE. Each retry must advance the signed
/// frontier if a complete usable entry fits; confirm the prefix survives a
/// native store reopen (the private relay harness separately uses OPFS).
#[test]
fn short_sessions_commit_a_reopenable_prefix_before_done() {
    let mut w = World::new().unwrap();
    w.step(&Action::Pair(1)).unwrap();
    w.step(&Action::Pair(2)).unwrap();
    w.sync(0, 1, 10, None, None).unwrap();
    for i in 0..32 {
        w.step(&Action::Add(0, i)).unwrap();
    }
    let count = |w: &World| {
        w.devices[1]
            .with(|s| Ok(s.vault(&w.vault).items().len()))
            .unwrap()
    };
    let mut before = count(&w);
    for _ in 0..2 {
        assert_eq!(
            w.sync(0, 1, 31, Some(800), None).unwrap(),
            sync::Attempt::Interrupted
        );
        let after = count(&w);
        assert!(
            after > before && after < 32,
            "cut persisted {before} -> {after} of 32"
        );
        before = after;
    }
    w.step(&Action::Crash(1)).unwrap();
    assert_eq!(count(&w), before);
    // No DONE/nudge, and the origin is gone. Ordinary anti-entropy must
    // still forward the intermediate device's durable prefix to a third peer.
    w.step(&Action::Partition(0, 1)).unwrap();
    w.step(&Action::Partition(0, 2)).unwrap();
    w.step(&Action::Startup(1)).unwrap();
    assert_eq!(
        w.sync(1, 2, 10, None, None).unwrap(),
        sync::Attempt::Complete
    );
    assert_eq!(
        w.devices[2]
            .with(|s| Ok(s.vault(&w.vault).items().len()))
            .unwrap(),
        before
    );
    w.step(&Action::Heal).unwrap();
    w.converge().unwrap();
}

#[test]
fn startup_retries_an_interrupted_exchange() {
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Crash(0)).unwrap();
    let peers = world.devices[0].with(|s| Ok(s.peer_set())).unwrap();
    let failed = world.sync(0, 1, 31, Some(40), None).unwrap();
    assert_eq!(failed, sync::Attempt::Interrupted);
    assert!(!sync::barrier_complete(
        &peers,
        &BTreeMap::from([(world.devices[1].id, failed)])
    ));
    let retried = world.sync(0, 1, 32, None, None).unwrap();
    assert_eq!(retried, sync::Attempt::Complete);
    assert!(sync::barrier_complete(
        &peers,
        &BTreeMap::from([(world.devices[1].id, retried)])
    ));
    world.converge().unwrap();
}

#[test]
fn startup_learns_removal_before_sending_locally_written_data() {
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Pair(2)).unwrap();
    world.sync(0, 1, 10, None, None).unwrap();
    world.step(&Action::Crash(1)).unwrap();
    world.step(&Action::Remove(2)).unwrap();
    world.step(&Action::Add(1, 99)).unwrap();
    assert!(!world.devices[1].ready.load(Ordering::SeqCst));
    // The removed peer answers before the honest peer carrying its removal.
    let fast = world.sync(1, 2, 11, None, None).unwrap();
    assert_eq!(fast, sync::Attempt::Complete);
    world.devices[2]
        .with(|s| {
            assert!(s.vault(&world.vault).items().is_empty());
            Ok(())
        })
        .unwrap();
    let honest = world.sync(1, 0, 12, None, None).unwrap();
    let peers = world.devices[1].with(|s| Ok(s.peer_set())).unwrap();
    assert!(!peers.contains(&world.devices[2].id));
    world.devices[1].ready.store(
        sync::barrier_complete(
            &peers,
            &BTreeMap::from([(world.devices[0].id, honest), (world.devices[2].id, fast)]),
        ),
        Ordering::SeqCst,
    );
    assert!(world.devices[1].ready.load(Ordering::SeqCst));
    assert_eq!(
        world.sync(1, 2, 13, None, None).unwrap(),
        sync::Attempt::Unreachable
    );
    world.devices[2]
        .with(|s| {
            assert!(s.vault(&world.vault).items().is_empty());
            Ok(())
        })
        .unwrap();
    world.converge().unwrap();
}

/// A file's name and contents carry the marker, and neither reaches the
/// disk in the clear: the scan looks for the marker and its base64.
#[test]
fn files_never_reach_the_disk_in_the_clear() {
    assert_eq!(
        data_encoding::BASE64.encode(&SECRET_MARKER.as_bytes()[..9]),
        FILE_MARKER
    );
    let mut world = World::new().unwrap();
    world.step(&Action::Pair(1)).unwrap();
    world.step(&Action::Attach(0, 3)).unwrap();
    world.step(&Action::Attach(0, 4)).unwrap();
    world.converge().unwrap();
    let file = world.devices[1]
        .with(|s| {
            let item = s.vault(&world.vault).items()[0].clone();
            Ok(item.fields["receipt"].value.clone())
        })
        .unwrap();
    let (name, contents) = deadbolt_core::item::file_parts(&file);
    assert!(name.starts_with(SECRET_MARKER), "{name}");
    assert!(contents.unwrap().starts_with(FILE_MARKER));
}

/// Pulls are separated by real durable writes. The sender must stop at its
/// original signed tips, not chase the live tail; another stream opened at
/// the same heads must stop entirely if the recipient loses membership.
#[tokio::test]
async fn outgoing_catchup_is_a_snapshot_and_rechecks_revocation() {
    let mut world = World::new().unwrap();
    world.pair(1).unwrap();
    let source = world.devices[0].handler();
    let target = world.devices[1].handler();
    let (a, b) = (world.devices[0].id, world.devices[1].id);
    let heads = target.heads(a).await.unwrap();
    for i in 1..=2 {
        world.step(&Action::Add(0, i)).unwrap();
    }
    // Use the non-streaming core selection as an independent oracle. A
    // login creation can include an audit entry as well as the create.
    let peer_heads = world.devices[1]
        .with(|s| Ok(s.vault(&world.vault).heads()))
        .unwrap();
    let expected = world.devices[0]
        .with(|s| {
            let vault = s.vault(&world.vault);
            Ok([LogKind::Member, LogKind::Data]
                .into_iter()
                .flat_map(|log| vault.missing(&peer_heads, log))
                .map(|f| deadbolt_net::Blob::new(f.encode()))
                .collect::<Vec<_>>())
        })
        .unwrap();
    assert!(expected.len() > 1);
    let mut first = source.missing_for(b, heads.clone()).await.unwrap();
    let mut revoked = source.missing_for(b, heads.clone()).await.unwrap();
    let prefix = first.next().unwrap().unwrap();
    assert_eq!(revoked.next().unwrap().unwrap(), prefix);
    world.step(&Action::Attach(0, 3)).unwrap();
    assert_eq!(prefix, expected[0]);
    assert_eq!(first.collect::<Result<Vec<_>, _>>().unwrap(), expected[1..]);
    let full = source
        .missing_for(b, heads)
        .await
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(full.len() > expected.len());
    assert!(full.starts_with(&expected));
    world.step(&Action::Remove(1)).unwrap();
    assert!(revoked.next().unwrap().is_err());
    world.check().unwrap();
}

/// PAIR connections use their own gate. Removal after the welcome header
/// must abort before the next entry even though admission was durable.
#[test]
fn outgoing_welcome_stops_after_removal() {
    let mut world = World::new().unwrap();
    let device = DeviceId::from_bytes(world.devices[1].id);
    let inviter = DeviceId::from_bytes(world.devices[0].id);
    let join = world.devices[1]
        .with(|s| pairing::join_blob(&s.keys(), "beta", inviter, &world.vault, None))
        .unwrap();
    let mut history = world.devices[0]
        .with(|s| Ok(pairing::welcome(s, world.vault, device, &join, None)?.0))
        .unwrap();
    world.devices[0]
        .with(|s| {
            assert!(history.next(s, true)?.is_some());
            Ok(())
        })
        .unwrap();
    world.step(&Action::Remove(1)).unwrap();
    assert!(
        world.devices[0]
            .with(|s| Ok(history.next(s, true)?))
            .is_err()
    );
    world.check().unwrap();
}

/// Application batches can overlap across sessions and arrive in any order.
/// Data frames name no data parents, so a batch delivered backwards lands
/// whole, survives a crash, and replaying it (or any part) adds nothing.
#[tokio::test]
async fn reordered_batches_land_whole_and_replay_as_no_ops_after_a_crash() {
    // The manual stream scheduler owns polling; an enclosing Tokio task's
    // cooperative budget must not make its duplex streams spuriously stall.
    tokio::task::unconstrained(async {
        let mut world = World::new().unwrap();
        world.step(&Action::Pair(1)).unwrap();
        world.devices[0]
            .with(|s| {
                super::super::items::create(s, None, "note", Some("reordered".into()), vec![])?;
                Ok(())
            })
            .unwrap();
        for action in [Action::Attach(0, 2), Action::Attach(0, 3)] {
            world.step(&action).unwrap();
        }
        let source = world.devices[0].handler();
        let target = world.devices[1].handler();
        let (a, b) = (world.devices[0].id, world.devices[1].id);
        let entries = source
            .missing_for(b, target.heads(a).await.unwrap())
            .await
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 3);
        let mut reversed = entries.clone();
        reversed.reverse();
        target
            .receive(a, reversed, &mut Default::default(), true)
            .await
            .unwrap();
        world.check().unwrap();
        let items = |world: &World, i: usize| {
            world.devices[i]
                .with(|s| Ok(s.vault(&world.vault).items()))
                .unwrap()
        };
        assert_eq!(items(&world, 1), items(&world, 0));
        world.step(&Action::Crash(1)).unwrap();
        world.step(&Action::Startup(1)).unwrap();
        let missing = source
            .missing_for(b, target.heads(a).await.unwrap())
            .await
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(missing.is_empty());
        for entry in entries.iter().cloned() {
            target
                .receive(a, vec![entry], &mut Default::default(), true)
                .await
                .unwrap();
            world.check().unwrap();
        }
        target
            .receive(a, entries, &mut Default::default(), true)
            .await
            .unwrap();
        world.check().unwrap();
        assert_eq!(items(&world, 1), items(&world, 0));
        world.step(&Action::Crash(1)).unwrap();
        world.converge().unwrap();
    })
    .await;
}

/// A frame that fails verification must not discard a removal beside it.
/// Another member's concurrent write still lands, and everything converges.
#[tokio::test]
async fn a_bad_frame_does_not_block_removal_or_other_members() {
    tokio::task::unconstrained(async {
        let mut world = World::new().unwrap();
        world.step(&Action::Pair(1)).unwrap();
        world.step(&Action::Pair(2)).unwrap();
        let removed = DeviceId::from_bytes(world.devices[2].id);
        let (forged, removal) = world.devices[0]
            .with(|s| {
                let id = s.update(world.vault, |v, a| Ok(v.remove(a, removed)?))?;
                let removal = s.vault(&world.vault).frame(&id).unwrap().encode();
                // The same frame with one signature byte flipped.
                let mut forged = removal.clone();
                *forged.last_mut().unwrap() ^= 1;
                Ok((
                    deadbolt_net::Blob::new(forged),
                    deadbolt_net::Blob::new(removal),
                ))
            })
            .unwrap();
        let renamed = world.devices[1]
            .with(|s| s.update(world.vault, |v, a| Ok(v.rename(a, "still-writable")?)))
            .unwrap();
        let handler = world.devices[1].handler();
        handler
            .receive(
                world.devices[0].id,
                vec![forged, removal],
                &mut Default::default(),
                true,
            )
            .await
            .unwrap();
        world.devices[1]
            .with(|s| {
                assert!(!s.vault(&world.vault).is_member(&removed));
                Ok(())
            })
            .unwrap();
        world.check().unwrap();
        world.step(&Action::Crash(1)).unwrap();
        world.converge().unwrap();
        world.devices[0]
            .with(|s| {
                assert!(s.vault(&world.vault).frame(&renamed).is_some());
                Ok(())
            })
            .unwrap();
    })
    .await;
}

/// The small-chunk scheduler intentionally bounds trace size. Exercise full
/// production frames separately with the same application handlers and stores,
/// without sockets: exact file cap, concurrent aggregate overflow, and reload.
#[tokio::test]
#[cfg_attr(
    debug_assertions,
    ignore = "full-sized file coverage runs automatically in nightly release; use --ignored in debug"
)]
async fn full_size_files_sync_and_concurrent_files_survive_reload() {
    use crate::protocol::FieldInput;
    use deadbolt_core::item::{MAX_FILE, file_parts, file_value, files_size};

    tokio::task::unconstrained(async {
        let mut world = World::new().unwrap();
        world.step(&Action::Pair(1)).unwrap();
        let mut bytes = vec![b'x'; MAX_FILE];
        bytes[..SECRET_MARKER.len()].copy_from_slice(SECRET_MARKER.as_bytes());
        let full = file_value("cap.bin", &bytes);
        let half = file_value("half.bin", &bytes[..MAX_FILE / 2 + 1]);
        let field = |name: &str, value: &str| FieldInput {
            name: name.into(),
            kind: Some("file".into()),
            value: value.into(),
        };
        let (document, note) = world.devices[0]
            .with(|s| {
                super::super::items::create(
                    s,
                    None,
                    "document",
                    Some("full".into()),
                    vec![field("file", &full)],
                )?;
                super::super::items::create(s, None, "note", Some("concurrent".into()), vec![])?;
                let items = s.vault(&world.vault).items();
                let document = items
                    .iter()
                    .find(|item| item.kind == "document")
                    .unwrap()
                    .id;
                let note = items.iter().find(|item| item.kind == "note").unwrap().id;
                let before = s.vault(&world.vault).heads();
                let error = super::super::items::set(
                    s,
                    None,
                    &[document.to_string()],
                    vec![field("extra", &file_value("one.bin", b"x"))],
                    None,
                    &[],
                )
                .unwrap_err();
                assert!(
                    error.to_string().contains("at most 10 MiB together"),
                    "{error:#}"
                );
                assert_eq!(s.vault(&world.vault).heads(), before);
                Ok((document, note))
            })
            .unwrap();
        for round in 0..2 {
            if round == 1 {
                for (i, name) in [(0, "left"), (1, "right")] {
                    world.devices[i]
                        .with(|s| {
                            super::super::items::set(
                                s,
                                None,
                                &[note.to_string()],
                                vec![field(name, &half)],
                                None,
                                &[],
                            )?;
                            Ok(())
                        })
                        .unwrap();
                }
            }
            let (a, b) = (world.devices[0].handler(), world.devices[1].handler());
            let (left, right) = tokio::io::duplex(64 * 1024);
            let (mut ar, mut aw) = tokio::io::split(left);
            let (mut br, mut bw) = tokio::io::split(right);
            let max = deadbolt_net::DEFAULT_MAX_FRAME_LEN;
            let (sent, received) = tokio::join!(
                run_sync_session(&a, world.devices[1].id, &mut aw, &mut ar, max, true),
                run_sync_session(&b, world.devices[0].id, &mut bw, &mut br, max, false),
            );
            assert_eq!(sent.unwrap().sent, received.unwrap().received);
            assert!(world.converged().unwrap());
            world.check().unwrap();
        }
        for i in 0..2 {
            world.step(&Action::Crash(i)).unwrap();
            world.devices[i]
                .with(|s| {
                    let items = s.vault(&world.vault).items();
                    let merged = items.iter().find(|item| item.id == note).unwrap();
                    assert_eq!(files_size(merged.fields.values()), MAX_FILE + 2);
                    // Ordinary app reads expose names; requesting one file leaves the
                    // other attachment hidden, even after a concurrent cap overflow.
                    for (id, selected, expected) in
                        [(document, "file", &full), (note, "left", &half)]
                    {
                        let query = [id.to_string()];
                        let listed =
                            super::super::items::get(s, None, &query, false, false, &[], false)?;
                        let names: Vec<_> = listed
                            .fields
                            .iter()
                            .filter(|f| f.kind == "file")
                            .map(|f| f.value.as_str())
                            .collect();
                        assert_eq!(
                            names,
                            if id == document {
                                vec!["cap.bin"]
                            } else {
                                vec!["half.bin", "half.bin"]
                            }
                        );
                        let fetched = super::super::items::get(
                            s,
                            None,
                            &query,
                            false,
                            false,
                            &[selected.into()],
                            false,
                        )?;
                        assert_eq!(
                            fetched
                                .fields
                                .iter()
                                .find(|f| f.name == selected)
                                .unwrap()
                                .value,
                            expected.as_str()
                        );
                        assert!(
                            fetched
                                .fields
                                .iter()
                                .filter(|f| f.kind == "file" && f.name != selected)
                                .all(|f| file_parts(&f.value).1.is_none())
                        );
                    }
                    Ok(())
                })
                .unwrap();
        }
        world.converge().unwrap();
    })
    .await;
}
