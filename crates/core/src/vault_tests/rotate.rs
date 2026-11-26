//! Handing the recovery root on (`rotate_recovery`): the old kit loses
//! all power, and a competing rotation by the old kit freezes recovery.

use crate::v2::{LogKind, RecoverySecret};
use crate::vault::testing::{author, recovery, vault};
use crate::{Error, Vault};

#[test]
fn the_old_kit_cannot_unseat_the_new_one_and_a_competing_rotation_freezes_recovery() {
    let a = author(1);
    let (mut v, _) = vault(&a, "personal");
    let (r0, r1, r2) = (
        recovery(),
        RecoverySecret::from_bytes([0xe1; 32]),
        RecoverySecret::from_bytes([0xe2; 32]),
    );
    let mut fork = v.clone();
    v.transact(|w| w.rotate_recovery(&r0, &r1), |_, _| Ok::<_, Error>(()))
        .unwrap();
    assert_eq!(v.recovery_root(), Some(r1.recovery_id()));

    // R0 no longer signs anything that counts.
    let stale = v.transact(|w| w.rotate_recovery(&r0, &r2), |_, _| Ok::<_, Error>(()));
    assert!(matches!(stale, Err(Error::NotRecoveryRoot)), "{stale:?}");
    let unseat = v.transact(|w| w.remove_by_root(&r0, a.id()), |_, _| Ok::<_, Error>(()));
    assert!(matches!(unseat, Err(Error::NotRecoveryRoot)), "{unseat:?}");
    assert!(v.is_member(&a.id()));

    // R0, from a copy that hadn't seen the rotation, hands the root on too:
    // two kits claim one root, so neither keeps it.
    fork.transact(|w| w.rotate_recovery(&r0, &r2), |_, _| Ok::<_, Error>(()))
        .unwrap();
    let theirs: Vec<_> = fork
        .frames()
        .filter(|f| f.header().kind.log_kind() == LogKind::Member)
        .cloned()
        .collect();
    let kem = a.keys().kem_key();
    v.transact(|w| w.apply(kem, theirs), |_, _| Ok::<_, Error>(()))
        .unwrap();
    assert_eq!(v.recovery_root(), None, "the lineage froze");
    let reopened = Vault::open(a.keys(), v.frames().cloned()).unwrap();
    assert_eq!(reopened.recovery_root(), None);
}
