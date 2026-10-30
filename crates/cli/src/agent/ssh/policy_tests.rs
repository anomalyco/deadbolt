use std::sync::atomic::{AtomicUsize, Ordering};

use zeroize::Zeroizing;

use super::super::super::passkeys::tests::agent::unlocked;
use super::super::keys::{KeyKind, generate};
use super::*;
use crate::protocol::{Ancestor, Claim, FieldInput};

#[tokio::test]
async fn per_use_15m_grant_ai_exclusion_lock_clear_and_cooldown() {
    let f = unlocked().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let (bio_key, seen) = (f.key, calls.clone());
    *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(bio_key))
    }));

    let (vault_id, item_id) = f
        .agent
        .with(|s| {
            let vid = s.resolve(None)?;
            let made = generate(KeyKind::Ed25519, Some("kit@mac"))?;
            let info = crate::agent::items::create(
                s,
                None,
                "ssh",
                Some("GitHub".into()),
                vec![FieldInput {
                    name: "private-key".into(),
                    kind: None,
                    value: made.private_key.to_string(),
                }],
            )?;
            Ok((vid, info.id))
        })
        .unwrap();

    let mut human_tty = CallerInfo::unverified("Ghostty › zsh › ssh");
    human_tty.tty = Some("/dev/ttys007".into());
    human_tty.session_started = Some(1_700_000_000);

    let target = SignTarget::SshSig {
        namespace: "git".into(),
    };
    fn make_ctx<'a>(
        caller: &'a CallerInfo,
        vault_id: VaultId,
        item_id: &'a str,
        target: &'a SignTarget,
    ) -> SignContext<'a> {
        SignContext {
            caller,
            vault_id,
            vault_name: "personal",
            item_id,
            item_title: "GitHub",
            target,
            dest_hop: None,
            first_hop: None,
            forwarded: false,
            known_hosts: None,
        }
    }
    let (_tx, closed) = watch::channel(false);

    // 1. Default (`each`): every call prompts Touch ID.
    f.agent
        .approve_ssh_sign(
            &make_ctx(&human_tty, vault_id, &item_id, &target),
            None,
            closed.clone(),
        )
        .await
        .unwrap();
    f.agent
        .approve_ssh_sign(
            &make_ctx(&human_tty, vault_id, &item_id, &target),
            None,
            closed.clone(),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // 2. `ssh_approval = "15m"` caches for the same `(tty, session_started)`,
    // NOT for another tty, NOT for AI callers, and `lock()` wipes it.
    std::fs::create_dir_all(f.agent.paths.config.parent().unwrap()).unwrap();
    std::fs::write(
        &f.agent.paths.config,
        "touch_id = true\nssh_approval = \"15m\"\n",
    )
    .unwrap();
    f.agent
        .approve_ssh_sign(
            &make_ctx(&human_tty, vault_id, &item_id, &target),
            None,
            closed.clone(),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    f.agent
        .approve_ssh_sign(
            &make_ctx(&human_tty, vault_id, &item_id, &target),
            None,
            closed.clone(),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3, "covered by 15m tty grant");

    // Different terminal tab asks again.
    let mut other_tty = human_tty.clone();
    other_tty.tty = Some("/dev/ttys008".into());
    f.agent
        .approve_ssh_sign(
            &make_ctx(&other_tty, vault_id, &item_id, &target),
            None,
            closed.clone(),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 4);

    // AI caller on the same tty NEVER uses or creates a 15m grant.
    let mut ai_caller = human_tty.clone();
    ai_caller.ancestry = vec![Ancestor {
        pid: 99,
        name: "opencode-cli".into(),
        path: Some("/usr/local/bin/opencode-cli".into()),
    }];
    ai_caller.claimed = Some(Claim {
        caller: None,
        opencode_session: Some("ses_1".into()),
    });
    f.agent
        .approve_ssh_sign(
            &make_ctx(&ai_caller, vault_id, &item_id, &target),
            None,
            closed.clone(),
        )
        .await
        .unwrap();
    f.agent
        .approve_ssh_sign(
            &make_ctx(&ai_caller, vault_id, &item_id, &target),
            None,
            closed.clone(),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 6, "AI asks every time");

    // Locking drops grants.
    f.agent.ssh.policy.clear_on_lock();
    f.agent
        .approve_ssh_sign(
            &make_ctx(&human_tty, vault_id, &item_id, &target),
            None,
            closed.clone(),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 7, "grant cleared on lock");

    // 3. 3 user cancellations trip the 10-minute cooldown.
    *f.agent.biometric_hook.lock().unwrap() =
        Some(Arc::new(|_| Err(biometric::UnlockError::Cancelled)));
    let mut noisy = CallerInfo::unverified("runaway");
    noisy.tty = Some("/dev/ttys099".into());
    for _ in 0..3 {
        assert!(
            f.agent
                .approve_ssh_sign(
                    &make_ctx(&noisy, vault_id, &item_id, &target),
                    None,
                    closed.clone()
                )
                .await
                .is_err()
        );
    }
    let err = f
        .agent
        .approve_ssh_sign(&make_ctx(&noisy, vault_id, &item_id, &target), None, closed)
        .await
        .unwrap_err();
    assert_eq!(
        crate::client::code(&err),
        Some(ErrorCode::RateLimited),
        "{err}"
    );
}
