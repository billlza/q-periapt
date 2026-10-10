// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityCheckpoint, AccountAuthorityIdentity,
    AccountAuthorityReplacementState as State, AccountAuthorityStore, ApplicationAccountId,
};

fn application(value: u8) -> ApplicationAccountId {
    ApplicationAccountId::from_trusted_state([value; 32]).expect("independent application identity")
}

#[test]
fn account_authority_registry_keeps_exact_root_intent_and_revokes_only_its_application() {
    let c = case();
    let base = c.path.parent().expect("fixture parent");
    let path = base.join("authority.redb");
    let key_path = base.join("authority-key");
    let identity = AccountAuthorityIdentity::generate().expect("original registry identity");
    let family = c.f.local_device().description.family;
    let mut registry = AccountAuthorityStore::provision(
        &path,
        JournalKey::provision(&key_path).expect("separate authority key"),
        identity,
        family,
        c.pin.clone(),
    )
    .expect("explicit authority registry");
    let first = registry
        .associate(application(1), c.f.local_device())
        .expect("independent first association");
    let other = registry
        .associate(application(2), c.f.initiator_device())
        .expect("unrelated association");
    let access = registry.access().expect("live parent");
    let old_lease = access.admit(first).expect("original entry");
    let unrelated = access.admit(other).expect("unrelated entry");
    assert_eq!(first.revision(), 1);
    let p = c.proposal(245);
    assert_eq!(
        registry
            .begin_replacement(first, p.clone())
            .expect("durable exact approval"),
        State::Pending
    );
    assert!(matches!(old_lease.check(), Err(DurableError::Suspended)));
    unrelated
        .check()
        .expect("unrelated account was not revoked");
    assert!(matches!(
        access.current(application(1)),
        Err(DurableError::Suspended)
    ));
    assert!(access.admit_account(p.successor_account()).is_err());
    assert!(registry
        .account_pin(application(1), c.next.roster().checkpoint())
        .is_err());
    assert_eq!(
        registry
            .begin_replacement(first, p.clone())
            .expect("same original pending operation"),
        State::Pending
    );
    let (_, state, retained) = registry
        .replacement(p.operation())
        .expect("original descriptor");
    assert_eq!(state, State::Pending);
    assert_eq!(retained, &p);
    crate::account_authority::tests::rejects_invalid_images(&registry);
    registry.close();
    assert!(matches!(unrelated.check(), Err(DurableError::Closed)));
    assert!(matches!(
        access.current(application(2)),
        Err(DurableError::Closed)
    ));

    registry = AccountAuthorityStore::open(
        &path,
        JournalKey::open(&key_path).expect("same key"),
        identity,
        family,
        c.pin.clone(),
    )
    .expect("same original registry");
    let restored = AccountAuthorityCheckpoint::from_trusted_state(
        first.application(),
        first.revision(),
        first.account(),
    )
    .expect("retained public expectation");
    assert_eq!(
        registry
            .begin_replacement(restored, p.clone())
            .expect("same pending after reopen"),
        State::Pending
    );
    let receipt = c.receipt(&p);
    let retired = c
        .pin
        .verify_retired_account(&p, &receipt)
        .expect("actual witness retirement");
    assert_eq!(
        registry
            .commit_replacement(&retired)
            .expect("select the exact successor"),
        State::Committed
    );
    let current = registry
        .access()
        .expect("current owner")
        .current(application(1))
        .expect("current mapping");
    assert_eq!(current.revision(), 2);
    assert_eq!(current.account(), p.successor_account());
    assert_eq!(
        registry
            .begin_replacement(restored, p.clone())
            .expect("historical original completion"),
        State::Committed
    );
    assert_eq!(
        registry
            .commit_replacement(&retired)
            .expect("exact commit retry"),
        State::Committed
    );
    assert_eq!(
        registry
            .access()
            .expect("access")
            .current(application(1))
            .expect("same target"),
        current
    );
    assert!(registry
        .associate(application(3), c.f.local_device())
        .is_err());
    assert!(matches!(
        access.current(application(1)),
        Err(DurableError::Closed)
    ));
    let pin = registry
        .account_pin(application(1), c.next.roster().checkpoint())
        .expect("selected independent root");
    assert!(pin
        .verify_historical_device(
            &c.f.local_device().certificate,
            c.f.local_device().roster().as_bytes()
        )
        .is_err());
    registry.close();
    registry = AccountAuthorityStore::open(
        &path,
        JournalKey::open(&key_path).expect("same key"),
        identity,
        family,
        c.pin.clone(),
    )
    .expect("committed mapping after restart");
    assert_eq!(
        registry
            .access()
            .expect("access")
            .current(application(1))
            .expect("same committed mapping"),
        current
    );
}

#[test]
fn account_authority_registry_requires_original_path_key_identity_and_version() {
    let c = case();
    let base = c.path.parent().expect("parent");
    let path = base.join("authority.redb");
    let key_path = base.join("authority-key");
    let identity = AccountAuthorityIdentity::generate().expect("original identity");
    let family = c.f.local_device().description.family;
    let mut registry = AccountAuthorityStore::provision(
        &path,
        JournalKey::provision(&key_path).expect("authority key"),
        identity,
        family,
        c.pin.clone(),
    )
    .expect("registry");
    let original = registry
        .associate(application(4), c.f.local_device())
        .expect("first association");
    let p = c.proposal(246);
    let invented = AccountAuthorityCheckpoint::from_trusted_state(
        original.application(),
        u64::MAX - 1,
        original.account(),
    )
    .expect("structurally valid but untrusted version");
    assert!(matches!(
        registry.begin_replacement(invented, p),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        registry
            .access()
            .expect("access")
            .current(application(4))
            .expect("unchanged mapping"),
        original
    );
    assert!(AccountAuthorityCheckpoint::from_trusted_state(
        original.application(),
        u64::MAX,
        original.account()
    )
    .is_err());
    assert!(AccountAuthorityStore::open(
        &path,
        JournalKey::open(&key_path).expect("key"),
        identity,
        family,
        c.pin.clone()
    )
    .is_err());
    registry.close();
    let wrong = AccountAuthorityIdentity::generate().expect("wrong independent identity");
    assert!(matches!(
        AccountAuthorityStore::open(
            &path,
            JournalKey::open(&key_path).expect("key"),
            wrong,
            family,
            c.pin.clone()
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        AccountAuthorityStore::open(
            &path,
            JournalKey::provision(&base.join("wrong-key")).expect("wrong key"),
            identity,
            family,
            c.pin.clone()
        ),
        Err(DurableError::Authentication)
    ));
    let copied = base.join("copied-authority.redb");
    fs::copy(&path, &copied).expect("owned copy at a different path");
    assert!(matches!(
        AccountAuthorityStore::open(
            &copied,
            JournalKey::open(&key_path).expect("key"),
            identity,
            family,
            c.pin.clone()
        ),
        Err(DurableError::Conflict)
    ));
    let absent = base.join("missing-authority.redb");
    assert!(AccountAuthorityStore::open(
        &absent,
        JournalKey::open(&key_path).expect("key"),
        identity,
        family,
        c.pin.clone()
    )
    .is_err());
    assert!(!absent.exists());
    registry = AccountAuthorityStore::open(
        &path,
        JournalKey::open(&key_path).expect("key"),
        identity,
        family,
        c.pin.clone(),
    )
    .expect("all invalid attempts preserved original state");
    assert_eq!(
        registry
            .access()
            .expect("access")
            .current(application(4))
            .expect("original selection"),
        original
    );
}

fn sync_case(commit: bool, cut: usize, after: bool) -> usize {
    let c = case();
    let base = c.path.parent().expect("parent");
    let path = base.join("authority.redb");
    let key_path = base.join("authority-key");
    let identity = AccountAuthorityIdentity::generate().expect("identity");
    let family = c.f.local_device().description.family;
    let mut registry = AccountAuthorityStore::provision(
        &path,
        JournalKey::provision(&key_path).expect("separate key"),
        identity,
        family,
        c.pin.clone(),
    )
    .expect("original registry");
    let original = registry
        .associate(application(5), c.f.local_device())
        .expect("old mapping");
    let other = registry
        .associate(application(6), c.f.initiator_device())
        .expect("unrelated mapping");
    let access = registry.access().expect("original parent");
    let old = access.admit(original).expect("original lease");
    let unrelated = access.admit(other).expect("other lease");
    let proposal = c.proposal(247);
    let retired = if commit {
        registry
            .begin_replacement(original, proposal.clone())
            .expect("original durable pending intent");
        Some(
            c.pin
                .verify_retired_account(&proposal, &c.receipt(&proposal))
                .expect("actual witness retirement"),
        )
    } else {
        None
    };
    let (remaining, count) =
        crate::account_authority::tests::fault_database(&mut registry, &path, after);
    remaining.store(cut, Ordering::SeqCst);
    let result = match &retired {
        Some(receipt) => registry.commit_replacement(receipt),
        None => registry.begin_replacement(original, proposal.clone()),
    };
    let barriers = count.load(Ordering::SeqCst);
    if cut == 0 {
        result.expect("measure actual transaction sync barriers");
        assert!(matches!(old.check(), Err(DurableError::Suspended)));
        unrelated
            .check()
            .expect("successful update preserves unrelated lease");
    } else {
        crate::durable::tests::assert_sync_failure(result, after);
        assert_eq!(remaining.load(Ordering::SeqCst), 0);
        assert!(matches!(registry.access(), Err(DurableError::Closed)));
        assert!(matches!(old.check(), Err(DurableError::Closed)));
        assert!(matches!(unrelated.check(), Err(DurableError::Closed)));
    }
    registry.close();
    registry = AccountAuthorityStore::open(
        &path,
        JournalKey::open(&key_path).expect("original key"),
        identity,
        family,
        c.pin.clone(),
    )
    .expect("reopen the original database after unknown commit");
    let recovered = registry.access().expect("new parent");
    assert_eq!(
        recovered
            .current(application(6))
            .expect("unrelated unchanged"),
        other
    );
    if commit {
        let (_, status, saved) = registry
            .replacement(proposal.operation())
            .expect("retained intent");
        assert_eq!(saved, &proposal);
        if status == State::Pending {
            assert!(matches!(
                recovered.current(application(5)),
                Err(DurableError::Suspended)
            ));
        } else {
            let current = recovered.current(application(5)).expect("committed target");
            assert_eq!(current.revision(), 2);
            assert_eq!(current.account(), proposal.successor_account());
        }
        registry
            .commit_replacement(retired.as_ref().expect("same verified receipt"))
            .expect("exact original commit retry");
        let current = recovered
            .current(application(5))
            .expect("target selected once");
        assert_eq!(current.revision(), 2);
        assert_eq!(current.account(), proposal.successor_account());
    } else {
        assert!(recovered
            .admit_account(proposal.successor_account())
            .is_err());
        match registry.replacement(proposal.operation()) {
            Ok((app, status, saved)) => {
                assert_eq!(app, application(5));
                assert_eq!(status, State::Pending);
                assert_eq!(saved, &proposal);
                assert!(matches!(
                    recovered.current(app),
                    Err(DurableError::Suspended)
                ));
                Ok(())
            }
            Err(DurableError::Absent) => {
                assert_eq!(
                    recovered
                        .current(application(5))
                        .expect("no committed fence"),
                    original
                );
                Ok(())
            }
            Err(error) => Err(error),
        }
        .expect("only original or pending state can survive a begin failure");
        assert_eq!(
            registry
                .begin_replacement(original, proposal)
                .expect("same begin retry"),
            State::Pending
        );
        assert!(matches!(
            recovered.current(application(5)),
            Err(DurableError::Suspended)
        ));
    }
    assert!(matches!(
        access.current(application(6)),
        Err(DurableError::Closed)
    ));
    barriers
}

#[test]
fn account_authority_registry_reconciles_every_pre_and_post_sync_failure() {
    for commit in [false, true] {
        let barriers = sync_case(commit, 0, false);
        assert!((1..=16).contains(&barriers));
        for after in [false, true] {
            for cut in 1..=barriers {
                sync_case(commit, cut, after);
            }
        }
        eprintln!(
            "ACCOUNT_AUTHORITY_SYNC commit={commit} barriers={barriers} injected_failures={}",
            barriers * 2
        );
    }
}
