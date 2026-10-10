// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn ordinary(m: &Managed, identity: JournalIdentity) -> Result<DeviceJournal, DurableError> {
    DeviceJournal::open_anchored(
        &m.path().join("state.redb"),
        JournalKey::open(&m.path().join("key"))?,
        m.c.f.initiator_device(),
        m.c.f.initiator.current_policy()?,
        identity,
        m.ordinary_client(),
    )
}

#[test]
fn journal_account_authority_rejects_pre_binding_backup_and_another_live_registry() {
    let mut m = Managed::unbound();
    let identity = m.sender.identity().expect("original identity");
    m.sender.close();
    let before = fs::read(m.path().join("state.redb")).expect("original unbound backup");
    m.sender = ordinary(&m, identity).expect("same original owner before binding");
    m.sender
        .adopt_account_authority(m.admission.clone())
        .expect("witnessed binding");
    m.sender.close();
    let bound = fs::read(m.path().join("state.redb")).expect("complete bound backup");
    fs::write(m.path().join("state.redb"), before).expect("restore only owned pre-binding backup");
    assert!(matches!(
        m.reopen(identity, m.ordinary_client()),
        Err(DurableError::Conflict)
    ));
    assert!(
        matches!(ordinary(&m, identity), Err(DurableError::Anchor(_))),
        "the original witness rejects the pre-adoption head"
    );
    fs::write(m.path().join("state.redb"), bound).expect("restore original committed bytes");
    let base = m.c.path.parent().expect("parent");
    let mut other = AccountAuthorityStore::provision(
        &base.join("other-authority.redb"),
        JournalKey::provision(&base.join("other-authority-key")).expect("different key"),
        AccountAuthorityIdentity::generate().expect("different registry"),
        m.c.f.initiator_device().description.family,
        m.c.pin.clone(),
    )
    .expect("independently provisioned other registry");
    let same_public_mapping = other
        .associate(m.local.application(), m.c.f.initiator_device())
        .expect("same public mapping");
    assert_eq!(same_public_mapping, m.local);
    let wrong =
        JournalAccountAuthority::new(other.access().expect("other owner"), same_public_mapping)
            .expect("other live admission");
    assert!(matches!(
        DeviceJournal::open_anchored_with_account_authority(
            &m.path().join("state.redb"),
            JournalKey::open(&m.path().join("key")).expect("same journal key"),
            m.c.f.initiator_device(),
            m.c.f.initiator.current_policy().expect("policy"),
            identity,
            m.ordinary_client(),
            wrong
        ),
        Err(DurableError::Conflict)
    ));
    m.sender = m
        .reopen(identity, m.ordinary_client())
        .expect("only original registry opens the journal");
    m.registry.lock().expect("registry").close();
    assert!(matches!(
        m.sender.next_message_id(&m.c.f.initiator, m.session, 150),
        Err(DurableError::Closed)
    ));
    assert!(matches!(m.sender.identity(), Err(DurableError::Closed)));
    other.close();
}

fn adoption_cut(cut: usize, after: bool) -> usize {
    let mut m = Managed::unbound();
    let identity = m.sender.identity().expect("original identity");
    let before = m.sender.image().expect("original image").digest;
    let path = m.path().join("state.redb");
    let (remaining, count) =
        crate::durable::tests::fault_existing_journal(&mut m.sender, &path, after);
    remaining.store(cut, Ordering::SeqCst);
    let result = m.sender.adopt_account_authority(m.admission.clone());
    let barriers = count.load(Ordering::SeqCst);
    if cut == 0 {
        result.expect("measure actual binding transaction barriers");
    } else {
        crate::durable::tests::assert_sync_failure(result, after);
        assert_eq!(remaining.load(Ordering::SeqCst), 0);
        assert!(matches!(m.sender.identity(), Err(DurableError::Closed)));
    }
    m.sender.close();
    let (has_binding, expected_target) = {
        let db =
            open_private_database(&path).expect("original database for read-only classification");
        let key = JournalKey::open(&m.path().join("key")).expect("original key");
        let owner = bootstrap::storage_owner(m.c.f.initiator_device());
        let (image, pending) =
            write_intent::load_snapshot(&db, &key, owner).expect("authenticated original state");
        let target = pending.as_ref().map(|p| {
            p.authenticated_target(&key, owner)
                .expect("exact authenticated pending image")
        });
        let has_binding = image.account_authority.is_some()
            || target
                .as_ref()
                .is_some_and(|i| i.account_authority.is_some());
        if !has_binding {
            assert!(pending.is_none());
            assert_eq!(image.digest, before);
        }
        (has_binding, target.map(|i| i.digest))
    };
    if has_binding {
        assert!(
            matches!(ordinary(&m, identity), Err(DurableError::Conflict)),
            "ordinary opening must not replay a managed pending transition"
        );
        m.sender = m
            .reopen(identity, m.ordinary_client())
            .expect("recover only original managed target");
        if let Some(expected) = expected_target {
            assert_eq!(
                m.sender.image().expect("recovered exact bytes").digest,
                expected
            );
        }
    } else {
        // A read-only classification and the fresh original witness both prove
        // this first adoption has no retained target. This is not an error fallback.
        m.sender = ordinary(&m, identity).expect("unchanged original witness head");
        m.sender
            .adopt_account_authority(m.admission.clone())
            .expect("explicit original first-adoption retry");
    }
    let committed = m.sender.image().expect("current bound image").digest;
    m.sender
        .adopt_account_authority(m.admission.clone())
        .expect("exact idempotent retry");
    assert_eq!(
        m.sender.image().expect("same committed image").digest,
        committed
    );
    let id = m
        .sender
        .next_message_id(&m.c.f.initiator, m.session, 150)
        .expect("current authority");
    let wire = m
        .sender
        .send_message(
            &m.c.f.initiator,
            m.session,
            id,
            b"after original recovery",
            b"authority",
            150,
        )
        .expect("actual application message");
    assert_eq!(
        m.c.journal
            .receive_message(&m.c.f.responder, m.session, &wire, b"authority", 150)
            .expect("actual remote delivery")
            .as_bytes(),
        b"after original recovery"
    );
    barriers
}

#[test]
fn journal_account_authority_adoption_recovers_every_pre_and_post_sync_failure() {
    let barriers = adoption_cut(0, false);
    assert!((1..=16).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            adoption_cut(cut, after);
        }
    }
    eprintln!(
        "JOURNAL_ACCOUNT_AUTHORITY_SYNC barriers={barriers} injected_failures={}",
        barriers * 2
    );
}

#[test]
fn journal_account_authority_stale_proposal_observation_retains_the_pending_intent() {
    let mut m = Managed::new();
    let proposal = m.c.proposal(251);
    // An ordinary old-device operation advances its witnessed head between
    // proposal capture and local approval retention. No malformed input is used.
    let id =
        m.c.journal
            .next_message_id(&m.c.f.responder, m.session, 150)
            .expect("old device message id");
    m.c.journal
        .send_message(
            &m.c.f.responder,
            m.session,
            id,
            b"concurrent old-device work",
            b"authority",
            150,
        )
        .expect("actual intervening witnessed commit");
    m.registry
        .lock()
        .expect("registry")
        .begin_replacement(m.peer, proposal.clone())
        .expect("original approved descriptor retained");
    assert!(matches!(
        m.c.witness.lock().expect("witness").replace_account_root(
            &proposal,
            &m.c.f.local_device().authority_key,
            &m.c.next_genesis,
            &m.c.next,
            m.c.f.responder.current_policy().expect("policy"),
            150,
        ),
        Err(DurableError::Conflict)
    ));
    let fresh = m.c.proposal(252);
    assert_ne!(fresh, proposal);
    assert!(matches!(
        m.registry
            .lock()
            .expect("registry")
            .begin_replacement(m.peer, fresh),
        Err(DurableError::Suspended)
    ));
    let mut registry = m.registry.lock().expect("registry");
    assert_eq!(
        registry
            .begin_replacement(m.peer, proposal.clone())
            .expect("same original retry"),
        crate::AccountAuthorityReplacementState::Pending
    );
    let (_, state, retained) = registry
        .replacement(proposal.operation())
        .expect("original pending operation");
    assert_eq!(state, crate::AccountAuthorityReplacementState::Pending);
    assert_eq!(retained, &proposal);
    assert!(matches!(
        registry
            .access()
            .expect("access")
            .current(m.peer.application()),
        Err(DurableError::Suspended)
    ));
    eprintln!("ACCOUNT_AUTHORITY_STALE_PROPOSAL actual_intervening_commit=true witness_conflict=true original_pending_retained=true recovery_workflow_complete=false");
}
