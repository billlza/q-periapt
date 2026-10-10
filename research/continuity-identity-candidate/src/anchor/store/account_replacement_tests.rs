// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AnchorAccountReplacementId as RootId, AnchorAccountReplacementProposal as RootProposal,
    AnchorAccountReplacementState as RootState, RootSigningKey,
};

fn root_device(c: &Case, root_seed: u8, device_seed: u8) -> (VerifiedDevice, DeviceSigningKey) {
    root_device_from(
        c.peer
            .responder
            .inventory_inputs()
            .expect("original verified inventory authority")
            .1,
        root_seed,
        device_seed,
    )
}
fn root_device_from(
    old: &VerifiedDevice,
    root_seed: u8,
    device_seed: u8,
) -> (VerifiedDevice, DeviceSigningKey) {
    let root = RootSigningKey::deterministic([root_seed; 32], [root_seed + 1; 32])
        .expect("fixture account root");
    let signer = DeviceSigningKey::deterministic([device_seed; 32], [device_seed + 1; 32])
        .expect("fixture device signer");
    let certificate = root
        .issue_device(
            old.description.clone(),
            signer.public_key().expect("fixture public key"),
        )
        .expect("root-issued fixture credential");
    let roster = root
        .issue_roster(
            1,
            old.roster_validity,
            &[root
                .roster_entry(&certificate)
                .expect("credential roster member")],
        )
        .expect("root-issued fixture roster");
    let pin = crate::AccountPin::new(
        root.account_id().expect("fixture cryptographic account"),
        root.public_key().expect("fixture public key"),
        roster.checkpoint(),
        old.description.family,
    )
    .expect("independent account pin");
    (
        pin.verify_device(&certificate, roster.as_bytes(), 150)
            .expect("verified target device"),
        signer,
    )
}
pub(super) fn root_target(c: &Case, root_seed: u8, device_seed: u8) -> Fresh {
    let (device, signer) = root_device(c, root_seed, device_seed);
    fresh_journal(
        c,
        c.peer
            .responder
            .current_policy()
            .expect("current fixture policy"),
        device,
        signer,
        device_seed,
    )
}
fn original_root(c: &Case) -> PublicKey {
    c.peer
        .responder
        .inventory_inputs()
        .expect("original verified inventory authority")
        .1
        .authority_key
        .clone()
}
fn root_proposal(c: &mut Case, next: &Fresh, operation: u8) -> RootProposal {
    c.store
        .account_root_replacement_proposal(
            RootId::from_trusted_state([operation; 32]).expect("original replacement operation"),
            &original_root(c),
            &next.genesis,
            &next.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150,
        )
        .expect("complete root replacement descriptor")
}
fn root_commit(
    c: &mut Case,
    p: &RootProposal,
    next: &Fresh,
    now: u64,
) -> Result<RootState, DurableError> {
    c.store.replace_account_root(
        p,
        &original_root(c),
        &next.genesis,
        &next.device,
        c.peer
            .responder
            .current_policy()
            .expect("current fixture policy"),
        now,
    )
}
fn unseen_old_device(c: &Case, seed: u8) -> Fresh {
    let old = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original verified inventory authority")
        .1;
    let mut description = old.description.clone();
    description.id = [seed; 16];
    let (device, signer) = signed_device(old, description, 3, seed, &[]);
    fresh_journal(
        c,
        c.peer
            .responder
            .current_policy()
            .expect("current fixture policy"),
        device,
        signer,
        seed,
    )
}

#[test]
fn account_root_retirement_fences_old_requests_unseen_enrollment_and_device_replacement() {
    let mut c = required_case();
    let same_root = fresh(&c, 2, 2, 174);
    let device_proposal = first_proposal(&mut c, &same_root);
    let next = root_target(&c, 190, 192);
    let p = root_proposal(&mut c, &next, 170);
    assert_eq!(
        p.predecessors().collect::<Vec<_>>(),
        vec![c.genesis.subject()]
    );
    assert_eq!(
        c.store
            .account_root_replacement_status(&p)
            .expect("original root replacement status"),
        RootState::Unavailable
    );
    let before = c
        .store
        .image()
        .expect("authenticated witness image")
        .revision;
    assert_eq!(
        root_commit(&mut c, &p, &next, 150).expect("exact root replacement commit"),
        RootState::Committed
    );
    assert_eq!(
        c.store
            .image()
            .expect("authenticated witness image")
            .revision,
        before + 1
    );
    assert_retired(&mut c, AnchorOperation::query());
    assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
    let unseen = unseen_old_device(&c, 196);
    for _ in 0..2 {
        assert!(matches!(
            c.store.enroll(
                &unseen.genesis,
                &unseen.device,
                c.peer
                    .responder
                    .current_policy()
                    .expect("current fixture policy"),
                150
            ),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert!(matches!(
            commit(&mut c, &device_proposal, &same_root, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert_eq!(
            root_commit(&mut c, &p, &next, 250).expect("exact root replacement commit"),
            RootState::Committed
        );
        assert_eq!(
            c.store
                .image()
                .expect("authenticated witness image")
                .revision,
            before + 1
        );
        assert_retired(&mut c, AnchorOperation::query());
        c.store.close();
        c.store = reopen(&c.server);
    }
    let image = c.store.image().expect("authenticated witness image");
    let active = c.store.active.as_ref().expect("live witness owner");
    let bytes = encode(&active.wrapping, &active.pin, &image)
        .expect("canonical authenticated witness image");
    assert_eq!(bytes.get(..8).expect("witness layout tag"), b"QPANC015");
    assert_eq!(image.entries.len(), 2);
    assert!(
        image.replacements.is_empty()
            && image.retired_cleanup.is_empty()
            && image.retired_reports.is_empty()
    );
}

#[test]
fn account_root_snapshot_race_refuses_but_unrelated_account_progress_is_preserved() {
    let mut c = required_case();
    let other = root_target(&c, 200, 202);
    c.store
        .enroll(
            &other.genesis,
            &other.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150,
        )
        .expect("independent fixture enrollment");
    let next = root_target(&c, 190, 192);
    let stale = root_proposal(&mut c, &next, 171);
    let old_request = request(
        &c,
        AnchorOperation::advance(initial(&c), [173; 32]).expect("exact original advance"),
    );
    let old_head = apply_request(&mut c, &old_request)
        .applied_head()
        .expect("committed witness head");
    assert!(matches!(
        root_commit(&mut c, &stale, &next, 150),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        c.store
            .account_root_replacement_status(&stale)
            .expect("original root replacement status"),
        RootState::Unavailable
    );
    let p = root_proposal(&mut c, &next, 172);
    let other_head = query(&mut c, &other).observed_head();
    let other_request = AnchorRequest::new(
        &c.pin,
        other.genesis.subject(),
        AnchorOperation::advance(other_head, [174; 32]).expect("exact original advance"),
        &other.signer,
    )
    .expect("signed original witness request");
    let wire = c
        .store
        .handle(other_request.as_bytes(), 150)
        .expect("admitted witness request");
    let advanced = c
        .pin
        .verify_reply(&other_request, &wire)
        .expect("authenticated witness reply")
        .applied_head()
        .expect("committed witness head");
    assert_eq!(
        root_commit(&mut c, &p, &next, 150).expect("exact root replacement commit"),
        RootState::Committed
    );
    let retired = c
        .store
        .retired_account_observation(&p)
        .expect("original account retirement");
    assert_eq!(
        retired
            .subject_observation(c.genesis.subject())
            .expect("exact frozen subject observation")
            .observed_head(),
        old_head
    );
    assert_eq!(
        retired
            .subject_observation(c.genesis.subject())
            .expect("exact frozen subject observation")
            .last_command_id(),
        Some(old_request.command_id())
    );
    assert_eq!(query(&mut c, &other).observed_head(), advanced);
    assert!(matches!(
        c.store.handle(old_request.as_bytes(), 150),
        Err(AnchorError::Rejected(Error::Scope))
    ));
}

#[test]
fn account_root_replacement_needs_fresh_independent_target_and_exact_operation() {
    let mut c = required_case();
    let same_root = fresh(&c, 2, 2, 174);
    let old_root = original_root(&c);
    let id = RootId::from_trusted_state([175; 32]).expect("original replacement operation");
    assert!(c
        .store
        .account_root_replacement_proposal(
            id,
            &old_root,
            &same_root.genesis,
            &same_root.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150
        )
        .is_err());
    let next = root_target(&c, 190, 192);
    let other = root_target(&c, 200, 202);
    let p = root_proposal(&mut c, &next, 176);
    let competing = root_proposal(&mut c, &other, 177);
    assert!(matches!(
        c.store.replace_account_root(
            &p,
            &other.device.authority_key,
            &next.genesis,
            &next.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(root_commit(&mut c, &p, &other, 150).is_err());
    root_commit(&mut c, &p, &next, 150).expect("exact root replacement commit");
    assert!(matches!(
        root_commit(&mut c, &competing, &other, 150),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store.account_root_replacement_status(&competing),
        Err(DurableError::Conflict)
    ));
    assert!(c
        .store
        .account_root_replacement_proposal(
            id,
            &next.device.authority_key,
            &c.genesis,
            c.peer
                .responder
                .inventory_inputs()
                .expect("original verified inventory authority")
                .1,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150
        )
        .is_err());
    assert!(RootId::from_trusted_state([0; 32]).is_err());
}

#[test]
fn account_root_retirement_can_fence_an_unseen_root_without_retiring_other_accounts() {
    let mut c = required_case();
    let previous = RootSigningKey::deterministic([210; 32], [211; 32])
        .expect("fixture account root")
        .public_key()
        .expect("fixture public key");
    let next = root_target(&c, 190, 192);
    let p = c
        .store
        .account_root_replacement_proposal(
            RootId::from_trusted_state([178; 32]).expect("original replacement operation"),
            &previous,
            &next.genesis,
            &next.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150,
        )
        .expect("complete root replacement descriptor");
    assert_eq!(p.predecessors().count(), 0);
    c.store
        .replace_account_root(
            &p,
            &previous,
            &next.genesis,
            &next.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150,
        )
        .expect("exact account replacement");
    let old_request = request(&c, AnchorOperation::query());
    assert_eq!(
        apply_request(&mut c, &old_request).outcome(),
        AnchorOutcome::Current
    );
    let forbidden = root_target(&c, 210, 214);
    assert!(matches!(
        c.store.enroll(
            &forbidden.genesis,
            &forbidden.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .account_root_replacement_status(&p)
            .expect("original root replacement status"),
        RootState::Committed
    );
}

#[test]
fn account_root_receipt_binds_full_descriptor_and_both_signatures_under_separate_purpose() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let p = root_proposal(&mut c, &next, 179);
    let competing = root_proposal(&mut c, &next, 180);
    let encoded = p.to_bytes().expect("canonical original descriptor");
    assert_eq!(encoded.len(), 4452 + 209 * p.predecessors().count());
    assert_eq!(
        RootProposal::from_trusted_state(&encoded).expect("decode retained replacement descriptor"),
        p
    );
    for length in [0, 8, encoded.len() - 1] {
        assert!(RootProposal::from_trusted_state(
            encoded.get(..length).expect("bounded truncation sample")
        )
        .is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(RootProposal::from_trusted_state(&trailing).is_err());
    assert!(c.store.retired_account_receipt(&p).is_err());
    root_commit(&mut c, &p, &next, 150).expect("exact root replacement commit");
    let receipt = c
        .store
        .retired_account_receipt(&p)
        .expect("signed permanent account retirement");
    assert_eq!(receipt.len(), 3449);
    let retired = c
        .pin
        .verify_retired_account(&p, &receipt)
        .expect("authenticated exact account retirement");
    assert_eq!(retired.proposal(), &p);
    assert!(c.pin.verify_retired_account(&competing, &receipt).is_err());
    let (body, signature) =
        crate::crypto::open_envelope(&receipt).expect("canonical signed envelope");
    for index in [0, q_periapt_backends::ML_DSA_65_SIG_LEN + 63] {
        let mut damaged = signature.to_vec();
        *damaged
            .get_mut(index)
            .expect("selected signature component byte") ^= 1;
        let wire = crate::crypto::envelope(body, &damaged).expect("bounded signature envelope");
        assert!(matches!(
            c.pin.verify_retired_account(&p, &wire),
            Err(Error::Authentication)
        ));
    }
    let signature = c
        .store
        .active
        .as_ref()
        .expect("live witness owner")
        .signer
        .sign(Purpose::AnchorRetirement, body)
        .expect("fixture purpose-separated signature");
    assert!(c
        .pin
        .verify_retired_account(
            &p,
            &crate::crypto::envelope(body, &signature).expect("bounded signature envelope")
        )
        .is_err());
    let request = AnchorRequest::new(
        &c.pin,
        next.genesis.subject(),
        AnchorOperation::query(),
        &next.signer,
    )
    .expect("signed original witness request");
    assert!(c.pin.verify_reply(&request, &receipt).is_err());
    c.peer
        .responder
        .current_policy()
        .expect("current fixture policy")
        .close();
    c.store.close();
    c.store = reopen(&c.server);
    let historical = c
        .store
        .retired_account_receipt(&p)
        .expect("signed permanent account retirement");
    assert_eq!(
        c.pin
            .verify_retired_account(&p, &historical)
            .expect("authenticated exact account retirement"),
        retired
    );
}

#[test]
fn account_root_each_sync_fault_reconciles_one_whole_decision() {
    let mut calibration = required_case();
    let next = root_target(&calibration, 190, 192);
    let p = root_proposal(&mut calibration, &next, 181);
    let (_, count) = with_fault_database(&mut calibration, false);
    count.store(0, Ordering::SeqCst);
    root_commit(&mut calibration, &p, &next, 150).expect("exact root replacement commit");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = required_case();
            let next = root_target(&c, 190, 192);
            let p = root_proposal(&mut c, &next, 182);
            let before = c
                .store
                .image()
                .expect("authenticated witness image")
                .revision;
            let (remaining, _) = with_fault_database(&mut c, after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(root_commit(&mut c, &p, &next, 150), after);
            assert!(c.store.active.is_none());
            c.store = reopen(&c.server);
            let image = c.store.image().expect("authenticated witness image");
            assert_eq!(
                image.entries.len(),
                if image.account_replacements.is_empty() {
                    1
                } else {
                    2
                }
            );
            assert_eq!(
                root_commit(&mut c, &p, &next, 150).expect("exact root replacement commit"),
                RootState::Committed
            );
            assert_eq!(
                c.store
                    .image()
                    .expect("authenticated witness image")
                    .revision,
                before + 1
            );
            assert_retired(&mut c, AnchorOperation::query());
        }
    }
    eprintln!(
        "ANCHOR_ACCOUNT_REPLACEMENT_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[test]
fn account_root_successor_replacement_preserves_history_and_operation_ids_cannot_change_scope() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let newest = root_target(&c, 200, 202);
    let p = root_proposal(&mut c, &next, 220);
    let unrelated_root = RootSigningKey::deterministic([210; 32], [211; 32])
        .expect("fixture account root")
        .public_key()
        .expect("fixture public key");
    let reused = c
        .store
        .account_root_replacement_proposal(
            p.operation(),
            &unrelated_root,
            &newest.genesis,
            &newest.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150,
        )
        .expect("complete root replacement descriptor");
    root_commit(&mut c, &p, &next, 150).expect("exact root replacement commit");
    assert!(matches!(
        c.store.account_root_replacement_status(&reused),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        c.store.replace_account_root(
            &reused,
            &unrelated_root,
            &newest.genesis,
            &newest.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150
        ),
        Err(DurableError::Conflict)
    ));
    let receipt = c
        .store
        .retired_account_receipt(&p)
        .expect("signed permanent account retirement");
    let second = c
        .store
        .account_root_replacement_proposal(
            RootId::from_trusted_state([221; 32]).expect("original replacement operation"),
            &next.device.authority_key,
            &newest.genesis,
            &newest.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150,
        )
        .expect("complete root replacement descriptor");
    assert_eq!(
        c.store
            .replace_account_root(
                &second,
                &next.device.authority_key,
                &newest.genesis,
                &newest.device,
                c.peer
                    .responder
                    .current_policy()
                    .expect("current fixture policy"),
                150
            )
            .expect("exact account replacement"),
        RootState::Committed
    );
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        root_commit(&mut c, &p, &next, 250).expect("exact root replacement commit"),
        RootState::Committed
    );
    assert_eq!(
        c.store
            .retired_account_observation(&p)
            .expect("original account retirement"),
        c.pin
            .verify_retired_account(&p, &receipt)
            .expect("authenticated exact account retirement")
    );
    let request = AnchorRequest::new(
        &c.pin,
        next.genesis.subject(),
        AnchorOperation::query(),
        &next.signer,
    )
    .expect("signed original witness request");
    assert!(matches!(
        c.store.handle(request.as_bytes(), 150),
        Err(AnchorError::Rejected(Error::Scope))
    ));
    assert_eq!(query(&mut c, &newest).outcome(), AnchorOutcome::Current);
    assert_eq!(
        c.store
            .image()
            .expect("authenticated witness image")
            .account_replacements
            .len(),
        2
    );
}

#[test]
fn account_root_replacement_requires_classification_of_original_legacy_entries() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let mut image = c.store.image().expect("authenticated witness image");
    image
        .entries
        .values_mut()
        .next()
        .expect("original enrolled entry")
        .original_identity = None;
    c.store
        .persist(&mut image)
        .expect("persist explicit fixture state");
    let before = c.store.image().expect("authenticated witness image").digest;
    assert!(matches!(
        c.store.account_root_replacement_proposal(
            RootId::from_trusted_state([222; 32]).expect("original replacement operation"),
            &original_root(&c),
            &next.genesis,
            &next.device,
            c.peer
                .responder
                .current_policy()
                .expect("current fixture policy"),
            150
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        c.store.image().expect("authenticated witness image").digest,
        before
    );
    c.store
        .retain_original_identity(
            c.genesis.subject(),
            c.peer
                .responder
                .inventory_inputs()
                .expect("original verified inventory authority")
                .1,
        )
        .expect("classify original authenticated identity");
    let p = root_proposal(&mut c, &next, 222);
    assert_eq!(
        root_commit(&mut c, &p, &next, 150).expect("exact root replacement commit"),
        RootState::Committed
    );
}

#[test]
fn account_root_retirement_authenticated_state_corruption_and_unknown_versions_are_refused() {
    let mut c = required_case();
    let next = root_target(&c, 190, 192);
    let p = root_proposal(&mut c, &next, 183);
    root_commit(&mut c, &p, &next, 150).expect("exact root replacement commit");
    let mut image = c.store.image().expect("authenticated witness image");
    let mut changed = p.to_bytes().expect("canonical original descriptor");
    *changed.last_mut().expect("final descriptor byte") ^= 1;
    image.account_replacements.insert(
        p.previous_account(),
        RootProposal::from_trusted_state(&changed).expect("decode retained replacement descriptor"),
    );
    let active = c.store.active.as_ref().expect("live witness owner");
    assert!(encode(&active.wrapping, &active.pin, &image).is_err());
    let image = c.store.image().expect("authenticated witness image");
    let active = c.store.active.as_ref().expect("live witness owner");
    let original = encode(&active.wrapping, &active.pin, &image)
        .expect("canonical authenticated witness image");
    for tag in [*b"QPANC005", *b"QPANC016", *b"XPANC015", *b"QPANC010"] {
        let body_length = original
            .len()
            .checked_sub(32)
            .expect("complete witness MAC");
        let mut bytes = original
            .get(..body_length)
            .expect("authenticated image body")
            .to_vec();
        bytes
            .get_mut(..8)
            .expect("witness layout tag")
            .copy_from_slice(&tag);
        let mut auth = authenticator(&active.wrapping).expect("witness image authenticator");
        auth.update(&bytes);
        bytes.extend_from_slice(&auth.finalize().into_bytes());
        assert!(decode(&active.wrapping, &active.pin, &bytes).is_err());
    }
}

#[test]
fn account_root_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ACCOUNT_REPLACEMENT_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let mut store = reopen(path);
    let pin = store.pin().expect("original witness pin");
    let peer = crate::bootstrap::tests::fixture_with_anchor_and_budget(
        PrekeyQuality::OneTimeBoth,
        crate::AnchorRequirement::required(&pin),
        crate::ApplicationSendBudget::new(1024).expect("fixture send allowance"),
    );
    let (policy, old, _) = peer
        .responder
        .inventory_inputs()
        .expect("original verified inventory authority");
    let (next, _) = root_device_from(old, 190, 192);
    let journal_path = path
        .parent()
        .expect("private fixture root directory")
        .join(format!(
            "new-{}-{}-192",
            next.generation(),
            next.roster().checkpoint().version()
        ));
    let identity = crate::JournalIdentity::from_trusted_state(
        fs::read(journal_path.join("store-id"))
            .expect("read original retained fixture")
            .try_into()
            .expect("exact stored identity width"),
    )
    .expect("original journal identity");
    let genesis = DeviceJournal::recover_anchor_genesis(
        &journal_path.join("state.redb"),
        JournalKey::open(&journal_path.join("key")).expect("original protected wrapping key"),
        &next,
        policy,
        identity,
    )
    .expect("recover the exact original target genesis");
    let p = RootProposal::from_trusted_state(
        &fs::read(path.join("root-replacement.bin")).expect("read original retained fixture"),
    )
    .expect("decode retained replacement descriptor");
    assert_eq!(
        store
            .replace_account_root(&p, &old.authority_key, &genesis, &next, policy, 150)
            .expect("exact account replacement"),
        RootState::Committed
    );
    fs::write(path.join("returned-root-replacement"), b"committed")
        .expect("retain original fixture bytes");
}

#[test]
fn account_root_process_loss_after_commit_preserves_exact_decision_and_frozen_head() {
    let mut c = required_case();
    let mut next = root_target(&c, 190, 192);
    let old = request(
        &c,
        AnchorOperation::advance(initial(&c), [189; 32]).expect("exact original advance"),
    );
    let head = apply_request(&mut c, &old)
        .applied_head()
        .expect("committed witness head");
    let p = root_proposal(&mut c, &next, 184);
    let before = c
        .store
        .image()
        .expect("authenticated witness image")
        .revision;
    fs::write(
        c.server.join("root-replacement.bin"),
        p.to_bytes().expect("canonical original descriptor"),
    )
    .expect("retain original fixture bytes");
    next.journal.close();
    c.store.close();
    let log = fs::File::create_new(c.server.join("root-child.log")).expect("fresh owned child log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("current test binary"))
            .args([
                "--exact",
                "anchor::store::tests::replacement::account_root::account_root_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_ACCOUNT_REPLACEMENT_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_CRASH_REVISION", (before + 1).to_string())
            .stdout(Stdio::from(
                log.try_clone().expect("clone owned log descriptor"),
            ))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn owned witness child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("observe owned child").is_none() && Instant::now() < deadline,
            "root replacement child deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.server.join("returned-root-replacement").exists());
    child.0.kill().expect("kill child after durable commit");
    assert!(!child.0.wait().expect("reap owned child").success());
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .account_root_replacement_status(&p)
            .expect("original root replacement status"),
        RootState::Committed
    );
    assert_eq!(
        root_commit(&mut c, &p, &next, 250).expect("exact root replacement commit"),
        RootState::Committed
    );
    assert_eq!(
        c.store
            .image()
            .expect("authenticated witness image")
            .revision,
        before + 1
    );
    let receipt = c
        .store
        .retired_account_receipt(&p)
        .expect("signed permanent account retirement");
    let observed = c
        .pin
        .verify_retired_account(&p, &receipt)
        .expect("authenticated exact account retirement");
    assert_eq!(
        observed
            .subject_observation(c.genesis.subject())
            .expect("exact frozen subject observation")
            .observed_head(),
        head
    );
    assert_eq!(
        observed
            .subject_observation(c.genesis.subject())
            .expect("exact frozen subject observation")
            .last_command_id(),
        Some(old.command_id())
    );
    assert_retired(&mut c, AnchorOperation::query());
    assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
    eprintln!("ANCHOR_ACCOUNT_REPLACEMENT_PROCESS commit_before_return=true original_genesis_recovered=true exact_retry=true frozen_head_preserved=true old_scope_denied=true new_current=true");
}
