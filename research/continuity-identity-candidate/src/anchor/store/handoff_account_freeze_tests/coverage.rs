// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn transferred_account_freeze_refuses_unclassified_legacy_subjects() {
    let mut c = PolicyCase::new();
    let mut original = c.store.image().expect("original store");
    original
        .entries
        .get_mut(&c.subject.id(&original.namespace))
        .expect("original subject")
        .original_identity = None;
    c.store
        .persist(&mut original)
        .expect("representable classified-identity-free legacy state");
    let (f, mut active, history, _) = activated(&mut c);
    let request = AnchorAccountFreezeRequest::from_trusted_state(
        AnchorAccountFreezeId::from_trusted_state([225; 32]).expect("operation"),
        c.account.public_key().expect("root"),
        &f.pin,
    )
    .expect("independent current scope");
    let before = active
        .handoff_source_state()
        .expect("complete legacy state");
    assert!(matches!(
        active.transferred_account_freeze_proposal(&request, &history),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        active
            .handoff_source_state()
            .expect("no fabricated account classification")
            .as_bytes(),
        before.as_bytes()
    );
}

#[test]
fn transferred_account_freeze_includes_offline_device_and_refuses_partial_approval() {
    let mut c = PolicyCase::new();
    let p0 = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
    assert_eq!(p0.checkpoint(), c.original.checkpoint());
    let signer = crate::DeviceSigningKey::generate().expect("independent offline device");
    let certificate = c
        .account
        .issue_device(
            crate::DeviceDescription::new(
                [9; 16],
                1,
                p0.family(),
                Validity::new(100, 400).expect("validity"),
            )
            .expect("device"),
            signer.public_key().expect("key"),
        )
        .expect("real account-issued certificate");
    let roster = c
        .account
        .issue_roster(
            2,
            Validity::new(100, 400).expect("roster validity"),
            &[
                c.account
                    .roster_entry(&c.certificate)
                    .expect("original member"),
                c.account
                    .roster_entry(&certificate)
                    .expect("offline member"),
            ],
        )
        .expect("whole account roster");
    let device = crate::AccountPin::new(
        c.account.account_id().expect("account"),
        c.account.public_key().expect("root"),
        roster.checkpoint(),
        p0.family(),
    )
    .expect("pin")
    .verify_device(&certificate, roster.as_bytes(), 150)
    .expect("offline credential");
    let directory = c.server.join("offline-client");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .expect("private client");
    let mut journal = DeviceJournal::provision_anchored(
        &directory.join("journal.redb"),
        JournalKey::provision(&directory.join("key")).expect("separate key"),
        &device,
        &p0,
        crate::JournalIdentity::generate().expect("separate original journal"),
        150,
    )
    .expect("actual second journal");
    let genesis = journal
        .anchor_genesis(&device, &p0)
        .expect("second original genesis");
    c.store
        .enroll(&genesis, &device, &p0, 150)
        .expect("independent second enrollment");
    journal.close();
    let device = c.device.clone();
    let policy = c.original.clone();
    let mut f = Prepared::from_case(c, device, policy);
    let approved = approval(&mut f, 209);
    assert_eq!(approved.proposal().subjects().count(), 2);
    let complete = f.active.handoff_source_state().expect("before freeze");
    let mut partial = approved.to_bytes().expect("retained approval");
    let count = 8 + 112 + 8 + 8 + 64 + PUBLIC_KEY_BYTES;
    assert_eq!(partial.get(count..count + 2), Some([0, 2].as_slice()));
    *partial.get_mut(count + 1).expect("retained subject count") = 1;
    partial.truncate(partial.len() - 209);
    let partial = AnchorTransferredAccountFreezeApproval::restore_trusted_state(
        &partial,
        approved.proposal().request(),
        &f.history,
    )
    .expect("well-formed deliberately incomplete operator input");
    assert!(matches!(
        f.active.freeze_transferred_account(&partial, || Ok(180)),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        f.active
            .handoff_source_state()
            .expect("no partial freeze")
            .as_bytes(),
        complete.as_bytes()
    );
    let wire = f
        .active
        .freeze_transferred_account(&approved, || Ok(180))
        .expect("all devices frozen");
    let frozen = approved
        .verify_receipt(&f.history, &wire)
        .expect("current authority signature");
    let subjects = frozen.subjects().map(|s| s.subject()).collect::<Vec<_>>();
    assert!(subjects.contains(&f.c.subject) && subjects.contains(&genesis.subject()));
    assert!(matches!(
        f.active.handoff_client_authorization(genesis.subject()),
        Err(DurableError::Absent)
    ));
    f.reopen();
    assert_eq!(
        f.active
            .transferred_account_freeze_receipt(&approved)
            .expect("full persisted proof"),
        wire
    );
}

#[test]
fn transferred_account_freeze_rejects_a_snapshot_changed_after_independent_approval() {
    let mut f = Prepared::new(None);
    let grant = f
        .active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("one client authorization");
    let approved = approval(&mut f, 211);
    let proof = f.c.approval(&f.c.original, None, &f.c.target);
    let proposal = f.c.proposal(&proof, f.c.initial, 213);
    f.active
        .transferred_control(&grant)
        .expect("separate subject control")
        .prepare_policy_renewal(
            proposal,
            &proof,
            &super::super::control::policy_materials(&f.c),
            180,
        )
        .expect("real pending P after snapshot");
    let changed = f.original_entry();
    assert!(matches!(
        f.active.freeze_transferred_account(&approved, || Ok(180)),
        Err(DurableError::Conflict)
    ));
    assert_eq!(f.original_entry(), changed);
    assert!(matches!(
        f.active.transferred_account_freeze_receipt(&approved),
        Err(DurableError::Absent)
    ));
}
