// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn old_device(c: &PolicyCase, pin: &AnchorPin, seed: u8, at: u64) -> Next {
    let (version, until) = if at == 150 { (1, 160) } else { (2, 260) };
    let (policy, policy_wire) = crate::anchor::store::policy_renewal::tests::policy_with_wire(
        &c.issuer, &c.runtime, pin, version, until, at,
    );
    let signer = crate::DeviceSigningKey::generate().expect("independent old-account device");
    let certificate = c
        .account
        .issue_device(
            crate::DeviceDescription::new(
                [seed; 16],
                1,
                policy.family(),
                Validity::new(100, 400).expect("device interval"),
            )
            .expect("description"),
            signer.public_key().expect("key"),
        )
        .expect("original root authenticates device");
    let roster = c
        .account
        .issue_roster(
            2,
            Validity::new(100, 400).expect("roster interval"),
            &[
                c.account
                    .roster_entry(&c.certificate)
                    .expect("original device"),
                c.account
                    .roster_entry(&certificate)
                    .expect("additional device"),
            ],
        )
        .expect("complete roster");
    let device = crate::AccountPin::new(
        c.account.account_id().expect("account"),
        c.account.public_key().expect("root"),
        roster.checkpoint(),
        policy.family(),
    )
    .expect("independent root and roster")
    .verify_device(&certificate, roster.as_bytes(), at)
    .expect("verified device");
    let dir = c.server.join(format!("original-device-{seed}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("private journal directory");
    let mut journal = DeviceJournal::provision_anchored(
        &dir.join("journal.redb"),
        JournalKey::provision(&dir.join("key")).expect("wrapping"),
        &device,
        &policy,
        crate::JournalIdentity::generate().expect("independent journal identity"),
        at,
    )
    .expect("actual journal");
    let genesis = journal
        .anchor_genesis(&device, &policy)
        .expect("actual original genesis");
    Next {
        device,
        signer,
        policy,
        genesis,
        _journal: journal,
        certificate,
        policy_wire,
    }
}

#[test]
fn transferred_account_decision_covers_offline_members_and_blocks_unseen_old_root_enrollment() {
    let mut original = PolicyCase::new();
    let offline = old_device(&original, &original.pin, 9, 150);
    original
        .store
        .enroll(&offline.genesis, &offline.device, &offline.policy, 150)
        .expect("second known device");
    super::super::adoption::pending(&mut original, "G", false);
    let mut c = RetirementCase::from_case(original, false);
    let n = next(&c, 220);
    let a = approve(&mut c, &n, 223);
    assert_eq!(a.proposal().predecessors().count(), 2);
    let original = c.old_entry();
    let decision = c
        .active
        .replace_transferred_account_root(&a, &materials(&c.root, &n, &c.history), || Ok(185))
        .expect("whole account retired");
    let retired = decision.retirement().expect("permanent historical fact");
    retired
        .subject_observation(c.c.subject)
        .expect("pending device covered");
    retired
        .subject_observation(offline.genesis.subject())
        .expect("offline device covered");
    let image = c.active.image().expect("durable complete account");
    assert_eq!(image.entries.len(), 3);
    for subject in [c.c.subject, offline.genesis.subject()] {
        assert!(image.subject_retired(subject));
    }
    assert!(!image.subject_retired(n.genesis.subject()));
    let unseen = old_device(&c.c, &c.f.pin, 10, 185);
    c.active
        .admit_enrollment(
            unseen.genesis.subject(),
            &unseen.device,
            &unseen.policy,
            185,
        )
        .expect("fresh valid policy and identity before account retirement fence");
    let before = c.active.handoff_source_state().expect("all original state");
    assert!(matches!(
        c.active
            .enroll(&unseen.genesis, &unseen.device, &unseen.policy, 185),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        c.active
            .handoff_source_state()
            .expect("no enrollment after old-root retirement")
            .as_bytes(),
        before.as_bytes()
    );
    c.reopen();
    assert_eq!(c.old_entry(), original);
    assert!(matches!(
        c.active
            .enroll(&unseen.genesis, &unseen.device, &unseen.policy, 185),
        Err(DurableError::Protocol(Error::Scope))
    ));
}

#[test]
fn transferred_account_decision_does_not_reset_an_advanced_successor() {
    let mut c = RetirementCase::new(Some(("R", true)), false);
    let n = next(&c, 230);
    let a = approve(&mut c, &n, 233);
    let m = materials(&c.root, &n, &c.history);
    let decision = c
        .active
        .replace_transferred_account_root(&a, &m, || Ok(185))
        .expect("initial exact successor");
    // Witness compare-and-set component test: this digest is an explicit signed
    // device expectation, not evidence of a complete client journal transaction.
    let head = AnchorHead::from_trusted_state(1, 1, n.genesis.image_digest())
        .expect("original genesis head");
    let request = AnchorRequest::new(
        &c.f.pin,
        n.genesis.subject(),
        AnchorOperation::advance(head, [239; 32]).expect("next head"),
        &n.signer,
    )
    .expect("signed successor command");
    let wire = c
        .active
        .handle(request.as_bytes(), 186)
        .expect("fresh successor may advance");
    let advanced =
        c.f.pin
            .verify_reply(&request, &wire)
            .expect("fresh current signature")
            .applied_head()
            .expect("committed advance");
    assert_ne!(advanced, head);
    assert_eq!(
        c.active
            .replace_transferred_account_root(&a, &m, || Err(DurableError::Conflict))
            .expect("exact historical retry without clock")
            .as_bytes(),
        decision.as_bytes()
    );
    c.reopen();
    let query = AnchorRequest::new(
        &c.f.pin,
        n.genesis.subject(),
        AnchorOperation::query(),
        &n.signer,
    )
    .expect("fresh query");
    let wire = c
        .active
        .handle(query.as_bytes(), 187)
        .expect("advanced original successor");
    assert_eq!(
        c.f.pin
            .verify_reply(&query, &wire)
            .expect("fresh current response")
            .observed_head(),
        advanced
    );
    assert_eq!(
        c.active
            .transferred_account_decision(&a)
            .expect("same historical proof")
            .as_bytes(),
        decision.as_bytes()
    );
}
