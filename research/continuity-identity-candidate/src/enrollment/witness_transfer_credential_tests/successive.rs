// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::AnchorCredentialRenewalState as State;
#[path = "root.rs"]
mod root;

fn prepared_original() -> (
    Fixture,
    crate::VerifiedCredentialRenewal,
    Proposal,
    [u8; 32],
) {
    let f = fixture();
    let mut active = activate(&f, 150).expect("original operating owner");
    let (service, _, device) = active.parts().expect("owners");
    let journal = service.stores().expect("journal").0;
    let id = PrekeyId::from_trusted_state([95; 32]).expect("retained prekey ID");
    journal
        .generate_prekey(
            &f.c.policy,
            device,
            id,
            LeafKind::OneTimePq,
            Validity::new(100, 160).expect("original lifetime"),
            150,
        )
        .expect("real retained secret before G");
    let digest = journal.test_retained_prekey_digest(id);
    active.close();
    let grant = grant(&f, &f.original, 2, 250);
    let proposal = prepare(&f, &grant, 170);
    (f, grant, proposal, digest)
}
fn target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Vec<u8> {
    let pending = saved.1.as_ref().expect("original G target");
    assert_eq!(pending.get(..8), Some(b"QPWINT02".as_slice()));
    pending
        .get(220..pending.len().checked_sub(32).expect("MAC"))
        .expect("same sealed target")
        .to_vec()
}

#[test]
fn enrollment_witness_successive_g_preserves_three_original_commit_stages() {
    for progress in [0, 1, 2] {
        let (f, g, p, digest) = prepared_original();
        let sealed = disk(&f);
        let signer = fs::read(&f.c.paths.signer).expect("original signer");
        let wrapping = fs::read(&f.c.paths.wrapping).expect("original key");
        let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("subject");
        let first = Transfer::new(
            &mut f.carrier.store.lock().expect("A"),
            &f.c,
            &f.original,
            &f.original,
            f.c.policy.historical(),
            subject,
            175,
        );
        first.adopt_parent(&f.c, 180).close();
        first.set_time(181);
        if progress > 0 {
            let mut owner = open(&f.c);
            let mut carrier = first.client(&mut owner, &f.c);
            assert_eq!(
                carrier
                    .exchange(subject, AnchorOperation::commit_credential_renewal(&p))
                    .expect("B applies original G")
                    .credential_renewal_state(&p)
                    .expect("exact G"),
                State::Applied
            );
            if progress == 2 {
                assert_eq!(
                    DeviceJournal::recover_credential_renewal(
                        f.c.paths.installation.files()[1],
                        JournalKey::open(&f.c.paths.wrapping).expect("key"),
                        &f.original,
                        &f.c.policy,
                        f.id,
                        p,
                        &mut carrier
                    )
                    .expect("install original target retaining pending"),
                    State::Applied
                );
                assert_eq!(disk(&f), (target(&sealed), sealed.1.clone()));
            }
            owner.close();
        }
        let before = disk(&f);
        let current = if progress > 0 {
            g.successor_device()
        } else {
            &f.original
        };
        let second = first.successor(
            &f.c,
            &f.original,
            current,
            f.c.policy.historical(),
            subject,
            (185, 96),
        );
        second.set_time(190);
        second.adopt_parent(&f.c, 186).close();
        assert_eq!(
            disk(&f),
            before,
            "successor cannot reseal or clear G at stage {progress}"
        );
        second.reopen_target();
        let mut owner = open(&f.c);
        let mut carrier = second.client(&mut owner, &f.c);
        assert_eq!(
            owner
                .commit_witnessed_credential_renewal(
                    g.operation(),
                    g.statement_digest(),
                    &f.c.policy,
                    190,
                    &mut carrier
                )
                .expect("original G parent completion and ACK"),
            renewal::committed(&g)
        );
        assert_eq!(
            carrier
                .exchange(subject, AnchorOperation::query())
                .expect("current head")
                .observed_head(),
            p.target_head()
        );
        owner.close();
        assert_eq!(disk(&f), (target(&sealed), None));
        let mut owner = open(&f.c);
        let carrier = second.client(&mut owner, &f.c);
        let mut active = owner
            .activate(&f.c.policy, 190, Some(carrier))
            .expect("same installation C1");
        let (service, _, device) = active.parts().expect("owners");
        assert_eq!(
            device.credential_digest(),
            g.successor_device().credential_digest()
        );
        let journal = service.stores().expect("original journal").0;
        assert_eq!(journal.identity().expect("id"), f.id);
        assert_eq!(
            journal
                .test_retained_prekey_digest(PrekeyId::from_trusted_state([95; 32]).expect("id")),
            digest
        );
        active.close();
        assert_eq!(
            fs::read(&f.c.paths.signer).expect("signer retained"),
            signer
        );
        assert_eq!(
            fs::read(&f.c.paths.wrapping).expect("key retained"),
            wrapping
        );
        eprintln!("SUCCESSIVE_G stage={progress} original_target=true original_prekey=true parent_ack=true");
    }
}

#[test]
fn enrollment_witness_successive_g_closes_original_prepared_target_after_expiry() {
    let (f, g, p, _) = prepared_original();
    let saved = disk(&f);
    let subject = AnchorSubject::for_device(f.id, &f.original, &f.c.policy).expect("subject");
    let first = Transfer::new(
        &mut f.carrier.store.lock().expect("A"),
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        175,
    );
    first.adopt_parent(&f.c, 180).close();
    let second = first.successor(
        &f.c,
        &f.original,
        &f.original,
        f.c.policy.historical(),
        subject,
        (185, 96),
    );
    second.adopt_parent(&f.c, 186).close();
    second.set_time(290);
    second
        .target
        .lock()
        .expect("C")
        .transferred_control(&second.control)
        .expect("current authority")
        .close_credential_renewal(p, g.historical(), f.c.policy.historical())
        .expect("exact historical close");
    second.reopen_target();
    let mut owner = open(&f.c);
    let mut carrier = second.client(&mut owner, &f.c);
    assert!(
        matches!(owner.close_witnessed_credential_renewal(g.operation(),g.statement_digest(),
        &f.c.policy,290,&mut carrier).expect("same G close and parent ACK"),CredentialRenewalStatus::Closed {operation,statement,..}
        if operation==g.operation() && statement==g.statement_digest())
    );
    owner.close();
    assert_eq!(disk(&f), (saved.0, None));
}
