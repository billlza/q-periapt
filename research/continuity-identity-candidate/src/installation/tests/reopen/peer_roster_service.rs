// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn local_profile_admits_only_remote_roster_and_preserves_original_session_and_ciphertext() {
    for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
        let mut c = Local::with_role(false, role);
        let (peer_role, seed) = match role {
            BootstrapRole::Initiator => (BootstrapRole::Responder, 94),
            BootstrapRole::Responder => (BootstrapRole::Initiator, 90),
        };
        let policy = c.f.policy_owner(role);
        let target = update(c.f.initiator.device(peer_role), seed, true);
        let original = c
            .service
            .stores()
            .expect("stores")
            .0
            .resume_message(&c.f.initiator, c.session, c.original_id, 150)
            .expect("original committed ciphertext");
        let local = c.f.initiator.device(role).roster().clone();
        assert!(matches!(
            c.service.admit_peer_roster(&local, &policy, 150),
            Err(DurableError::Conflict)
        ));
        assert_eq!(
            c.service
                .admit_peer_roster(&target, &policy, 150)
                .expect("local-profile original service"),
            target.checkpoint()
        );
        let before = c.service.stores().expect("stores").0.test_snapshot();
        assert_eq!(
            c.service
                .admit_peer_roster(&target, &policy, 150)
                .expect("same canonical target"),
            target.checkpoint()
        );
        let journal = c.service.stores().expect("stores").0;
        let after = journal.test_snapshot();
        assert_eq!(
            (before.id, before.owner, before.revision, before.digest),
            (after.id, after.owner, after.revision, after.digest)
        );
        assert_eq!(
            journal
                .resume_message(&c.f.initiator, c.session, c.original_id, 150)
                .expect("same original session"),
            original
        );
    }
    eprintln!("PEER_ROSTER_LOCAL_PROFILE roles=2 original_owner=true original_ciphertext=true exact_retry=true");
}
