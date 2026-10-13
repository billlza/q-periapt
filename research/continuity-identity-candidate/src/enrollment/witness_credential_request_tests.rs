// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Required-witness issuer snapshots retain original G identity and actual history.
use super::*;
use crate::{CredentialRenewalId, CredentialRenewalRequest, VerifiedCredentialRenewal};

fn request(
    f: &Fixture,
    operation: CredentialRenewalId,
) -> Result<CredentialRenewalRequest, DurableError> {
    let mut owner = open(&f.c);
    let anchor = owner.credential_renewal_request_anchor_client(
        f.c.policy.historical(),
        f.pin.clone(),
        Box::new(f.carrier.clone()),
        Duration::from_secs(3),
    )?;
    owner.witnessed_credential_renewal_request(operation, f.c.policy.historical(), anchor)
}
fn issue(
    f: &Fixture,
    request: &CredentialRenewalRequest,
    until: u64,
    at: u64,
) -> VerifiedCredentialRenewal {
    let successor =
        f.c.root
            .issue_credential_extension(request.previous_device(), until, at)
            .expect("same-key issuer extension");
    let roster =
        f.c.root
            .issue_roster(
                request.authorization().previous.version() + 1,
                Validity::new(100, until + 20).expect("target interval"),
                &[f.c.root.roster_entry(&successor).expect("successor member")],
            )
            .expect("independent signed target");
    let pin = AccountPin::new(
        f.c.root.account_id().expect("account"),
        f.c.root.public_key().expect("root"),
        roster.checkpoint(),
        f.c.policy.family(),
    )
    .expect("independent target pin");
    let grant =
        f.c.root
            .issue_credential_renewal(
                request.materials(&successor, roster.as_bytes()),
                &request.authorization(),
                &pin,
                at,
            )
            .expect("independent root authorization");
    VerifiedCredentialRenewal::verify(
        grant.as_bytes(),
        &pin,
        request.authorization().policy_digest,
        at,
    )
    .expect("current grant")
}
fn same(a: &CredentialRenewalRequest, b: &CredentialRenewalRequest) {
    assert_eq!(a.operation(), b.operation());
    assert_eq!(a.journal(), b.journal());
    assert_eq!(a.original_owner(), b.original_owner());
    assert_eq!(a.original_credential(), b.original_credential());
    assert_eq!(a.previous_credential(), b.previous_credential());
    assert_eq!(a.original_roster(), b.original_roster());
    assert_eq!(a.previous_roster(), b.previous_roster());
    assert_eq!(a.authorization().previous, b.authorization().previous);
    assert_eq!(a.current_policy(), b.current_policy());
    assert_eq!(
        a.current_policy_authorization(),
        b.current_policy_authorization()
    );
}

#[test]
fn required_credential_request_uses_expired_history_without_live_runtime_or_logical_mutation() {
    let f = fixture_with_policy_expiry(Some(160));
    f.carrier.clock.store(170, Ordering::SeqCst);
    f.c.policy.close();
    f.c.policy.runtime.close();
    let operation = CredentialRenewalId::generate().expect("retained G ID");
    let before = disk(&f);
    let value = request(&f, operation).expect("historical witnessed snapshot");
    assert_eq!(value.operation(), operation);
    assert_eq!(value.journal(), f.id);
    assert_eq!(
        value.original_owner(),
        crate::bootstrap::storage_owner(&f.original)
    );
    assert_eq!(
        value.previous_device().credential_digest(),
        f.original.credential_digest()
    );
    assert_eq!(
        value.previous_validity(),
        Validity::new(100, 160).expect("expired C0")
    );
    assert_eq!(value.current_policy(), f.c.policy.checkpoint());
    assert_eq!(
        open(&f.c)
            .credential_renewal_status()
            .expect("no reservation"),
        CredentialRenewalStatus::Absent
    );
    same(
        &value,
        &request(&f, operation).expect("exact read-only retry"),
    );
    assert_eq!(disk(&f), before);
    assert!(matches!(
        open(&f.c).credential_renewal_request(operation, f.c.policy.historical()),
        Err(DurableError::AnchorRequired)
    ));
}

#[test]
fn required_credential_request_tracks_completed_g_and_refuses_pending_or_reused_operations() {
    let f = fixture();
    f.carrier.clock.store(170, Ordering::SeqCst);
    let operation = CredentialRenewalId::generate().expect("first ID");
    let original = request(&f, operation).expect("original issuer inputs");
    let first = issue(&f, &original, 190, 170);
    let mut owner = open(&f.c);
    owner
        .stage_credential_renewal(&first, operation, &f.c.policy, 170)
        .expect("original pending G");
    let rejected = owner.credential_renewal_request_anchor_client(
        f.c.policy.historical(),
        f.pin.clone(),
        Box::new(f.carrier.clone()),
        Duration::from_secs(3),
    );
    assert!(matches!(rejected, Err(DurableError::Suspended)));
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    prepare(&f, &first, 170);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 170);
    assert_eq!(
        owner
            .commit_witnessed_credential_renewal(
                operation,
                first.statement_digest(),
                &f.c.policy,
                170,
                &mut anchor
            )
            .expect("actual G commit/ACK/cleanup"),
        renewal::committed(&first)
    );
    owner.close();
    assert!(matches!(
        request(&f, operation),
        Err(DurableError::Conflict)
    ));
    f.carrier.clock.store(195, Ordering::SeqCst);
    let next = request(&f, CredentialRenewalId::generate().expect("next ID"))
        .expect("expired actual C1 predecessor");
    assert_eq!(next.original_credential(), original.original_credential());
    assert_eq!(
        next.previous_device().credential_digest(),
        first.successor_device().credential_digest()
    );
    assert_eq!(
        next.authorization().previous,
        first.successor_device().roster().checkpoint()
    );
    let second = issue(&f, &next, 230, 195);
    assert_eq!(
        second.previous_device().credential_digest(),
        first.successor_device().credential_digest()
    );
    assert_eq!(second.original_storage_owner(), original.original_owner());
}

#[test]
fn required_credential_request_refuses_wrong_witness_and_recovers_only_original_after_read_loss() {
    let f = fixture();
    let operation = CredentialRenewalId::generate().expect("request ID");
    f.carrier.requests.lock().expect("requests").clear();
    let expected = request(&f, operation).expect("baseline");
    let command = *f
        .carrier
        .requests
        .lock()
        .expect("requests")
        .first()
        .expect("real witness contact");
    for processed in [false, true] {
        *f.carrier.cut.lock().expect("cut") = Some((command, processed));
        let mut owner = open(&f.c);
        let anchor = owner
            .credential_renewal_request_anchor_client(
                f.c.policy.historical(),
                f.pin.clone(),
                Box::new(f.carrier.clone()),
                Duration::from_secs(3),
            )
            .expect("original client");
        assert!(matches!(
            owner.witnessed_credential_renewal_request(operation, f.c.policy.historical(), anchor),
            Err(DurableError::Anchor(_))
        ));
        assert!(matches!(owner.status(), Err(DurableError::Closed)));
        same(
            &expected,
            &request(&f, operation).expect("same request after unknown read"),
        );
    }
    let other = fixture();
    let mut owner = open(&f.c);
    assert!(matches!(
        owner.credential_renewal_request_anchor_client(
            f.c.policy.historical(),
            other.pin,
            Box::new(f.carrier.clone()),
            Duration::from_secs(3)
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
}

#[test]
fn required_credential_request_requires_original_ack_cleanup_and_refuses_closed_id() {
    for processed in [false, true] {
        let f = fixture();
        let proof = grant(&f, &f.original, 2, 190);
        prepare(&f, &proof, 170);
        *f.carrier.cut.lock().expect("ACK cut") = Some((8, processed));
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 170);
        assert!(owner
            .commit_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                170,
                &mut anchor
            )
            .is_err());
        let next = CredentialRenewalId::generate().expect("next request");
        assert!(matches!(request(&f, next), Err(DurableError::Suspended)));
        let mut owner = open(&f.c);
        let mut anchor = client(&f, &mut owner, 170);
        owner
            .reconcile_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                170,
                &mut anchor,
            )
            .expect("original terminal/ACK/cleanup");
        owner.close();
        let value = request(&f, next).expect("only retired completion admits issuer snapshot");
        assert_eq!(
            value.previous_device().credential_digest(),
            proof.successor_device().credential_digest()
        );
    }
    let f = fixture();
    let proof = grant(&f, &f.original, 2, 190);
    prepare(&f, &proof, 150);
    let mut owner = open(&f.c);
    let mut anchor = client(&f, &mut owner, 150);
    owner
        .close_witnessed_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &f.c.policy,
            150,
            &mut anchor,
        )
        .expect("original closed target");
    owner.close();
    assert!(matches!(
        request(&f, proof.operation()),
        Err(DurableError::Conflict)
    ));
    let fresh = request(&f, CredentialRenewalId::generate().expect("fresh G"))
        .expect("actual predecessor after closed target");
    assert_eq!(
        fresh.previous_device().credential_digest(),
        f.original.credential_digest()
    );
}
