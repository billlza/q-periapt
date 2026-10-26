// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real original enrollment transactions before Witness transfer or root freeze.
use super::*;
use crate::retired_device::{Intent, Transaction};

pub(super) struct Prepared {
    pub(super) current: VerifiedDevice,
    pub(super) certificate: Vec<u8>,
    pub(super) policy: Option<(VerifiedSessionPolicy, Vec<u8>)>,
    pub(super) expected: Intent,
}
fn open(f: &Fixture, authority: Option<JournalAccountAuthority>) -> DeviceEnrollment {
    let mut owner = DeviceEnrollment::open(f.original.paths.clone(), f.original.intent.clone())
        .expect("same original parent before pending work");
    if let Some(authority) = authority {
        owner
            .select_account_authority(authority)
            .expect("same original registry");
    }
    owner
}
fn credential_client(f: &Fixture, owner: &mut DeviceEnrollment) -> AnchorClient {
    owner
        .credential_renewal_anchor_client(
            &f.policy,
            150,
            f.pin.clone(),
            Box::new(Carrier(Arc::clone(&f.witness))),
            Duration::from_secs(3),
        )
        .expect("original G control client")
}
fn credential_grant(
    f: &Fixture,
    owner: &mut DeviceEnrollment,
) -> (VerifiedCredentialRenewal, Vec<u8>) {
    let client = owner
        .credential_renewal_request_anchor_client(
            f.policy.historical(),
            f.pin.clone(),
            Box::new(Carrier(Arc::clone(&f.witness))),
            Duration::from_secs(3),
        )
        .expect("original public request carrier");
    let request = owner
        .witnessed_credential_renewal_request(
            CredentialRenewalId::generate().expect("original G ID"),
            f.policy.historical(),
            client,
        )
        .expect("actual original predecessor and retained public credential");
    let certificate = f
        .original
        .root
        .issue_credential_extension(request.previous_device(), 240, 150)
        .expect("independent same-key extension");
    let roster = f
        .original
        .root
        .issue_roster(
            2,
            Validity::new(100, 250).expect("target interval"),
            &[f.original
                .root
                .roster_entry(&certificate)
                .expect("target member")],
        )
        .expect("independent roster");
    let pin = AccountPin::new(
        f.original.device.account_id(),
        f.original.root.public_key().expect("root"),
        roster.checkpoint(),
        f.policy.family(),
    )
    .expect("target pin");
    let grant = f
        .original
        .root
        .issue_credential_renewal(
            request.materials(&certificate, roster.as_bytes()),
            &request.authorization(),
            &pin,
            150,
        )
        .expect("independent original request approval");
    let verified = VerifiedCredentialRenewal::verify(
        grant.as_bytes(),
        &pin,
        request.authorization().policy_digest,
        150,
    )
    .expect("exact independently verified G");
    (verified, certificate)
}
fn credential(
    f: &Fixture,
    stage: u8,
    authority: Option<JournalAccountAuthority>,
    original: Vec<u8>,
) -> Prepared {
    assert!(stage <= 2);
    let mut owner = open(f, authority);
    let (grant, certificate) = credential_grant(f, &mut owner);
    owner
        .stage_credential_renewal(&grant, grant.operation(), &f.policy, 150)
        .expect("persist exact G grant");
    let carrier = credential_client(f, &mut owner);
    let proposal = owner
        .prepare_witnessed_credential_renewal(&f.policy, 150, carrier)
        .expect("seal actual original G target");
    f.witness
        .lock()
        .expect("A")
        .prepare_credential_renewal(proposal, &grant, &f.policy, 150)
        .expect("independent Witness G approval");
    let mut carrier = credential_client(f, &mut owner);
    if stage >= 1 {
        assert_eq!(
            carrier
                .exchange(
                    f.original.genesis.subject(),
                    AnchorOperation::commit_credential_renewal(&proposal)
                )
                .expect("real G commit")
                .credential_renewal_state(&proposal)
                .expect("typed G result"),
            AnchorCredentialRenewalState::Applied
        );
    }
    if stage == 2 {
        assert_eq!(
            DeviceJournal::recover_credential_renewal(
                f.original.paths.installation.files()[1],
                JournalKey::open(&f.original.paths.wrapping).expect("original key"),
                &f.original.device,
                f.policy.historical(),
                JournalIdentity::from_trusted_state(f.original.genesis.subject().journal_parts().0)
                    .expect("original journal"),
                proposal,
                &mut carrier
            )
            .expect("install original G target with pending record retained"),
            AnchorCredentialRenewalState::Applied
        );
    }
    owner.close();
    Prepared {
        certificate: if stage >= 1 { certificate } else { original },
        current: if stage >= 1 {
            grant.successor_device().clone()
        } else {
            f.original.device.clone()
        },
        policy: None,
        expected: Intent::Write {
            expected: proposal.expected_head(),
            target: proposal.target_head(),
            transaction: Transaction::Credential {
                operation: *grant.operation().as_bytes(),
                statement: grant.statement_digest(),
                policy: None,
            },
        },
    }
}
fn roster(f: &Fixture, stage: u8, authority: Option<JournalAccountAuthority>) -> Prepared {
    assert!(stage <= 2);
    let mut owner = open(f, authority);
    let image = owner.image().expect("original parent image");
    let certificate = match image.phase {
        Phase::Accepted { admission, .. } => Ok(admission.certificate),
        _ => Err("not accepted"),
    }
    .expect("actual retained original certificate");
    let roster = f
        .original
        .root
        .issue_roster(
            2,
            Validity::new(100, 240).expect("target roster interval"),
            &[f.original
                .root
                .roster_entry(&certificate)
                .expect("unchanged credential member")],
        )
        .expect("independent R target");
    let target = AccountPin::new(
        f.original.device.account_id(),
        f.original.root.public_key().expect("root"),
        roster.checkpoint(),
        f.policy.family(),
    )
    .expect("new roster checkpoint")
    .verify_device(&certificate, roster.as_bytes(), 150)
    .expect("same original credential");
    let client = |owner: &mut DeviceEnrollment| {
        owner
            .roster_refresh_anchor_client(
                f.policy.historical(),
                f.pin.clone(),
                Box::new(Carrier(Arc::clone(&f.witness))),
                Duration::from_secs(3),
            )
            .expect("original R control client")
    };
    let carrier = client(&mut owner);
    let proposal = owner
        .prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("original R ID"),
            f.policy.historical(),
            &f.policy,
            &target,
            150,
            carrier,
        )
        .expect("seal original R target");
    f.witness
        .lock()
        .expect("A")
        .prepare_roster_refresh(proposal, &f.original.device, &target, &f.policy, 150)
        .expect("independent Witness R approval");
    let mut carrier = client(&mut owner);
    if stage >= 1 {
        assert_eq!(
            carrier
                .exchange(
                    f.original.genesis.subject(),
                    AnchorOperation::commit_roster_refresh(&proposal)
                )
                .expect("real R commit")
                .roster_refresh_state(&proposal)
                .expect("typed R result"),
            AnchorRosterRefreshState::Applied
        );
    }
    if stage == 2 {
        assert_eq!(
            DeviceJournal::recover_roster_refresh(
                f.original.paths.installation.files()[1],
                JournalKey::open(&f.original.paths.wrapping).expect("original key"),
                &f.original.device,
                f.policy.historical(),
                JournalIdentity::from_trusted_state(f.original.genesis.subject().journal_parts().0)
                    .expect("original journal"),
                proposal,
                &mut carrier
            )
            .expect("install only original R target"),
            AnchorRosterRefreshState::Applied
        );
    }
    owner.close();
    let mut scope = Vec::new();
    proposal.scope().encode(&mut scope);
    Prepared {
        certificate,
        current: if stage >= 1 {
            target
        } else {
            f.original.device.clone()
        },
        policy: None,
        expected: Intent::Write {
            expected: proposal.expected_head(),
            target: proposal.target_head(),
            transaction: Transaction::Roster(scope),
        },
    }
}
fn cancellation(
    f: &Fixture,
    closed: bool,
    authority: Option<JournalAccountAuthority>,
    original: Vec<u8>,
) -> Prepared {
    let mut owner = open(f, authority);
    let (grant, _) = credential_grant(f, &mut owner);
    owner
        .stage_credential_renewal(&grant, grant.operation(), &f.policy, 150)
        .expect("stage original grant for independent cancellation");
    let cancellation = owner
        .prepare_witnessed_credential_cancellation(&f.policy, 150)
        .expect("reserve actual target-free cancellation");
    if closed {
        assert_eq!(
            f.witness
                .lock()
                .expect("A")
                .close_unprepared_credential_renewal(cancellation, &grant, &f.policy)
                .expect("actual independent cancellation decision"),
            AnchorCredentialCancellationState::Closed
        );
    }
    owner.close();
    Prepared {
        certificate: original,
        current: f.original.device.clone(),
        policy: None,
        expected: Intent::Cancellation(cancellation.to_bytes()),
    }
}
pub(super) fn prepare(
    f: &Fixture,
    work: Work,
    authority: Option<JournalAccountAuthority>,
) -> Prepared {
    let mut owner = open(f, None);
    let original = match owner.image().expect("original credential snapshot").phase {
        Phase::Accepted { admission, .. } => Ok(admission.certificate),
        _ => Err("original admission missing"),
    }
    .expect("retain exact signed bytes without re-signing");
    owner.close();
    match work {
        Work::None => Prepared {
            certificate: original,
            current: f.original.device.clone(),
            policy: None,
            expected: Intent::None,
        },
        Work::Policy(stage) => {
            let (policy, wire, proposal) = super::policy::prepare_policy(f, stage, authority);
            Prepared {
                certificate: original,
                current: f.original.device.clone(),
                policy: if stage >= 1 {
                    Some((policy, wire))
                } else {
                    None
                },
                expected: Intent::Write {
                    expected: proposal.expected_head(),
                    target: proposal.target_head(),
                    transaction: Transaction::Policy {
                        operation: *proposal.operation().as_bytes(),
                        statement: proposal.statement(),
                    },
                },
            }
        }
        Work::Credential(stage) => credential(f, stage, authority, original),
        Work::Roster(stage) => roster(f, stage, authority),
        Work::Cancellation(closed) => cancellation(f, closed, authority, original),
    }
}
