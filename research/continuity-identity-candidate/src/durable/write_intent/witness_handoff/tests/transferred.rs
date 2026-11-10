// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::anchor::transferred::Authority;
use crate::{AnchorOperation, AnchorOutcome, AnchorRequest, DeviceSigningKey};
pub(super) mod network;
mod recovery;

fn signer() -> DeviceSigningKey {
    DeviceSigningKey::deterministic([111; 32], [112; 32]).expect("original test device signer")
}
fn authority(c: &Case) -> Authority {
    Authority::verified(
        &c.plan.approved,
        &c.plan.history,
        &c.receipt,
        &c.plan.request,
    )
    .expect("verified original authority selection")
}

#[test]
fn transferred_witness_preserves_command_identity_and_distinguishes_current_signer_after_restart() {
    let mut c = Case::new(None);
    let authority = authority(&c);
    let active = c.journal.active.as_ref().expect("original journal");
    let image = load(&active.db, &active.key, active.owner).expect("original image");
    let expected = image
        .protection
        .head(image.revision, image.digest)
        .expect("original head");
    let op =
        AnchorOperation::advance(expected, [231; 32]).expect("explicit witness-component target");
    let old = AnchorRequest::new(&authority.logical, c.plan.scope().subject(), op, &signer())
        .expect("unchanged old command");
    let request = authority
        .request(c.plan.scope().subject(), op, &signer())
        .expect("new attempt");
    let response = c
        .target
        .as_mut()
        .expect("target")
        .handle(request.as_bytes(), 180)
        .expect("target commits");
    let reply = authority
        .verify(&request, &response)
        .expect("actual current signer");
    assert_eq!(reply.command_id(), old.command_id());
    assert_eq!(reply.outcome(), AnchorOutcome::Advanced);
    assert_eq!(reply.logical_witness_binding(), authority.logical.binding());
    assert_eq!(
        reply.signing_witness_binding(),
        authority.current().binding()
    );
    assert_ne!(
        reply.logical_witness_binding(),
        reply.signing_witness_binding()
    );
    assert_eq!(reply.handoff_context(), Some(&authority.context));
    assert!(authority.logical.verify_reply(&old, &response).is_err());
    assert!(
        authority.verify(&request, &response).is_err(),
        "single consumption"
    );
    c.reopen_target();
    let retry = authority
        .request(c.plan.scope().subject(), op, &signer())
        .expect("fresh retry");
    assert_ne!(retry.as_bytes(), request.as_bytes());
    assert!(
        authority.verify(&retry, &response).is_err(),
        "old reply cannot satisfy a new challenge"
    );
    let response = c
        .target
        .as_mut()
        .expect("target")
        .handle(retry.as_bytes(), 180)
        .expect("exact original retry");
    let reply = authority.verify(&retry, &response).expect("retry response");
    assert_eq!(reply.outcome(), AnchorOutcome::AlreadyAppliedExact);
    assert_eq!(reply.command_id(), old.command_id());
    let legacy = AnchorRequest::new(
        authority.current(),
        c.plan.scope().subject(),
        AnchorOperation::query(),
        &signer(),
    )
    .expect("legacy under current pin");
    assert!(
        c.target
            .as_mut()
            .expect("target")
            .handle(legacy.as_bytes(), 180)
            .is_err(),
        "authorization cannot unlock legacy current-pin requests"
    );
    assert!(
        authority
            .current()
            .verify_reply(&legacy, &response)
            .is_err(),
        "new signature purpose is not v1"
    );
}

#[test]
fn transferred_witness_rejects_device_signed_context_substitution_without_mutating_state() {
    let mut c = Case::new(None);
    let authority = authority(&c);
    let request = authority
        .request(
            c.plan.scope().subject(),
            AnchorOperation::query(),
            &signer(),
        )
        .expect("request");
    let (original, _) = crate::crypto::open_envelope(request.as_bytes()).expect("body");
    let before = fs::read(c.root.join("target/state.redb")).expect("same open target");
    for field in 0..5 {
        let mut body = original.to_vec();
        *body.get_mut(8 + 32 * field).expect("context field") ^= 1;
        if field == 1 {
            let logical = body
                .get(40..72)
                .expect("logical field")
                .try_into()
                .expect("32 bytes");
            let command = crate::anchor::command_id(
                &logical,
                c.plan.scope().subject(),
                AnchorOperation::query(),
            );
            body.get_mut(264..296)
                .expect("command")
                .copy_from_slice(&command);
        }
        let wire = crate::crypto::envelope(
            &body,
            &signer()
                .sign(crate::crypto::Purpose::AnchorTransferredRequest, &body)
                .expect("valid device signature"),
        )
        .expect("wire");
        assert!(
            c.target
                .as_mut()
                .expect("target")
                .handle(&wire, 180)
                .is_err(),
            "unapproved context field {field}"
        );
    }
    assert!(
        fs::read(c.root.join("target/state.redb")).expect("no unauthorized mutation") == before
    );
    let response = c
        .target
        .as_mut()
        .expect("target")
        .handle(request.as_bytes(), 180)
        .expect("original context still works");
    assert_eq!(
        authority
            .verify(&request, &response)
            .expect("verified")
            .outcome(),
        AnchorOutcome::Current
    );
}

#[test]
fn transferred_witness_requires_durable_local_adoption_and_exact_device_signer() {
    let mut c = Case::new(None);
    let mut owner = c
        .journal
        .begin_witness_handoff(c.plan.clone(), || Ok(180))
        .expect("prepared");
    assert!(owner
        .attach_current_witness(
            signer(),
            Box::new(crate::AnchorTcpTransport::new(
                "127.0.0.1:9".parse().expect("unused endpoint")
            )),
            Duration::from_secs(1)
        )
        .is_err());
    let mut owner = c.resume();
    owner.adopt_authorization(&c.receipt).expect("adopted");
    assert!(owner
        .attach_current_witness(
            DeviceSigningKey::generate().expect("foreign device"),
            Box::new(crate::AnchorTcpTransport::new(
                "127.0.0.1:9".parse().expect("unused endpoint")
            )),
            Duration::from_secs(1)
        )
        .is_err());
    assert!(matches!(owner.status(), Err(DurableError::Closed)));
    assert_eq!(
        c.resume().status().expect("decision retained"),
        WitnessJournalAdoptionState::Adopted
    );
}
