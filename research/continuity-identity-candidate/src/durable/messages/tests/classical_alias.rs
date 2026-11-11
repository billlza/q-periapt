// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::crypto::{
    classical_compromise_tests::{capture_classical, sign_classical_only},
    envelope, open_envelope, PublicKey, Purpose,
};
use q_periapt_backends::ML_DSA_65_SIG_LEN;

// The substituter receives only the classical secret and public wire/key.
// Honest endpoint operations retain their original hybrid signing owners.
fn alias(
    classic: &p256::ecdsa::SigningKey,
    public: &PublicKey,
    purpose: Purpose,
    wire: &[u8],
) -> Vec<u8> {
    let (body, signature) = open_envelope(wire).expect("original envelope");
    let pq = signature
        .get(..ML_DSA_65_SIG_LEN)
        .expect("original PQ signature");
    let alternative =
        sign_classical_only(classic, purpose, body).expect("classical-only signature");
    assert_ne!(
        signature
            .get(ML_DSA_65_SIG_LEN..)
            .expect("original classical signature"),
        alternative
    );
    let mut replaced = pq.to_vec();
    replaced.extend_from_slice(&alternative);
    assert_eq!(
        replaced
            .get(..ML_DSA_65_SIG_LEN)
            .expect("retained PQ signature"),
        pq
    );
    public
        .verify(purpose, body, &replaced)
        .expect("both signature components verify");
    let substituted = envelope(body, &replaced).expect("canonical alias envelope");
    assert_eq!(open_envelope(&substituted).expect("alias envelope").0, body);
    assert_ne!(substituted, wire);
    substituted
}

fn control_traffic(pair: &mut Pair) {
    assert_eq!(complete_rekey(pair), 1);
    let next = pair
        .ji
        .next_message_id(&pair.f.initiator, pair.session, 150)
        .expect("new epoch ID");
    let wire = pair.send(next, b"original rekey wires still complete");
    assert_eq!(
        pair.receive(&wire).as_bytes(),
        b"original rekey wires still complete"
    );
}

#[test]
fn classical_offer_alias_authenticates_but_cannot_replace_the_retained_rekey_offer() {
    for substitute in [false, true] {
        let mut p = Pair::new();
        p.activate();
        let offer =
            p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                .expect("original offer");
        let presented = if substitute {
            alias(
                &capture_classical(&p.f.signer_i).expect("classical component"),
                &p.f.signer_i.public_key().expect("public key"),
                Purpose::RekeyOffer,
                &offer,
            )
        } else {
            offer.clone()
        };
        let reply =
            p.jr.respond_rekey_offer(&p.f.responder, p.session, &presented, &p.f.signer_r, 150)
                .expect("authenticated offer reaches encapsulation");
        if !substitute {
            control_traffic(&mut p);
            continue;
        }
        let before_i = p.ji.image().expect("before rejection").digest;
        assert!(matches!(
            p.ji.accept_rekey_response(&p.f.initiator, p.session, &reply, &p.f.signer_i, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert_eq!(p.ji.image().expect("unchanged proposer").digest, before_i);
        let before_r = p.jr.image().expect("saved original presented offer").digest;
        assert!(matches!(
            p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150),
            Err(DurableError::Conflict)
        ));
        assert_eq!(p.jr.image().expect("unchanged responder").digest, before_r);
        p.ji.close();
        p.jr.close();
        p.ji = reopen(&p.pi, p.f.initiator_device());
        p.jr = reopen(&p.pr, p.f.local_device());
        assert_eq!(
            p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                .expect("original offer retry"),
            offer
        );
        assert_eq!(
            p.jr.respond_rekey_offer(&p.f.responder, p.session, &presented, &p.f.signer_r, 150)
                .expect("exact alias retry"),
            reply
        );
        assert!(matches!(
            p.ji.accept_rekey_response(&p.f.initiator, p.session, &reply, &p.f.signer_i, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert_eq!(
            p.ji.image().expect("unchanged reopened proposer").digest,
            before_i
        );
        assert_eq!(
            p.jr.image().expect("unchanged reopened responder").digest,
            before_r
        );
    }
    eprintln!("REKEY_OFFER_CLASSICAL_ALIAS controls=1 aliases=1 body_unchanged=1 pq_bytes_unchanged=1 alias_authenticated=1 original_offer_bound=1 exact_retry_after_reopen=1");
}

#[test]
fn classical_response_alias_passes_root_confirmation_but_final_binds_the_original_wire() {
    for substitute in [false, true] {
        let mut p = Pair::new();
        p.activate();
        let offer =
            p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)
                .expect("original offer");
        let reply =
            p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
                .expect("original response");
        let presented = if substitute {
            alias(
                &capture_classical(&p.f.signer_r).expect("classical component"),
                &p.f.signer_r.public_key().expect("public key"),
                Purpose::RekeyResponse,
                &reply,
            )
        } else {
            reply.clone()
        };
        if !substitute {
            control_traffic(&mut p);
            continue;
        }
        let final_wire =
            p.ji.accept_rekey_response(&p.f.initiator, p.session, &presented, &p.f.signer_i, 150)
                .expect("unchanged response body passes KEM/root confirmation");
        let before_r = p.jr.image().expect("before final rejection").digest;
        assert!(matches!(
            p.jr.finish_rekey(&p.f.responder, p.session, &final_wire, &p.f.signer_r, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert_eq!(p.jr.image().expect("unchanged responder").digest, before_r);
        let before_i = p.ji.image().expect("saved response alias").digest;
        assert!(matches!(
            p.ji.accept_rekey_response(&p.f.initiator, p.session, &reply, &p.f.signer_i, 150),
            Err(DurableError::Conflict)
        ));
        assert_eq!(p.ji.image().expect("unchanged proposer").digest, before_i);
        p.ji.close();
        p.jr.close();
        p.ji = reopen(&p.pi, p.f.initiator_device());
        p.jr = reopen(&p.pr, p.f.local_device());
        assert_eq!(
            p.ji.accept_rekey_response(&p.f.initiator, p.session, &presented, &p.f.signer_i, 150)
                .expect("exact final retry"),
            final_wire
        );
        assert_eq!(
            p.jr.respond_rekey_offer(&p.f.responder, p.session, &offer, &p.f.signer_r, 150)
                .expect("original response retry"),
            reply
        );
        assert!(matches!(
            p.jr.finish_rekey(&p.f.responder, p.session, &final_wire, &p.f.signer_r, 150),
            Err(DurableError::Protocol(Error::Scope))
        ));
        assert_eq!(
            p.ji.image().expect("unchanged reopened proposer").digest,
            before_i
        );
        assert_eq!(
            p.jr.image().expect("unchanged reopened responder").digest,
            before_r
        );
    }
    eprintln!("REKEY_RESPONSE_CLASSICAL_ALIAS controls=1 aliases=1 body_unchanged=1 pq_bytes_unchanged=1 root_confirmation_passed=1 original_response_bound_at_final=1 exact_retry_after_reopen=1");
}
