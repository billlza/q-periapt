// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::crypto::classical_compromise_tests::{capture_classical, sign_classical_only};
use crate::PrekeyQuality;
use q_periapt_backends::ML_DSA_65_SIG_LEN;

#[test]
fn classical_signature_alias_preserves_reply_authentication_but_final_rejects_root_split() {
    let mut controls = 0;
    let mut aliases = 0;
    for quality in [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ] {
        let mut f = tests::fixture(quality);
        for substitute in [false, true] {
            let mut initiator =
                InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
                    .expect("fresh original initiator");
            let initial = initiator.initial_message(150).expect("initial").to_vec();
            let mut responder = ResponderOperation::new(Arc::clone(&f.responder));
            let (pq, classic) = f.sources();
            let reply = responder
                .respond(&initial, &f.signer_r, pq, classic, 150)
                .expect("honest responder reply")
                .to_vec();
            let (body, signature) = open_envelope(&reply).expect("public reply envelope");
            let presented = if substitute {
                let compromised_classic = capture_classical(&f.signer_r)
                    .expect("only the classical fixture signing key is disclosed");
                f.signer_r.close();
                assert!(matches!(f.signer_r.public_key(), Err(Error::Closed)));
                let alternative =
                    sign_classical_only(&compromised_classic, Purpose::BootstrapResponder, body)
                        .expect("valid new classical signature, without an ML-DSA signer");
                assert_ne!(
                    signature.get(ML_DSA_65_SIG_LEN..).expect("original P-256"),
                    alternative
                );
                let original_pq = signature.get(..ML_DSA_65_SIG_LEN).expect("original ML-DSA");
                let mut replaced = original_pq.to_vec();
                replaced.extend_from_slice(&alternative);
                assert_eq!(
                    replaced.get(..ML_DSA_65_SIG_LEN).expect("same ML-DSA"),
                    original_pq
                );
                f.responder
                    .responder
                    .key
                    .verify(Purpose::BootstrapResponder, body, &replaced)
                    .expect("both required signature components still verify");
                envelope(body, &replaced).expect("unchanged body and canonical new signature")
            } else {
                reply.clone()
            };
            let presented_body = open_envelope(&presented).expect("presented envelope").0;
            assert_eq!(presented_body, body, "ciphertext and MACR are unchanged");
            let outcome = initiator
                .finish(&presented, 150)
                .expect("real reply signature, KEM decapsulation and MACR pass");
            let final_wire = outcome.final_message().to_vec();
            let prepared = match &responder.state {
                ResponderState::Prepared(prepared) => prepared,
                _ => unreachable!("honest retained responder state"),
            };
            if substitute {
                assert_ne!(outcome.session.id(), prepared.session.id());
                assert_ne!(
                    outcome
                        .session
                        .root
                        .as_ref()
                        .expect("initiator root")
                        .as_bytes(),
                    prepared
                        .session
                        .root
                        .as_ref()
                        .expect("responder root")
                        .as_bytes()
                );
                assert!(matches!(
                    responder.finish(&final_wire, 150),
                    Err(Error::Scope)
                ));
                assert!(matches!(
                    initiator.finish(&reply, 150),
                    Err(Error::Conflict)
                ));
                aliases += 1;
            } else {
                assert_eq!(outcome.session.id(), prepared.session.id());
                assert_eq!(
                    outcome
                        .session
                        .root
                        .as_ref()
                        .expect("initiator root")
                        .as_bytes(),
                    prepared
                        .session
                        .root
                        .as_ref()
                        .expect("responder root")
                        .as_bytes()
                );
                responder
                    .finish(&final_wire, 150)
                    .expect("honest final completes");
                controls += 1;
            }
        }
    }
    assert_eq!((controls, aliases), (4, 4));
    eprintln!("BOOTSTRAP_CLASSICAL_ALIAS controls=4 aliases=4 pq_bytes_unchanged=4 bodies_unchanged=4 initiator_reply_checks_passed=4 final_scope_rejections=4 original_reply_conflicts=4");
}
