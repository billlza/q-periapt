// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::Validity;

fn signed_request(signer: &DeviceSigningKey, intent: &EnrollmentIntent) -> Vec<u8> {
    let mut body = b"QPENRQ01".to_vec();
    body.extend_from_slice(SigningKeyId::generate().expect("identity").as_bytes());
    intent.encode(&mut body);
    body.extend_from_slice(&signer.public_key().expect("public").encode());
    envelope(
        &body,
        &signer
            .sign(Purpose::EnrollmentRequest, &body)
            .expect("signature"),
    )
    .expect("envelope")
}

#[test]
fn current_replacement_request_rejects_either_reused_key_component() {
    let c = case();
    let old = DeviceSigningKey::deterministic([11; 32], [12; 32]).expect("original key");
    let cert = c
        .root
        .issue_device(c.intent.description.clone(), old.public_key().expect("key"))
        .expect("credential");
    let roster = c
        .root
        .issue_roster(
            1,
            interval(),
            &[c.root.roster_entry(&cert).expect("member")],
        )
        .expect("roster");
    let pin = AccountPin::new(
        c.root.account_id().expect("account"),
        c.root.public_key().expect("root"),
        roster.checkpoint(),
        c.policy.family(),
    )
    .expect("pin");
    let previous = pin
        .verify_historical_device(&cert, roster.as_bytes())
        .expect("historical device");
    let intent = EnrollmentIntent::new(
        c.root.public_key().expect("root"),
        DeviceDescription::new(
            c.intent.description.id,
            2,
            c.policy.family(),
            Validity::new(210, 400).expect("new interval"),
        )
        .expect("description"),
    );
    for (ed, pq) in [(11, 12), (11, 14), (13, 12)] {
        let key = DeviceSigningKey::deterministic([ed; 32], [pq; 32]).expect("candidate key");
        let wire = signed_request(&key, &intent);
        assert!(VerifiedEnrollmentRequest::verify(&wire, &intent, 220).is_ok());
        assert!(matches!(
            VerifiedEnrollmentRequest::verify_replacement(&wire, &intent, &previous, 220),
            Err(Error::Scope)
        ));
    }
    let key = DeviceSigningKey::deterministic([13; 32], [14; 32]).expect("fresh key");
    let wire = signed_request(&key, &intent);
    let verified = VerifiedEnrollmentRequest::verify_replacement(&wire, &intent, &previous, 220)
        .expect("fresh generation after old expiry");
    c.root
        .issue_enrollment(&verified, 220)
        .expect("independently authorized issuance");
    assert!(VerifiedEnrollmentRequest::verify_replacement(&wire, &intent, &previous, 400).is_err());
    let mut forged = wire.clone();
    *forged.last_mut().expect("signature") ^= 1;
    assert!(
        VerifiedEnrollmentRequest::verify_replacement(&forged, &intent, &previous, 220).is_err()
    );
    for (device, generation, family) in [
        (c.intent.description.id, 1, c.policy.family()),
        ([8; 16], 2, c.policy.family()),
        (c.intent.description.id, 2, [9; 32]),
    ] {
        let wrong = EnrollmentIntent::new(
            c.root.public_key().expect("root"),
            DeviceDescription::new(
                device,
                generation,
                family,
                Validity::new(210, 400).expect("interval"),
            )
            .expect("description"),
        );
        assert!(VerifiedEnrollmentRequest::verify_replacement(
            &signed_request(&key, &wrong),
            &wrong,
            &previous,
            220
        )
        .is_err());
    }
    let another = RootSigningKey::generate().expect("another account");
    let wrong = EnrollmentIntent::new(
        another.public_key().expect("root"),
        intent.description.clone(),
    );
    assert!(VerifiedEnrollmentRequest::verify_replacement(
        &signed_request(&key, &wrong),
        &wrong,
        &previous,
        220
    )
    .is_err());
}
