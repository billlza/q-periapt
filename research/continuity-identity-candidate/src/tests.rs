// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::crypto::{envelope, open_envelope, Purpose};
use q_periapt_backends::{ML_DSA_65_SIG_LEN, ML_KEM_768_PK_LEN};

struct Fixture {
    root: RootSigningKey,
    signer: DeviceSigningKey,
    certificate: Vec<u8>,
    roster: IssuedRoster,
    pin: AccountPin,
}

fn interval() -> Validity {
    Validity::new(100, 200).expect("interval")
}
fn fixture() -> Fixture {
    let root = RootSigningKey::deterministic([1; 32], [2; 32]).expect("root");
    let signer = DeviceSigningKey::deterministic([3; 32], [4; 32]).expect("device");
    let description = DeviceDescription::new([5; 16], 1, [6; 32], interval()).expect("description");
    let certificate = root
        .issue_device(description, signer.public_key().expect("public"))
        .expect("certificate");
    let entry = root.roster_entry(&certificate).expect("membership");
    let roster = root.issue_roster(1, interval(), &[entry]).expect("roster");
    let pin = AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root public"),
        roster.checkpoint(),
        [6; 32],
    )
    .expect("pin");
    Fixture {
        root,
        signer,
        certificate,
        roster,
        pin,
    }
}
fn device(f: &Fixture) -> VerifiedDevice {
    f.pin
        .verify_device(&f.certificate, f.roster.as_bytes(), 150)
        .expect("verified device")
}
fn context(epoch: u64) -> ManifestContext {
    ManifestContext::new(epoch, [7; 32], [8; 32], [9; 32], interval()).expect("context")
}
fn leaves() -> Vec<PrekeyLeaf> {
    [
        (LeafKind::SignedClassical, vec![11; 32]),
        (LeafKind::OneTimeClassical, vec![12; 32]),
        (LeafKind::LastResortPq, vec![13; ML_KEM_768_PK_LEN]),
        (LeafKind::OneTimePq, vec![14; ML_KEM_768_PK_LEN]),
        (LeafKind::OneTimePq, vec![15; ML_KEM_768_PK_LEN]),
    ]
    .into_iter()
    .map(|(kind, public)| PrekeyLeaf::new(kind, &public, interval()).expect("public leaf"))
    .collect()
}
fn fail<T>(result: Result<T, Error>, expected: Error) {
    assert_eq!(result.err(), Some(expected));
}

#[test]
fn actual_hybrid_chain_and_all_leaf_roles_round_trip() {
    let f = fixture();
    let verified = device(&f);
    let issued = f
        .signer
        .issue_manifest(&verified, context(1), &leaves())
        .expect("manifest");
    let manifest = verified
        .verify_manifest(issued.as_bytes(), 150)
        .expect("verify manifest");
    assert_eq!(manifest.context(), context(1));
    let mut kinds = Vec::new();
    for index in 0..issued.leaf_count() {
        let wire = issued
            .proof(index)
            .expect("proof")
            .encode()
            .expect("encode");
        let parsed = LeafProof::decode(&wire).expect("parse");
        assert_eq!(parsed.encode().expect("canonical"), wire);
        let leaf = manifest.verify_leaf(&parsed, 150).expect("leaf");
        assert_eq!(leaf.manifest_digest(), manifest.digest());
        assert_eq!(leaf.authority_binding(), verified.authority_binding());
        assert!(!leaf.public_key().is_empty());
        kinds.push(leaf.kind() as u8);
    }
    kinds.sort();
    assert_eq!(kinds, [1, 2, 3, 4, 4]);
}

#[test]
fn attacker_self_signature_cannot_replace_the_pinned_root() {
    let f = fixture();
    let attacker = RootSigningKey::deterministic([21; 32], [22; 32]).expect("attacker");
    fail(
        AccountPin::new(
            f.root.account_id().expect("account"),
            attacker.public_key().expect("public"),
            f.roster.checkpoint(),
            [6; 32],
        ),
        Error::Scope,
    );
    let description = DeviceDescription::new([5; 16], 1, [6; 32], interval()).expect("description");
    let forged = attacker
        .issue_device(description, f.signer.public_key().expect("public"))
        .expect("self signature");
    fail(
        f.pin.verify_device(&forged, f.roster.as_bytes(), 150),
        Error::Authentication,
    );
}

#[test]
fn each_signature_component_is_required_and_purposes_are_separate() {
    let f = fixture();
    let (body, signature) = open_envelope(&f.certificate).expect("envelope");
    for index in [0, ML_DSA_65_SIG_LEN + 63] {
        let mut changed = signature.to_vec();
        *changed.get_mut(index).expect("signature byte") ^= 1;
        let wire = envelope(body, &changed).expect("shape");
        fail(
            f.pin.verify_device(&wire, f.roster.as_bytes(), 150),
            Error::Authentication,
        );
    }
    let wrong_purpose = envelope(
        body,
        &f.root.sign(Purpose::Roster, body).expect("signature"),
    )
    .expect("envelope");
    fail(
        f.pin
            .verify_device(&wrong_purpose, f.roster.as_bytes(), 150),
        Error::Authentication,
    );
}

#[test]
fn mathematically_valid_high_s_alias_is_rejected() {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let f = fixture();
    let (body, signature) = open_envelope(&f.certificate).expect("envelope");
    let classic = Signature::from_slice(signature.get(ML_DSA_65_SIG_LEN..).expect("classic"))
        .expect("signature");
    assert!(classic.normalize_s().is_none());
    let high =
        Signature::from_scalars(classic.r().to_bytes(), (-classic.s()).to_bytes()).expect("high s");
    assert_eq!(high.normalize_s(), Some(classic));
    let mut bound = b"Q-PERIAPT-CONTINUITY-IDENTITY-CANDIDATE/v1".to_vec();
    bound.push(1);
    bound.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bound.extend_from_slice(body);
    let public = f.root.public_key().expect("public").encode();
    let verifier = VerifyingKey::from_sec1_bytes(public.get(1952..).expect("classic public"))
        .expect("public point");
    assert!(verifier.verify(&bound, &high).is_ok());
    let mut changed = signature.to_vec();
    changed
        .get_mut(ML_DSA_65_SIG_LEN..)
        .expect("classic")
        .copy_from_slice(&high.to_bytes());
    let wire = envelope(body, &changed).expect("wire");
    fail(
        f.pin.verify_device(&wire, f.roster.as_bytes(), 150),
        Error::Authentication,
    );
}

#[test]
fn signed_but_wrong_account_and_family_are_rejected() {
    let f = fixture();
    let (body, _) = open_envelope(&f.certificate).expect("body");
    for offset in [8, 80] {
        let mut changed = body.to_vec();
        *changed.get_mut(offset).expect("field") ^= 1;
        let signature = f
            .root
            .sign(Purpose::Credential, &changed)
            .expect("real signature");
        let wire = envelope(&changed, &signature).expect("wire");
        fail(
            f.pin.verify_device(&wire, f.roster.as_bytes(), 150),
            Error::Scope,
        );
    }
}

#[test]
fn root_components_cannot_be_enrolled_as_device_keys() {
    let f = fixture();
    let description = DeviceDescription::new([5; 16], 1, [6; 32], interval()).expect("description");
    fail(
        f.root
            .issue_device(description.clone(), f.root.public_key().expect("public")),
        Error::Scope,
    );
    let mut mixed = f.signer.public_key().expect("public").encode();
    let root_public = f.root.public_key().expect("public").encode();
    let length = q_periapt_backends::ML_DSA_65_VK_LEN;
    mixed
        .get_mut(..length)
        .expect("pq")
        .copy_from_slice(root_public.get(..length).expect("pq"));
    fail(
        f.root.issue_device(
            description,
            PublicKey::decode(&mixed).expect("canonical point"),
        ),
        Error::Scope,
    );
}

#[test]
fn roster_fork_revocation_and_generation_changes_require_the_exact_pin() {
    let f = fixture();
    let empty = f
        .root
        .issue_roster(1, interval(), &[])
        .expect("same-version fork");
    fail(
        f.pin.verify_device(&f.certificate, empty.as_bytes(), 150),
        Error::Checkpoint,
    );
    let revoked = f.root.issue_roster(2, interval(), &[]).expect("revoke all");
    fail(
        f.pin.verify_device(&f.certificate, revoked.as_bytes(), 150),
        Error::Checkpoint,
    );
    let new_pin = AccountPin::new(
        f.root.account_id().expect("id"),
        f.root.public_key().expect("public"),
        revoked.checkpoint(),
        [6; 32],
    )
    .expect("new pin");
    fail(
        new_pin.verify_device(&f.certificate, revoked.as_bytes(), 150),
        Error::Scope,
    );
    fail(
        new_pin.verify_device(&f.certificate, f.roster.as_bytes(), 150),
        Error::Checkpoint,
    );
    let description =
        DeviceDescription::new([5; 16], 2, [6; 32], interval()).expect("new generation");
    let successor = f
        .root
        .issue_device(description, f.signer.public_key().expect("public"))
        .expect("successor");
    fail(
        f.pin.verify_device(&successor, f.roster.as_bytes(), 150),
        Error::Scope,
    );
}

#[test]
fn intervals_are_half_open_and_rechecked_on_retained_verified_objects() {
    let f = fixture();
    fail(
        f.pin.verify_device(&f.certificate, f.roster.as_bytes(), 99),
        Error::Validity,
    );
    f.pin
        .verify_device(&f.certificate, f.roster.as_bytes(), 100)
        .expect("beginning");
    fail(
        f.pin
            .verify_device(&f.certificate, f.roster.as_bytes(), 200),
        Error::Validity,
    );
    let verified = device(&f);
    let issued = f
        .signer
        .issue_manifest(&verified, context(1), &leaves())
        .expect("manifest");
    fail(
        verified.verify_manifest(issued.as_bytes(), 200),
        Error::Validity,
    );
    let manifest = verified
        .verify_manifest(issued.as_bytes(), 150)
        .expect("manifest");
    fail(
        manifest.verify_leaf(&issued.proof(0).expect("proof"), 200),
        Error::Validity,
    );
    fail(Validity::new(100, 100), Error::Validity);
    fail(Validity::new(100, u64::MAX), Error::Validity);
}

#[test]
fn mismatched_signing_owner_and_manifest_grafts_fail() {
    let f = fixture();
    let verified = device(&f);
    let other = DeviceSigningKey::deterministic([31; 32], [32; 32]).expect("other owner");
    fail(
        other.issue_manifest(&verified, context(1), &leaves()),
        Error::Scope,
    );
    let issued = f
        .signer
        .issue_manifest(&verified, context(1), &leaves())
        .expect("manifest");
    let (body, _) = open_envelope(issued.as_bytes()).expect("body");
    // Alter each fixed account/device/generation/credential/roster binding and
    // re-sign with the legitimate device: signature success is not enough.
    for offset in [8, 40, 56, 64, 96, 104] {
        let mut changed = body.to_vec();
        *changed.get_mut(offset).expect("scope field") ^= 1;
        let wire = envelope(
            &changed,
            &f.signer
                .sign(Purpose::Manifest, &changed)
                .expect("signature"),
        )
        .expect("wire");
        fail(verified.verify_manifest(&wire, 150), Error::Scope);
    }
}

#[test]
fn exact_public_byte_aliases_cannot_be_hidden_by_a_role_or_validity_change() {
    let f = fixture();
    let verified = device(&f);
    let first =
        PrekeyLeaf::new(LeafKind::OneTimePq, &[44; ML_KEM_768_PK_LEN], interval()).expect("leaf");
    let alias = PrekeyLeaf::new(
        LeafKind::LastResortPq,
        &[44; ML_KEM_768_PK_LEN],
        Validity::new(110, 190).expect("interval"),
    )
    .expect("alias");
    assert_eq!(first.key_fingerprint(), alias.key_fingerprint());
    fail(
        f.signer
            .issue_manifest(&verified, context(1), &[first, alias]),
        Error::Scope,
    );
}

#[test]
fn a_new_manifest_changes_leaf_id_but_not_the_exact_public_key_fingerprint() {
    let f = fixture();
    let verified = device(&f);
    let leaf =
        PrekeyLeaf::new(LeafKind::OneTimePq, &[55; ML_KEM_768_PK_LEN], interval()).expect("leaf");
    let mut admitted = Vec::new();
    for epoch in [1, 2] {
        let issued = f
            .signer
            .issue_manifest(&verified, context(epoch), std::slice::from_ref(&leaf))
            .expect("manifest");
        let manifest = verified
            .verify_manifest(issued.as_bytes(), 150)
            .expect("verify");
        admitted.push(
            manifest
                .verify_leaf(&issued.proof(0).expect("proof"), 150)
                .expect("leaf"),
        );
    }
    let mut iterator = admitted.iter();
    let first = iterator.next().expect("first");
    let second = iterator.next().expect("second");
    assert_ne!(first.id(), second.id());
    assert_ne!(first.manifest_digest(), second.manifest_digest());
    assert_eq!(first.key_fingerprint(), second.key_fingerprint());
}

#[test]
fn membership_paths_bind_index_length_leaf_and_sibling_order() {
    for count in [1, 2, 3, 5, 17, 32, 1024] {
        let leaves: Vec<_> = (0..count)
            .map(|i: usize| crate::crypto::digest(b"test-leaf", &i.to_be_bytes()))
            .collect();
        let expected = crate::merkle::root(&leaves).expect("root");
        for index in [0, count / 2, count - 1] {
            let leaf = *leaves.get(index).expect("leaf");
            let path = crate::merkle::proof(&leaves, index).expect("proof");
            assert_eq!(
                crate::merkle::reconstruct(leaf, index, count, &path).expect("reconstruct"),
                expected
            );
            let mut extra = path.clone();
            extra.push([0; 32]);
            assert!(crate::merkle::reconstruct(leaf, index, count, &extra).is_err());
            if !path.is_empty() {
                let mut changed = path.clone();
                changed.first_mut().expect("sibling").fill(0);
                assert_ne!(
                    crate::merkle::reconstruct(leaf, index, count, &changed).expect("shape"),
                    expected
                );
                assert!(crate::merkle::reconstruct(
                    leaf,
                    index,
                    count,
                    path.get(1..).expect("shorter")
                )
                .is_err());
            }
        }
    }
}

#[test]
fn parsers_reject_truncation_trailing_data_unknown_roles_and_bad_points() {
    let f = fixture();
    let verified = device(&f);
    let issued = f
        .signer
        .issue_manifest(&verified, context(1), &leaves())
        .expect("manifest");
    let proof = issued.proof(0).expect("proof").encode().expect("encode");
    for length in 0..proof.len() {
        assert!(LeafProof::decode(proof.get(..length).expect("prefix")).is_err());
    }
    let mut extra = proof.clone();
    extra.push(0);
    assert!(LeafProof::decode(&extra).is_err());
    let mut unknown = proof;
    *unknown.get_mut(12).expect("leaf kind") = 255;
    assert!(LeafProof::decode(&unknown).is_err());
    let mut certificate = f.certificate.clone();
    certificate.push(0);
    fail(
        f.pin.verify_device(&certificate, f.roster.as_bytes(), 150),
        Error::Encoding,
    );
    let mut key = f.signer.public_key().expect("public").encode();
    *key.get_mut(q_periapt_backends::ML_DSA_65_VK_LEN)
        .expect("SEC1 tag") = 4;
    fail(PublicKey::decode(&key), Error::Encoding);
}

#[test]
fn close_revokes_signing_without_revoking_existing_public_verification() {
    let mut f = fixture();
    let verified = device(&f);
    let issued = f
        .signer
        .issue_manifest(&verified, context(1), &leaves())
        .expect("manifest");
    f.signer.close();
    f.signer.close();
    fail(
        f.signer.issue_manifest(&verified, context(1), &leaves()),
        Error::Closed,
    );
    fail(f.signer.public_key(), Error::Closed);
    f.root.close();
    fail(f.root.issue_roster(2, interval(), &[]), Error::Closed);
    verified
        .verify_manifest(issued.as_bytes(), 150)
        .expect("public signatures remain valid");
}

#[test]
fn issuer_and_authenticated_parser_enforce_resource_limits() {
    let f = fixture();
    let verified = device(&f);
    fail(
        f.signer.issue_manifest(&verified, context(1), &[]),
        Error::Capacity,
    );
    let leaf = leaves().first().expect("leaf").clone();
    fail(
        f.signer
            .issue_manifest(&verified, context(1), &vec![leaf; MAX_PREKEYS + 1]),
        Error::Capacity,
    );
    let entry = f.root.roster_entry(&f.certificate).expect("entry");
    fail(
        f.root
            .issue_roster(1, interval(), &vec![entry; MAX_DEVICES + 1]),
        Error::Capacity,
    );
    let (body, _) = open_envelope(f.roster.as_bytes()).expect("body");
    let mut excessive = body.to_vec();
    excessive
        .get_mut(64..66)
        .expect("count")
        .copy_from_slice(&33u16.to_be_bytes());
    let digest = crate::crypto::digest(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", &excessive);
    let signed = envelope(
        &excessive,
        &f.root.sign(Purpose::Roster, &excessive).expect("signature"),
    )
    .expect("envelope");
    let pin = AccountPin::new(
        f.root.account_id().expect("account"),
        f.root.public_key().expect("public"),
        RosterCheckpoint::from_trusted_state(1, digest).expect("pin"),
        [6; 32],
    )
    .expect("pin");
    fail(
        pin.verify_device(&f.certificate, &signed, 150),
        Error::Capacity,
    );
    fail(open_envelope(&u32::MAX.to_be_bytes()), Error::Capacity);
    let maximum = vec![1; crate::crypto::MAX_SIGNED_BODY_BYTES + 1];
    fail(f.root.sign(Purpose::Credential, &maximum), Error::Capacity);
}
