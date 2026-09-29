// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::crypto::{envelope, open_envelope, Purpose};
use q_periapt_backends::{ML_DSA_65_SIG_LEN, ML_KEM_768_PK_LEN};
use std::sync::Arc;

struct Fixture {
    root: RootSigningKey,
    signer: DeviceSigningKey,
    certificate: Vec<u8>,
    roster: IssuedRoster,
    pin: AccountPin,
}

pub(super) fn interval() -> Validity {
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
    assert_eq!(classic.normalize_s(), classic);
    let high =
        Signature::from_scalars(classic.r().to_bytes(), (-classic.s()).to_bytes()).expect("high s");
    assert_ne!(high, classic);
    assert_eq!(high.normalize_s(), classic);
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

fn proof_for_kind(
    issued: &IssuedManifest,
    manifest: &VerifiedManifest,
    kind: LeafKind,
) -> LeafProof {
    let index = (0..issued.leaf_count())
        .find(|index| {
            let proof = issued.proof(*index).expect("proof");
            manifest.verify_leaf(&proof, 150).expect("member").kind() == kind
        })
        .expect("required kind");
    issued.proof(index).expect("selected proof")
}

#[test]
fn all_selection_modes_derive_ids_quality_and_public_keys_from_real_members() {
    let f = fixture();
    let device = device(&f);
    let issued = f
        .signer
        .issue_manifest(&device, context(3), &leaves())
        .expect("manifest");
    let manifest = device
        .verify_manifest(issued.as_bytes(), 150)
        .expect("verified");
    let signed = proof_for_kind(&issued, &manifest, LeafKind::SignedClassical);
    let last = proof_for_kind(&issued, &manifest, LeafKind::LastResortPq);
    let once_c = proof_for_kind(&issued, &manifest, LeafKind::OneTimeClassical);
    let once_p = proof_for_kind(&issued, &manifest, LeafKind::OneTimePq);
    let mut digests = std::collections::BTreeSet::new();
    for (classical, pq, expected) in [
        (
            ClassicalChoice::OneTime(&once_c),
            PqChoice::OneTime(&once_p),
            PrekeyQuality::OneTimeBoth,
        ),
        (
            ClassicalChoice::SignedOnly,
            PqChoice::LastResort,
            PrekeyQuality::ReusableBoth,
        ),
        (
            ClassicalChoice::SignedOnly,
            PqChoice::OneTime(&once_p),
            PrekeyQuality::SignedClassicalOneTimePq,
        ),
        (
            ClassicalChoice::OneTime(&once_c),
            PqChoice::LastResort,
            PrekeyQuality::OneTimeClassicalLastResortPq,
        ),
    ] {
        let selection = manifest
            .select_prekeys(&signed, &last, classical, pq, 150)
            .expect("selection");
        assert_eq!(selection.quality(), expected);
        assert_eq!(selection.authority_binding(), device.authority_binding());
        assert_eq!(selection.manifest_digest(), manifest.digest());
        assert!(digests.insert(selection.digest()));
        let mut decoder = crate::codec::Decoder::new(selection.as_bytes());
        let mut fields = Vec::new();
        for length in [40, 2, 32, 32, 16, 8, 32, 8, 32, 32, 1, 32, 32, 1, 32, 32] {
            assert_eq!(decoder.u64().expect("LP8 length"), length as u64);
            fields.push(decoder.take(length).expect("field"));
        }
        decoder.finish().expect("exact record");
        assert_eq!(
            fields.first().expect("domain"),
            &b"Q-PERIAPT-CONTINUITY-PREKEY-SELECTION/v1".as_slice()
        );
        assert_eq!(
            fields.get(3).expect("account"),
            &f.root.account_id().expect("account").as_slice()
        );
        assert_eq!(fields.get(4).expect("device"), &[5; 16].as_slice());
        assert_eq!(
            fields.get(7).expect("epoch"),
            &3u64.to_be_bytes().as_slice()
        );
        assert_eq!(
            fields.get(9).expect("manifest"),
            &manifest.digest().as_slice()
        );
        assert_eq!(
            fields.get(12).expect("classical id"),
            &selection.classical().id().as_slice()
        );
        assert_eq!(
            fields.get(15).expect("pq id"),
            &selection.post_quantum().id().as_slice()
        );
        assert_eq!(selection.classical().public_key().len(), 32);
        assert_eq!(
            selection.post_quantum().public_key().len(),
            ML_KEM_768_PK_LEN
        );
    }
}

#[test]
fn selection_rejects_wrong_roles_cross_manifest_proofs_and_expiry() {
    let f = fixture();
    let device = device(&f);
    let issued = f
        .signer
        .issue_manifest(&device, context(1), &leaves())
        .expect("manifest");
    let manifest = device
        .verify_manifest(issued.as_bytes(), 150)
        .expect("verified");
    let signed = proof_for_kind(&issued, &manifest, LeafKind::SignedClassical);
    let last = proof_for_kind(&issued, &manifest, LeafKind::LastResortPq);
    let once = proof_for_kind(&issued, &manifest, LeafKind::OneTimeClassical);
    for (c, p, chosen) in [
        (&once, &last, ClassicalChoice::SignedOnly),
        (&last, &signed, ClassicalChoice::SignedOnly),
        (&signed, &last, ClassicalChoice::OneTime(&signed)),
    ] {
        fail(
            manifest.select_prekeys(c, p, chosen, PqChoice::LastResort, 150),
            Error::Scope,
        );
    }
    fail(
        manifest.select_prekeys(
            &signed,
            &last,
            ClassicalChoice::SignedOnly,
            PqChoice::OneTime(&last),
            150,
        ),
        Error::Scope,
    );
    fail(
        manifest.select_prekeys(
            &signed,
            &last,
            ClassicalChoice::SignedOnly,
            PqChoice::LastResort,
            200,
        ),
        Error::Validity,
    );
    let other = f
        .signer
        .issue_manifest(&device, context(2), &leaves())
        .expect("other");
    let other_manifest = device
        .verify_manifest(other.as_bytes(), 150)
        .expect("other verified");
    let graft = proof_for_kind(&other, &other_manifest, LeafKind::OneTimeClassical);
    fail(
        manifest.select_prekeys(
            &signed,
            &last,
            ClassicalChoice::OneTime(&graft),
            PqChoice::LastResort,
            150,
        ),
        Error::Authentication,
    );
}

#[test]
fn retained_selection_cannot_outlive_a_referenced_reusable_baseline() {
    let f = fixture();
    let device = device(&f);
    let mut entries = leaves();
    *entries.first_mut().expect("signed baseline") = PrekeyLeaf::new(
        LeafKind::SignedClassical,
        &[11; 32],
        Validity::new(140, 160).expect("narrow interval"),
    )
    .expect("baseline");
    let issued = f
        .signer
        .issue_manifest(&device, context(1), &entries)
        .expect("manifest");
    let manifest = device
        .verify_manifest(issued.as_bytes(), 150)
        .expect("verified");
    let signed = proof_for_kind(&issued, &manifest, LeafKind::SignedClassical);
    let last = proof_for_kind(&issued, &manifest, LeafKind::LastResortPq);
    let once_c = proof_for_kind(&issued, &manifest, LeafKind::OneTimeClassical);
    let once_p = proof_for_kind(&issued, &manifest, LeafKind::OneTimePq);
    let selection = manifest
        .select_prekeys(
            &signed,
            &last,
            ClassicalChoice::OneTime(&once_c),
            PqChoice::OneTime(&once_p),
            150,
        )
        .expect("selection");
    assert_eq!(selection.classical().validity(), interval());
    assert_eq!(
        selection.validity(),
        Validity::new(140, 160).expect("intersection")
    );
    assert!(selection.check_time(140).is_ok());
    assert!(selection.check_time(159).is_ok());
    fail(selection.check_time(139), Error::Validity);
    fail(selection.check_time(160), Error::Validity);
}

pub(super) fn sdk_runtime() -> Arc<q_periapt_sdk::Runtime> {
    sdk_runtime_with_limits(q_periapt_sdk::Limits::default())
}
pub(super) fn sdk_runtime_with_limits(
    limits: q_periapt_sdk::Limits,
) -> Arc<q_periapt_sdk::Runtime> {
    use q_periapt_sig::Signer;
    use zeroize::Zeroize;
    let policy = b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n";
    let (mut secret, public) = q_periapt_backends::MlDsa65::generate([80; 32]);
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    let result = q_periapt_backends::MlDsa65.sign(
        &secret,
        &q_periapt_policy::policy_signature_message(policy),
        &[81; 32],
        &mut signature,
    );
    secret.zeroize();
    result.expect("algorithm policy signature");
    Arc::new(
        q_periapt_sdk::Runtime::from_signed_policy(policy, &signature, &public, None, limits)
            .expect("algorithm policy"),
    )
}

pub(super) fn session_policy_fixture(
    modes: &[PrekeyQuality],
) -> (
    PolicySigningKey,
    IssuedSessionPolicy,
    PolicyPin,
    Arc<q_periapt_sdk::Runtime>,
) {
    session_policy_fixture_with_anchor(modes, AnchorRequirement::local_only())
}
pub(crate) fn session_policy_fixture_with_anchor(
    modes: &[PrekeyQuality],
    anchor: AnchorRequirement,
) -> (
    PolicySigningKey,
    IssuedSessionPolicy,
    PolicyPin,
    Arc<q_periapt_sdk::Runtime>,
) {
    let signer = PolicySigningKey::deterministic([82; 32], [83; 32]).expect("policy signer");
    let runtime = sdk_runtime();
    let issued = signer
        .issue_session_policy(
            &runtime,
            SessionPolicyParameters::new(
                1,
                interval(),
                AllowedPrekeyModes::new(modes).expect("explicit modes"),
                anchor,
            )
            .expect("parameters"),
        )
        .expect("policy");
    let pin = PolicyPin::new(
        signer.policy_family().expect("family"),
        signer.public_key().expect("public"),
        issued.checkpoint(),
    )
    .expect("pin");
    (signer, issued, pin, runtime)
}

#[test]
fn protocol_policy_binds_real_sdk_runtime_and_explicit_mode_permissions() {
    let (_signer, issued, pin, runtime) = session_policy_fixture(&[
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
    ]);
    let policy = pin
        .verify(issued.as_bytes(), Arc::clone(&runtime), 150)
        .expect("verified policy");
    assert_eq!(
        policy.sdk_binding(),
        runtime.policy_binding().expect("binding")
    );
    assert_eq!(policy.checkpoint(), issued.checkpoint());
    for mode in [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
    ] {
        assert!(policy.check_mode(mode, 150).is_ok());
    }
    for mode in [
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ] {
        fail(policy.check_mode(mode, 150), Error::PolicyDenied);
    }
    fail(
        policy.check_mode(PrekeyQuality::OneTimeBoth, 200),
        Error::Validity,
    );
    policy.close();
    fail(
        policy.check_mode(PrekeyQuality::OneTimeBoth, 150),
        Error::Closed,
    );
    assert!(runtime
        .is_enabled()
        .expect("SDK not closed by protocol close"));
    let policy = pin
        .verify(issued.as_bytes(), Arc::clone(&runtime), 150)
        .expect("independently loaded instance");
    runtime.close();
    fail(
        policy.check_mode(PrekeyQuality::OneTimeBoth, 150),
        Error::Runtime(q_periapt_sdk::Error::Closed),
    );
    let (_signer, disabled, pin, runtime) = session_policy_fixture(&[]);
    let disabled = pin
        .verify(disabled.as_bytes(), runtime, 150)
        .expect("authenticated disabled policy");
    fail(
        disabled.check_mode(PrekeyQuality::OneTimeBoth, 150),
        Error::PolicyDenied,
    );
    fail(
        AllowedPrekeyModes::new(&[PrekeyQuality::OneTimeBoth, PrekeyQuality::OneTimeBoth]),
        Error::Encoding,
    );
}

#[test]
fn protocol_policy_rejects_signature_and_checkpoint_substitution() {
    let (signer, issued, pin, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let (body, signature) = open_envelope(issued.as_bytes()).expect("body");
    for offset in [0, ML_DSA_65_SIG_LEN + 63] {
        let mut corrupt = signature.to_vec();
        *corrupt.get_mut(offset).expect("signature byte") ^= 1;
        let wire = envelope(body, &corrupt).expect("wire");
        fail(
            pin.verify(&wire, Arc::clone(&runtime), 150),
            Error::Authentication,
        );
    }
    let wrong = envelope(
        body,
        &signer.sign(Purpose::Manifest, body).expect("other purpose"),
    )
    .expect("wire");
    fail(
        pin.verify(&wrong, Arc::clone(&runtime), 150),
        Error::Authentication,
    );
    let other = signer
        .issue_session_policy(
            &runtime,
            SessionPolicyParameters::new(
                1,
                interval(),
                AllowedPrekeyModes::new(&[PrekeyQuality::ReusableBoth]).expect("modes"),
                AnchorRequirement::local_only(),
            )
            .expect("parameters"),
        )
        .expect("other body same version");
    fail(
        pin.verify(other.as_bytes(), Arc::clone(&runtime), 150),
        Error::Checkpoint,
    );
    let future_pin = PolicyPin::new(
        signer.policy_family().expect("family"),
        signer.public_key().expect("public"),
        PolicyCheckpoint::from_trusted_state(2, issued.checkpoint().digest()).expect("newer pin"),
    )
    .expect("pin");
    fail(
        future_pin.verify(issued.as_bytes(), runtime, 150),
        Error::Checkpoint,
    );
}

#[test]
fn correctly_resigned_protocol_policy_cannot_override_profile_family_or_sdk_binding() {
    let (signer, issued, _, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let (body, _) = open_envelope(issued.as_bytes()).expect("body");
    assert_eq!(body.len(), 198);
    for (offset, expected) in [
        (8, Error::Scope),
        (64, Error::Scope),
        (96, Error::Scope),
        (164, Error::Encoding),
        (165, Error::Encoding),
        (166, Error::Encoding),
    ] {
        let mut changed = body.to_vec();
        *changed.get_mut(offset).expect("field") ^= 0x80;
        let checkpoint = PolicyCheckpoint::from_trusted_state(
            1,
            crate::crypto::digest(
                b"Q-PERIAPT-CONTINUITY-SESSION-POLICY-CANDIDATE/v1",
                &changed,
            ),
        )
        .expect("checkpoint");
        let pin = PolicyPin::new(
            signer.policy_family().expect("family"),
            signer.public_key().expect("public"),
            checkpoint,
        )
        .expect("pin");
        let wire = envelope(
            &changed,
            &signer
                .sign(Purpose::SessionPolicy, &changed)
                .expect("real signature"),
        )
        .expect("wire");
        fail(pin.verify(&wire, Arc::clone(&runtime), 150), expected);
    }
}

#[test]
fn protocol_authority_components_cannot_be_reused_as_active_device_identity() {
    let (_, issued, pin, runtime) = session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
    let policy = pin.verify(issued.as_bytes(), runtime, 150).expect("policy");
    let root = RootSigningKey::deterministic([110; 32], [111; 32]).expect("account");
    // Reuse either protocol-policy component or the algorithm-policy ML-DSA
    // root. Each device is otherwise genuinely enrolled by its own account.
    for (pq, classic, family) in [
        (82, 112, policy.family()),
        (112, 83, policy.family()),
        (80, 112, policy.family()),
        (112, 113, [6; 32]),
    ] {
        let signer = DeviceSigningKey::deterministic([pq; 32], [classic; 32]).expect("device");
        let cert = root
            .issue_device(
                DeviceDescription::new([114; 16], 1, family, interval()).expect("description"),
                signer.public_key().expect("public"),
            )
            .expect("credential");
        let roster = root
            .issue_roster(1, interval(), &[root.roster_entry(&cert).expect("entry")])
            .expect("roster");
        let account = AccountPin::new(
            root.account_id().expect("account"),
            root.public_key().expect("public"),
            roster.checkpoint(),
            family,
        )
        .expect("pin");
        let device = account
            .verify_device(&cert, roster.as_bytes(), 150)
            .expect("real chain");
        fail(policy.check_device(&device, 150), Error::Scope);
    }
}

#[test]
fn malicious_signer_cannot_relabel_a_reusable_public_key_as_one_time_in_selection() {
    let f = fixture();
    let device = device(&f);
    let issued = f
        .signer
        .issue_manifest(&device, context(1), &leaves())
        .expect("manifest");
    let (body, _) = open_envelope(issued.as_bytes()).expect("body");
    let scope = body.get(8..256).expect("scope");
    let mut records = Vec::new();
    // Bypass the honest issuer's duplicate check by constructing a genuinely
    // signed tree whose classical roles have distinct IDs but identical keys.
    for index in 0..issued.leaf_count() {
        let wire = issued.proof(index).expect("proof").encode().expect("wire");
        let mut decoder = crate::codec::Decoder::new(&wire);
        decoder.u16().expect("index");
        let size = usize::from(decoder.u16().expect("size"));
        let mut leaf = decoder.take(size).expect("leaf").to_vec();
        if leaf.get(8) == Some(&(LeafKind::OneTimeClassical as u8)) {
            leaf.get_mut(25..).expect("public").fill(11);
        }
        let mut committed = scope.to_vec();
        committed.extend_from_slice(&leaf);
        let id =
            crate::crypto::digest(b"Q-PERIAPT-CONTINUITY-PREKEY-LEAF-CANDIDATE/v1", &committed);
        records.push((id, leaf));
    }
    records.sort_by_key(|(id, _)| *id);
    let ids: Vec<_> = records.iter().map(|(id, _)| *id).collect();
    let mut malicious_body = body.to_vec();
    malicious_body
        .get_mut(258..)
        .expect("root")
        .copy_from_slice(&crate::merkle::root(&ids).expect("root"));
    let wire = envelope(
        &malicious_body,
        &f.signer
            .sign(Purpose::Manifest, &malicious_body)
            .expect("sign"),
    )
    .expect("envelope");
    let manifest = device.verify_manifest(&wire, 150).expect("real signature");
    let mut proofs = Vec::new();
    for (index, (_, leaf)) in records.iter().enumerate() {
        let siblings = crate::merkle::proof(&ids, index).expect("siblings");
        let mut encoded = (index as u16).to_be_bytes().to_vec();
        encoded.extend_from_slice(&(leaf.len() as u16).to_be_bytes());
        encoded.extend_from_slice(leaf);
        encoded.push(siblings.len() as u8);
        for sibling in siblings {
            encoded.extend_from_slice(&sibling);
        }
        let proof = LeafProof::decode(&encoded).expect("proof");
        let member = manifest.verify_leaf(&proof, 150).expect("authentic member");
        proofs.push((member.kind(), proof));
    }
    let by_kind = |kind| &proofs.iter().find(|(k, _)| *k == kind).expect("kind").1;
    fail(
        manifest.select_prekeys(
            by_kind(LeafKind::SignedClassical),
            by_kind(LeafKind::LastResortPq),
            ClassicalChoice::OneTime(by_kind(LeafKind::OneTimeClassical)),
            PqChoice::LastResort,
            150,
        ),
        Error::Scope,
    );
}

#[test]
fn complete_roster_updates_reauthorize_only_exact_retained_devices() {
    let f = fixture();
    let original = device(&f);
    let entry = f.root.roster_entry(&f.certificate).expect("entry");
    let updated = f
        .root
        .issue_roster(2, interval(), &[entry])
        .expect("update");
    let pin = AccountPin::new(
        original.account_id(),
        f.root.public_key().expect("root"),
        updated.checkpoint(),
        [6; 32],
    )
    .expect("updated pin");
    let roster = pin
        .verify_roster(updated.as_bytes(), 150)
        .expect("whole roster");
    assert_eq!(roster.account_id(), original.account_id());
    assert_eq!(roster.checkpoint(), updated.checkpoint());
    assert_eq!(roster.as_bytes(), updated.as_bytes());
    roster
        .authorize_device(&original, 150)
        .expect("retained credential");
    let current = pin
        .verify_device(&f.certificate, updated.as_bytes(), 150)
        .expect("current");
    fail(
        original.roster().authorize_device(&current, 150),
        Error::Checkpoint,
    );
    fail(roster.authorize_device(&original, 200), Error::Validity);

    let removed = f.root.issue_roster(3, interval(), &[]).expect("revoke all");
    let pin = AccountPin::new(
        original.account_id(),
        f.root.public_key().expect("root"),
        removed.checkpoint(),
        [6; 32],
    )
    .expect("revocation pin");
    let roster = pin
        .verify_roster(removed.as_bytes(), 150)
        .expect("empty roster is authenticated");
    fail(roster.authorize_device(&original, 150), Error::Scope);
    fail(roster.authorize_device(&current, 150), Error::Scope);
    fail(
        pin.verify_device(&f.certificate, removed.as_bytes(), 150),
        Error::Scope,
    );
}

#[test]
fn complete_roster_rejects_forks_replacements_and_each_forged_signature() {
    let f = fixture();
    let original = device(&f);
    let fork = f
        .root
        .issue_roster(1, interval(), &[])
        .expect("signed fork");
    let fork_pin = AccountPin::new(
        original.account_id(),
        f.root.public_key().expect("root"),
        fork.checkpoint(),
        [6; 32],
    )
    .expect("fork pin");
    let roster = fork_pin
        .verify_roster(fork.as_bytes(), 150)
        .expect("independent fork expectation");
    fail(roster.authorize_device(&original, 150), Error::Checkpoint);
    fail(f.pin.verify_roster(fork.as_bytes(), 150), Error::Checkpoint);

    let replacement = DeviceSigningKey::deterministic([23; 32], [24; 32]).expect("replacement");
    let certificate = f
        .root
        .issue_device(
            DeviceDescription::new([5; 16], 2, [6; 32], interval()).expect("generation"),
            replacement.public_key().expect("public"),
        )
        .expect("replacement certificate");
    let updated = f
        .root
        .issue_roster(
            2,
            interval(),
            &[f.root.roster_entry(&certificate).expect("entry")],
        )
        .expect("replacement roster");
    let pin = AccountPin::new(
        original.account_id(),
        f.root.public_key().expect("root"),
        updated.checkpoint(),
        [6; 32],
    )
    .expect("replacement pin");
    let roster = pin.verify_roster(updated.as_bytes(), 150).expect("roster");
    fail(roster.authorize_device(&original, 150), Error::Scope);
    let current = pin
        .verify_device(&certificate, updated.as_bytes(), 150)
        .expect("new device");
    roster
        .authorize_device(&current, 150)
        .expect("exact new generation");

    let (body, signature) = open_envelope(updated.as_bytes()).expect("envelope");
    for offset in [0, ML_DSA_65_SIG_LEN + 63] {
        let mut forged = signature.to_vec();
        *forged.get_mut(offset).expect("signature byte") ^= 1;
        fail(
            pin.verify_roster(&envelope(body, &forged).expect("encoded"), 150),
            Error::Authentication,
        );
    }
    let wrong_purpose = envelope(
        body,
        &f.root
            .sign(Purpose::Credential, body)
            .expect("wrong purpose"),
    )
    .expect("encoded");
    fail(
        pin.verify_roster(&wrong_purpose, 150),
        Error::Authentication,
    );
}
