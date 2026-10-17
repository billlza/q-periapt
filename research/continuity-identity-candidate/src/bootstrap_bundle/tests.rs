// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::bootstrap::tests::fixture;
use crate::BootstrapRole;

mod historical;

#[test]
fn bundle_roundtrip_verifies_all_modes_and_preserves_original_context_identity() {
    for quality in [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ] {
        let f = fixture(quality);
        let parsed =
            BootstrapBundle::from_bytes(f.bundle.as_bytes()).expect("canonical public transport");
        assert_eq!(parsed.as_bytes(), f.bundle.as_bytes());
        for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
            let context = parsed
                .verify(f.policy_owner(role), f.bundle_requirements(quality), 150)
                .expect("full existing verification");
            assert_eq!(context.digest(), f.initiator.digest());
        }
    }
}
#[test]
fn bundle_rejects_every_truncation_trailing_bytes_and_noncanonical_optional_shape() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    for length in 0..f.bundle.as_bytes().len() {
        assert!(
            BootstrapBundle::from_bytes(f.bundle.as_bytes().get(..length).expect("prefix"))
                .is_err()
        );
    }
    let mut bytes = f.bundle.as_bytes().to_vec();
    bytes.push(0);
    assert!(BootstrapBundle::from_bytes(&bytes).is_err());
    for mode in [0, 2, 3, 4, 5, 255] {
        let mut bytes = f.bundle.as_bytes().to_vec();
        *bytes.get_mut(8).expect("quality") = mode;
        assert!(BootstrapBundle::from_bytes(&bytes).is_err());
    }
    let mut bytes = f.bundle.as_bytes().to_vec();
    bytes
        .get_mut(9..11)
        .expect("first size")
        .copy_from_slice(&8193u16.to_be_bytes());
    assert!(matches!(
        BootstrapBundle::from_bytes(&bytes),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        BootstrapBundle::from_bytes(&vec![0; MAX_BOOTSTRAP_BUNDLE_BYTES + 1]),
        Err(Error::Capacity)
    ));
}
#[test]
fn bundle_cannot_choose_identity_generation_directory_quality_or_reopen_closed_policy() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let policy = f.policy_owner(BootstrapRole::Initiator);
    let mut requirements = f.bundle_requirements(PrekeyQuality::OneTimeBoth);
    requirements.responder =
        ExpectedDevice::new(&f.pin_r, [93; 16], 1).expect("different intended device");
    assert!(matches!(
        f.bundle.verify(Arc::clone(&policy), requirements, 150),
        Err(Error::Scope)
    ));
    let mut requirements = f.bundle_requirements(PrekeyQuality::OneTimeBoth);
    requirements.responder =
        ExpectedDevice::new(&f.pin_r, [94; 16], 2).expect("different generation");
    assert!(matches!(
        f.bundle.verify(Arc::clone(&policy), requirements, 150),
        Err(Error::Scope)
    ));
    let mut requirements = f.bundle_requirements(PrekeyQuality::OneTimeBoth);
    requirements.directory =
        DirectoryExpectation::from_trusted_state([98; 32]).expect("independent expectation");
    assert!(matches!(
        f.bundle.verify(Arc::clone(&policy), requirements, 150),
        Err(Error::Scope)
    ));
    assert!(matches!(
        f.bundle.verify(
            Arc::clone(&policy),
            f.bundle_requirements(PrekeyQuality::ReusableBoth),
            150
        ),
        Err(Error::Scope)
    ));
    for now in [99, 200, u64::MAX] {
        assert!(f
            .bundle
            .verify(
                Arc::clone(&policy),
                f.bundle_requirements(PrekeyQuality::OneTimeBoth),
                now
            )
            .is_err());
    }
    policy.close();
    assert!(matches!(
        f.bundle.verify(
            policy,
            f.bundle_requirements(PrekeyQuality::OneTimeBoth),
            150
        ),
        Err(Error::Closed)
    ));
}

fn fields(bundle: &BootstrapBundle) -> Vec<Vec<u8>> {
    let (_, m) = codec::decode(bundle.as_bytes()).expect("outer structure");
    [
        m.initiator_credential,
        m.initiator_roster,
        m.responder_credential,
        m.responder_roster,
        m.responder_manifest,
        m.signed_classical,
        m.last_resort_pq,
        m.one_time_classical.unwrap_or(&[]),
        m.one_time_pq.unwrap_or(&[]),
    ]
    .into_iter()
    .map(<[u8]>::to_vec)
    .collect()
}
fn untrusted(fields: &[Vec<u8>], quality: PrekeyQuality) -> BootstrapBundle {
    let mut wire = b"QPBNDL01".to_vec();
    wire.push(quality as u8);
    for field in fields {
        wire.extend_from_slice(
            &u16::try_from(field.len())
                .expect("bounded fixture field")
                .to_be_bytes(),
        );
        wire.extend_from_slice(field);
    }
    BootstrapBundle::from_bytes(&wire).expect("outer framing only")
}
#[test]
fn bundle_verifies_all_signed_materials_and_rejects_cross_manifest_proofs() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let g = fixture(PrekeyQuality::OneTimeBoth);
    let original = fields(&f.bundle);
    for index in 0..9 {
        let mut changed = original.clone();
        *changed
            .get_mut(index)
            .expect("field")
            .last_mut()
            .expect("nonempty") ^= 1;
        let bundle = untrusted(&changed, PrekeyQuality::OneTimeBoth);
        assert!(
            bundle
                .verify(
                    f.policy_owner(BootstrapRole::Initiator),
                    f.bundle_requirements(PrekeyQuality::OneTimeBoth),
                    150
                )
                .is_err(),
            "unverified field {index}"
        );
    }
    let other = fields(&g.bundle);
    for index in 4..9 {
        let mut changed = original.clone();
        *changed.get_mut(index).expect("field") = other.get(index).expect("other fixture").clone();
        let bundle = untrusted(&changed, PrekeyQuality::OneTimeBoth);
        assert!(
            bundle
                .verify(
                    f.policy_owner(BootstrapRole::Initiator),
                    f.bundle_requirements(PrekeyQuality::OneTimeBoth),
                    150
                )
                .is_err(),
            "cross-manifest field {index}"
        );
    }
}
#[test]
fn bundle_preserves_independent_roster_checkpoints_and_runtime_lifetime() {
    use crate::{RootSigningKey, RosterCheckpoint};
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let root = RootSigningKey::deterministic([94; 32], [95; 32])
        .expect("independent retained account key");
    for version in [1, 2] {
        let pin = AccountPin::new(
            root.account_id().expect("account"),
            root.public_key().expect("public"),
            RosterCheckpoint::from_trusted_state(version, [77; 32])
                .expect("different protected head"),
            f.policy_owner(BootstrapRole::Initiator).family(),
        )
        .expect("pin");
        let mut required = f.bundle_requirements(PrekeyQuality::OneTimeBoth);
        required.responder =
            ExpectedDevice::new(&pin, [94; 16], 1).expect("same device, different checkpoint");
        assert!(matches!(
            f.bundle
                .verify(f.policy_owner(BootstrapRole::Initiator), required, 150),
            Err(Error::Checkpoint)
        ));
    }
    let owner = f.policy_owner(BootstrapRole::Initiator);
    owner.runtime.close();
    assert!(f
        .bundle
        .verify(
            owner,
            f.bundle_requirements(PrekeyQuality::OneTimeBoth),
            150
        )
        .is_err());
}

#[test]
fn bundle_rejects_a_fully_valid_same_account_bundle_for_the_wrong_device_roles() {
    use crate::{
        DeviceDescription, DeviceSigningKey, LeafKind, ManifestContext, PrekeyLeaf, RootSigningKey,
    };
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let policy = f.policy_owner(BootstrapRole::Initiator);
    let root = RootSigningKey::deterministic([111; 32], [112; 32]).expect("separate account");
    let interval = crate::tests::interval();
    let certificate_a = root
        .issue_device(
            DeviceDescription::new([1; 16], 1, policy.family(), interval).expect("device A"),
            f.signer_i.public_key().expect("A key"),
        )
        .expect("credential A");
    let certificate_b = root
        .issue_device(
            DeviceDescription::new([2; 16], 1, policy.family(), interval).expect("device B"),
            f.signer_r.public_key().expect("B key"),
        )
        .expect("credential B");
    let roster = root
        .issue_roster(
            1,
            interval,
            &[
                root.roster_entry(&certificate_a).expect("A entry"),
                root.roster_entry(&certificate_b).expect("B entry"),
            ],
        )
        .expect("same-account roster");
    let pin = AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root public"),
        roster.checkpoint(),
        policy.family(),
    )
    .expect("independent account pin");
    let a = pin
        .verify_device(&certificate_a, roster.as_bytes(), 150)
        .expect("A");
    let b = pin
        .verify_device(&certificate_b, roster.as_bytes(), 150)
        .expect("B");
    let reusable = f.reusable.public_key().expect("reusable").to_bytes();
    let once = f.once.public_key().expect("one-time").to_bytes();
    let (pq, c) = reusable.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let (opq, oc) = once.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let leaves = [
        (LeafKind::SignedClassical, c),
        (LeafKind::OneTimeClassical, oc),
        (LeafKind::LastResortPq, pq),
        (LeafKind::OneTimePq, opq),
    ]
    .map(|(kind, key)| PrekeyLeaf::new(kind, key, interval).expect("leaf"));
    let package =
        |first: &[u8], second: &[u8], device: &VerifiedDevice, signer: &DeviceSigningKey| {
            let manifest = signer
                .issue_manifest(
                    device,
                    ManifestContext::new(
                        1,
                        policy.runtime.trusted_state().digest(),
                        crate::bootstrap_suite_digest(),
                        [99; 32],
                        interval,
                    )
                    .expect("scope"),
                    &leaves,
                )
                .expect("real device signature");
            let verified = device
                .verify_manifest(manifest.as_bytes(), 150)
                .expect("verified manifest");
            let mut proofs = std::collections::BTreeMap::new();
            for index in 0..manifest.leaf_count() {
                let proof = manifest.proof(index).expect("proof");
                proofs.insert(
                    verified.verify_leaf(&proof, 150).expect("member").kind() as u8,
                    proof.encode().expect("proof bytes"),
                );
            }
            BootstrapBundle::from_materials(
                PrekeyQuality::OneTimeBoth,
                BootstrapMaterials {
                    initiator_credential: first,
                    initiator_roster: roster.as_bytes(),
                    responder_credential: second,
                    responder_roster: roster.as_bytes(),
                    responder_manifest: manifest.as_bytes(),
                    signed_classical: proofs.get(&1).expect("baseline C"),
                    last_resort_pq: proofs.get(&3).expect("baseline PQ"),
                    one_time_classical: Some(proofs.get(&2).expect("one-time C")),
                    one_time_pq: Some(proofs.get(&4).expect("one-time PQ")),
                },
            )
            .expect("public package")
        };
    let requirements = |first, second| BootstrapRequirements {
        initiator: ExpectedDevice::new(&pin, first, 1).expect("expected first"),
        responder: ExpectedDevice::new(&pin, second, 1).expect("expected second"),
        quality: PrekeyQuality::OneTimeBoth,
        directory: DirectoryExpectation::from_trusted_state([99; 32]).expect("directory"),
    };
    let forward = package(&certificate_a, &certificate_b, &b, &f.signer_r);
    assert!(forward
        .verify(Arc::clone(&policy), requirements([1; 16], [2; 16]), 150)
        .is_ok());
    let reversed = package(&certificate_b, &certificate_a, &a, &f.signer_i);
    assert!(
        reversed
            .verify(Arc::clone(&policy), requirements([2; 16], [1; 16]), 150)
            .is_ok(),
        "alternative is fully signed and internally valid"
    );
    assert!(
        matches!(
            reversed.verify(policy, requirements([1; 16], [2; 16]), 150),
            Err(Error::Scope)
        ),
        "valid signatures cannot replace the caller's intended roles"
    );
}

#[test]
fn reopen_request_authenticates_every_historical_field_and_preserves_all_mode_identities() {
    use crate::{bootstrap::tests::fixture_with_public_validity, Validity};
    for quality in [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ] {
        let short = Validity::new(100, 160).expect("short public snapshot");
        let f = fixture_with_public_validity(quality, short, short);
        let policy = f.policy_owner(BootstrapRole::Initiator);
        let request = f
            .bundle
            .request_reopen(
                Arc::clone(&policy),
                f.bundle_requirements(quality),
                BootstrapRole::Initiator,
                [75; 32],
                170,
            )
            .expect("historical authentication");
        assert_eq!(request.context.digest(), f.initiator.digest());
        assert!(matches!(request.context.check(170), Err(Error::Validity)));
        request
            .context
            .check_session_identity(170)
            .expect("still valid identity");
        let original = fields(&f.bundle);
        for (index, field) in original.iter().enumerate() {
            if field.is_empty() {
                continue;
            }
            let mut changed = original.clone();
            *changed
                .get_mut(index)
                .expect("field")
                .last_mut()
                .expect("nonempty field") ^= 1;
            assert!(
                untrusted(&changed, quality)
                    .request_reopen(
                        Arc::clone(&policy),
                        f.bundle_requirements(quality),
                        BootstrapRole::Initiator,
                        [75; 32],
                        170
                    )
                    .is_err(),
                "historical field {index} was not authenticated"
            );
        }
        for now in [99, 200, u64::MAX] {
            assert!(f
                .bundle
                .request_reopen(
                    Arc::clone(&policy),
                    f.bundle_requirements(quality),
                    BootstrapRole::Initiator,
                    [75; 32],
                    now
                )
                .is_err());
        }
        let mut wrong = f.bundle_requirements(quality);
        wrong.responder = ExpectedDevice::new(&f.pin_r, [93; 16], 1).expect("wrong identity");
        assert!(matches!(
            f.bundle.request_reopen(
                Arc::clone(&policy),
                wrong,
                BootstrapRole::Initiator,
                [75; 32],
                170
            ),
            Err(Error::Scope)
        ));
        policy.close();
        assert!(matches!(
            f.bundle.request_reopen(
                policy,
                f.bundle_requirements(quality),
                BootstrapRole::Initiator,
                [75; 32],
                170
            ),
            Err(Error::Closed)
        ));
    }
}

#[test]
fn historical_request_does_not_extend_device_credential_lifetime() {
    use crate::{bootstrap::tests::fixture_with_public_and_credential_validity, Validity};
    let quality = PrekeyQuality::OneTimeBoth;
    let f = fixture_with_public_and_credential_validity(
        quality,
        crate::tests::interval(),
        Validity::new(100, 160).expect("prekeys"),
        Validity::new(100, 170).expect("credential"),
    );
    let policy = f.policy_owner(BootstrapRole::Initiator);
    policy
        .check_mode(quality, 170)
        .expect("policy and runtime still live");
    f.bundle
        .request_reopen(
            Arc::clone(&policy),
            f.bundle_requirements(quality),
            BootstrapRole::Initiator,
            [75; 32],
            169,
        )
        .expect("credential live after advertisement expiry");
    assert!(matches!(
        f.bundle.request_reopen(
            policy,
            f.bundle_requirements(quality),
            BootstrapRole::Initiator,
            [75; 32],
            170
        ),
        Err(Error::Validity)
    ));
}
