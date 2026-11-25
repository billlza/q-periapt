// Fixture adapted from the immutable 358b bootstrap tests; all setup is outside timing.
use q_periapt_continuity_identity_candidate::*;
use q_periapt_sdk::HybridKey;
use std::sync::Arc;

pub(crate) struct Fixture {
        pub(crate) initiator: Arc<BootstrapContext>,
        pub(crate) responder: Arc<BootstrapContext>,
        pub(crate) signer_i: DeviceSigningKey,
        pub(crate) signer_r: DeviceSigningKey,
        pub(crate) reusable: HybridKey,
        pub(crate) once: HybridKey,
        pub(crate) bundle: BootstrapBundle,
        pub(crate) pin_i: AccountPin,
        pub(crate) pin_r: AccountPin,
    }

struct Enrollment {
        signer: DeviceSigningKey,
        device: Arc<VerifiedDevice>,
        certificate: Vec<u8>,
        roster: IssuedRoster,
        pin: AccountPin,
    }

fn enrolled(
        seed: u8,
        family: [u8; 32],
        signer: Option<DeviceSigningKey>,
        roster_validity: Validity,
        credential_validity: Validity,
    ) -> Enrollment {
        let root = RootSigningKey::generate().expect("root");
        let signer = signer.unwrap_or_else(|| {
            DeviceSigningKey::generate().expect("device")
        });
        let certificate = root
            .issue_device(
                DeviceDescription::new([seed; 16], 1, family, credential_validity)
                    .expect("description"),
                signer.public_key().expect("public"),
            )
            .expect("certificate");
        let roster = root
            .issue_roster(
                1,
                roster_validity,
                &[root.roster_entry(&certificate).expect("entry")],
            )
            .expect("roster");
        let pin = AccountPin::new(
            root.account_id().expect("account"),
            root.public_key().expect("root public"),
            roster.checkpoint(),
            family,
        )
        .expect("pin");
        let device = Arc::new(
            pin.verify_device(&certificate, roster.as_bytes(), 150)
                .expect("verified"),
        );
        Enrollment {
            signer,
            device,
            certificate,
            roster,
            pin,
        }
    }

pub(crate) fn fixture_with_options(
        quality: PrekeyQuality,
        public_keys: Option<(
            [u8; q_periapt_sdk::PUBLIC_KEY_LEN],
            [u8; q_periapt_sdk::PUBLIC_KEY_LEN],
        )>,
        limits: q_periapt_sdk::Limits,
        signers: Option<(DeviceSigningKey, DeviceSigningKey)>,
        anchor: AnchorRequirement,
        budget: ApplicationSendBudget,
        public_validity: Option<(Validity, Validity, [Validity; 2])>,
    ) -> Fixture {
        let (roster_validity, prekey_validity, credential_validity) =
            public_validity.unwrap_or((interval(), interval(), [interval(); 2]));
        let (_, issued, pin, runtime_r) =
            session_policy_fixture_with_budget(&[quality], anchor, budget);
        let runtime_i = sdk_runtime_with_limits(limits);
        let policy_i = Arc::new(
            pin.verify(issued.as_bytes(), runtime_i, 150)
                .expect("initiator policy"),
        );
        let policy_r = Arc::new(
            pin.verify(issued.as_bytes(), Arc::clone(&runtime_r), 150)
                .expect("responder policy"),
        );
        let (signer_i, signer_r) = match signers {
            Some((i, r)) => (Some(i), Some(r)),
            None => (None, None),
        };
        let Enrollment {
            signer: signer_i,
            device: device_i,
            certificate: certificate_i,
            roster: roster_i,
            pin: pin_i,
        } = enrolled(
            90,
            policy_r.family(),
            signer_i,
            roster_validity,
            credential_validity[0],
        );
        let Enrollment {
            signer: signer_r,
            device: device_r,
            certificate: certificate_r,
            roster: roster_r,
            pin: pin_r,
        } = enrolled(
            94,
            policy_r.family(),
            signer_r,
            roster_validity,
            credential_validity[1],
        );
        let reusable = runtime_r.generate_key().expect("reusable");
        let once = runtime_r.generate_key().expect("one time");
        let (public, one) = match public_keys {
            Some(keys) => keys,
            None => (
                reusable.public_key().expect("public").to_bytes(),
                once.public_key().expect("public").to_bytes(),
            ),
        };
        let (pq, classic) = public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
        let (pq_once, classic_once) = one.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
        let leaves = [
            (LeafKind::SignedClassical, classic),
            (LeafKind::OneTimeClassical, classic_once),
            (LeafKind::LastResortPq, pq),
            (LeafKind::OneTimePq, pq_once),
        ]
        .map(|(kind, key)| PrekeyLeaf::new(kind, key, prekey_validity).expect("leaf"));
        let manifest = signer_r
            .issue_manifest(
                &device_r,
                ManifestContext::new(
                    1,
                    runtime_r.trusted_state().digest(),
                    bootstrap_suite_digest(),
                    [99; 32],
                    prekey_validity,
                )
                .expect("manifest context"),
                &leaves,
            )
            .expect("manifest");
        let verified = device_r
            .verify_manifest(manifest.as_bytes(), 150)
            .expect("verify manifest");
        let proofs: Vec<_> = (0..manifest.leaf_count())
            .map(|i| {
                let proof = manifest.proof(i).expect("proof");
                (
                    verified.verify_leaf(&proof, 150).expect("leaf").kind(),
                    proof,
                )
            })
            .collect();
        let proof = |kind| &proofs.iter().find(|(k, _)| *k == kind).expect("role").1;
        let classical = match quality {
            PrekeyQuality::OneTimeBoth | PrekeyQuality::OneTimeClassicalLastResortPq => {
                ClassicalChoice::OneTime(proof(LeafKind::OneTimeClassical))
            }
            _ => ClassicalChoice::SignedOnly,
        };
        let pq = match quality {
            PrekeyQuality::OneTimeBoth | PrekeyQuality::SignedClassicalOneTimePq => {
                PqChoice::OneTime(proof(LeafKind::OneTimePq))
            }
            _ => PqChoice::LastResort,
        };
        let selection = Arc::new(
            verified
                .select_prekeys(
                    proof(LeafKind::SignedClassical),
                    proof(LeafKind::LastResortPq),
                    classical,
                    pq,
                    150,
                )
                .expect("selection"),
        );
        let signed = proof(LeafKind::SignedClassical)
            .encode()
            .expect("proof encoding");
        let last = proof(LeafKind::LastResortPq)
            .encode()
            .expect("proof encoding");
        let once_c = proof(LeafKind::OneTimeClassical)
            .encode()
            .expect("proof encoding");
        let once_p = proof(LeafKind::OneTimePq).encode().expect("proof encoding");
        let bundle = BootstrapBundle::from_materials(
            quality,
            BootstrapMaterials {
                initiator_credential: &certificate_i,
                initiator_roster: roster_i.as_bytes(),
                responder_credential: &certificate_r,
                responder_roster: roster_r.as_bytes(),
                responder_manifest: manifest.as_bytes(),
                signed_classical: &signed,
                last_resort_pq: &last,
                one_time_classical: if matches!(
                    quality,
                    PrekeyQuality::OneTimeBoth | PrekeyQuality::OneTimeClassicalLastResortPq
                ) {
                    Some(&once_c)
                } else {
                    None
                },
                one_time_pq: if matches!(
                    quality,
                    PrekeyQuality::OneTimeBoth | PrekeyQuality::SignedClassicalOneTimePq
                ) {
                    Some(&once_p)
                } else {
                    None
                },
            },
        )
        .expect("public bundle");
        let directory = DirectoryExpectation::from_trusted_state([99; 32]).expect("directory");
        let initiator = Arc::new(
            BootstrapContext::new(
                policy_i,
                Arc::clone(&device_i),
                Arc::clone(&device_r),
                Arc::clone(&selection),
                directory,
                150,
            )
            .expect("initiator context"),
        );
        let responder = Arc::new(
            BootstrapContext::new(policy_r, device_i, device_r, selection, directory, 150)
                .expect("responder context"),
        );
        assert_eq!(initiator.digest(), responder.digest());
        Fixture {
            initiator,
            responder,
            signer_i,
            signer_r,
            reusable,
            once,
            bundle,
            pin_i,
            pin_r,
        }
    }

pub(super) fn interval() -> Validity {
    Validity::new(100, 200).expect("interval")
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
    let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
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

pub(crate) fn session_policy_fixture_with_budget(
    modes: &[PrekeyQuality],
    anchor: AnchorRequirement,
    budget: ApplicationSendBudget,
) -> (
    PolicySigningKey,
    IssuedSessionPolicy,
    PolicyPin,
    Arc<q_periapt_sdk::Runtime>,
) {
    let signer = PolicySigningKey::generate().expect("policy signer");
    let runtime = sdk_runtime();
    let issued = signer
        .issue_session_policy(
            &runtime,
            SessionPolicyParameters::new(
                1,
                interval(),
                AllowedPrekeyModes::new(modes).expect("explicit modes"),
                anchor,
                budget,
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

