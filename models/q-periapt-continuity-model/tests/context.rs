//! Candidate canonical lifecycle-context encoding controls.

use q_periapt_continuity_model::{
    AccountId, AuthenticationStage, BootstrapContext, ClassicalPrekeySelection, CommonContext,
    ContextDigest, ContextDigestError, ContextEncodingError, ContextParty, ContextProtocol,
    ContextRoles, DeviceEpoch, DeviceId, Direction, DirectoryCheckpointDigest, DirectoryContext,
    IdentityCredentialDigest, IdentityMode, LifecycleContextV1, PolicyDigest,
    PostQuantumPrekeySelection, PrekeyBundleEpoch, PrekeyId, PrekeyQuality, PrekeyResponder,
    PrekeySelectionV1, ProtocolId, RatchetEpoch, RootEpochs, RootTransitionContext,
    RootTransitionKind, RosterDigest, RosterVersion, SessionId, SignedPrekeyManifestDigest,
    SuiteDigest, TranscriptDigest, WireVersion, BOOTSTRAP_BODY_LEN, BOOTSTRAP_DIGEST_PREIMAGE_LEN,
    BOOTSTRAP_POLICY_BOUND_KCTX_LEN, CONTEXT_DIGEST_DOMAIN, LIFECYCLE_CONTEXT_DOMAIN,
    POLICY_CONTEXT_DOMAIN, ROOT_TRANSITION_BODY_LEN, ROOT_TRANSITION_DIGEST_PREIMAGE_LEN,
    ROOT_TRANSITION_POLICY_BOUND_KCTX_LEN,
};

fn bytes<const N: usize>(tag: u8) -> [u8; N] {
    [tag; N]
}

#[derive(Clone, Copy)]
struct Sample {
    protocol: u8,
    wire: u16,
    suite: u8,
    session: u8,
    initiator_account: u8,
    initiator_device: u8,
    initiator_epoch: u64,
    initiator_credential: u8,
    responder_account: u8,
    responder_device: u8,
    responder_epoch: u64,
    responder_credential: u8,
    roster_version: u64,
    roster: u8,
    checkpoint: u8,
    manifest: u8,
    selection: u8,
    transcript: u8,
}

impl Sample {
    const fn baseline() -> Self {
        Self {
            protocol: 1,
            wire: 1,
            suite: 2,
            session: 3,
            initiator_account: 4,
            initiator_device: 5,
            initiator_epoch: 6,
            initiator_credential: 7,
            responder_account: 8,
            responder_device: 9,
            responder_epoch: 10,
            responder_credential: 11,
            roster_version: 12,
            roster: 13,
            checkpoint: 14,
            manifest: 15,
            selection: 16,
            transcript: 17,
        }
    }

    fn common(
        self,
        identity_mode: IdentityMode,
        direction: Direction,
        stage: AuthenticationStage,
    ) -> CommonContext {
        CommonContext::new(
            ContextProtocol::new(
                ProtocolId::from_bytes(bytes(self.protocol)),
                WireVersion::new(self.wire),
                SuiteDigest::from_bytes(bytes(self.suite)),
                SessionId::from_bytes(bytes(self.session)),
            ),
            ContextRoles::new(
                ContextParty::new(
                    AccountId::from_bytes(bytes(self.initiator_account)),
                    DeviceId::from_bytes(bytes(self.initiator_device)),
                    DeviceEpoch::new(self.initiator_epoch),
                    IdentityCredentialDigest::from_bytes(bytes(self.initiator_credential)),
                ),
                ContextParty::new(
                    AccountId::from_bytes(bytes(self.responder_account)),
                    DeviceId::from_bytes(bytes(self.responder_device)),
                    DeviceEpoch::new(self.responder_epoch),
                    IdentityCredentialDigest::from_bytes(bytes(self.responder_credential)),
                ),
                identity_mode,
                direction,
                stage,
            ),
        )
    }

    fn canonical_prekey(
        self,
        quality: PrekeyQuality,
    ) -> q_periapt_continuity_model::CanonicalPrekeySelection {
        let classical = match quality {
            PrekeyQuality::BothOneTime | PrekeyQuality::ClassicalOneTimePqLastResort => {
                ClassicalPrekeySelection::one_time(
                    PrekeyId::from_bytes(bytes(31)),
                    PrekeyId::from_bytes(bytes(32)),
                )
                .expect("valid classical OPK")
            }
            PrekeyQuality::ClassicalSignedOnlyPqLastResort
            | PrekeyQuality::ClassicalSignedOnlyPqOneTime => {
                ClassicalPrekeySelection::signed_only(PrekeyId::from_bytes(bytes(31)))
                    .expect("valid classical SPK")
            }
        };
        let post_quantum = match quality {
            PrekeyQuality::BothOneTime | PrekeyQuality::ClassicalSignedOnlyPqOneTime => {
                PostQuantumPrekeySelection::one_time(
                    PrekeyId::from_bytes(bytes(33)),
                    PrekeyId::from_bytes(bytes(34)),
                )
                .expect("valid PQ OPK")
            }
            PrekeyQuality::ClassicalSignedOnlyPqLastResort
            | PrekeyQuality::ClassicalOneTimePqLastResort => {
                PostQuantumPrekeySelection::last_resort(PrekeyId::from_bytes(bytes(33)))
                    .expect("valid PQ last-resort key")
            }
        };
        PrekeySelectionV1::new(
            SuiteDigest::from_bytes(bytes(self.suite)),
            PrekeyResponder::new(
                AccountId::from_bytes(bytes(self.responder_account)),
                DeviceId::from_bytes(bytes(self.responder_device)),
                DeviceEpoch::new(self.responder_epoch),
                IdentityCredentialDigest::from_bytes(bytes(self.responder_credential)),
            ),
            PrekeyBundleEpoch::new(30),
            DirectoryCheckpointDigest::from_bytes(bytes(self.checkpoint)),
            SignedPrekeyManifestDigest::from_bytes(bytes(self.manifest)),
            classical,
            post_quantum,
        )
        .expect("valid prekey selection")
        .derive_with(|_| Ok::<_, ()>(bytes(self.selection)))
        .expect("valid prekey digest")
    }

    fn bootstrap(self, quality: PrekeyQuality) -> LifecycleContextV1 {
        LifecycleContextV1::Bootstrap(
            BootstrapContext::new(
                self.common(
                    IdentityMode::Accountable,
                    Direction::InitiatorToResponder,
                    AuthenticationStage::PrekeyAuthenticated,
                ),
                DirectoryContext::new(
                    RosterVersion::new(self.roster_version),
                    RosterDigest::from_bytes(bytes(self.roster)),
                    DirectoryCheckpointDigest::from_bytes(bytes(self.checkpoint)),
                ),
                self.canonical_prekey(quality),
                TranscriptDigest::from_bytes(bytes(self.transcript)),
            )
            .expect("matching bootstrap prekey scope"),
        )
    }

    fn root(
        self,
        kind: RootTransitionKind,
        stage: AuthenticationStage,
        epochs: RootEpochs,
    ) -> LifecycleContextV1 {
        LifecycleContextV1::RootTransition(RootTransitionContext::new(
            self.common(
                IdentityMode::Accountable,
                Direction::InitiatorToResponder,
                stage,
            ),
            kind,
            ContextDigest::from_bytes(bytes(18)),
            epochs,
            TranscriptDigest::from_bytes(bytes(self.transcript)),
        ))
    }
}

fn dh_epochs() -> RootEpochs {
    RootEpochs::new(
        (RatchetEpoch::new(20), RatchetEpoch::new(21)),
        (RatchetEpoch::new(30), RatchetEpoch::new(31)),
        (RatchetEpoch::new(40), RatchetEpoch::new(40)),
    )
}

fn pq_epochs() -> RootEpochs {
    RootEpochs::new(
        (RatchetEpoch::new(20), RatchetEpoch::new(21)),
        (RatchetEpoch::new(30), RatchetEpoch::new(30)),
        (RatchetEpoch::new(40), RatchetEpoch::new(41)),
    )
}

fn hybrid_epochs() -> RootEpochs {
    RootEpochs::new(
        (RatchetEpoch::new(20), RatchetEpoch::new(21)),
        (RatchetEpoch::new(30), RatchetEpoch::new(31)),
        (RatchetEpoch::new(40), RatchetEpoch::new(41)),
    )
}

fn encode_body(context: LifecycleContextV1) -> Vec<u8> {
    let mut out = vec![0u8; context.body_len()];
    assert_eq!(context.encode_body(&mut out), Ok(out.len()));
    out
}

fn encode_policy_bound(context: LifecycleContextV1, policy: u8) -> Vec<u8> {
    let mut out = vec![0u8; context.policy_bound_kctx_len()];
    assert_eq!(
        context.encode_policy_bound_kctx(PolicyDigest::from_bytes(bytes(policy)), &mut out),
        Ok(out.len())
    );
    out
}

fn lp_fields(mut encoded: &[u8]) -> Vec<&[u8]> {
    let mut fields = Vec::new();
    while !encoded.is_empty() {
        assert!(encoded.len() >= 8, "truncated LP8 prefix");
        let (prefix, rest) = encoded.split_at(8);
        let length = u64::from_be_bytes(prefix.try_into().expect("eight-byte prefix"));
        let length = usize::try_from(length).expect("test length fits usize");
        assert!(rest.len() >= length, "truncated LP8 body");
        let (field, tail) = rest.split_at(length);
        fields.push(field);
        encoded = tail;
    }
    fields
}

fn assert_field(fields: &[&[u8]], index: usize, expected: &[u8]) {
    assert_eq!(fields.get(index).copied(), Some(expected));
}

#[test]
fn bootstrap_body_vector_has_exact_length_order_and_big_endian_integers() {
    let context = Sample::baseline().bootstrap(PrekeyQuality::BothOneTime);
    let body = encode_body(context);
    assert_eq!(body.len(), BOOTSTRAP_BODY_LEN);
    let fields = lp_fields(&body);
    assert_eq!(fields.len(), 25);
    assert_field(&fields, 0, LIFECYCLE_CONTEXT_DOMAIN);
    assert_field(&fields, 1, &1u16.to_be_bytes());
    assert_field(&fields, 2, &[1]);
    assert_field(&fields, 4, &1u16.to_be_bytes());
    assert_field(&fields, 9, &6u64.to_be_bytes());
    assert_field(&fields, 13, &10u64.to_be_bytes());
    assert_field(&fields, 18, &12u64.to_be_bytes());
    assert_field(&fields, 21, &[PrekeyQuality::BothOneTime as u8]);
}

#[test]
fn bootstrap_derives_all_four_b21_values_from_one_canonical_selection() {
    for (quality, expected) in [
        (PrekeyQuality::BothOneTime, 1u8),
        (PrekeyQuality::ClassicalSignedOnlyPqLastResort, 2),
        (PrekeyQuality::ClassicalSignedOnlyPqOneTime, 3),
        (PrekeyQuality::ClassicalOneTimePqLastResort, 4),
    ] {
        let body = encode_body(Sample::baseline().bootstrap(quality));
        let fields = lp_fields(&body);
        assert_field(&fields, 21, &[expected]);
        assert_field(&fields, 22, &bytes::<32>(15));
        assert_field(&fields, 23, &bytes::<32>(16));
    }
}

#[test]
fn bootstrap_rejects_prekey_scope_grafting_before_context_construction() {
    let sample = Sample::baseline();
    let common = sample.common(
        IdentityMode::Accountable,
        Direction::InitiatorToResponder,
        AuthenticationStage::PrekeyAuthenticated,
    );
    let directory = DirectoryContext::new(
        RosterVersion::new(sample.roster_version),
        RosterDigest::from_bytes(bytes(sample.roster)),
        DirectoryCheckpointDigest::from_bytes(bytes(sample.checkpoint)),
    );
    for (selection_sample, expected) in [
        (
            Sample {
                suite: 20,
                ..sample
            },
            ContextEncodingError::PrekeySuiteMismatch,
        ),
        (
            Sample {
                responder_account: 20,
                ..sample
            },
            ContextEncodingError::PrekeyResponderMismatch,
        ),
        (
            Sample {
                responder_device: 20,
                ..sample
            },
            ContextEncodingError::PrekeyResponderMismatch,
        ),
        (
            Sample {
                responder_epoch: 20,
                ..sample
            },
            ContextEncodingError::PrekeyResponderMismatch,
        ),
        (
            Sample {
                responder_credential: 20,
                ..sample
            },
            ContextEncodingError::PrekeyResponderMismatch,
        ),
        (
            Sample {
                checkpoint: 20,
                ..sample
            },
            ContextEncodingError::PrekeyDirectoryMismatch,
        ),
    ] {
        assert_eq!(
            BootstrapContext::new(
                common,
                directory,
                selection_sample.canonical_prekey(PrekeyQuality::BothOneTime),
                TranscriptDigest::from_bytes(bytes(sample.transcript)),
            ),
            Err(expected)
        );
    }
}

#[test]
fn root_transition_vectors_have_exact_length_order_and_closed_epoch_patterns() {
    for (kind, epochs, expected_dh, expected_pq) in [
        (
            RootTransitionKind::Dh,
            dh_epochs(),
            (30u64, 31u64),
            (40u64, 40u64),
        ),
        (
            RootTransitionKind::Pq,
            pq_epochs(),
            (30u64, 30u64),
            (40u64, 41u64),
        ),
        (
            RootTransitionKind::Hybrid,
            hybrid_epochs(),
            (30u64, 31u64),
            (40u64, 41u64),
        ),
    ] {
        let context = Sample::baseline().root(kind, AuthenticationStage::PeerConfirmed, epochs);
        let body = encode_body(context);
        assert_eq!(body.len(), ROOT_TRANSITION_BODY_LEN);
        let fields = lp_fields(&body);
        assert_eq!(fields.len(), 27);
        assert_field(&fields, 0, LIFECYCLE_CONTEXT_DOMAIN);
        assert_field(&fields, 2, &[2]);
        assert_field(&fields, 18, &[kind as u8]);
        assert_field(&fields, 20, &20u64.to_be_bytes());
        assert_field(&fields, 21, &21u64.to_be_bytes());
        assert_field(&fields, 22, &expected_dh.0.to_be_bytes());
        assert_field(&fields, 23, &expected_dh.1.to_be_bytes());
        assert_field(&fields, 24, &expected_pq.0.to_be_bytes());
        assert_field(&fields, 25, &expected_pq.1.to_be_bytes());
    }

    // Ratchet epochs use the full u64 counter domain. Zero is a valid initial
    // epoch, MAX is a valid terminal value, and only a transition that would
    // require MAX + 1 is overflow. Keep this distinct from device/roster
    // generations, where zero and MAX are reserved sentinels.
    for context in [
        Sample::baseline().root(
            RootTransitionKind::Hybrid,
            AuthenticationStage::PeerConfirmed,
            RootEpochs::new(
                (RatchetEpoch::new(0), RatchetEpoch::new(1)),
                (RatchetEpoch::new(0), RatchetEpoch::new(1)),
                (RatchetEpoch::new(0), RatchetEpoch::new(1)),
            ),
        ),
        Sample::baseline().root(
            RootTransitionKind::Hybrid,
            AuthenticationStage::PeerConfirmed,
            RootEpochs::new(
                (RatchetEpoch::new(u64::MAX - 1), RatchetEpoch::new(u64::MAX)),
                (RatchetEpoch::new(u64::MAX - 1), RatchetEpoch::new(u64::MAX)),
                (RatchetEpoch::new(u64::MAX - 1), RatchetEpoch::new(u64::MAX)),
            ),
        ),
        Sample::baseline().root(
            RootTransitionKind::Dh,
            AuthenticationStage::PeerConfirmed,
            RootEpochs::new(
                (RatchetEpoch::new(20), RatchetEpoch::new(21)),
                (RatchetEpoch::new(30), RatchetEpoch::new(31)),
                (RatchetEpoch::new(u64::MAX), RatchetEpoch::new(u64::MAX)),
            ),
        ),
    ] {
        assert_eq!(encode_body(context).len(), ROOT_TRANSITION_BODY_LEN);
    }
}

#[test]
fn policy_bound_and_digest_preimage_layers_have_exact_domains_and_lengths() {
    for context in [
        Sample::baseline().bootstrap(PrekeyQuality::BothOneTime),
        Sample::baseline().root(
            RootTransitionKind::Hybrid,
            AuthenticationStage::MutuallyConfirmed,
            hybrid_epochs(),
        ),
    ] {
        let full = encode_policy_bound(context, 19);
        assert_eq!(
            full.len(),
            if matches!(context, LifecycleContextV1::Bootstrap(_)) {
                BOOTSTRAP_POLICY_BOUND_KCTX_LEN
            } else {
                ROOT_TRANSITION_POLICY_BOUND_KCTX_LEN
            }
        );
        let fields = lp_fields(&full);
        assert_eq!(fields.len(), 3);
        assert_field(&fields, 0, POLICY_CONTEXT_DOMAIN);
        assert_field(&fields, 1, &bytes::<32>(19));
        assert_field(&fields, 2, &encode_body(context));

        let mut preimage = vec![0u8; context.digest_preimage_len()];
        assert_eq!(
            context.encode_digest_preimage(PolicyDigest::from_bytes(bytes(19)), &mut preimage,),
            Ok(preimage.len())
        );
        assert_eq!(
            preimage.len(),
            if matches!(context, LifecycleContextV1::Bootstrap(_)) {
                BOOTSTRAP_DIGEST_PREIMAGE_LEN
            } else {
                ROOT_TRANSITION_DIGEST_PREIMAGE_LEN
            }
        );
        let fields = lp_fields(&preimage);
        assert_eq!(fields.len(), 2);
        assert_field(&fields, 0, CONTEXT_DIGEST_DOMAIN);
        assert_field(&fields, 1, &full);
    }
}

#[test]
fn every_common_and_bootstrap_commitment_changes_the_canonical_body() {
    let base_sample = Sample::baseline();
    let base = encode_body(base_sample.bootstrap(PrekeyQuality::BothOneTime));
    let variants = [
        Sample {
            protocol: 20,
            ..base_sample
        },
        Sample {
            wire: 2,
            ..base_sample
        },
        Sample {
            suite: 20,
            ..base_sample
        },
        Sample {
            session: 20,
            ..base_sample
        },
        Sample {
            initiator_account: 20,
            ..base_sample
        },
        Sample {
            initiator_device: 20,
            ..base_sample
        },
        Sample {
            initiator_epoch: 20,
            ..base_sample
        },
        Sample {
            initiator_credential: 20,
            ..base_sample
        },
        Sample {
            responder_account: 20,
            ..base_sample
        },
        Sample {
            responder_device: 20,
            ..base_sample
        },
        Sample {
            responder_epoch: 20,
            ..base_sample
        },
        Sample {
            responder_credential: 20,
            ..base_sample
        },
        Sample {
            roster_version: 20,
            ..base_sample
        },
        Sample {
            roster: 20,
            ..base_sample
        },
        Sample {
            checkpoint: 20,
            ..base_sample
        },
        Sample {
            manifest: 20,
            ..base_sample
        },
        Sample {
            selection: 20,
            ..base_sample
        },
        Sample {
            transcript: 20,
            ..base_sample
        },
    ];
    for variant in variants {
        assert_ne!(
            encode_body(variant.bootstrap(PrekeyQuality::BothOneTime)),
            base
        );
    }
    assert_ne!(
        encode_body(base_sample.bootstrap(PrekeyQuality::ClassicalSignedOnlyPqLastResort)),
        base
    );

    let deniable = LifecycleContextV1::Bootstrap(
        BootstrapContext::new(
            base_sample.common(
                IdentityMode::Deniable,
                Direction::InitiatorToResponder,
                AuthenticationStage::PrekeyAuthenticated,
            ),
            DirectoryContext::new(
                RosterVersion::new(base_sample.roster_version),
                RosterDigest::from_bytes(bytes(base_sample.roster)),
                DirectoryCheckpointDigest::from_bytes(bytes(base_sample.checkpoint)),
            ),
            base_sample.canonical_prekey(PrekeyQuality::BothOneTime),
            TranscriptDigest::from_bytes(bytes(base_sample.transcript)),
        )
        .expect("matching deniable bootstrap scope"),
    );
    assert_ne!(encode_body(deniable), base);

    assert_eq!(
        BootstrapContext::new(
            base_sample.common(
                IdentityMode::Accountable,
                Direction::ResponderToInitiator,
                AuthenticationStage::PrekeyAuthenticated,
            ),
            DirectoryContext::new(
                RosterVersion::new(base_sample.roster_version),
                RosterDigest::from_bytes(bytes(base_sample.roster)),
                DirectoryCheckpointDigest::from_bytes(bytes(base_sample.checkpoint)),
            ),
            base_sample.canonical_prekey(PrekeyQuality::BothOneTime),
            TranscriptDigest::from_bytes(bytes(base_sample.transcript)),
        ),
        Err(ContextEncodingError::InvalidBootstrapDirection)
    );
}

#[test]
fn role_reflection_is_neither_normalized_nor_admitted_as_the_same_party() {
    let sample = Sample::baseline();
    let base = encode_body(sample.bootstrap(PrekeyQuality::BothOneTime));
    let swapped = Sample {
        initiator_account: sample.responder_account,
        initiator_device: sample.responder_device,
        initiator_epoch: sample.responder_epoch,
        initiator_credential: sample.responder_credential,
        responder_account: sample.initiator_account,
        responder_device: sample.initiator_device,
        responder_epoch: sample.initiator_epoch,
        responder_credential: sample.initiator_credential,
        ..sample
    };
    assert_ne!(
        encode_body(swapped.bootstrap(PrekeyQuality::BothOneTime)),
        base
    );

    let same = Sample {
        responder_account: sample.initiator_account,
        responder_device: sample.initiator_device,
        responder_epoch: sample.initiator_epoch,
        ..sample
    };
    let context = same.bootstrap(PrekeyQuality::BothOneTime);
    let mut out = vec![0xA5; context.body_len()];
    assert_eq!(
        context.encode_body(&mut out),
        Err(ContextEncodingError::SameParty)
    );
    assert!(out.iter().all(|byte| *byte == 0xA5));

    let same_logical_device_new_epoch = Sample {
        responder_account: sample.initiator_account,
        responder_device: sample.initiator_device,
        responder_epoch: sample.initiator_epoch + 1,
        ..sample
    }
    .bootstrap(PrekeyQuality::BothOneTime);
    let mut out = vec![0xA5; same_logical_device_new_epoch.body_len()];
    assert_eq!(
        same_logical_device_new_epoch.encode_body(&mut out),
        Err(ContextEncodingError::SameParty)
    );
    assert!(out.iter().all(|byte| *byte == 0xA5));
}

#[test]
fn variant_stage_and_epoch_rules_fail_before_writing_output() {
    let sample = Sample::baseline();
    let invalid_bootstrap = LifecycleContextV1::Bootstrap(
        BootstrapContext::new(
            sample.common(
                IdentityMode::Accountable,
                Direction::InitiatorToResponder,
                AuthenticationStage::PeerConfirmed,
            ),
            DirectoryContext::new(
                RosterVersion::new(sample.roster_version),
                RosterDigest::from_bytes(bytes(sample.roster)),
                DirectoryCheckpointDigest::from_bytes(bytes(sample.checkpoint)),
            ),
            sample.canonical_prekey(PrekeyQuality::BothOneTime),
            TranscriptDigest::from_bytes(bytes(sample.transcript)),
        )
        .expect("matching invalid-stage bootstrap scope"),
    );
    let invalid_root = sample.root(
        RootTransitionKind::Dh,
        AuthenticationStage::PrekeyAuthenticated,
        dh_epochs(),
    );
    let skipped_epoch = sample.root(
        RootTransitionKind::Dh,
        AuthenticationStage::PeerConfirmed,
        RootEpochs::new(
            (RatchetEpoch::new(20), RatchetEpoch::new(22)),
            (RatchetEpoch::new(30), RatchetEpoch::new(31)),
            (RatchetEpoch::new(40), RatchetEpoch::new(40)),
        ),
    );
    let wrong_leg = sample.root(
        RootTransitionKind::Dh,
        AuthenticationStage::PeerConfirmed,
        pq_epochs(),
    );
    let overflow = sample.root(
        RootTransitionKind::Hybrid,
        AuthenticationStage::MutuallyConfirmed,
        RootEpochs::new(
            (RatchetEpoch::new(u64::MAX), RatchetEpoch::new(0)),
            (RatchetEpoch::new(30), RatchetEpoch::new(31)),
            (RatchetEpoch::new(40), RatchetEpoch::new(41)),
        ),
    );
    for (context, expected) in [
        (
            invalid_bootstrap,
            ContextEncodingError::InvalidAuthenticationStage,
        ),
        (
            invalid_root,
            ContextEncodingError::InvalidAuthenticationStage,
        ),
        (skipped_epoch, ContextEncodingError::InvalidEpochAdvance),
        (wrong_leg, ContextEncodingError::InvalidEpochAdvance),
        (overflow, ContextEncodingError::InvalidEpochAdvance),
    ] {
        let mut out = vec![0xA5; context.body_len()];
        assert_eq!(context.encode_body(&mut out), Err(expected));
        assert!(out.iter().all(|byte| *byte == 0xA5));
    }
}

#[test]
fn zero_and_reserved_monotonic_fields_fail_closed() {
    let baseline = Sample::baseline();
    for context in [
        Sample {
            protocol: 0,
            ..baseline
        }
        .bootstrap(PrekeyQuality::BothOneTime),
        Sample {
            wire: 0,
            ..baseline
        }
        .bootstrap(PrekeyQuality::BothOneTime),
        Sample {
            initiator_epoch: 0,
            ..baseline
        }
        .bootstrap(PrekeyQuality::BothOneTime),
        Sample {
            roster_version: 0,
            ..baseline
        }
        .bootstrap(PrekeyQuality::BothOneTime),
    ] {
        assert!(context.validate().is_err());
    }
}

#[test]
fn wrong_output_lengths_and_invalid_policy_are_atomic() {
    let context = Sample::baseline().bootstrap(PrekeyQuality::BothOneTime);
    let mut short = vec![0xA5; context.body_len() - 1];
    assert_eq!(
        context.encode_body(&mut short),
        Err(ContextEncodingError::InvalidOutputLength)
    );
    assert!(short.iter().all(|byte| *byte == 0xA5));

    let mut full = vec![0xA5; context.policy_bound_kctx_len()];
    assert_eq!(
        context.encode_policy_bound_kctx(PolicyDigest::from_bytes([0u8; 32]), &mut full),
        Err(ContextEncodingError::ZeroField)
    );
    assert!(full.iter().all(|byte| *byte == 0xA5));
}

#[test]
fn digest_adapter_receives_only_the_complete_preimage_and_fails_explicitly() {
    let context = Sample::baseline().bootstrap(PrekeyQuality::BothOneTime);
    let policy = PolicyDigest::from_bytes(bytes(19));
    let digest = context
        .derive_digest_with(policy, |preimage| {
            assert_eq!(preimage.len(), BOOTSTRAP_DIGEST_PREIMAGE_LEN);
            let fields = lp_fields(preimage);
            assert_field(&fields, 0, CONTEXT_DIGEST_DOMAIN);
            assert_field(&fields, 1, &encode_policy_bound(context, 19));
            Ok::<_, ()>(bytes(20))
        })
        .expect("trusted adapter");
    assert_eq!(digest, ContextDigest::from_bytes(bytes(20)));

    assert_eq!(
        context.derive_digest_with(policy, |_| Err::<[u8; 32], _>(7u8)),
        Err(ContextDigestError::Backend(7))
    );
    assert_eq!(
        context.derive_digest_with(policy, |_| Ok::<_, ()>([0u8; 32])),
        Err(ContextDigestError::ZeroDigest)
    );

    let invalid = Sample {
        wire: 0,
        ..Sample::baseline()
    }
    .bootstrap(PrekeyQuality::BothOneTime);
    let mut adapter_called = false;
    assert_eq!(
        invalid.derive_digest_with(policy, |_| {
            adapter_called = true;
            Ok::<_, ()>(bytes(20))
        }),
        Err(ContextDigestError::Encoding(
            ContextEncodingError::InvalidWireVersion
        ))
    );
    assert!(!adapter_called);
}

#[test]
fn policy_identity_is_part_of_both_full_kctx_and_durable_digest_preimage() {
    let context = Sample::baseline().bootstrap(PrekeyQuality::BothOneTime);
    let first = encode_policy_bound(context, 19);
    let second = encode_policy_bound(context, 20);
    assert_ne!(first, second);

    let mut first_preimage = vec![0u8; context.digest_preimage_len()];
    let mut second_preimage = vec![0u8; context.digest_preimage_len()];
    context
        .encode_digest_preimage(PolicyDigest::from_bytes(bytes(19)), &mut first_preimage)
        .expect("first");
    context
        .encode_digest_preimage(PolicyDigest::from_bytes(bytes(20)), &mut second_preimage)
        .expect("second");
    assert_ne!(first_preimage, second_preimage);
}
