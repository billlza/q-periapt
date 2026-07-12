//! Finite lifecycle controls for the non-normative Continuity model.

use q_periapt_continuity_model::{
    AccountId, AnchorId, AnchorOutcome, AnchorPlan, AnchorProfile, AnchorValue, AssuranceLevel,
    AuthenticatedContext, AuthenticationStage, BootstrapContext, ClassicalPrekeySelection,
    CommandCommitment, CommandKind, CommandOrdinal, CommitIdentity, CommitReceipt, CommonContext,
    ContextDigest, ContextParty, ContextProtocol, ContextRoles, CryptoCommand, CryptoCompletion,
    CryptoPurpose, CryptoResult, DeviceEpoch, DeviceId, Direction, DirectoryCheckpointDigest,
    DirectoryContext, Effect, FenceToken, IdentityCredentialDigest, IdentityMode,
    LifecycleContextV1, LifecycleError, ModeledOperation, OperationBinding, OperationDraft,
    OperationId, PersistStage, PersistSubject, PhaseTag, PolicyDigest, PostQuantumPrekeySelection,
    PrekeyBundleEpoch, PrekeyId, PrekeyResponder, PrekeySelectionV1, ProtocolId, ProtocolScope,
    ProviderBinding, ProviderEpoch, ProviderProfileDigest, RatchetEpoch, RecordCommitment,
    RepositoryOutcome, ResultCommitment, ResultKind, ResultPinPlan, RootEpochs,
    RootTransitionContext, RootTransitionKind, RosterDigest, RosterVersion, SessionId,
    SessionIdentity, SessionScope, SignedPrekeyManifestDigest, StateAdvance, StateDigest,
    StateReservation, StateRevision, StateVersion, SuiteDigest, SuspensionEvidence,
    SuspensionOutcome, SuspensionPlan, SuspensionReason, TranscriptDigest, TransitionId,
    TransitionModel, TransitionScope, WireVersion,
};

fn bytes<const N: usize>(tag: u8) -> [u8; N] {
    [tag; N]
}

fn operation(kind: CommandKind, commitment: u8) -> ModeledOperation {
    let command_commitment = CommandCommitment::from_bytes(bytes(commitment));
    match kind {
        CommandKind::Deterministic => {
            ModeledOperation::DeterministicBootstrap { command_commitment }
        }
        CommandKind::StableHandle => {
            ModeledOperation::StableHandleRootTransition { command_commitment }
        }
        CommandKind::NonRepeatable => {
            ModeledOperation::NonRepeatableMessageProtection { command_commitment }
        }
    }
}

fn baseline_context() -> AuthenticatedContext {
    BindingParts::baseline(CommandKind::Deterministic, AnchorProfile::None).authenticated_context()
}

fn baseline_session_identity() -> SessionIdentity {
    SessionIdentity::new(
        SessionId::from_bytes(bytes(3)),
        DeviceId::from_bytes(bytes(4)),
        DeviceId::from_bytes(bytes(5)),
    )
}

#[derive(Clone, Copy)]
struct BindingParts {
    protocol: u8,
    wire: u16,
    policy: u8,
    anchor_profile: AnchorProfile,
    session: u8,
    local_device: u8,
    peer_device: u8,
    prior_version: u64,
    reserved_version: u64,
    prior_digest: u8,
    reserved_digest: u8,
    transition: u8,
    ordinal: u32,
    fence: u64,
    context_stage: AuthenticationStage,
    context: u8,
    provider_profile: u8,
    provider_epoch: u64,
    operation: ModeledOperation,
    suspension_record: u8,
}

impl BindingParts {
    fn baseline(kind: CommandKind, anchor_profile: AnchorProfile) -> Self {
        let context_stage = match kind {
            CommandKind::Deterministic => AuthenticationStage::PrekeyAuthenticated,
            CommandKind::StableHandle => AuthenticationStage::PeerConfirmed,
            CommandKind::NonRepeatable => AuthenticationStage::MutuallyConfirmed,
        };
        Self {
            protocol: 1,
            wire: 1,
            policy: 2,
            anchor_profile,
            session: 3,
            local_device: 4,
            peer_device: 5,
            prior_version: 7,
            reserved_version: 8,
            prior_digest: 6,
            reserved_digest: 7,
            transition: 8,
            ordinal: 9,
            fence: 11,
            context_stage,
            context: 9,
            provider_profile: 10,
            provider_epoch: 12,
            operation: operation(kind, 11),
            suspension_record: 99,
        }
    }

    fn binding(self) -> OperationBinding {
        let protocol = ProtocolScope::new(
            ProtocolId::from_bytes(bytes(self.protocol)),
            WireVersion::new(self.wire),
            PolicyDigest::from_bytes(bytes(self.policy)),
            self.anchor_profile,
        );
        let identity = SessionIdentity::new(
            SessionId::from_bytes(bytes(self.session)),
            DeviceId::from_bytes(bytes(self.local_device)),
            DeviceId::from_bytes(bytes(self.peer_device)),
        );
        let state = StateReservation::new(
            StateVersion::new(self.prior_version),
            StateVersion::new(self.reserved_version),
            StateDigest::from_bytes(bytes(self.prior_digest)),
            StateDigest::from_bytes(bytes(self.reserved_digest)),
        );
        let transition = TransitionScope::new(
            TransitionId::from_bytes(bytes(self.transition)),
            CommandOrdinal::new(self.ordinal),
            FenceToken::new(self.fence),
        );
        OperationBinding::new(
            protocol,
            SessionScope::new(identity, state, transition),
            self.authenticated_context(),
            ProviderBinding::new(
                ProviderProfileDigest::from_bytes(bytes(self.provider_profile)),
                ProviderEpoch::new(self.provider_epoch),
            ),
            self.operation,
            SuspensionPlan::new(RecordCommitment::from_bytes(bytes(self.suspension_record))),
        )
    }

    fn authenticated_context(self) -> AuthenticatedContext {
        let common = CommonContext::new(
            ContextProtocol::new(
                ProtocolId::from_bytes(bytes(self.protocol)),
                WireVersion::new(self.wire),
                SuiteDigest::from_bytes(bytes(self.provider_profile)),
                SessionId::from_bytes(bytes(self.session)),
            ),
            ContextRoles::new(
                ContextParty::new(
                    AccountId::from_bytes(bytes(self.local_device.wrapping_add(20))),
                    DeviceId::from_bytes(bytes(self.local_device)),
                    DeviceEpoch::new(1),
                    IdentityCredentialDigest::from_bytes(bytes(self.local_device.wrapping_add(40))),
                ),
                ContextParty::new(
                    AccountId::from_bytes(bytes(self.peer_device.wrapping_add(20))),
                    DeviceId::from_bytes(bytes(self.peer_device)),
                    DeviceEpoch::new(2),
                    IdentityCredentialDigest::from_bytes(bytes(self.peer_device.wrapping_add(40))),
                ),
                IdentityMode::Accountable,
                Direction::InitiatorToResponder,
                self.context_stage,
            ),
        );
        let lifecycle = match self.context_stage {
            AuthenticationStage::PrekeyAuthenticated => {
                let directory = DirectoryContext::new(
                    RosterVersion::new(1),
                    RosterDigest::from_bytes(bytes(60)),
                    DirectoryCheckpointDigest::from_bytes(bytes(61)),
                );
                let prekey = PrekeySelectionV1::new(
                    SuiteDigest::from_bytes(bytes(self.provider_profile)),
                    PrekeyResponder::new(
                        AccountId::from_bytes(bytes(self.peer_device.wrapping_add(20))),
                        DeviceId::from_bytes(bytes(self.peer_device)),
                        DeviceEpoch::new(2),
                        IdentityCredentialDigest::from_bytes(bytes(
                            self.peer_device.wrapping_add(40),
                        )),
                    ),
                    PrekeyBundleEpoch::new(3),
                    DirectoryCheckpointDigest::from_bytes(bytes(61)),
                    SignedPrekeyManifestDigest::from_bytes(bytes(62)),
                    ClassicalPrekeySelection::one_time(
                        PrekeyId::from_bytes(bytes(64)),
                        PrekeyId::from_bytes(bytes(65)),
                    )
                    .expect("valid classical selection"),
                    PostQuantumPrekeySelection::one_time(
                        PrekeyId::from_bytes(bytes(66)),
                        PrekeyId::from_bytes(bytes(67)),
                    )
                    .expect("valid PQ selection"),
                )
                .expect("valid prekey record")
                .derive_with(|_| Ok::<_, ()>(bytes(63)))
                .expect("valid prekey digest");
                LifecycleContextV1::Bootstrap(
                    BootstrapContext::new(
                        common,
                        directory,
                        prekey,
                        TranscriptDigest::from_bytes(bytes(self.context)),
                    )
                    .expect("matching bootstrap prekey scope"),
                )
            }
            AuthenticationStage::PeerConfirmed | AuthenticationStage::MutuallyConfirmed => {
                LifecycleContextV1::RootTransition(RootTransitionContext::new(
                    common,
                    RootTransitionKind::Hybrid,
                    ContextDigest::from_bytes(bytes(64)),
                    RootEpochs::new(
                        (RatchetEpoch::new(1), RatchetEpoch::new(2)),
                        (RatchetEpoch::new(3), RatchetEpoch::new(4)),
                        (RatchetEpoch::new(5), RatchetEpoch::new(6)),
                    ),
                    TranscriptDigest::from_bytes(bytes(self.context)),
                ))
            }
        };
        lifecycle
            .derive_authenticated_context_with(PolicyDigest::from_bytes(bytes(self.policy)), |_| {
                Ok::<_, ()>(bytes(self.context))
            })
            .expect("valid synthetic canonical context")
    }
}

fn protocol_scope(anchor_profile: AnchorProfile) -> ProtocolScope {
    ProtocolScope::new(
        ProtocolId::from_bytes(bytes(1)),
        WireVersion::new(1),
        PolicyDigest::from_bytes(bytes(2)),
        anchor_profile,
    )
}

fn new_model() -> TransitionModel {
    new_model_for_profile(AnchorProfile::None)
}

fn new_model_for_profile(anchor_profile: AnchorProfile) -> TransitionModel {
    new_model_with_profile_and_fence(anchor_profile, 11)
}

fn new_model_with_fence(fence: u64) -> TransitionModel {
    new_model_with_profile_and_fence(AnchorProfile::None, fence)
}

fn new_model_with_profile_and_fence(anchor_profile: AnchorProfile, fence: u64) -> TransitionModel {
    new_model_for_kind_profile_and_fence(CommandKind::Deterministic, anchor_profile, fence)
}

fn new_model_for_kind_profile_and_fence(
    kind: CommandKind,
    anchor_profile: AnchorProfile,
    fence: u64,
) -> TransitionModel {
    TransitionModel::new(
        protocol_scope(anchor_profile),
        baseline_session_identity(),
        BindingParts::baseline(kind, anchor_profile).authenticated_context(),
        StateVersion::new(7),
        StateDigest::from_bytes(bytes(6)),
        FenceToken::new(fence),
        CommandOrdinal::new(9),
    )
}

fn draft(kind: CommandKind, anchor_profile: AnchorProfile) -> OperationDraft {
    draft_with_fence(kind, anchor_profile, 11)
}

fn draft_with_fence(
    kind: CommandKind,
    anchor_profile: AnchorProfile,
    fence: u64,
) -> OperationDraft {
    let mut parts = BindingParts::baseline(kind, anchor_profile);
    parts.fence = fence;
    OperationDraft::new(OperationId::from_bytes(bytes(12)), parts.binding())
}

fn exact_result(command: CryptoCommand, tag: u8) -> CryptoResult {
    CryptoResult::new(
        command.operation_id(),
        command.binding(),
        command.expected_result_kind(),
        ResultCommitment::from_bytes(bytes(tag)),
    )
}

fn result_for_draft(draft: OperationDraft, tag: u8) -> CryptoResult {
    CryptoResult::new(
        draft.operation_id(),
        draft.binding(),
        draft.binding().expected_result_kind(),
        ResultCommitment::from_bytes(bytes(tag)),
    )
}

fn apply_persist(model: &mut TransitionModel, effect: Effect) -> Effect {
    let intent = effect.persist_intent().expect("expected persist effect");
    model
        .repository_outcome(&RepositoryOutcome::applied(intent.exact_receipt()))
        .expect("exact receipt must apply")
}

fn apply_suspension(model: &mut TransitionModel, effect: Effect) -> Effect {
    let intent = effect
        .suspension_intent()
        .expect("expected suspension intent");
    assert!(matches!(effect, Effect::PersistSuspension(_)));
    model
        .suspension_outcome(&SuspensionOutcome::applied(intent.exact_receipt()))
        .expect("exact suspension must apply")
}

fn reserved_model(kind: CommandKind, anchor_profile: AnchorProfile) -> TransitionModel {
    let mut model = new_model_for_kind_profile_and_fence(kind, anchor_profile, 11);
    let reserve = model
        .prepare(
            draft(kind, anchor_profile),
            RecordCommitment::from_bytes(bytes(13)),
        )
        .expect("prepare");
    assert_eq!(apply_persist(&mut model, reserve), Effect::None);
    assert_eq!(model.phase(), PhaseTag::Reserved);
    model
}

fn dispatched_model(
    kind: CommandKind,
    anchor_profile: AnchorProfile,
) -> (TransitionModel, CryptoCommand) {
    let mut model = reserved_model(kind, anchor_profile);
    let effect = model.dispatch().expect("dispatch");
    let command = effect.crypto_command().expect("expected execute effect");
    (model, command)
}

fn result_pinned_model(
    kind: CommandKind,
    anchor_profile: AnchorProfile,
) -> (TransitionModel, CryptoCommand) {
    let (mut model, command) = dispatched_model(kind, anchor_profile);
    assert_eq!(
        model
            .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20)))
            .expect("result"),
        Effect::None
    );
    let pin = model
        .pin_result(ResultPinPlan::new(
            RecordCommitment::from_bytes(bytes(21)),
            StateDigest::from_bytes(bytes(22)),
        ))
        .expect("pin result");
    assert_eq!(apply_persist(&mut model, pin), Effect::None);
    assert_eq!(model.phase(), PhaseTag::ResultPinned);
    (model, command)
}

fn anchor_plan(tag: u8) -> AnchorPlan {
    AnchorPlan::new(
        AnchorId::from_bytes(bytes(30)),
        AnchorValue::from_bytes(bytes(31)),
        AnchorValue::from_bytes(bytes(tag)),
        RecordCommitment::from_bytes(bytes(33)),
        StateDigest::from_bytes(bytes(34)),
    )
}

fn final_commit(model: &mut TransitionModel, command: CryptoCommand, final_tag: u8) -> Effect {
    let plan = match command.binding().protocol().anchor_profile() {
        AnchorProfile::PerTransitionDigest => Some(anchor_plan(final_tag.wrapping_add(1))),
        AnchorProfile::None | AnchorProfile::EpochOnly => None,
    };
    let start = model
        .begin_finalize(
            RecordCommitment::from_bytes(bytes(final_tag)),
            StateDigest::from_bytes(bytes(final_tag.wrapping_add(1))),
            plan,
        )
        .expect("begin finalize");
    if command.binding().protocol().anchor_profile() == AnchorProfile::PerTransitionDigest {
        assert_eq!(
            start.persist_intent().expect("anchor reservation").stage(),
            q_periapt_continuity_model::PersistStage::AnchorReservation
        );
        assert_eq!(apply_persist(model, start), Effect::None);
        let advance = model.advance_anchor().expect("advance anchor");
        let intent = advance.anchor_intent().expect("anchor intent");
        model
            .anchor_outcome(AnchorOutcome::AppliedExact(intent))
            .expect("anchor applied")
    } else {
        start
    }
}

fn acknowledge_release(model: &mut TransitionModel, release: Effect) {
    let permit = release.release_permit().expect("expected release permit");
    let acknowledgement = model
        .acknowledge_release(
            permit,
            RecordCommitment::from_bytes(bytes(90)),
            StateDigest::from_bytes(bytes(91)),
        )
        .expect("acknowledge release");
    assert_eq!(model.release_count(), 0);
    assert_eq!(apply_persist(model, acknowledgement), Effect::None);
    assert_eq!(model.release_count(), 1);
    assert_eq!(model.phase(), PhaseTag::Committed);
}

fn pending_stage(stage: PersistStage) -> (TransitionModel, Effect) {
    match stage {
        PersistStage::Reservation => {
            let mut model = new_model();
            let effect = model
                .prepare(
                    draft(CommandKind::Deterministic, AnchorProfile::None),
                    RecordCommitment::from_bytes(bytes(13)),
                )
                .expect("reservation");
            (model, effect)
        }
        PersistStage::ResultPin => {
            let (mut model, command) =
                dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
            model
                .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20)))
                .expect("result");
            let effect = model
                .pin_result(ResultPinPlan::new(
                    RecordCommitment::from_bytes(bytes(21)),
                    StateDigest::from_bytes(bytes(22)),
                ))
                .expect("pin");
            (model, effect)
        }
        PersistStage::AnchorReservation => {
            let (mut model, _) = result_pinned_model(
                CommandKind::Deterministic,
                AnchorProfile::PerTransitionDigest,
            );
            let effect = model
                .begin_finalize(
                    RecordCommitment::from_bytes(bytes(40)),
                    StateDigest::from_bytes(bytes(41)),
                    Some(anchor_plan(42)),
                )
                .expect("anchor reservation");
            (model, effect)
        }
        PersistStage::FinalCommit => {
            let (mut model, command) =
                result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
            let effect = final_commit(&mut model, command, 40);
            (model, effect)
        }
        PersistStage::ReleaseAck => {
            let (mut model, command) =
                result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
            let final_write = final_commit(&mut model, command, 40);
            let release = apply_persist(&mut model, final_write);
            let permit = release.release_permit().expect("release");
            let effect = model
                .acknowledge_release(
                    permit,
                    RecordCommitment::from_bytes(bytes(90)),
                    StateDigest::from_bytes(bytes(91)),
                )
                .expect("release ack");
            (model, effect)
        }
        PersistStage::Cancellation => {
            let mut model = reserved_model(CommandKind::Deterministic, AnchorProfile::None);
            let effect = model
                .cancel(
                    RecordCommitment::from_bytes(bytes(50)),
                    StateDigest::from_bytes(bytes(51)),
                )
                .expect("cancellation");
            (model, effect)
        }
        PersistStage::Supersession => {
            let (mut model, _) =
                result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
            let effect = model
                .supersede(
                    RecordCommitment::from_bytes(bytes(52)),
                    StateDigest::from_bytes(bytes(53)),
                )
                .expect("supersession");
            (model, effect)
        }
    }
}

#[test]
fn reserve_result_pin_final_commit_and_release_ack_are_ordered() {
    let mut model = new_model();
    assert_eq!(model.authenticated_context(), baseline_context());
    let reserve = model
        .prepare(
            draft(CommandKind::Deterministic, AnchorProfile::None),
            RecordCommitment::from_bytes(bytes(13)),
        )
        .expect("prepare");
    assert_eq!(model.phase(), PhaseTag::AwaitingReservation);
    assert_eq!(
        model.dispatch(),
        Err(LifecycleError::EffectReservationRequired)
    );
    assert_eq!(model.provider_dispatch_count(), 0);

    assert_eq!(apply_persist(&mut model, reserve), Effect::None);
    assert_eq!(model.authenticated_context(), baseline_context());
    let command = model
        .dispatch()
        .expect("dispatch after reserve")
        .crypto_command()
        .expect("execute permission");
    assert_eq!(
        model
            .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20)))
            .expect("provider result"),
        Effect::None
    );
    assert_eq!(model.phase(), PhaseTag::ResultReceived);
    let pin = model
        .pin_result(ResultPinPlan::new(
            RecordCommitment::from_bytes(bytes(21)),
            StateDigest::from_bytes(bytes(22)),
        ))
        .expect("pin");
    assert_eq!(apply_persist(&mut model, pin), Effect::None);
    assert_eq!(model.authenticated_context(), baseline_context());

    let final_write = final_commit(&mut model, command, 40);
    assert_eq!(model.release_count(), 0);
    let release = apply_persist(&mut model, final_write);
    let permit = release.release_permit().expect("release");
    assert_eq!(permit.assurance(), AssuranceLevel::CommitOrderingOnly);
    assert_eq!(
        permit.final_record_commitment(),
        RecordCommitment::from_bytes(bytes(40))
    );
    assert_eq!(model.phase(), PhaseTag::CommittedPendingRelease);
    assert_eq!(model.authenticated_context(), baseline_context());
    assert_eq!(model.release_count(), 0);
    acknowledge_release(&mut model, release);
    assert_eq!(model.authenticated_context(), baseline_context());
}

#[test]
fn completion_before_reservation_or_dispatch_reconciles_then_suspends_durably() {
    for unknown_before_completion in [false, true] {
        for reservation_applied in [false, true] {
            let pending_draft = draft(CommandKind::NonRepeatable, AnchorProfile::None);
            let mut pending = new_model_for_kind_profile_and_fence(
                CommandKind::NonRepeatable,
                AnchorProfile::None,
                11,
            );
            let reserve = pending
                .prepare(pending_draft, RecordCommitment::from_bytes(bytes(13)))
                .expect("prepare");
            let intent = reserve.persist_intent().expect("reservation");
            if unknown_before_completion {
                assert_eq!(
                    pending
                        .repository_outcome(&RepositoryOutcome::unknown())
                        .expect("reservation unknown"),
                    Effect::QueryRepository(intent)
                );
            }
            assert_eq!(
                pending
                    .provider_completion(CryptoCompletion::Succeeded(result_for_draft(
                        pending_draft,
                        20
                    )))
                    .expect("early completion must reconcile"),
                Effect::QueryRepository(intent)
            );
            assert_eq!(pending.phase(), PhaseTag::CommitUnknown);
            let snapshot = pending
                .durable_snapshot()
                .expect("pending journal snapshot");
            let mut reconstructed = TransitionModel::reconstruct(snapshot);
            assert_eq!(
                reconstructed
                    .resume_from_durable()
                    .expect("resume pending reservation"),
                Effect::QueryRepository(intent)
            );
            let repository = if reservation_applied {
                RepositoryOutcome::applied(intent.exact_receipt())
            } else {
                RepositoryOutcome::not_applied()
            };
            let suspension = reconstructed
                .reconcile_repository(&repository)
                .expect("reconcile before suspension");
            let quarantine = apply_suspension(&mut reconstructed, suspension);
            let suspension_intent = quarantine.suspension_intent().expect("durable suspension");
            assert_eq!(
                suspension_intent.reason(),
                SuspensionReason::ResultBeforeDispatch
            );
            assert_eq!(reconstructed.phase(), PhaseTag::Suspended);
            let durable = reconstructed
                .durable_snapshot()
                .expect("suspended snapshot");
            let mut restarted = TransitionModel::reconstruct(durable);
            assert_eq!(
                restarted.resume_from_durable().expect("durable quarantine"),
                Effect::Quarantine(suspension_intent)
            );
            assert_eq!(restarted.dispatch(), Err(LifecycleError::InvalidPhase));
            assert_eq!(restarted.provider_dispatch_count(), 0);
        }
    }

    let mut reserved = reserved_model(CommandKind::NonRepeatable, AnchorProfile::None);
    let reserved_draft = draft(CommandKind::NonRepeatable, AnchorProfile::None);
    let suspension = reserved
        .provider_completion(CryptoCompletion::Succeeded(result_for_draft(
            reserved_draft,
            20,
        )))
        .expect("reserved completion must suspend");
    assert!(matches!(suspension, Effect::PersistSuspension(_)));
    assert!(matches!(
        apply_suspension(&mut reserved, suspension),
        Effect::Quarantine(_)
    ));
    assert_eq!(reserved.phase(), PhaseTag::Suspended);
}

#[test]
fn every_structured_binding_field_is_checked_even_when_op_id_is_reused() {
    let base = BindingParts::baseline(CommandKind::Deterministic, AnchorProfile::None);
    let mut variants = [base; 21];
    variants[0].protocol = 90;
    variants[1].wire = 2;
    variants[2].policy = 90;
    variants[3].anchor_profile = AnchorProfile::EpochOnly;
    variants[4].session = 90;
    variants[5].local_device = 90;
    variants[6].peer_device = 90;
    variants[7].prior_version = 90;
    variants[8].reserved_version = 90;
    variants[9].prior_digest = 90;
    variants[10].reserved_digest = 90;
    variants[11].transition = 90;
    variants[12].ordinal = 90;
    variants[13].fence = 90;
    variants[14].context_stage = AuthenticationStage::PeerConfirmed;
    variants[15].context = 90;
    variants[16].provider_profile = 90;
    variants[17].provider_epoch = 90;
    variants[18].operation = operation(CommandKind::StableHandle, 11);
    variants[19].operation = operation(CommandKind::Deterministic, 90);
    variants[20].suspension_record = 90;

    for altered in variants {
        let (mut model, command) =
            dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
        let binding = altered.binding();
        let result = CryptoResult::new(
            command.operation_id(),
            binding,
            binding.expected_result_kind(),
            ResultCommitment::from_bytes(bytes(20)),
        );
        let suspension = model
            .provider_completion(CryptoCompletion::Succeeded(result))
            .expect("binding mismatch must persist suspension");
        assert_eq!(
            suspension.suspension_intent().expect("suspension").reason(),
            SuspensionReason::ResultBindingMismatch
        );
        apply_suspension(&mut model, suspension);
        assert_eq!(model.phase(), PhaseTag::Suspended);
        assert_eq!(model.release_count(), 0);
    }
}

#[test]
fn session_and_context_authority_are_checked_before_reservation_and_survive_restart() {
    let base = BindingParts::baseline(CommandKind::Deterministic, AnchorProfile::None);
    let mut wrong_session = base;
    wrong_session.session = 90;
    let mut wrong_local_device = base;
    wrong_local_device.local_device = 90;
    let mut wrong_peer_device = base;
    wrong_peer_device.peer_device = 90;
    let mut reflected_devices = base;
    reflected_devices.local_device = base.peer_device;
    reflected_devices.peer_device = base.local_device;
    let mut wrong_prior_context = base;
    wrong_prior_context.context = 90;
    let mut peer_confirmed_context = base;
    peer_confirmed_context.context_stage = AuthenticationStage::PeerConfirmed;
    let mut mutually_confirmed_context = base;
    mutually_confirmed_context.context_stage = AuthenticationStage::MutuallyConfirmed;
    let mut wrong_context_operation = base;
    wrong_context_operation.operation = operation(CommandKind::StableHandle, 11);

    let cases = [
        (
            OperationDraft::new(OperationId::from_bytes(bytes(12)), wrong_session.binding()),
            LifecycleError::SessionIdentityMismatch,
        ),
        (
            OperationDraft::new(
                OperationId::from_bytes(bytes(12)),
                wrong_local_device.binding(),
            ),
            LifecycleError::SessionIdentityMismatch,
        ),
        (
            OperationDraft::new(
                OperationId::from_bytes(bytes(12)),
                wrong_peer_device.binding(),
            ),
            LifecycleError::SessionIdentityMismatch,
        ),
        (
            OperationDraft::new(
                OperationId::from_bytes(bytes(12)),
                reflected_devices.binding(),
            ),
            LifecycleError::SessionIdentityMismatch,
        ),
        (
            OperationDraft::new(
                OperationId::from_bytes(bytes(12)),
                wrong_prior_context.binding(),
            ),
            LifecycleError::AuthenticatedContextMismatch,
        ),
        (
            OperationDraft::new(
                OperationId::from_bytes(bytes(12)),
                peer_confirmed_context.binding(),
            ),
            LifecycleError::AuthenticatedContextMismatch,
        ),
        (
            OperationDraft::new(
                OperationId::from_bytes(bytes(12)),
                mutually_confirmed_context.binding(),
            ),
            LifecycleError::AuthenticatedContextMismatch,
        ),
        (
            OperationDraft::new(
                OperationId::from_bytes(bytes(12)),
                wrong_context_operation.binding(),
            ),
            LifecycleError::ContextOperationMismatch,
        ),
    ];

    let assert_rejected = |model: &mut TransitionModel| {
        for (candidate, expected) in cases {
            assert_eq!(
                model.prepare(candidate, RecordCommitment::from_bytes(bytes(13))),
                Err(expected)
            );
            assert_eq!(model.phase(), PhaseTag::Idle);
            assert_eq!(model.state_version(), StateVersion::new(7));
            assert_eq!(model.state_digest(), StateDigest::from_bytes(bytes(6)));
            assert_eq!(model.session_identity(), baseline_session_identity());
            assert_eq!(model.authenticated_context(), baseline_context());
            assert_eq!(model.provider_dispatch_count(), 0);
            assert_eq!(model.release_count(), 0);
        }
    };

    let mut model = new_model();
    assert_rejected(&mut model);
    let snapshot = model.durable_snapshot().expect("trusted idle snapshot");
    assert_eq!(snapshot.schema_version(), 3);
    assert_eq!(snapshot.session_identity(), baseline_session_identity());
    assert_eq!(snapshot.authenticated_context(), baseline_context());

    let mut reconstructed = TransitionModel::reconstruct(snapshot);
    assert_eq!(
        reconstructed.session_identity(),
        baseline_session_identity()
    );
    assert_eq!(reconstructed.authenticated_context(), baseline_context());
    assert_rejected(&mut reconstructed);
    assert!(matches!(
        reconstructed
            .prepare(
                draft(CommandKind::Deterministic, AnchorProfile::None),
                RecordCommitment::from_bytes(bytes(13)),
            )
            .expect("exact trusted draft"),
        Effect::Persist(_)
    ));
}

#[test]
fn closed_operation_rejects_the_wrong_result_shape() {
    for operation in [
        operation(CommandKind::Deterministic, 11),
        operation(CommandKind::StableHandle, 11),
        operation(CommandKind::NonRepeatable, 11),
    ] {
        assert_ne!(operation.purpose(), CryptoPurpose::Confirmation);
    }

    let (mut model, command) = dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
    let wrong = CryptoResult::new(
        command.operation_id(),
        command.binding(),
        ResultKind::StableHandle,
        ResultCommitment::from_bytes(bytes(20)),
    );
    let suspension = model
        .provider_completion(CryptoCompletion::Succeeded(wrong))
        .expect("shape mismatch must persist suspension");
    apply_suspension(&mut model, suspension);
    assert_eq!(model.phase(), PhaseTag::Suspended);
    assert_eq!(
        model.suspension_reason(),
        Some(SuspensionReason::ResultShapeMismatch)
    );
}

#[test]
fn conflicting_result_preserves_and_reconciles_the_first_pin_intent() {
    for applied in [false, true] {
        let (mut model, command) =
            dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
        let first = exact_result(command, 20);
        assert_eq!(
            model
                .provider_completion(CryptoCompletion::Succeeded(first))
                .expect("first"),
            Effect::None
        );
        let pin = model
            .pin_result(ResultPinPlan::new(
                RecordCommitment::from_bytes(bytes(21)),
                StateDigest::from_bytes(bytes(22)),
            ))
            .expect("pin");
        let intent = pin.persist_intent().expect("pin intent");
        let snapshot = model
            .durable_snapshot()
            .expect("pending result pin must be journalable");
        model = TransitionModel::reconstruct(snapshot);
        assert_eq!(
            model.provider_completion(CryptoCompletion::Succeeded(first)),
            Err(LifecycleError::DuplicateResult)
        );
        assert_eq!(model.phase(), PhaseTag::AwaitingResultPin);

        let conflict = exact_result(command, 23);
        assert_eq!(
            model
                .provider_completion(CryptoCompletion::Succeeded(conflict))
                .expect("conflict requires reconciliation"),
            Effect::QueryRepository(intent)
        );
        assert_eq!(model.phase(), PhaseTag::CommitUnknown);
        assert_eq!(
            model
                .fence_lost(FenceToken::new(12))
                .expect("later fence loss must preserve the first suspension cause"),
            Effect::QueryRepository(intent)
        );
        let pending_cause = model
            .durable_snapshot()
            .expect("pending first cause must survive reconstruction");
        assert!(!pending_cause.contains_volatile_provider_result());
        model = TransitionModel::reconstruct(pending_cause);
        assert_eq!(
            model.resume_from_durable().expect("resume first cause"),
            Effect::QueryRepository(intent)
        );
        let outcome = if applied {
            RepositoryOutcome::applied(intent.exact_receipt())
        } else {
            RepositoryOutcome::not_applied()
        };
        let suspension = model
            .reconcile_repository(&outcome)
            .expect("reconcile first pin");
        assert!(matches!(suspension, Effect::PersistSuspension(_)));
        assert_eq!(
            suspension
                .suspension_intent()
                .expect("suspension intent")
                .evidence(),
            SuspensionEvidence::None
        );
        assert!(matches!(
            apply_suspension(&mut model, suspension),
            Effect::Quarantine(_)
        ));
        assert_eq!(model.phase(), PhaseTag::Suspended);
        assert_eq!(
            model.suspension_reason(),
            Some(SuspensionReason::ConflictingProviderResult)
        );
        assert_eq!(model.release_count(), 0);
    }
}

#[test]
fn provider_cannot_contradict_an_already_accepted_success() {
    for reports_unknown in [false, true] {
        for repeated_unknown in [false, true] {
            for repository_world in 0..3 {
                let (mut model, command) =
                    dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
                let first = exact_result(command, 20);
                model
                    .provider_completion(CryptoCompletion::Succeeded(first))
                    .expect("first success");
                let pin = model
                    .pin_result(ResultPinPlan::new(
                        RecordCommitment::from_bytes(bytes(21)),
                        StateDigest::from_bytes(bytes(22)),
                    ))
                    .expect("pin first success");
                let intent = pin.persist_intent().expect("pin intent");
                let pending_pin = model
                    .durable_snapshot()
                    .expect("pending pin snapshot before contradiction");
                assert!(!pending_pin.contains_volatile_provider_result());
                model = TransitionModel::reconstruct(pending_pin);
                let completion = if reports_unknown {
                    CryptoCompletion::OutcomeUnknown {
                        operation_id: command.operation_id(),
                        binding: command.binding(),
                    }
                } else {
                    CryptoCompletion::DefinitiveFailure {
                        operation_id: command.operation_id(),
                        binding: command.binding(),
                    }
                };
                assert_eq!(
                    model
                        .provider_completion(completion)
                        .expect("contradiction must reconcile the pin first"),
                    Effect::QueryRepository(intent)
                );
                let snapshot = model
                    .durable_snapshot()
                    .expect("contradiction journal snapshot");
                assert!(!snapshot.contains_volatile_provider_result());
                model = TransitionModel::reconstruct(snapshot);
                assert_eq!(
                    model.resume_from_durable().expect("resume contradiction"),
                    Effect::QueryRepository(intent)
                );
                if repeated_unknown {
                    assert_eq!(
                        model
                            .reconcile_repository(&RepositoryOutcome::unknown())
                            .expect("repeated unknown"),
                        Effect::QueryRepository(intent)
                    );
                    let repeated = model.durable_snapshot().expect("repeated unknown snapshot");
                    model = TransitionModel::reconstruct(repeated);
                    assert_eq!(
                        model
                            .resume_from_durable()
                            .expect("resume repeated unknown"),
                        Effect::QueryRepository(intent)
                    );
                }
                let outcome = match repository_world {
                    0 => RepositoryOutcome::applied(intent.exact_receipt()),
                    1 => RepositoryOutcome::not_applied(),
                    2 => RepositoryOutcome::conflict(FenceToken::new(12)),
                    _ => unreachable!(),
                };
                let suspension = model
                    .reconcile_repository(&outcome)
                    .expect("repository truth must preserve contradiction");
                let suspension_intent = suspension.suspension_intent().expect("suspension");
                assert_eq!(
                    suspension_intent.reason(),
                    SuspensionReason::ProviderOutcomeContradiction
                );
                assert_eq!(suspension_intent.evidence(), SuspensionEvidence::None);
                let suspension_snapshot = model
                    .durable_snapshot()
                    .expect("contradiction suspension snapshot");
                assert!(!suspension_snapshot.contains_volatile_provider_result());
                model = TransitionModel::reconstruct(suspension_snapshot);
                assert_eq!(
                    model
                        .resume_from_durable()
                        .expect("resume contradiction suspension"),
                    Effect::QuerySuspension(suspension_intent)
                );
                assert_eq!(
                    model
                        .suspension_outcome(&SuspensionOutcome::applied(
                            suspension_intent.exact_receipt(),
                        ))
                        .expect("durable contradiction"),
                    Effect::Quarantine(suspension_intent)
                );
                assert_eq!(model.phase(), PhaseTag::Suspended);
                assert_eq!(model.release_count(), 0);
            }
        }
    }
}

#[test]
fn anchor_profile_is_prebound_and_anchor_plan_is_durable_before_advance() {
    let (mut model, command) = result_pinned_model(
        CommandKind::Deterministic,
        AnchorProfile::PerTransitionDigest,
    );
    assert_eq!(
        model.begin_finalize(
            RecordCommitment::from_bytes(bytes(40)),
            StateDigest::from_bytes(bytes(41)),
            None
        ),
        Err(LifecycleError::AnchorRequired)
    );
    let preparation = model
        .begin_finalize(
            RecordCommitment::from_bytes(bytes(40)),
            StateDigest::from_bytes(bytes(41)),
            Some(anchor_plan(42)),
        )
        .expect("prepare anchor");
    let preparation_intent = preparation.persist_intent().expect("anchor reservation");
    assert_eq!(model.phase(), PhaseTag::AwaitingAnchorReservation);
    assert_eq!(model.advance_anchor(), Err(LifecycleError::InvalidPhase));
    assert_eq!(apply_persist(&mut model, preparation), Effect::None);
    assert_eq!(model.phase(), PhaseTag::AnchorReserved);
    let advance = model.advance_anchor().expect("advance");
    let intent = advance.anchor_intent().expect("anchor intent");
    assert_eq!(intent.operation_id(), command.operation_id());
    assert_eq!(
        intent.final_record_commitment(),
        RecordCommitment::from_bytes(bytes(40))
    );
    assert_eq!(
        intent.final_state_digest(),
        StateDigest::from_bytes(bytes(41))
    );
    assert_ne!(
        preparation_intent.record_commitment(),
        intent.final_record_commitment()
    );
    assert_eq!(
        model
            .anchor_outcome(AnchorOutcome::Unknown)
            .expect("unknown"),
        Effect::QueryAnchor(intent)
    );
    let final_write = model
        .anchor_outcome(AnchorOutcome::AlreadyAppliedExact(intent))
        .expect("exact anchor");
    let release = apply_persist(&mut model, final_write);
    assert_eq!(
        release.release_permit().expect("release").assurance(),
        AssuranceLevel::PerTransitionAnchored
    );
}

#[test]
fn per_transition_anchor_rejects_a_noop_plan_before_mutating_state() {
    let (mut model, _) = result_pinned_model(
        CommandKind::Deterministic,
        AnchorProfile::PerTransitionDigest,
    );
    let before = model
        .durable_snapshot()
        .expect("result-pinned state is durable");
    let no_op = AnchorPlan::new(
        AnchorId::from_bytes(bytes(30)),
        AnchorValue::from_bytes(bytes(31)),
        AnchorValue::from_bytes(bytes(31)),
        RecordCommitment::from_bytes(bytes(33)),
        StateDigest::from_bytes(bytes(34)),
    );

    assert_eq!(
        model.begin_finalize(
            RecordCommitment::from_bytes(bytes(40)),
            StateDigest::from_bytes(bytes(41)),
            Some(no_op),
        ),
        Err(LifecycleError::AnchorDidNotAdvance)
    );
    assert_eq!(model.phase(), PhaseTag::ResultPinned);
    assert_eq!(
        model.durable_snapshot().expect("unchanged durable state"),
        before
    );
    assert_eq!(model.advance_anchor(), Err(LifecycleError::InvalidPhase));

    assert!(matches!(
        model
            .begin_finalize(
                RecordCommitment::from_bytes(bytes(40)),
                StateDigest::from_bytes(bytes(41)),
                Some(anchor_plan(42)),
            )
            .expect("valid anchor plan remains admissible"),
        Effect::Persist(_)
    ));
}

#[test]
fn unrelated_anchor_and_anchor_profile_downgrade_controls_fail_closed() {
    let (mut first, _) = result_pinned_model(
        CommandKind::Deterministic,
        AnchorProfile::PerTransitionDigest,
    );
    let first_prepare = first
        .begin_finalize(
            RecordCommitment::from_bytes(bytes(40)),
            StateDigest::from_bytes(bytes(41)),
            Some(anchor_plan(42)),
        )
        .expect("first prepare");
    apply_persist(&mut first, first_prepare);
    let first_intent = first
        .advance_anchor()
        .expect("first anchor")
        .anchor_intent()
        .expect("first intent");

    let (mut second, _) = result_pinned_model(
        CommandKind::Deterministic,
        AnchorProfile::PerTransitionDigest,
    );
    let second_prepare = second
        .begin_finalize(
            RecordCommitment::from_bytes(bytes(50)),
            StateDigest::from_bytes(bytes(51)),
            Some(anchor_plan(52)),
        )
        .expect("second prepare");
    apply_persist(&mut second, second_prepare);
    let second_intent = second
        .advance_anchor()
        .expect("second anchor")
        .anchor_intent()
        .expect("second intent");
    assert_ne!(first_intent, second_intent);
    let suspension = first
        .anchor_outcome(AnchorOutcome::AppliedExact(second_intent))
        .expect("unrelated anchor must persist suspension");
    apply_suspension(&mut first, suspension);
    assert_eq!(first.phase(), PhaseTag::Suspended);

    let (mut no_anchor, _) = result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
    assert_eq!(
        no_anchor.begin_finalize(
            RecordCommitment::from_bytes(bytes(40)),
            StateDigest::from_bytes(bytes(41)),
            Some(anchor_plan(42))
        ),
        Err(LifecycleError::UnexpectedAnchor)
    );

    let mut expected_per_transition = new_model_for_profile(AnchorProfile::PerTransitionDigest);
    assert_eq!(
        expected_per_transition.prepare(
            draft(CommandKind::Deterministic, AnchorProfile::None),
            RecordCommitment::from_bytes(bytes(13))
        ),
        Err(LifecycleError::DraftBindingMismatch)
    );
}

#[test]
fn anchor_equivocation_survives_restart_as_the_same_durable_quarantine() {
    let (mut model, _) = result_pinned_model(
        CommandKind::Deterministic,
        AnchorProfile::PerTransitionDigest,
    );
    let preparation = model
        .begin_finalize(
            RecordCommitment::from_bytes(bytes(40)),
            StateDigest::from_bytes(bytes(41)),
            Some(anchor_plan(42)),
        )
        .expect("anchor preparation");
    apply_persist(&mut model, preparation);
    let anchor_snapshot = model.durable_snapshot().expect("anchor snapshot");
    let mut reconstructed = TransitionModel::reconstruct(anchor_snapshot);
    assert!(matches!(
        reconstructed.resume_from_durable().expect("query anchor"),
        Effect::QueryAnchor(_)
    ));
    let suspension = reconstructed
        .anchor_outcome(AnchorOutcome::Equivocation)
        .expect("equivocation suspension");
    let suspension_intent = suspension.suspension_intent().expect("suspension intent");
    assert_eq!(
        suspension_intent.reason(),
        SuspensionReason::AnchorEquivocation
    );
    let pending = reconstructed
        .durable_snapshot()
        .expect("pending suspension snapshot");
    let mut restarted = TransitionModel::reconstruct(pending);
    assert_eq!(
        restarted.resume_from_durable().expect("query suspension"),
        Effect::QuerySuspension(suspension_intent)
    );
    assert_eq!(
        restarted
            .suspension_outcome(&SuspensionOutcome::applied(
                suspension_intent.exact_receipt()
            ))
            .expect("durable suspension"),
        Effect::Quarantine(suspension_intent)
    );
    let durable = restarted
        .durable_snapshot()
        .expect("durable suspension snapshot");
    let mut final_restart = TransitionModel::reconstruct(durable);
    assert_eq!(final_restart.authenticated_context(), baseline_context());
    assert_eq!(
        final_restart
            .resume_from_durable()
            .expect("quarantine replay"),
        Effect::Quarantine(suspension_intent)
    );
}

#[test]
fn epoch_profile_without_modeled_evidence_never_claims_epoch_assurance() {
    let (mut model, command) =
        result_pinned_model(CommandKind::Deterministic, AnchorProfile::EpochOnly);
    let final_write = final_commit(&mut model, command, 40);
    let release = apply_persist(&mut model, final_write);
    assert_eq!(
        release.release_permit().expect("release").assurance(),
        AssuranceLevel::CommitOrderingOnly
    );
}

#[test]
fn repository_unknown_reconciles_exact_absent_and_conflict_worlds() {
    let (mut applied, command) =
        result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
    let final_write = final_commit(&mut applied, command, 40);
    let intent = final_write.persist_intent().expect("final persist");
    assert_eq!(
        applied
            .repository_outcome(&RepositoryOutcome::unknown())
            .expect("unknown"),
        Effect::QueryRepository(intent)
    );
    let snapshot = applied.durable_snapshot().expect("commit-unknown snapshot");
    let mut applied = TransitionModel::reconstruct(snapshot);
    assert_eq!(
        applied
            .resume_from_durable()
            .expect("resume commit unknown"),
        Effect::QueryRepository(intent)
    );
    let release = applied
        .reconcile_repository(&RepositoryOutcome::applied(intent.exact_receipt()))
        .expect("applied");
    assert!(matches!(release, Effect::Release(_)));
    assert_eq!(applied.release_count(), 0);

    let (mut absent, absent_command) =
        result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
    let absent_intent = final_commit(&mut absent, absent_command, 40)
        .persist_intent()
        .expect("final persist");
    absent
        .repository_outcome(&RepositoryOutcome::unknown())
        .expect("unknown");
    assert_eq!(
        absent
            .reconcile_repository(&RepositoryOutcome::not_applied())
            .expect("absent"),
        Effect::Persist(absent_intent)
    );

    let (mut conflict, conflict_command) =
        result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
    final_commit(&mut conflict, conflict_command, 40);
    conflict
        .repository_outcome(&RepositoryOutcome::unknown())
        .expect("unknown");
    let suspension = conflict
        .reconcile_repository(&RepositoryOutcome::conflict(FenceToken::new(12)))
        .expect("conflict");
    assert!(matches!(suspension, Effect::PersistSuspension(_)));
    apply_suspension(&mut conflict, suspension);
    assert_eq!(conflict.phase(), PhaseTag::Suspended);
}

#[test]
fn every_persist_stage_survives_unknown_reconstruction_and_closed_outcomes() {
    let stages = [
        PersistStage::Reservation,
        PersistStage::ResultPin,
        PersistStage::AnchorReservation,
        PersistStage::FinalCommit,
        PersistStage::ReleaseAck,
        PersistStage::Cancellation,
        PersistStage::Supersession,
    ];

    for stage in stages {
        for repository_world in 0..4 {
            let (mut model, effect) = pending_stage(stage);
            let intent = effect.persist_intent().expect("persist intent");
            assert_eq!(intent.stage(), stage);
            assert!(matches!(
                (stage, intent.subject()),
                (PersistStage::Reservation, PersistSubject::Reservation)
                    | (PersistStage::ResultPin, PersistSubject::ResultPin { .. })
                    | (
                        PersistStage::AnchorReservation,
                        PersistSubject::AnchorReservation(_)
                    )
                    | (
                        PersistStage::FinalCommit,
                        PersistSubject::FinalCommit { .. }
                    )
                    | (PersistStage::ReleaseAck, PersistSubject::ReleaseAck(_))
                    | (PersistStage::Cancellation, PersistSubject::Cancellation)
                    | (PersistStage::Supersession, PersistSubject::Supersession)
            ));
            assert_eq!(
                model
                    .repository_outcome(&RepositoryOutcome::unknown())
                    .expect("unknown"),
                Effect::QueryRepository(intent)
            );
            let snapshot = model.durable_snapshot().expect("pending journal snapshot");
            assert!(!snapshot.contains_volatile_provider_result());
            model = TransitionModel::reconstruct(snapshot);
            assert_eq!(
                model.resume_from_durable().expect("resume unknown"),
                Effect::QueryRepository(intent)
            );

            match repository_world {
                0 => {
                    let applied_effect = model
                        .reconcile_repository(&RepositoryOutcome::applied(intent.exact_receipt()))
                        .expect("exact applied after reconstruction");
                    if stage == PersistStage::FinalCommit {
                        assert!(matches!(applied_effect, Effect::Release(_)));
                    } else {
                        assert_eq!(applied_effect, Effect::None);
                    }
                }
                1 => assert_eq!(
                    model
                        .reconcile_repository(&RepositoryOutcome::not_applied())
                        .expect("exact absent after reconstruction"),
                    Effect::Persist(intent)
                ),
                2 => {
                    let suspension = model
                        .reconcile_repository(&RepositoryOutcome::conflict(FenceToken::new(12)))
                        .expect("conflict after reconstruction");
                    let suspension_intent =
                        suspension.suspension_intent().expect("suspension intent");
                    assert_eq!(
                        suspension_intent.reason(),
                        SuspensionReason::RepositoryConflict
                    );
                    assert_eq!(
                        suspension_intent.evidence(),
                        SuspensionEvidence::RepositoryConflict {
                            observed_fence: FenceToken::new(12)
                        }
                    );
                    let suspension_snapshot = model
                        .durable_snapshot()
                        .expect("evidence-bearing suspension snapshot");
                    assert!(!suspension_snapshot.contains_volatile_provider_result());
                    model = TransitionModel::reconstruct(suspension_snapshot);
                    assert_eq!(
                        model.resume_from_durable().expect("resume suspension"),
                        Effect::QuerySuspension(suspension_intent)
                    );
                    assert_eq!(
                        model
                            .suspension_outcome(&SuspensionOutcome::applied(
                                suspension_intent.exact_receipt(),
                            ))
                            .expect("apply exact suspension"),
                        Effect::Quarantine(suspension_intent)
                    );
                    assert_eq!(model.phase(), PhaseTag::Suspended);
                    assert_eq!(model.release_count(), 0);
                }
                3 => {
                    assert_eq!(
                        model
                            .reconcile_repository(&RepositoryOutcome::unknown())
                            .expect("repeated unknown after reconstruction"),
                        Effect::QueryRepository(intent)
                    );
                    let repeated = model.durable_snapshot().expect("repeated unknown snapshot");
                    model = TransitionModel::reconstruct(repeated);
                    assert_eq!(
                        model
                            .resume_from_durable()
                            .expect("resume repeated unknown"),
                        Effect::QueryRepository(intent)
                    );
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn durable_reconstruction_discards_an_unpinned_result() {
    for kind in [
        CommandKind::Deterministic,
        CommandKind::StableHandle,
        CommandKind::NonRepeatable,
    ] {
        let durable = {
            let mut model = reserved_model(kind, AnchorProfile::None);
            let snapshot = model.durable_snapshot().expect("reserved snapshot");
            let command = model
                .dispatch()
                .expect("dispatch")
                .crypto_command()
                .expect("command");
            assert_eq!(
                model
                    .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20)))
                    .expect("volatile result"),
                Effect::None
            );
            assert_eq!(
                model.durable_snapshot(),
                Err(LifecycleError::DurableSnapshotUnavailable)
            );
            snapshot
        };

        let mut reconstructed = TransitionModel::reconstruct(durable);
        assert_eq!(durable.schema_version(), 3);
        let recovery = reconstructed
            .resume_from_durable()
            .expect("recovery effect");
        match kind {
            CommandKind::Deterministic => assert!(matches!(recovery, Effect::RetryExact(_))),
            CommandKind::StableHandle => assert!(matches!(recovery, Effect::QueryProvider(_))),
            CommandKind::NonRepeatable => {
                assert!(matches!(recovery, Effect::PersistSuspension(_)));
                assert!(matches!(
                    apply_suspension(&mut reconstructed, recovery),
                    Effect::Quarantine(_)
                ));
            }
        }
        assert_eq!(reconstructed.release_count(), 0);
    }
}

#[test]
fn every_durable_cut_scrubs_a_volatile_provider_result() {
    for use_fence_loss in [false, true] {
        let (mut model, command) =
            dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
        model
            .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20)))
            .expect("volatile success");
        let suspension = if use_fence_loss {
            model
                .fence_lost(FenceToken::new(12))
                .expect("fence suspension")
        } else {
            model
                .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 21)))
                .expect("result conflict suspension")
        };
        let intent = suspension.suspension_intent().expect("suspension");
        let snapshot = model.durable_snapshot().expect("suspension durable cut");
        assert!(!snapshot.contains_volatile_provider_result());
        let mut reconstructed = TransitionModel::reconstruct(snapshot);
        assert_eq!(
            reconstructed
                .resume_from_durable()
                .expect("resume suspension"),
            Effect::QuerySuspension(intent)
        );
    }

    for supersede in [false, true] {
        let (mut model, command) =
            dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
        model
            .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20)))
            .expect("volatile success");
        let closure = if supersede {
            model
                .supersede(
                    RecordCommitment::from_bytes(bytes(52)),
                    StateDigest::from_bytes(bytes(53)),
                )
                .expect("supersession")
        } else {
            model
                .cancel(
                    RecordCommitment::from_bytes(bytes(50)),
                    StateDigest::from_bytes(bytes(51)),
                )
                .expect("cancellation")
        };
        let intent = closure.persist_intent().expect("closure intent");
        let snapshot = model.durable_snapshot().expect("closure durable cut");
        assert!(!snapshot.contains_volatile_provider_result());
        let mut reconstructed = TransitionModel::reconstruct(snapshot);
        assert_eq!(
            reconstructed.resume_from_durable().expect("resume closure"),
            Effect::QueryRepository(intent)
        );
    }
}

#[test]
fn durable_anchor_snapshot_reconstructs_to_exact_query() {
    let (snapshot, expected) = {
        let (mut model, _) = result_pinned_model(
            CommandKind::Deterministic,
            AnchorProfile::PerTransitionDigest,
        );
        let preparation = model
            .begin_finalize(
                RecordCommitment::from_bytes(bytes(40)),
                StateDigest::from_bytes(bytes(41)),
                Some(anchor_plan(42)),
            )
            .expect("prepare anchor");
        let preparation_intent = preparation.persist_intent().expect("anchor persist");
        let pending = model
            .durable_snapshot()
            .expect("pending anchor journal snapshot");
        let mut model = TransitionModel::reconstruct(pending);
        assert_eq!(
            model.resume_from_durable().expect("resume pending anchor"),
            Effect::QueryRepository(preparation_intent)
        );
        assert_eq!(
            model
                .reconcile_repository(&RepositoryOutcome::applied(
                    preparation_intent.exact_receipt()
                ))
                .expect("anchor reservation applied"),
            Effect::None
        );
        let snapshot = model.durable_snapshot().expect("anchor snapshot");
        let expected = model
            .advance_anchor()
            .expect("advance")
            .anchor_intent()
            .expect("intent");
        (snapshot, expected)
    };
    let mut reconstructed = TransitionModel::reconstruct(snapshot);
    assert_eq!(
        reconstructed
            .resume_from_durable()
            .expect("anchor recovery"),
        Effect::QueryAnchor(expected)
    );
}

#[test]
fn committed_release_is_replayed_exactly_until_durable_ack() {
    let (committed_snapshot, permit) = {
        let (mut model, command) =
            result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
        let final_write = final_commit(&mut model, command, 40);
        let release = apply_persist(&mut model, final_write);
        let permit = release.release_permit().expect("permit");
        let snapshot = model.durable_snapshot().expect("pending release snapshot");
        (snapshot, permit)
    };

    let mut reconstructed = TransitionModel::reconstruct(committed_snapshot);
    assert_eq!(reconstructed.authenticated_context(), baseline_context());
    assert_eq!(
        reconstructed.resume_from_durable().expect("replay release"),
        Effect::Release(permit)
    );
    let ack = reconstructed
        .acknowledge_release(
            permit,
            RecordCommitment::from_bytes(bytes(90)),
            StateDigest::from_bytes(bytes(91)),
        )
        .expect("ack");
    let ack_intent = ack.persist_intent().expect("release ack intent");
    let pending_ack = reconstructed
        .durable_snapshot()
        .expect("pending release-ack journal snapshot");
    let mut reconstructed = TransitionModel::reconstruct(pending_ack);
    assert_eq!(reconstructed.authenticated_context(), baseline_context());
    assert_eq!(
        reconstructed
            .resume_from_durable()
            .expect("resume pending release ack"),
        Effect::QueryRepository(ack_intent)
    );

    let mut crashed_before_ack = TransitionModel::reconstruct(committed_snapshot);
    assert_eq!(
        crashed_before_ack.authenticated_context(),
        baseline_context()
    );
    assert_eq!(
        crashed_before_ack
            .resume_from_durable()
            .expect("same release"),
        Effect::Release(permit)
    );

    let closed = {
        assert_eq!(
            reconstructed
                .reconcile_repository(&RepositoryOutcome::applied(ack_intent.exact_receipt()))
                .expect("release ack applied"),
            Effect::None
        );
        reconstructed.durable_snapshot().expect("closed snapshot")
    };
    let mut closed_model = TransitionModel::reconstruct(closed);
    assert_eq!(closed_model.authenticated_context(), baseline_context());
    assert_eq!(
        closed_model.resume_from_durable().expect("closed"),
        Effect::None
    );
    assert_eq!(closed_model.release_count(), 1);
}

#[derive(Clone, Copy)]
struct SharedRepository {
    state_version: StateVersion,
    state_digest: StateDigest,
    authoritative_fence: FenceToken,
}

impl SharedRepository {
    fn apply(&mut self, intent: q_periapt_continuity_model::PersistIntent) -> RepositoryOutcome {
        if intent.fence_token() != self.authoritative_fence
            || intent.expected_state_version() != self.state_version
            || intent.expected_state_digest() != self.state_digest
        {
            return RepositoryOutcome::conflict(self.authoritative_fence);
        }
        self.state_version = intent.next_state_version();
        self.state_digest = intent.next_state_digest();
        RepositoryOutcome::applied(intent.exact_receipt())
    }
}

#[test]
fn same_version_different_digest_cannot_win_the_repository_cas() {
    let mut repository = SharedRepository {
        state_version: StateVersion::new(7),
        state_digest: StateDigest::from_bytes(bytes(99)),
        authoritative_fence: FenceToken::new(11),
    };
    let mut model = new_model_with_fence(11);
    let intent = model
        .prepare(
            draft_with_fence(CommandKind::Deterministic, AnchorProfile::None, 11),
            RecordCommitment::from_bytes(bytes(13)),
        )
        .expect("prepare")
        .persist_intent()
        .expect("reservation intent");

    let outcome = repository.apply(intent);
    let suspension = model
        .repository_outcome(&outcome)
        .expect("same-version digest conflict must suspend");
    assert!(matches!(suspension, Effect::PersistSuspension(_)));
    assert_eq!(model.dispatch(), Err(LifecycleError::InvalidPhase));
    apply_suspension(&mut model, suspension);
    assert_eq!(model.phase(), PhaseTag::Suspended);
    assert_eq!(model.provider_dispatch_count(), 0);
}

#[test]
fn every_persist_stage_cas_binds_the_expected_version_and_digest() {
    for stage in [
        PersistStage::Reservation,
        PersistStage::ResultPin,
        PersistStage::AnchorReservation,
        PersistStage::FinalCommit,
        PersistStage::ReleaseAck,
        PersistStage::Cancellation,
        PersistStage::Supersession,
    ] {
        let (mut model, effect) = pending_stage(stage);
        let intent = effect.persist_intent().expect("persist intent");
        let mut repository = SharedRepository {
            state_version: intent.expected_state_version(),
            state_digest: StateDigest::from_bytes(bytes(98)),
            authoritative_fence: intent.fence_token(),
        };

        let suspension = model
            .repository_outcome(&repository.apply(intent))
            .expect("same-version digest fork must suspend at every stage");
        assert!(matches!(suspension, Effect::PersistSuspension(_)));
        apply_suspension(&mut model, suspension);
        assert_eq!(model.phase(), PhaseTag::Suspended);
        assert_eq!(model.release_count(), 0);
    }
}

#[test]
fn receipt_with_the_wrong_prior_digest_reconciles_before_quarantine() {
    let mut model = new_model();
    let intent = model
        .prepare(
            draft(CommandKind::Deterministic, AnchorProfile::None),
            RecordCommitment::from_bytes(bytes(13)),
        )
        .expect("prepare")
        .persist_intent()
        .expect("reservation intent");
    let wrong_advance = StateAdvance::new(
        StateRevision::new(
            intent.expected_state_version(),
            StateDigest::from_bytes(bytes(97)),
        ),
        StateRevision::new(intent.next_state_version(), intent.next_state_digest()),
    );
    let wrong_receipt = CommitReceipt::new(
        CommitIdentity::new(
            intent.stage(),
            intent.transition_id(),
            intent.operation_id(),
        ),
        intent.subject(),
        intent.binding(),
        wrong_advance,
        intent.record_commitment(),
        intent.fence_token(),
    );

    assert_eq!(
        model
            .repository_outcome(&RepositoryOutcome::applied(wrong_receipt))
            .expect("wrong receipt must trigger exact reconciliation"),
        Effect::QueryRepository(intent)
    );
    let suspension = model
        .reconcile_repository(&RepositoryOutcome::not_applied())
        .expect("absence must preserve the receipt-integrity failure");
    assert_eq!(
        suspension.suspension_intent().expect("suspension").reason(),
        SuspensionReason::RepositoryReceiptMismatch
    );
    apply_suspension(&mut model, suspension);
    assert_eq!(model.phase(), PhaseTag::Suspended);
    assert_eq!(model.provider_dispatch_count(), 0);
}

#[test]
fn two_writer_fence_interleavings_authorize_at_most_one_dispatch() {
    for low_first in [false, true] {
        let mut repository = SharedRepository {
            state_version: StateVersion::new(7),
            state_digest: StateDigest::from_bytes(bytes(6)),
            authoritative_fence: FenceToken::new(12),
        };
        let mut low = new_model_with_fence(11);
        let mut high = new_model_with_fence(12);
        let low_intent = low
            .prepare(
                draft_with_fence(CommandKind::Deterministic, AnchorProfile::None, 11),
                RecordCommitment::from_bytes(bytes(13)),
            )
            .expect("low prepare")
            .persist_intent()
            .expect("low intent");
        let high_intent = high
            .prepare(
                draft_with_fence(CommandKind::Deterministic, AnchorProfile::None, 12),
                RecordCommitment::from_bytes(bytes(14)),
            )
            .expect("high prepare")
            .persist_intent()
            .expect("high intent");

        let low_effect;
        if low_first {
            let low_outcome = repository.apply(low_intent);
            low_effect = low.repository_outcome(&low_outcome).expect("low outcome");
            let high_outcome = repository.apply(high_intent);
            high.repository_outcome(&high_outcome)
                .expect("high outcome");
        } else {
            let high_outcome = repository.apply(high_intent);
            high.repository_outcome(&high_outcome)
                .expect("high outcome");
            let low_outcome = repository.apply(low_intent);
            low_effect = low.repository_outcome(&low_outcome).expect("low outcome");
        }

        assert!(matches!(low_effect, Effect::PersistSuspension(_)));
        apply_suspension(&mut low, low_effect);
        assert_eq!(low.phase(), PhaseTag::Suspended);
        assert_eq!(low.dispatch(), Err(LifecycleError::InvalidPhase));
        assert!(matches!(
            high.dispatch().expect("winner dispatch"),
            Effect::Execute(_)
        ));
        assert_eq!(
            low.provider_dispatch_count() + high.provider_dispatch_count(),
            1
        );
    }
}

#[test]
fn fence_loss_after_dispatch_is_durably_suspended_before_any_result_pin() {
    let (mut stale_writer, command) =
        dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
    assert_eq!(
        stale_writer.fence_lost(FenceToken::new(11)),
        Err(LifecycleError::FenceNotAdvanced)
    );
    let suspension = stale_writer
        .fence_lost(FenceToken::new(12))
        .expect("higher authoritative fence must suspend");
    assert_eq!(
        suspension.suspension_intent().expect("suspension").reason(),
        SuspensionReason::FenceLost
    );
    assert_eq!(
        suspension
            .suspension_intent()
            .expect("suspension")
            .evidence(),
        SuspensionEvidence::FenceLoss {
            observed_fence: FenceToken::new(12)
        }
    );
    let suspension_intent = suspension.suspension_intent().expect("suspension");
    let snapshot = stale_writer
        .durable_snapshot()
        .expect("fence evidence snapshot");
    assert!(!snapshot.contains_volatile_provider_result());
    stale_writer = TransitionModel::reconstruct(snapshot);
    assert_eq!(
        stale_writer
            .resume_from_durable()
            .expect("resume fence suspension"),
        Effect::QuerySuspension(suspension_intent)
    );
    assert_eq!(
        stale_writer
            .suspension_outcome(&SuspensionOutcome::applied(
                suspension_intent.exact_receipt(),
            ))
            .expect("durable fence suspension"),
        Effect::Quarantine(suspension_intent)
    );
    assert_eq!(stale_writer.phase(), PhaseTag::Suspended);
    assert_eq!(
        stale_writer.provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20))),
        Err(LifecycleError::InvalidPhase)
    );
    assert_eq!(stale_writer.release_count(), 0);

    for result_pin_applied in [false, true] {
        let (mut pending, command) =
            dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
        pending
            .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20)))
            .expect("first result");
        let persist = pending
            .pin_result(ResultPinPlan::new(
                RecordCommitment::from_bytes(bytes(21)),
                StateDigest::from_bytes(bytes(22)),
            ))
            .expect("pending result pin");
        let intent = persist.persist_intent().expect("result pin intent");
        assert_eq!(
            pending
                .fence_lost(FenceToken::new(12))
                .expect("fence loss must first reconcile the pending result pin"),
            Effect::QueryRepository(intent)
        );
        let snapshot = pending
            .durable_snapshot()
            .expect("pending fence cause snapshot");
        pending = TransitionModel::reconstruct(snapshot);
        assert_eq!(
            pending
                .resume_from_durable()
                .expect("resume pending fence cause"),
            Effect::QueryRepository(intent)
        );
        let repository = if result_pin_applied {
            RepositoryOutcome::applied(intent.exact_receipt())
        } else {
            RepositoryOutcome::not_applied()
        };
        let suspension = pending
            .reconcile_repository(&repository)
            .expect("reconcile result pin before fence suspension");
        let suspension_intent = suspension.suspension_intent().expect("fence suspension");
        assert_eq!(suspension_intent.reason(), SuspensionReason::FenceLost);
        assert_eq!(
            suspension_intent.evidence(),
            SuspensionEvidence::FenceLoss {
                observed_fence: FenceToken::new(12)
            }
        );
        apply_suspension(&mut pending, suspension);
        assert_eq!(pending.phase(), PhaseTag::Suspended);
        assert_eq!(pending.release_count(), 0);
    }
}

#[test]
fn suspension_journal_unknown_is_replayed_until_exact_tombstone_is_durable() {
    let (mut model, command) = dispatched_model(CommandKind::Deterministic, AnchorProfile::None);
    let wrong = CryptoResult::new(
        command.operation_id(),
        command.binding(),
        ResultKind::StableHandle,
        ResultCommitment::from_bytes(bytes(20)),
    );
    let persist = model
        .provider_completion(CryptoCompletion::Succeeded(wrong))
        .expect("shape mismatch suspension");
    let intent = persist.suspension_intent().expect("suspension intent");
    assert_eq!(
        model
            .suspension_outcome(&SuspensionOutcome::unknown())
            .expect("unknown suspension"),
        Effect::QuerySuspension(intent)
    );
    let snapshot = model
        .durable_snapshot()
        .expect("suspension-unknown snapshot");
    let mut reconstructed = TransitionModel::reconstruct(snapshot);
    assert_eq!(
        reconstructed
            .resume_from_durable()
            .expect("resume suspension"),
        Effect::QuerySuspension(intent)
    );
    assert_eq!(
        reconstructed
            .suspension_outcome(&SuspensionOutcome::not_applied())
            .expect("absent suspension"),
        Effect::RetrySuspension(intent)
    );
    assert_eq!(
        reconstructed
            .suspension_outcome(&SuspensionOutcome::applied(intent.exact_receipt()))
            .expect("applied suspension"),
        Effect::Quarantine(intent)
    );
    let durable = reconstructed
        .durable_snapshot()
        .expect("durable suspended snapshot");
    let mut restarted = TransitionModel::reconstruct(durable);
    assert_eq!(
        restarted.resume_from_durable().expect("quarantine replay"),
        Effect::Quarantine(intent)
    );
}

#[test]
fn stale_receipt_binding_and_fence_fail_closed() {
    for mismatch_subject in [false, true] {
        for actual_applied in [false, true] {
            let mut model = new_model();
            let intent = model
                .prepare(
                    draft(CommandKind::Deterministic, AnchorProfile::None),
                    RecordCommitment::from_bytes(bytes(13)),
                )
                .expect("prepare")
                .persist_intent()
                .expect("persist");
            let stale = CommitReceipt::new(
                CommitIdentity::new(
                    intent.stage(),
                    intent.transition_id(),
                    intent.operation_id(),
                ),
                if mismatch_subject {
                    PersistSubject::Cancellation
                } else {
                    intent.subject()
                },
                intent.binding(),
                intent.state_advance(),
                intent.record_commitment(),
                if mismatch_subject {
                    intent.fence_token()
                } else {
                    FenceToken::new(12)
                },
            );
            assert_eq!(
                model
                    .repository_outcome(&RepositoryOutcome::applied(stale))
                    .expect("mismatched receipt must query exact intent"),
                Effect::QueryRepository(intent)
            );
            let snapshot = model
                .durable_snapshot()
                .expect("mismatched-receipt journal snapshot");
            let mut reconstructed = TransitionModel::reconstruct(snapshot);
            assert_eq!(
                reconstructed
                    .resume_from_durable()
                    .expect("resume exact query"),
                Effect::QueryRepository(intent)
            );
            let repository = if actual_applied {
                RepositoryOutcome::applied(intent.exact_receipt())
            } else {
                RepositoryOutcome::not_applied()
            };
            let suspension = reconstructed
                .reconcile_repository(&repository)
                .expect("exact repository truth");
            apply_suspension(&mut reconstructed, suspension);
            assert_eq!(reconstructed.phase(), PhaseTag::Suspended);
            assert_eq!(reconstructed.provider_dispatch_count(), 0);
        }
    }

    for stage in [
        PersistStage::ResultPin,
        PersistStage::AnchorReservation,
        PersistStage::FinalCommit,
        PersistStage::ReleaseAck,
    ] {
        let (mut model, effect) = pending_stage(stage);
        let intent = effect.persist_intent().expect("persist intent");
        let wrong_subject = match stage {
            PersistStage::ResultPin => PersistSubject::ResultPin {
                result_kind: ResultKind::VerificationDecision,
                result_commitment: ResultCommitment::from_bytes(bytes(99)),
            },
            PersistStage::AnchorReservation => {
                let (mut alternate, _) = result_pinned_model(
                    CommandKind::Deterministic,
                    AnchorProfile::PerTransitionDigest,
                );
                alternate
                    .begin_finalize(
                        RecordCommitment::from_bytes(bytes(90)),
                        StateDigest::from_bytes(bytes(91)),
                        Some(anchor_plan(92)),
                    )
                    .expect("alternate anchor reservation")
                    .persist_intent()
                    .expect("alternate anchor intent")
                    .subject()
            }
            PersistStage::FinalCommit => {
                let (mut alternate, _) = result_pinned_model(
                    CommandKind::Deterministic,
                    AnchorProfile::PerTransitionDigest,
                );
                let alternate_anchor = match alternate
                    .begin_finalize(
                        RecordCommitment::from_bytes(bytes(90)),
                        StateDigest::from_bytes(bytes(91)),
                        Some(anchor_plan(92)),
                    )
                    .expect("alternate anchor reservation")
                    .persist_intent()
                    .expect("alternate anchor intent")
                    .subject()
                {
                    PersistSubject::AnchorReservation(anchor) => anchor,
                    _ => unreachable!(),
                };
                PersistSubject::FinalCommit {
                    anchor_intent: Some(alternate_anchor),
                }
            }
            PersistStage::ReleaseAck => {
                let (mut alternate, command) =
                    result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
                let final_write = final_commit(&mut alternate, command, 41);
                let permit = apply_persist(&mut alternate, final_write)
                    .release_permit()
                    .expect("alternate release permit");
                PersistSubject::ReleaseAck(permit)
            }
            _ => unreachable!(),
        };
        assert_ne!(wrong_subject, intent.subject());
        let wrong_receipt = CommitReceipt::new(
            CommitIdentity::new(
                intent.stage(),
                intent.transition_id(),
                intent.operation_id(),
            ),
            wrong_subject,
            intent.binding(),
            intent.state_advance(),
            intent.record_commitment(),
            intent.fence_token(),
        );
        assert_eq!(
            model
                .repository_outcome(&RepositoryOutcome::applied(wrong_receipt))
                .expect("same-variant payload mismatch must query exact intent"),
            Effect::QueryRepository(intent)
        );
        let snapshot = model.durable_snapshot().expect("payload-mismatch snapshot");
        model = TransitionModel::reconstruct(snapshot);
        assert_eq!(
            model
                .resume_from_durable()
                .expect("resume payload mismatch"),
            Effect::QueryRepository(intent)
        );
        let suspension = model
            .reconcile_repository(&RepositoryOutcome::not_applied())
            .expect("exact absence after payload mismatch");
        assert_eq!(
            suspension.suspension_intent().expect("suspension").reason(),
            SuspensionReason::RepositoryReceiptMismatch
        );
        apply_suspension(&mut model, suspension);
        assert_eq!(model.phase(), PhaseTag::Suspended);
        assert_eq!(model.release_count(), 0);
    }
}

#[test]
fn retry_contracts_are_derived_from_closed_operation_variants() {
    for kind in [
        CommandKind::Deterministic,
        CommandKind::StableHandle,
        CommandKind::NonRepeatable,
    ] {
        let (mut model, command) = dispatched_model(kind, AnchorProfile::None);
        assert_eq!(command.binding().command_kind(), kind);
        let effect = model
            .provider_completion(CryptoCompletion::OutcomeUnknown {
                operation_id: command.operation_id(),
                binding: command.binding(),
            })
            .expect("closed retry contract");
        match kind {
            CommandKind::Deterministic => assert_eq!(effect, Effect::RetryExact(command)),
            CommandKind::StableHandle => assert_eq!(effect, Effect::QueryProvider(command)),
            CommandKind::NonRepeatable => {
                assert!(matches!(effect, Effect::PersistSuspension(_)));
                apply_suspension(&mut model, effect);
                assert_eq!(model.phase(), PhaseTag::Suspended);
            }
        }
    }
}

#[test]
fn provider_restart_epoch_is_part_of_the_full_binding() {
    let (mut model, command) = dispatched_model(CommandKind::StableHandle, AnchorProfile::None);
    let mut changed = BindingParts::baseline(CommandKind::StableHandle, AnchorProfile::None);
    changed.provider_epoch = 13;
    let binding = changed.binding();
    let result = CryptoResult::new(
        command.operation_id(),
        binding,
        binding.expected_result_kind(),
        ResultCommitment::from_bytes(bytes(20)),
    );
    let suspension = model
        .provider_completion(CryptoCompletion::Succeeded(result))
        .expect("provider epoch mismatch must suspend");
    apply_suspension(&mut model, suspension);
    assert_eq!(model.phase(), PhaseTag::Suspended);
}

#[test]
fn cancellation_and_supersession_are_durable_tombstone_points() {
    let mut cancelled = reserved_model(CommandKind::Deterministic, AnchorProfile::None);
    let command = cancelled
        .dispatch()
        .expect("dispatch")
        .crypto_command()
        .expect("command");
    let close = cancelled
        .cancel(
            RecordCommitment::from_bytes(bytes(50)),
            StateDigest::from_bytes(bytes(51)),
        )
        .expect("cancel");
    assert_eq!(
        cancelled.provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20))),
        Err(LifecycleError::Closing)
    );
    apply_persist(&mut cancelled, close);
    assert_eq!(cancelled.phase(), PhaseTag::Cancelled);
    assert_eq!(
        cancelled.provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20))),
        Err(LifecycleError::AlreadyCancelled)
    );
    assert_eq!(
        TransitionModel::reconstruct(cancelled.durable_snapshot().expect("cancelled snapshot"))
            .phase(),
        PhaseTag::Cancelled
    );

    let (mut superseded, superseded_command) =
        result_pinned_model(CommandKind::Deterministic, AnchorProfile::None);
    let close = superseded
        .supersede(
            RecordCommitment::from_bytes(bytes(52)),
            StateDigest::from_bytes(bytes(53)),
        )
        .expect("supersede");
    apply_persist(&mut superseded, close);
    assert_eq!(superseded.phase(), PhaseTag::Superseded);
    assert_eq!(
        superseded.provider_completion(CryptoCompletion::Succeeded(exact_result(
            superseded_command,
            20
        ))),
        Err(LifecycleError::AlreadySuperseded)
    );
}

#[derive(Clone, Copy)]
enum TraceEvent {
    ReserveDurable,
    Execute,
    ResultA,
    ResultB,
    ResultPinDurable,
    FenceLost,
    NonRepeatableUnknown,
    FinalCommitDurable,
    Release,
}

fn independent_trace_oracle(trace: &[TraceEvent]) -> bool {
    let mut reserved = false;
    let mut executed = false;
    let mut result_seen = false;
    let mut result_conflict = false;
    let mut result_pinned = false;
    let mut fence_live = true;
    let mut nonrepeatable_unknown = false;
    let mut committed = false;
    for event in trace {
        match event {
            TraceEvent::ReserveDurable => reserved = true,
            TraceEvent::Execute => {
                if !reserved || !fence_live || nonrepeatable_unknown {
                    return false;
                }
                executed = true;
            }
            TraceEvent::ResultA => {
                if !executed {
                    return false;
                }
                result_seen = true;
            }
            TraceEvent::ResultB => {
                if result_seen {
                    result_conflict = true;
                }
            }
            TraceEvent::ResultPinDurable => {
                if !result_seen || result_conflict {
                    return false;
                }
                result_pinned = true;
            }
            TraceEvent::FenceLost => fence_live = false,
            TraceEvent::NonRepeatableUnknown => nonrepeatable_unknown = true,
            TraceEvent::FinalCommitDurable => {
                if !result_pinned || !fence_live || result_conflict {
                    return false;
                }
                committed = true;
            }
            TraceEvent::Release => {
                if !committed {
                    return false;
                }
            }
        }
    }
    true
}

#[test]
fn independent_oracle_rejects_five_intentionally_unsafe_traces() {
    let valid = [
        TraceEvent::ReserveDurable,
        TraceEvent::Execute,
        TraceEvent::ResultA,
        TraceEvent::ResultPinDurable,
        TraceEvent::FinalCommitDurable,
        TraceEvent::Release,
    ];
    assert!(independent_trace_oracle(&valid));

    let unsafe_traces: [&[TraceEvent]; 5] = [
        &[TraceEvent::Execute],
        &[TraceEvent::Release],
        &[
            TraceEvent::ReserveDurable,
            TraceEvent::Execute,
            TraceEvent::ResultA,
            TraceEvent::ResultPinDurable,
            TraceEvent::FenceLost,
            TraceEvent::FinalCommitDurable,
        ],
        &[
            TraceEvent::ReserveDurable,
            TraceEvent::Execute,
            TraceEvent::NonRepeatableUnknown,
            TraceEvent::Execute,
        ],
        &[
            TraceEvent::ReserveDurable,
            TraceEvent::Execute,
            TraceEvent::ResultA,
            TraceEvent::ResultB,
            TraceEvent::ResultPinDurable,
        ],
    ];
    for trace in unsafe_traces {
        assert!(!independent_trace_oracle(trace));
    }
}

#[test]
fn closed_outcome_class_matrix_has_no_false_release() {
    for kind in [
        CommandKind::Deterministic,
        CommandKind::StableHandle,
        CommandKind::NonRepeatable,
    ] {
        let (mut model, command) = dispatched_model(kind, AnchorProfile::None);
        let outcome = model
            .provider_completion(CryptoCompletion::OutcomeUnknown {
                operation_id: command.operation_id(),
                binding: command.binding(),
            })
            .expect("closed retry class");
        assert!(!matches!(outcome, Effect::Release(_)));
        assert_eq!(model.release_count(), 0);
    }

    for outcome in [
        AnchorOutcome::Ahead,
        AnchorOutcome::Conflict,
        AnchorOutcome::Equivocation,
        AnchorOutcome::Unavailable,
        AnchorOutcome::Unauthenticated,
    ] {
        let (mut model, _) = result_pinned_model(
            CommandKind::Deterministic,
            AnchorProfile::PerTransitionDigest,
        );
        let preparation = model
            .begin_finalize(
                RecordCommitment::from_bytes(bytes(40)),
                StateDigest::from_bytes(bytes(41)),
                Some(anchor_plan(42)),
            )
            .expect("prepare anchor");
        apply_persist(&mut model, preparation);
        model.advance_anchor().expect("advance");
        let effect = model.anchor_outcome(outcome).expect("closed anchor class");
        assert!(matches!(effect, Effect::PersistSuspension(_)));
        assert!(matches!(
            apply_suspension(&mut model, effect),
            Effect::Quarantine(_)
        ));
        assert_eq!(model.release_count(), 0);
    }
}

#[test]
fn version_overflow_fails_before_reservation_or_provider_effect() {
    let mut parts = BindingParts::baseline(CommandKind::Deterministic, AnchorProfile::None);
    parts.prior_version = u64::MAX;
    parts.reserved_version = 0;
    let mut model = TransitionModel::new(
        protocol_scope(AnchorProfile::None),
        baseline_session_identity(),
        baseline_context(),
        StateVersion::new(u64::MAX),
        StateDigest::from_bytes(bytes(6)),
        FenceToken::new(11),
        CommandOrdinal::new(9),
    );
    assert_eq!(
        model.prepare(
            OperationDraft::new(OperationId::from_bytes(bytes(12)), parts.binding()),
            RecordCommitment::from_bytes(bytes(13))
        ),
        Err(LifecycleError::CounterOverflow)
    );
    assert_eq!(model.phase(), PhaseTag::Idle);
    assert_eq!(model.provider_dispatch_count(), 0);
    assert_eq!(model.release_count(), 0);

    for (profile, plan) in [
        (AnchorProfile::None, None),
        (AnchorProfile::PerTransitionDigest, Some(anchor_plan(42))),
    ] {
        let mut parts = BindingParts::baseline(CommandKind::Deterministic, profile);
        parts.prior_version = u64::MAX - 2;
        parts.reserved_version = u64::MAX - 1;
        let mut model = TransitionModel::new(
            protocol_scope(profile),
            baseline_session_identity(),
            baseline_context(),
            StateVersion::new(u64::MAX - 2),
            StateDigest::from_bytes(bytes(6)),
            FenceToken::new(11),
            CommandOrdinal::new(9),
        );
        let reservation = model
            .prepare(
                OperationDraft::new(OperationId::from_bytes(bytes(12)), parts.binding()),
                RecordCommitment::from_bytes(bytes(13)),
            )
            .expect("near-overflow reservation");
        apply_persist(&mut model, reservation);
        let command = model
            .dispatch()
            .expect("near-overflow dispatch")
            .crypto_command()
            .expect("near-overflow command");
        model
            .provider_completion(CryptoCompletion::Succeeded(exact_result(command, 20)))
            .expect("near-overflow provider result");
        let pin = model
            .pin_result(ResultPinPlan::new(
                RecordCommitment::from_bytes(bytes(21)),
                StateDigest::from_bytes(bytes(22)),
            ))
            .expect("near-overflow result pin");
        apply_persist(&mut model, pin);
        assert_eq!(model.state_version(), StateVersion::new(u64::MAX));
        let before = model.clone();
        assert_eq!(
            model.begin_finalize(
                RecordCommitment::from_bytes(bytes(40)),
                StateDigest::from_bytes(bytes(41)),
                plan,
            ),
            Err(LifecycleError::CounterOverflow)
        );
        assert_eq!(model, before);
    }
}
