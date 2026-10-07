//! Emit deterministic bytes for the independent Python correspondence test.

use q_periapt_continuity_model::{
    AccountId, AuthenticationStage, BootstrapContext, ClassicalPrekeySelection, CommonContext,
    ContextDigest, ContextParty, ContextProtocol, ContextRoles, DeviceEpoch, DeviceId, Direction,
    DirectoryCheckpointDigest, DirectoryContext, IdentityCredentialDigest, IdentityMode,
    LifecycleContextV1, PolicyDigest, PostQuantumPrekeySelection, PrekeyBundleEpoch, PrekeyId,
    PrekeyResponder, PrekeySelectionV1, ProtocolId, RatchetEpoch, RootEpochs,
    RootTransitionContext, RootTransitionKind, RosterDigest, RosterVersion, SessionId,
    SignedPrekeyManifestDigest, SuiteDigest, TranscriptDigest, WireVersion,
    BOOTSTRAP_DIGEST_PREIMAGE_LEN, BOOTSTRAP_POLICY_BOUND_KCTX_LEN,
    ROOT_TRANSITION_DIGEST_PREIMAGE_LEN, ROOT_TRANSITION_POLICY_BOUND_KCTX_LEN,
};

fn bytes<const N: usize>(tag: u8) -> [u8; N] {
    [tag; N]
}

const BOOTSTRAP_PREKEY_SELECTION_DIGEST: [u8; 32] = [
    0xcf, 0xcf, 0x62, 0x89, 0x4f, 0x82, 0x66, 0xd6, 0x44, 0x44, 0xa4, 0xdc, 0x09, 0x60, 0x62, 0xed,
    0x6e, 0x24, 0xce, 0xf9, 0x09, 0x07, 0x9e, 0x38, 0x5e, 0x67, 0x44, 0x9c, 0xb0, 0xe2, 0xb4, 0xa1,
];

fn party(account: u8, device: u8, epoch: u64, credential: u8) -> ContextParty {
    ContextParty::new(
        AccountId::from_bytes(bytes(account)),
        DeviceId::from_bytes(bytes(device)),
        DeviceEpoch::new(epoch),
        IdentityCredentialDigest::from_bytes(bytes(credential)),
    )
}

fn common(stage: AuthenticationStage, direction: Direction) -> CommonContext {
    CommonContext::new(
        ContextProtocol::new(
            ProtocolId::from_bytes(bytes(1)),
            WireVersion::new(1),
            SuiteDigest::from_bytes(bytes(2)),
            SessionId::from_bytes(bytes(3)),
        ),
        ContextRoles::new(
            party(4, 5, 6, 7),
            party(8, 9, 10, 11),
            IdentityMode::Accountable,
            direction,
            stage,
        ),
    )
}

fn bootstrap() -> LifecycleContextV1 {
    let prekey = PrekeySelectionV1::new(
        SuiteDigest::from_bytes(bytes(2)),
        PrekeyResponder::new(
            AccountId::from_bytes(bytes(8)),
            DeviceId::from_bytes(bytes(9)),
            DeviceEpoch::new(10),
            IdentityCredentialDigest::from_bytes(bytes(11)),
        ),
        PrekeyBundleEpoch::new(30),
        DirectoryCheckpointDigest::from_bytes(bytes(14)),
        SignedPrekeyManifestDigest::from_bytes(bytes(15)),
        ClassicalPrekeySelection::one_time(
            PrekeyId::from_bytes(bytes(31)),
            PrekeyId::from_bytes(bytes(32)),
        )
        .expect("valid classical selection"),
        PostQuantumPrekeySelection::one_time(
            PrekeyId::from_bytes(bytes(33)),
            PrekeyId::from_bytes(bytes(34)),
        )
        .expect("valid PQ selection"),
    )
    .expect("valid prekey record")
    .derive_with(|_| Ok::<_, ()>(BOOTSTRAP_PREKEY_SELECTION_DIGEST))
    .expect("valid prekey digest");
    LifecycleContextV1::Bootstrap(
        BootstrapContext::new(
            common(
                AuthenticationStage::PrekeyAuthenticated,
                Direction::InitiatorToResponder,
            ),
            DirectoryContext::new(
                RosterVersion::new(12),
                RosterDigest::from_bytes(bytes(13)),
                DirectoryCheckpointDigest::from_bytes(bytes(14)),
            ),
            prekey,
            TranscriptDigest::from_bytes(bytes(17)),
        )
        .expect("matching bootstrap prekey scope"),
    )
}

fn root() -> LifecycleContextV1 {
    LifecycleContextV1::RootTransition(RootTransitionContext::new(
        common(
            AuthenticationStage::MutuallyConfirmed,
            Direction::ResponderToInitiator,
        ),
        RootTransitionKind::Hybrid,
        ContextDigest::from_bytes(bytes(18)),
        RootEpochs::new(
            (RatchetEpoch::new(20), RatchetEpoch::new(21)),
            (RatchetEpoch::new(30), RatchetEpoch::new(31)),
            (RatchetEpoch::new(40), RatchetEpoch::new(41)),
        ),
        TranscriptDigest::from_bytes(bytes(17)),
    ))
}

fn print_hex(label: &str, value: &[u8]) {
    print!("{label}=");
    for byte in value {
        print!("{byte:02x}");
    }
    println!();
}

fn emit(
    name: &str,
    context: LifecycleContextV1,
    policy_out: &mut [u8],
    digest_out: &mut [u8],
) -> bool {
    let policy = PolicyDigest::from_bytes(bytes(19));
    if context
        .encode_policy_bound_kctx(policy, policy_out)
        .is_err()
        || context.encode_digest_preimage(policy, digest_out).is_err()
    {
        return false;
    }
    print_hex(&format!("{name}.policy_bound_kctx"), policy_out);
    print_hex(&format!("{name}.digest_preimage"), digest_out);
    true
}

fn main() {
    let mut bootstrap_policy = [0u8; BOOTSTRAP_POLICY_BOUND_KCTX_LEN];
    let mut bootstrap_digest = [0u8; BOOTSTRAP_DIGEST_PREIMAGE_LEN];
    let mut root_policy = [0u8; ROOT_TRANSITION_POLICY_BOUND_KCTX_LEN];
    let mut root_digest = [0u8; ROOT_TRANSITION_DIGEST_PREIMAGE_LEN];
    if !emit(
        "bootstrap-accountable-one-time",
        bootstrap(),
        &mut bootstrap_policy,
        &mut bootstrap_digest,
    ) || !emit(
        "root-hybrid-mutually-confirmed",
        root(),
        &mut root_policy,
        &mut root_digest,
    ) {
        std::process::exit(1);
    }
}
