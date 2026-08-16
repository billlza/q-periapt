//! Authenticated Migration Contract V2 state, negotiation, transcript, and confirmation tests.

use q_periapt_backends::{MlDsa65, Sha3_256Xof, ML_DSA_65_SIG_LEN};
use q_periapt_core::{Error as CoreError, Secret, ZeroizingBytes};
use q_periapt_migration::{
    Abi2MigrationApplicationContextV2, AuthenticatedCapabilityOfferV1,
    AuthenticatedMigrationContextV2Input, AuthenticatedNegotiationInputV1,
    AuthenticatedNegotiationV1, CapabilityError, CapabilityOfferInputV1, CapabilityOfferV1,
    ComponentMode, ConfirmationError, EndpointKeyShareV1, EndpointRole, InitiatorConfirmationV1,
    InitiatorFinishedV1, MigrationAuthorityKeyId, MigrationChainId, MigrationContextV2,
    MigrationContractError, MigrationIdentityKeyId, MigrationNonce, MigrationProtocolId,
    MigrationResetNonce, MigrationResetV1, MigrationSecurityPosture, MigrationSessionId,
    MigrationStateDigest, MigrationStateDraftV1, MigrationStateError, MigrationStateMachineV1,
    MigrationStateV1, MigrationSuiteSet, PostKemTranscriptV1, PreKemTranscriptV1,
    ResponderAwaitingInitiatorFinishedV1, ResponderFinishedV1, SecurityFloor,
    SignedCapabilityOfferV1, SignedMigrationResetV1, SignedMigrationStateV1, StateCertificateKind,
    TranscriptError, UninitializedMigrationStateV1, MIGRATION_CONTEXT_V2_ENCODED_LEN,
};
use q_periapt_policy::{AuthenticatedPolicy, AuthenticatedResolvedSuite, HybridSuite, Policy};
use q_periapt_sig::{SigAlg, Signer, Verifier};
use sha3::{Digest, Sha3_256};

const PROTOCOL: MigrationProtocolId = MigrationProtocolId::from_bytes([0x10; 16]);
const CHAIN: MigrationChainId = MigrationChainId::from_bytes([0x20; 32]);
const AUTHORITY: MigrationAuthorityKeyId = MigrationAuthorityKeyId::from_bytes([0x30; 32]);
const RECOVERY: MigrationAuthorityKeyId = MigrationAuthorityKeyId::from_bytes([0x31; 32]);
const INITIATOR_ID: MigrationIdentityKeyId = MigrationIdentityKeyId::from_bytes([0x40; 32]);
const RESPONDER_ID: MigrationIdentityKeyId = MigrationIdentityKeyId::from_bytes([0x41; 32]);
const AUTHORITY_KEY: &[u8] = b"authority-test-key";
const RECOVERY_KEY: &[u8] = b"recovery-test-key";
const INITIATOR_KEY: &[u8] = b"initiator-identity-key";
const RESPONDER_KEY: &[u8] = b"responder-identity-key";

#[derive(Clone, Copy)]
struct TestSignature(SigAlg);

impl Signer for TestSignature {
    fn algorithm(&self) -> SigAlg {
        self.0
    }

    fn sign(
        &self,
        sk: &[u8],
        msg: &[u8],
        _randomness: &[u8],
        out_sig: &mut [u8],
    ) -> Result<usize, CoreError> {
        let signature = test_signature(sk, msg);
        let output = out_sig
            .get_mut(..signature.len())
            .ok_or(CoreError::InvalidLength)?;
        output.copy_from_slice(&signature);
        Ok(signature.len())
    }
}

impl Verifier for TestSignature {
    fn algorithm(&self) -> SigAlg {
        self.0
    }

    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CoreError> {
        if sig == test_signature(pk, msg) {
            Ok(())
        } else {
            Err(CoreError::Backend)
        }
    }
}

struct AcceptingVerifier(SigAlg);

impl Verifier for AcceptingVerifier {
    fn algorithm(&self) -> SigAlg {
        self.0
    }

    fn verify(&self, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<(), CoreError> {
        Ok(())
    }
}

fn test_signature(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut digest = Sha3_256::new();
    digest.update((key.len() as u64).to_be_bytes());
    digest.update(key);
    digest.update((message.len() as u64).to_be_bytes());
    digest.update(message);
    digest.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vector_string<'a>(vector: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    vector
        .get("expected")
        .and_then(|expected| expected.get(name))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("V2 vector lacks expected.{name}"))
}

fn sign_test_state(
    kind: StateCertificateKind,
    state: MigrationStateV1,
    key: &[u8],
    algorithm: SigAlg,
) -> Result<SignedMigrationStateV1, String> {
    let mut signature = [0u8; 32];
    SignedMigrationStateV1::sign(
        kind,
        state,
        &TestSignature(algorithm),
        key,
        &[0u8; 32],
        &mut signature,
    )
    .map_err(|error| error.to_string())
}

fn sign_test_reset(reset: MigrationResetV1) -> Result<SignedMigrationResetV1, String> {
    let mut signature = [0u8; 32];
    SignedMigrationResetV1::sign(
        reset,
        &TestSignature(SigAlg::MlDsa65),
        RECOVERY_KEY,
        &[0u8; 32],
        &mut signature,
    )
    .map_err(|error| error.to_string())
}

fn policy(
    version: u32,
    floor: u8,
    profile: &str,
    pq_kem: &str,
    signature: &str,
    verifier: SigAlg,
) -> Result<AuthenticatedPolicy, String> {
    let text = format!(
        "schema_version = 1\n\
         policy_version = {version}\n\
         min_nist_level = {floor}\n\
         default_profile = \"{profile}\"\n\
         allowed_kems = [\"{pq_kem}\", \"X25519\"]\n\
         allowed_sigs = [\"{signature}\"]\n\
         deprecated = []\n"
    );
    Policy::load_signed(
        &AcceptingVerifier(verifier),
        b"policy-key",
        text.as_bytes(),
        b"policy-signature",
    )
    .map_err(|error| error.to_string())
}

fn execution(
    policy: &AuthenticatedPolicy,
    suite: HybridSuite,
) -> Result<AuthenticatedResolvedSuite, String> {
    policy
        .resolve_suite(core::slice::from_ref(&suite))
        .map_err(|error| error.to_string())
}

fn suite_set(suite: HybridSuite) -> Result<MigrationSuiteSet, String> {
    MigrationSuiteSet::from_suites(core::slice::from_ref(&suite)).map_err(|error| error.to_string())
}

fn genesis_owner(
    execution: AuthenticatedResolvedSuite,
    floor: SecurityFloor,
    mode: ComponentMode,
    suites: MigrationSuiteSet,
) -> Result<MigrationStateMachineV1, String> {
    let state = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 1,
        chain_id: CHAIN,
        protocol_id: PROTOCOL,
        epoch: 1,
        previous_state_digest: MigrationStateDigest::from_bytes([0u8; 32]),
        authority_key_id: AUTHORITY,
        execution_policy_state: execution.trusted_state(),
        posture: MigrationSecurityPosture::new(floor, mode),
        allowed_suites: suites,
    })
    .map_err(|error| error.to_string())?;
    let signature = TestSignature(match floor {
        SecurityFloor::Level5 => SigAlg::MlDsa87,
        SecurityFloor::Level1 | SecurityFloor::Level2 | SecurityFloor::Level3 => SigAlg::MlDsa65,
    });
    let certificate = sign_test_state(
        StateCertificateKind::Genesis,
        state,
        AUTHORITY_KEY,
        signature.0,
    )?;
    UninitializedMigrationStateV1
        .verify_genesis(&certificate, &signature, AUTHORITY_KEY, AUTHORITY)
        .map_err(|error| error.to_string())?
        .commit()
        .map_err(|error| error.to_string())
}

fn key_shares() -> Result<(EndpointKeyShareV1, EndpointKeyShareV1), String> {
    Ok((
        EndpointKeyShareV1::new(&[0x51; 64], &[0x52; 32]).map_err(|error| error.to_string())?,
        EndpointKeyShareV1::new(&[0x61; 64], &[0x62; 32]).map_err(|error| error.to_string())?,
    ))
}

struct TestSignedOfferInput<'a> {
    offer: CapabilityOfferInputV1<'a>,
    identity_key: &'a [u8],
    signer: TestSignature,
}

fn signed_offer(
    input: TestSignedOfferInput<'_>,
) -> Result<(SignedCapabilityOfferV1, AuthenticatedCapabilityOfferV1), String> {
    let sender_identity = input.offer.sender_identity;
    let offer = CapabilityOfferV1::from_authenticated_state(input.offer)
        .map_err(|error| error.to_string())?;
    let mut signature = [0u8; 32];
    let signed = SignedCapabilityOfferV1::sign(
        offer,
        &input.signer,
        input.identity_key,
        &[0u8; 32],
        &mut signature,
    )
    .map_err(|error| error.to_string())?;
    let authenticated = signed
        .authenticate(&input.signer, input.identity_key, sender_identity)
        .map_err(|error| error.to_string())?;
    Ok((signed, authenticated))
}

struct ContractFixture {
    initiator_policy: AuthenticatedPolicy,
    responder_policy: AuthenticatedPolicy,
    execution: AuthenticatedResolvedSuite,
    owner: MigrationStateMachineV1,
    initiator_offer: AuthenticatedCapabilityOfferV1,
    responder_offer: AuthenticatedCapabilityOfferV1,
    negotiation: AuthenticatedNegotiationV1,
    initiator_keys: EndpointKeyShareV1,
    responder_keys: EndpointKeyShareV1,
    pre_kem: PreKemTranscriptV1,
    context: MigrationContextV2,
}

fn fixture(session: u8) -> Result<ContractFixture, String> {
    let initiator_policy = policy(
        1,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let responder_policy = policy(
        2,
        2,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let execution = execution(&initiator_policy, HybridSuite::MlKem768X25519)?;
    let suites = suite_set(HybridSuite::MlKem768X25519)?;
    let owner = genesis_owner(
        execution,
        SecurityFloor::Level3,
        ComponentMode::HybridRequired,
        suites,
    )?;
    let (initiator_keys, responder_keys) = key_shares()?;
    let (_, initiator_offer) = signed_offer(TestSignedOfferInput {
        offer: CapabilityOfferInputV1 {
            protocol_id: PROTOCOL,
            session_id: MigrationSessionId::from_bytes([session; 32]),
            sender_role: EndpointRole::Initiator,
            sender_identity: INITIATOR_ID,
            receiver_identity: RESPONDER_ID,
            sender_nonce: MigrationNonce::from_bytes([0x71; 32]),
            sender_policy: &initiator_policy,
            committed_state: owner.current(),
            offered_suites: suites,
            sender_key_share: &initiator_keys,
        },
        identity_key: INITIATOR_KEY,
        signer: TestSignature(SigAlg::MlDsa65),
    })?;
    let (_, responder_offer) = signed_offer(TestSignedOfferInput {
        offer: CapabilityOfferInputV1 {
            protocol_id: PROTOCOL,
            session_id: MigrationSessionId::from_bytes([session; 32]),
            sender_role: EndpointRole::Responder,
            sender_identity: RESPONDER_ID,
            receiver_identity: INITIATOR_ID,
            sender_nonce: MigrationNonce::from_bytes([0x72; 32]),
            sender_policy: &responder_policy,
            committed_state: owner.current(),
            offered_suites: suites,
            sender_key_share: &responder_keys,
        },
        identity_key: RESPONDER_KEY,
        signer: TestSignature(SigAlg::MlDsa65),
    })?;
    let negotiation =
        AuthenticatedNegotiationV1::from_local_peer(AuthenticatedNegotiationInputV1 {
            local_role: EndpointRole::Initiator,
            local_offer: initiator_offer,
            peer_offer: responder_offer,
            local_policy: &initiator_policy,
            peer_policy: &responder_policy,
            committed_state: owner.current(),
            execution,
        })
        .map_err(|error| error.to_string())?;
    let pre_kem = PreKemTranscriptV1::from_authenticated_contract(
        negotiation,
        owner.current(),
        execution,
        EndpointRole::Initiator,
        responder_keys.clone(),
    )
    .map_err(|error| error.to_string())?;
    let context =
        MigrationContextV2::from_authenticated_contract(AuthenticatedMigrationContextV2Input {
            local_role: EndpointRole::Initiator,
            encapsulator_role: EndpointRole::Initiator,
            execution,
            local_policy: &initiator_policy,
            peer_policy: &responder_policy,
            committed_state: owner.current(),
            negotiation,
            pre_kem: &pre_kem,
        })
        .map_err(|error| error.to_string())?;
    Ok(ContractFixture {
        initiator_policy,
        responder_policy,
        execution,
        owner,
        initiator_offer,
        responder_offer,
        negotiation,
        initiator_keys,
        responder_keys,
        pre_kem,
        context,
    })
}

fn responder_context(fixture: &ContractFixture) -> Result<MigrationContextV2, String> {
    MigrationContextV2::from_authenticated_contract(AuthenticatedMigrationContextV2Input {
        local_role: EndpointRole::Responder,
        encapsulator_role: fixture.context.encapsulator_role(),
        execution: fixture.execution,
        local_policy: &fixture.responder_policy,
        peer_policy: &fixture.initiator_policy,
        committed_state: fixture.owner.current(),
        negotiation: fixture.negotiation,
        pre_kem: &fixture.pre_kem,
    })
    .map_err(|error| error.to_string())
}

#[test]
fn v2_role_views_produce_one_exact_thirteen_field_context() -> Result<(), String> {
    let fixture = fixture(0x70)?;
    let responder_view = responder_context(&fixture)?;
    let initiator_bytes = fixture
        .context
        .encode()
        .map_err(|error| error.to_string())?;
    let responder_bytes = responder_view.encode().map_err(|error| error.to_string())?;
    assert_eq!(initiator_bytes, responder_bytes);
    assert_eq!(initiator_bytes.len(), MIGRATION_CONTEXT_V2_ENCODED_LEN);

    let mut remaining = initiator_bytes.as_slice();
    let mut fields = 0usize;
    while !remaining.is_empty() {
        let length_bytes: [u8; 8] = remaining
            .get(..8)
            .ok_or_else(|| "truncated V2 length".to_owned())?
            .try_into()
            .map_err(|_| "invalid V2 length".to_owned())?;
        let length = usize::try_from(u64::from_be_bytes(length_bytes))
            .map_err(|_| "V2 field length overflow".to_owned())?;
        remaining = remaining
            .get(8 + length..)
            .ok_or_else(|| "truncated V2 field".to_owned())?;
        fields += 1;
    }
    assert_eq!(fields, 13);
    let state_body = fixture
        .owner
        .current()
        .state()
        .encode()
        .map_err(|error| error.to_string())?;
    let initiator_offer_body = fixture
        .initiator_offer
        .canonical_body()
        .map_err(|error| error.to_string())?;
    let responder_offer_body = fixture
        .responder_offer
        .canonical_body()
        .map_err(|error| error.to_string())?;
    let post = PostKemTranscriptV1::from_context(&fixture.context, &[0xC1; 64], &[0xC2; 32])
        .map_err(|error| error.to_string())?;
    let initiator = InitiatorConfirmationV1::<Sha3_256Xof>::new(
        Secret::from_bytes([0xC3; 32]),
        &fixture.context,
        &post,
    )
    .map_err(|error| error.to_string())?;
    let responder = ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
        Secret::from_bytes([0xC3; 32]),
        &responder_view,
        &post,
    )
    .map_err(|error| error.to_string())?;
    let (initiator, initiator_finished) = initiator.issue_finished();
    let (responder_accepted, responder_finished) = responder
        .verify_accept_and_issue_finished(&fixture.owner, &initiator_finished)
        .map_err(|error| error.to_string())?;
    let accepted = initiator
        .verify_and_accept(&fixture.owner, &responder_finished)
        .map_err(|error| error.to_string())?;
    assert_eq!(
        accepted.secret().as_bytes(),
        responder_accepted.secret().as_bytes()
    );
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/migration-contract-v2.json"))
            .map_err(|error| error.to_string())?;
    let actual = [
        ("state_body_hex", hex(&state_body)),
        ("initiator_offer_body_hex", hex(&initiator_offer_body)),
        ("responder_offer_body_hex", hex(&responder_offer_body)),
        (
            "state_digest",
            hex(fixture.owner.current_revision().digest().as_bytes()),
        ),
        (
            "negotiation_digest",
            hex(fixture.negotiation.digest().as_bytes()),
        ),
        ("pre_kem_hex", hex(fixture.pre_kem.as_bytes())),
        ("pre_kem_digest", hex(fixture.pre_kem.digest().as_bytes())),
        ("context_hex", hex(&initiator_bytes)),
        (
            "context_digest",
            hex(fixture
                .context
                .digest()
                .map_err(|error| error.to_string())?
                .as_bytes()),
        ),
        ("post_kem_digest", hex(post.digest().as_bytes())),
        ("initiator_finished", hex(initiator_finished.as_bytes())),
        ("responder_finished", hex(responder_finished.as_bytes())),
        ("accepted_key", hex(accepted.secret().as_bytes())),
    ];
    for (name, value) in actual {
        assert_eq!(value, vector_string(&vector, name)?, "V2 vector {name}");
    }
    Ok(())
}

#[test]
fn signed_offer_decoder_and_signature_fail_closed() -> Result<(), String> {
    let fixture = fixture(0x73)?;
    let suites = suite_set(HybridSuite::MlKem768X25519)?;
    let (signed, _) = signed_offer(TestSignedOfferInput {
        offer: CapabilityOfferInputV1 {
            protocol_id: PROTOCOL,
            session_id: MigrationSessionId::from_bytes([0x74; 32]),
            sender_role: EndpointRole::Initiator,
            sender_identity: INITIATOR_ID,
            receiver_identity: RESPONDER_ID,
            sender_nonce: MigrationNonce::from_bytes([0x75; 32]),
            sender_policy: &fixture.initiator_policy,
            committed_state: fixture.owner.current(),
            offered_suites: suites,
            sender_key_share: &fixture.initiator_keys,
        },
        identity_key: INITIATOR_KEY,
        signer: TestSignature(SigAlg::MlDsa65),
    })?;
    let encoded = signed.encode().map_err(|error| error.to_string())?;
    let decoded = SignedCapabilityOfferV1::decode(&encoded).map_err(|error| error.to_string())?;
    decoded
        .authenticate(&TestSignature(SigAlg::MlDsa65), INITIATOR_KEY, INITIATOR_ID)
        .map_err(|error| error.to_string())?;

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        SignedCapabilityOfferV1::decode(&trailing),
        Err(CapabilityError::InvalidEncoding)
    );
    let mut mutated = encoded;
    let last = mutated
        .last_mut()
        .ok_or_else(|| "signed offer unexpectedly empty".to_owned())?;
    *last ^= 1;
    let decoded = SignedCapabilityOfferV1::decode(&mutated).map_err(|error| error.to_string())?;
    assert_eq!(
        decoded.authenticate(&TestSignature(SigAlg::MlDsa65), INITIATOR_KEY, INITIATOR_ID,),
        Err(CapabilityError::SignatureFailure)
    );
    Ok(())
}

#[test]
fn real_ml_dsa_65_authenticates_state_reset_and_capability_bytes() -> Result<(), String> {
    let endpoint_policy = policy(
        1,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let execution = execution(&endpoint_policy, HybridSuite::MlKem768X25519)?;
    let suites = suite_set(HybridSuite::MlKem768X25519)?;
    let (secret_key, verification_key) = MlDsa65::generate([0x33; 32]);
    let secret_key = ZeroizingBytes::from_bytes(secret_key);
    let state = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 1,
        chain_id: CHAIN,
        protocol_id: PROTOCOL,
        epoch: 1,
        previous_state_digest: MigrationStateDigest::from_bytes([0u8; 32]),
        authority_key_id: AUTHORITY,
        execution_policy_state: execution.trusted_state(),
        posture: MigrationSecurityPosture::new(
            SecurityFloor::Level3,
            ComponentMode::HybridRequired,
        ),
        allowed_suites: suites,
    })
    .map_err(|error| error.to_string())?;
    let mut state_signature = [0u8; ML_DSA_65_SIG_LEN];
    let certificate = SignedMigrationStateV1::sign(
        StateCertificateKind::Genesis,
        state,
        &MlDsa65,
        secret_key.as_bytes(),
        &[0x44; 32],
        &mut state_signature,
    )
    .map_err(|error| error.to_string())?;
    let mut owner = UninitializedMigrationStateV1
        .verify_genesis(&certificate, &MlDsa65, &verification_key, AUTHORITY)
        .map_err(|error| error.to_string())?
        .commit()
        .map_err(|error| error.to_string())?;

    let endpoint_keys =
        EndpointKeyShareV1::new(&[0x45; 64], &[0x46; 32]).map_err(|error| error.to_string())?;
    let offer = CapabilityOfferV1::from_authenticated_state(CapabilityOfferInputV1 {
        protocol_id: PROTOCOL,
        session_id: MigrationSessionId::from_bytes([0x47; 32]),
        sender_role: EndpointRole::Initiator,
        sender_identity: INITIATOR_ID,
        receiver_identity: RESPONDER_ID,
        sender_nonce: MigrationNonce::from_bytes([0x48; 32]),
        sender_policy: &endpoint_policy,
        committed_state: owner.current(),
        offered_suites: suites,
        sender_key_share: &endpoint_keys,
    })
    .map_err(|error| error.to_string())?;
    let mut offer_signature = [0u8; ML_DSA_65_SIG_LEN];
    let signed = SignedCapabilityOfferV1::sign(
        offer,
        &MlDsa65,
        secret_key.as_bytes(),
        &[0x49; 32],
        &mut offer_signature,
    )
    .map_err(|error| error.to_string())?;
    signed
        .authenticate(&MlDsa65, &verification_key, INITIATOR_ID)
        .map_err(|error| error.to_string())?;

    let (recovery_secret_key, recovery_verification_key) = MlDsa65::generate([0x4A; 32]);
    let recovery_secret_key = ZeroizingBytes::from_bytes(recovery_secret_key);
    let reset_state = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: MigrationChainId::from_bytes([0x4B; 32]),
        protocol_id: PROTOCOL,
        epoch: 1,
        previous_state_digest: owner.current_revision().digest(),
        authority_key_id: AUTHORITY,
        execution_policy_state: execution.trusted_state(),
        posture: MigrationSecurityPosture::new(
            SecurityFloor::Level3,
            ComponentMode::HybridRequired,
        ),
        allowed_suites: suites,
    })
    .map_err(|error| error.to_string())?;
    let reset = MigrationResetV1::new(
        owner.current_revision(),
        reset_state,
        MigrationResetNonce::from_bytes([0x4C; 32]),
        RECOVERY,
    );
    let mut reset_signature = [0u8; ML_DSA_65_SIG_LEN];
    let signed_reset = SignedMigrationResetV1::sign(
        reset,
        &MlDsa65,
        recovery_secret_key.as_bytes(),
        &[0x4D; 32],
        &mut reset_signature,
    )
    .map_err(|error| error.to_string())?;
    let encoded_reset = signed_reset.encode().map_err(|error| error.to_string())?;
    let decoded_reset =
        SignedMigrationResetV1::decode(&encoded_reset).map_err(|error| error.to_string())?;
    let pending_reset = owner
        .prepare_reset(
            &decoded_reset,
            &MlDsa65,
            &recovery_verification_key,
            RECOVERY,
        )
        .map_err(|error| error.to_string())?;
    owner
        .commit(pending_reset)
        .map_err(|error| error.to_string())?;
    assert_eq!(owner.current_revision().global_generation(), 2);
    assert_eq!(owner.current_revision().epoch(), 1);
    Ok(())
}

#[test]
fn signing_helpers_require_an_exact_fully_written_output() -> Result<(), String> {
    let fixture = fixture(0x4E)?;
    let current = fixture.owner.current();
    let signer = TestSignature(SigAlg::MlDsa65);
    let mut oversized_output = [0u8; 33];
    assert_eq!(
        SignedMigrationStateV1::sign(
            StateCertificateKind::Genesis,
            current.state(),
            &signer,
            AUTHORITY_KEY,
            &[0u8; 32],
            &mut oversized_output,
        ),
        Err(MigrationStateError::InvalidSignatureLength)
    );
    let reset = MigrationResetV1::new(
        current.revision(),
        current.state(),
        MigrationResetNonce::from_bytes([0x4F; 32]),
        RECOVERY,
    );
    assert_eq!(
        SignedMigrationResetV1::sign(
            reset,
            &signer,
            RECOVERY_KEY,
            &[0u8; 32],
            &mut oversized_output,
        ),
        Err(MigrationStateError::InvalidSignatureLength)
    );
    let offer = CapabilityOfferV1::decode(
        &fixture
            .initiator_offer
            .canonical_body()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    assert_eq!(
        SignedCapabilityOfferV1::sign(
            offer,
            &signer,
            INITIATOR_KEY,
            &[0u8; 32],
            &mut oversized_output,
        ),
        Err(CapabilityError::InvalidSignatureLength)
    );
    Ok(())
}

#[test]
fn key_share_direction_and_negotiation_graft_are_rejected() -> Result<(), String> {
    let first = fixture(0x76)?;
    assert_eq!(
        PreKemTranscriptV1::from_authenticated_contract(
            first.negotiation,
            first.owner.current(),
            first.execution,
            EndpointRole::Initiator,
            first.initiator_keys.clone(),
        ),
        Err(TranscriptError::KeyShareMismatch)
    );
    PreKemTranscriptV1::from_authenticated_contract(
        first.negotiation,
        first.owner.current(),
        first.execution,
        EndpointRole::Responder,
        first.initiator_keys.clone(),
    )
    .map_err(|error| error.to_string())?;

    let second = fixture(0x77)?;
    assert_eq!(
        MigrationContextV2::from_authenticated_contract(AuthenticatedMigrationContextV2Input {
            local_role: EndpointRole::Initiator,
            encapsulator_role: EndpointRole::Initiator,
            execution: second.execution,
            local_policy: &second.initiator_policy,
            peer_policy: &second.responder_policy,
            committed_state: second.owner.current(),
            negotiation: second.negotiation,
            pre_kem: &first.pre_kem,
        },),
        Err(MigrationContractError::SnapshotMismatch)
    );
    Ok(())
}

#[test]
fn endpoint_policy_must_really_authorize_context_bound_execution() -> Result<(), String> {
    let fixture = fixture(0x78)?;
    let denied = policy(
        9,
        3,
        "ContextBound",
        "ML-KEM-1024",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let suites = suite_set(HybridSuite::MlKem768X25519)?;
    let (_, denied_offer) = signed_offer(TestSignedOfferInput {
        offer: CapabilityOfferInputV1 {
            protocol_id: PROTOCOL,
            session_id: MigrationSessionId::from_bytes([0x78; 32]),
            sender_role: EndpointRole::Responder,
            sender_identity: RESPONDER_ID,
            receiver_identity: INITIATOR_ID,
            sender_nonce: MigrationNonce::from_bytes([0x79; 32]),
            sender_policy: &denied,
            committed_state: fixture.owner.current(),
            offered_suites: suites,
            sender_key_share: &fixture.responder_keys,
        },
        identity_key: RESPONDER_KEY,
        signer: TestSignature(SigAlg::MlDsa65),
    })?;
    assert_eq!(
        AuthenticatedNegotiationV1::from_local_peer(AuthenticatedNegotiationInputV1 {
            local_role: EndpointRole::Initiator,
            local_offer: fixture.initiator_offer,
            peer_offer: denied_offer,
            local_policy: &fixture.initiator_policy,
            peer_policy: &denied,
            committed_state: fixture.owner.current(),
            execution: fixture.execution,
        },),
        Err(CapabilityError::EndpointPolicyRejected)
    );

    let compat = policy(
        10,
        3,
        "CompatXWing",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let (_, compat_offer) = signed_offer(TestSignedOfferInput {
        offer: CapabilityOfferInputV1 {
            protocol_id: PROTOCOL,
            session_id: MigrationSessionId::from_bytes([0x78; 32]),
            sender_role: EndpointRole::Responder,
            sender_identity: RESPONDER_ID,
            receiver_identity: INITIATOR_ID,
            sender_nonce: MigrationNonce::from_bytes([0x7A; 32]),
            sender_policy: &compat,
            committed_state: fixture.owner.current(),
            offered_suites: suites,
            sender_key_share: &fixture.responder_keys,
        },
        identity_key: RESPONDER_KEY,
        signer: TestSignature(SigAlg::MlDsa65),
    })?;
    assert_eq!(
        AuthenticatedNegotiationV1::from_local_peer(AuthenticatedNegotiationInputV1 {
            local_role: EndpointRole::Initiator,
            local_offer: fixture.initiator_offer,
            peer_offer: compat_offer,
            local_policy: &fixture.initiator_policy,
            peer_policy: &compat,
            committed_state: fixture.owner.current(),
            execution: fixture.execution,
        },),
        Err(CapabilityError::EndpointPolicyRejected)
    );
    Ok(())
}

#[test]
fn capability_signer_floor_and_reflection_inputs_fail_closed() -> Result<(), String> {
    let level_five_policy = policy(
        1,
        5,
        "ContextBound",
        "ML-KEM-1024",
        "ML-DSA-87",
        SigAlg::MlDsa87,
    )?;
    let level_five_execution = execution(&level_five_policy, HybridSuite::MlKem1024X25519)?;
    let level_five_suites = suite_set(HybridSuite::MlKem1024X25519)?;
    let level_five_owner = genesis_owner(
        level_five_execution,
        SecurityFloor::Level5,
        ComponentMode::HybridRequired,
        level_five_suites,
    )?;
    let (endpoint_keys, _) = key_shares()?;
    let offer = CapabilityOfferV1::from_authenticated_state(CapabilityOfferInputV1 {
        protocol_id: PROTOCOL,
        session_id: MigrationSessionId::from_bytes([0xD0; 32]),
        sender_role: EndpointRole::Initiator,
        sender_identity: INITIATOR_ID,
        receiver_identity: RESPONDER_ID,
        sender_nonce: MigrationNonce::from_bytes([0xD1; 32]),
        sender_policy: &level_five_policy,
        committed_state: level_five_owner.current(),
        offered_suites: level_five_suites,
        sender_key_share: &endpoint_keys,
    })
    .map_err(|error| error.to_string())?;
    let mut weak_signature = [0u8; 32];
    let weakly_signed = SignedCapabilityOfferV1::sign(
        offer,
        &TestSignature(SigAlg::MlDsa65),
        INITIATOR_KEY,
        &[0u8; 32],
        &mut weak_signature,
    )
    .map_err(|error| error.to_string())?;
    assert_eq!(
        weakly_signed.authenticate(&TestSignature(SigAlg::MlDsa65), INITIATOR_KEY, INITIATOR_ID,),
        Err(CapabilityError::WeakSigner)
    );

    let fixture = fixture(0xD2)?;
    let suites = suite_set(HybridSuite::MlKem768X25519)?;
    let (_, reflected_nonce_offer) = signed_offer(TestSignedOfferInput {
        offer: CapabilityOfferInputV1 {
            protocol_id: PROTOCOL,
            session_id: MigrationSessionId::from_bytes([0xD2; 32]),
            sender_role: EndpointRole::Responder,
            sender_identity: RESPONDER_ID,
            receiver_identity: INITIATOR_ID,
            sender_nonce: MigrationNonce::from_bytes([0x71; 32]),
            sender_policy: &fixture.responder_policy,
            committed_state: fixture.owner.current(),
            offered_suites: suites,
            sender_key_share: &fixture.responder_keys,
        },
        identity_key: RESPONDER_KEY,
        signer: TestSignature(SigAlg::MlDsa65),
    })?;
    assert_eq!(
        AuthenticatedNegotiationV1::from_local_peer(AuthenticatedNegotiationInputV1 {
            local_role: EndpointRole::Initiator,
            local_offer: fixture.initiator_offer,
            peer_offer: reflected_nonce_offer,
            local_policy: &fixture.initiator_policy,
            peer_policy: &fixture.responder_policy,
            committed_state: fixture.owner.current(),
            execution: fixture.execution,
        },),
        Err(CapabilityError::ReflectionRisk)
    );
    Ok(())
}

#[test]
fn every_signed_advance_and_reset_byte_is_load_bearing() -> Result<(), String> {
    let fixture = fixture(0xD3)?;
    let current = fixture.owner.current();
    let state = current.state();
    let next = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: state.chain_id(),
        protocol_id: state.protocol_id(),
        epoch: 2,
        previous_state_digest: current.revision().digest(),
        authority_key_id: state.authority_key_id(),
        execution_policy_state: state.execution_policy_state(),
        posture: state.posture(),
        allowed_suites: state.allowed_suites(),
    })
    .map_err(|error| error.to_string())?;
    let advance = sign_test_state(
        StateCertificateKind::Advance,
        next,
        AUTHORITY_KEY,
        SigAlg::MlDsa65,
    )?;
    let encoded_advance = advance.encode().map_err(|error| error.to_string())?;
    for index in 0..encoded_advance.len() {
        let mut mutated = encoded_advance.clone();
        let byte = mutated
            .get_mut(index)
            .ok_or_else(|| "advance mutation index escaped extent".to_owned())?;
        *byte ^= 1;
        if let Ok(decoded) = SignedMigrationStateV1::decode(&mutated) {
            assert!(
                fixture
                    .owner
                    .prepare_advance(&decoded, &TestSignature(SigAlg::MlDsa65), AUTHORITY_KEY,)
                    .is_err(),
                "mutated advance byte {index} was accepted"
            );
        }
    }

    let reset_state = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: MigrationChainId::from_bytes([0xD4; 32]),
        protocol_id: state.protocol_id(),
        epoch: 1,
        previous_state_digest: current.revision().digest(),
        authority_key_id: MigrationAuthorityKeyId::from_bytes([0xD5; 32]),
        execution_policy_state: state.execution_policy_state(),
        posture: state.posture(),
        allowed_suites: state.allowed_suites(),
    })
    .map_err(|error| error.to_string())?;
    let reset = MigrationResetV1::new(
        current.revision(),
        reset_state,
        MigrationResetNonce::from_bytes([0xD6; 32]),
        RECOVERY,
    );
    let reset = sign_test_reset(reset)?;
    let encoded_reset = reset.encode().map_err(|error| error.to_string())?;
    for index in 0..encoded_reset.len() {
        let mut mutated = encoded_reset.clone();
        let byte = mutated
            .get_mut(index)
            .ok_or_else(|| "reset mutation index escaped extent".to_owned())?;
        *byte ^= 1;
        if let Ok(decoded) = SignedMigrationResetV1::decode(&mutated) {
            assert!(
                fixture
                    .owner
                    .prepare_reset(
                        &decoded,
                        &TestSignature(SigAlg::MlDsa65),
                        RECOVERY_KEY,
                        RECOVERY,
                    )
                    .is_err(),
                "mutated reset byte {index} was accepted"
            );
        }
    }
    Ok(())
}

#[test]
fn state_semantics_reject_forks_generation_gaps_and_weaker_postures() -> Result<(), String> {
    let fixture = fixture(0xD7)?;
    let current = fixture.owner.current();
    let state = current.state();
    let signer = TestSignature(SigAlg::MlDsa65);
    let candidates = [
        (
            MigrationStateV1::new(MigrationStateDraftV1 {
                global_generation: 3,
                chain_id: state.chain_id(),
                protocol_id: state.protocol_id(),
                epoch: 2,
                previous_state_digest: current.revision().digest(),
                authority_key_id: state.authority_key_id(),
                execution_policy_state: state.execution_policy_state(),
                posture: state.posture(),
                allowed_suites: state.allowed_suites(),
            })
            .map_err(|error| error.to_string())?,
            MigrationStateError::GlobalGenerationNotNext,
        ),
        (
            MigrationStateV1::new(MigrationStateDraftV1 {
                global_generation: 2,
                chain_id: state.chain_id(),
                protocol_id: state.protocol_id(),
                epoch: 2,
                previous_state_digest: MigrationStateDigest::from_bytes([0xD8; 32]),
                authority_key_id: state.authority_key_id(),
                execution_policy_state: state.execution_policy_state(),
                posture: state.posture(),
                allowed_suites: state.allowed_suites(),
            })
            .map_err(|error| error.to_string())?,
            MigrationStateError::PreviousDigestMismatch,
        ),
        (
            MigrationStateV1::new(MigrationStateDraftV1 {
                global_generation: 2,
                chain_id: state.chain_id(),
                protocol_id: state.protocol_id(),
                epoch: 2,
                previous_state_digest: current.revision().digest(),
                authority_key_id: state.authority_key_id(),
                execution_policy_state: state.execution_policy_state(),
                posture: MigrationSecurityPosture::new(
                    SecurityFloor::Level2,
                    ComponentMode::HybridRequired,
                ),
                allowed_suites: state.allowed_suites(),
            })
            .map_err(|error| error.to_string())?,
            MigrationStateError::FloorDowngrade,
        ),
    ];
    for (candidate, expected) in candidates {
        let certificate = sign_test_state(
            StateCertificateKind::Advance,
            candidate,
            AUTHORITY_KEY,
            signer.0,
        )?;
        assert_eq!(
            fixture
                .owner
                .prepare_advance(&certificate, &signer, AUTHORITY_KEY)
                .err(),
            Some(expected)
        );
    }

    let pq_only_owner = genesis_owner(
        fixture.execution,
        SecurityFloor::Level3,
        ComponentMode::PostQuantumOnly,
        state.allowed_suites(),
    )?;
    let pq_current = pq_only_owner.current();
    let weaker_mode = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: pq_current.state().chain_id(),
        protocol_id: pq_current.state().protocol_id(),
        epoch: 2,
        previous_state_digest: pq_current.revision().digest(),
        authority_key_id: pq_current.state().authority_key_id(),
        execution_policy_state: pq_current.state().execution_policy_state(),
        posture: MigrationSecurityPosture::new(
            SecurityFloor::Level3,
            ComponentMode::HybridRequired,
        ),
        allowed_suites: pq_current.state().allowed_suites(),
    })
    .map_err(|error| error.to_string())?;
    let certificate = sign_test_state(
        StateCertificateKind::Advance,
        weaker_mode,
        AUTHORITY_KEY,
        signer.0,
    )?;
    assert_eq!(
        pq_only_owner
            .prepare_advance(&certificate, &signer, AUTHORITY_KEY)
            .err(),
        Some(MigrationStateError::ComponentModeDowngrade)
    );
    Ok(())
}

#[test]
fn state_advance_and_explicit_reset_enforce_exact_monotonicity() -> Result<(), String> {
    let fixture = fixture(0x80)?;
    let mut owner = fixture.owner;
    let current = owner.current();
    let state = current.state();
    let next = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: state.chain_id(),
        protocol_id: state.protocol_id(),
        epoch: 2,
        previous_state_digest: current.revision().digest(),
        authority_key_id: state.authority_key_id(),
        execution_policy_state: state.execution_policy_state(),
        posture: state.posture(),
        allowed_suites: state.allowed_suites(),
    })
    .map_err(|error| error.to_string())?;
    let certificate = sign_test_state(
        StateCertificateKind::Advance,
        next,
        AUTHORITY_KEY,
        SigAlg::MlDsa65,
    )?;
    let pending = owner
        .prepare_advance(&certificate, &TestSignature(SigAlg::MlDsa65), AUTHORITY_KEY)
        .map_err(|error| error.to_string())?;
    owner.commit(pending).map_err(|error| error.to_string())?;
    assert_eq!(owner.current_revision().global_generation(), 2);

    let same_epoch = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 3,
        chain_id: state.chain_id(),
        protocol_id: state.protocol_id(),
        epoch: 2,
        previous_state_digest: owner.current_revision().digest(),
        authority_key_id: state.authority_key_id(),
        execution_policy_state: state.execution_policy_state(),
        posture: state.posture(),
        allowed_suites: state.allowed_suites(),
    })
    .map_err(|error| error.to_string())?;
    let same_epoch = sign_test_state(
        StateCertificateKind::Advance,
        same_epoch,
        AUTHORITY_KEY,
        SigAlg::MlDsa65,
    )?;
    assert_eq!(
        owner
            .prepare_advance(&same_epoch, &TestSignature(SigAlg::MlDsa65), AUTHORITY_KEY,)
            .err(),
        Some(MigrationStateError::EpochNotNext)
    );

    let reset_state = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 3,
        chain_id: MigrationChainId::from_bytes([0x90; 32]),
        protocol_id: state.protocol_id(),
        epoch: 1,
        previous_state_digest: owner.current_revision().digest(),
        authority_key_id: MigrationAuthorityKeyId::from_bytes([0x91; 32]),
        execution_policy_state: state.execution_policy_state(),
        posture: state.posture(),
        allowed_suites: state.allowed_suites(),
    })
    .map_err(|error| error.to_string())?;
    let reset = MigrationResetV1::new(
        owner.current_revision(),
        reset_state,
        MigrationResetNonce::from_bytes([0x92; 32]),
        RECOVERY,
    );
    let signed_reset = sign_test_reset(reset)?;
    let encoded = signed_reset.encode().map_err(|error| error.to_string())?;
    let decoded = SignedMigrationResetV1::decode(&encoded).map_err(|error| error.to_string())?;
    let pending = owner
        .prepare_reset(
            &decoded,
            &TestSignature(SigAlg::MlDsa65),
            RECOVERY_KEY,
            RECOVERY,
        )
        .map_err(|error| error.to_string())?;
    owner.commit(pending).map_err(|error| error.to_string())?;
    assert_eq!(owner.current_revision().global_generation(), 3);
    assert_eq!(owner.current_revision().epoch(), 1);

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        SignedMigrationResetV1::decode(&trailing),
        Err(MigrationStateError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn pq_only_state_is_explicitly_incompatible_with_abi2_and_confirmation() -> Result<(), String> {
    let initiator_policy = policy(
        1,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let responder_policy = policy(
        2,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let execution = execution(&initiator_policy, HybridSuite::MlKem768X25519)?;
    let suites = suite_set(HybridSuite::MlKem768X25519)?;
    let owner = genesis_owner(
        execution,
        SecurityFloor::Level3,
        ComponentMode::PostQuantumOnly,
        suites,
    )?;
    let (initiator_keys, responder_keys) = key_shares()?;
    let (_, initiator_offer) = signed_offer(TestSignedOfferInput {
        offer: CapabilityOfferInputV1 {
            protocol_id: PROTOCOL,
            session_id: MigrationSessionId::from_bytes([0xA0; 32]),
            sender_role: EndpointRole::Initiator,
            sender_identity: INITIATOR_ID,
            receiver_identity: RESPONDER_ID,
            sender_nonce: MigrationNonce::from_bytes([0xA1; 32]),
            sender_policy: &initiator_policy,
            committed_state: owner.current(),
            offered_suites: suites,
            sender_key_share: &initiator_keys,
        },
        identity_key: INITIATOR_KEY,
        signer: TestSignature(SigAlg::MlDsa65),
    })?;
    let (_, responder_offer) = signed_offer(TestSignedOfferInput {
        offer: CapabilityOfferInputV1 {
            protocol_id: PROTOCOL,
            session_id: MigrationSessionId::from_bytes([0xA0; 32]),
            sender_role: EndpointRole::Responder,
            sender_identity: RESPONDER_ID,
            receiver_identity: INITIATOR_ID,
            sender_nonce: MigrationNonce::from_bytes([0xA2; 32]),
            sender_policy: &responder_policy,
            committed_state: owner.current(),
            offered_suites: suites,
            sender_key_share: &responder_keys,
        },
        identity_key: RESPONDER_KEY,
        signer: TestSignature(SigAlg::MlDsa65),
    })?;
    let negotiation =
        AuthenticatedNegotiationV1::from_local_peer(AuthenticatedNegotiationInputV1 {
            local_role: EndpointRole::Initiator,
            local_offer: initiator_offer,
            peer_offer: responder_offer,
            local_policy: &initiator_policy,
            peer_policy: &responder_policy,
            committed_state: owner.current(),
            execution,
        })
        .map_err(|error| error.to_string())?;
    let pre_kem = PreKemTranscriptV1::from_authenticated_contract(
        negotiation,
        owner.current(),
        execution,
        EndpointRole::Initiator,
        responder_keys,
    )
    .map_err(|error| error.to_string())?;
    let context =
        MigrationContextV2::from_authenticated_contract(AuthenticatedMigrationContextV2Input {
            local_role: EndpointRole::Initiator,
            encapsulator_role: EndpointRole::Initiator,
            execution,
            local_policy: &initiator_policy,
            peer_policy: &responder_policy,
            committed_state: owner.current(),
            negotiation,
            pre_kem: &pre_kem,
        })
        .map_err(|error| error.to_string())?;
    assert_eq!(
        Abi2MigrationApplicationContextV2::try_from(&context),
        Err(MigrationContractError::TraditionalComponentForbidden)
    );
    let post = PostKemTranscriptV1::from_context(&context, &[0xB1; 64], &[0xB2; 32])
        .map_err(|error| error.to_string())?;
    assert_eq!(
        InitiatorConfirmationV1::<Sha3_256Xof>::new(
            Secret::from_bytes([0xB3; 32]),
            &context,
            &post,
        )
        .err(),
        Some(ConfirmationError::TraditionalComponentForbidden)
    );
    Ok(())
}

#[test]
fn confirmation_constructors_reject_the_opposite_role() -> Result<(), String> {
    let fixture = fixture(0xC0)?;
    let responder_context = responder_context(&fixture)?;
    let post = PostKemTranscriptV1::from_context(&fixture.context, &[0xC1; 64], &[0xC2; 32])
        .map_err(|error| error.to_string())?;

    assert_eq!(
        InitiatorConfirmationV1::<Sha3_256Xof>::new(
            Secret::from_bytes([0xC3; 32]),
            &responder_context,
            &post,
        )
        .err(),
        Some(ConfirmationError::RoleMismatch)
    );
    assert_eq!(
        ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
            Secret::from_bytes([0xC3; 32]),
            &fixture.context,
            &post,
        )
        .err(),
        Some(ConfirmationError::RoleMismatch)
    );
    Ok(())
}

#[test]
fn finished_flights_follow_initiator_responder_acceptance_order() -> Result<(), String> {
    let fixture = fixture(0xC0)?;
    let responder_context = responder_context(&fixture)?;
    let post = PostKemTranscriptV1::from_context(&fixture.context, &[0xC1; 64], &[0xC2; 32])
        .map_err(|error| error.to_string())?;
    let initiator = InitiatorConfirmationV1::<Sha3_256Xof>::new(
        Secret::from_bytes([0xC3; 32]),
        &fixture.context,
        &post,
    )
    .map_err(|error| error.to_string())?;
    let responder = ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
        Secret::from_bytes([0xC3; 32]),
        &responder_context,
        &post,
    )
    .map_err(|error| error.to_string())?;

    let (initiator, initiator_finished) = initiator.issue_finished();
    let (responder_key, responder_finished) = responder
        .verify_accept_and_issue_finished(&fixture.owner, &initiator_finished)
        .map_err(|error| error.to_string())?;
    assert_ne!(initiator_finished.as_bytes(), responder_finished.as_bytes());
    let initiator_key = initiator
        .verify_and_accept(&fixture.owner, &responder_finished)
        .map_err(|error| error.to_string())?;
    assert_eq!(
        initiator_key.secret().as_bytes(),
        responder_key.secret().as_bytes()
    );

    let reflected_responder = ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
        Secret::from_bytes([0xC3; 32]),
        &responder_context,
        &post,
    )
    .map_err(|error| error.to_string())?;
    let reflected_as_initiator = InitiatorFinishedV1::from_bytes(*responder_finished.as_bytes());
    assert_eq!(
        reflected_responder
            .verify_accept_and_issue_finished(&fixture.owner, &reflected_as_initiator)
            .err(),
        Some(ConfirmationError::PeerFinishedMismatch)
    );

    let reflected_initiator = InitiatorConfirmationV1::<Sha3_256Xof>::new(
        Secret::from_bytes([0xC3; 32]),
        &fixture.context,
        &post,
    )
    .map_err(|error| error.to_string())?;
    let (reflected_initiator, reflected_initiator_finished) = reflected_initiator.issue_finished();
    let reflected_as_responder =
        ResponderFinishedV1::from_bytes(*reflected_initiator_finished.as_bytes());
    assert_eq!(
        reflected_initiator
            .verify_and_accept(&fixture.owner, &reflected_as_responder)
            .err(),
        Some(ConfirmationError::PeerFinishedMismatch)
    );
    Ok(())
}

#[test]
fn stale_state_precedes_finished_verification_for_both_roles() -> Result<(), String> {
    let mut fixture = fixture(0xC0)?;
    let responder_context = responder_context(&fixture)?;
    let post = PostKemTranscriptV1::from_context(&fixture.context, &[0xC1; 64], &[0xC2; 32])
        .map_err(|error| error.to_string())?;
    let initiator = InitiatorConfirmationV1::<Sha3_256Xof>::new(
        Secret::from_bytes([0xC3; 32]),
        &fixture.context,
        &post,
    )
    .map_err(|error| error.to_string())?
    .issue_finished()
    .0;
    let responder = ResponderAwaitingInitiatorFinishedV1::<Sha3_256Xof>::new(
        Secret::from_bytes([0xC3; 32]),
        &responder_context,
        &post,
    )
    .map_err(|error| error.to_string())?;

    let current = fixture.owner.current();
    let state = current.state();
    let next = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: state.chain_id(),
        protocol_id: state.protocol_id(),
        epoch: 2,
        previous_state_digest: current.revision().digest(),
        authority_key_id: state.authority_key_id(),
        execution_policy_state: state.execution_policy_state(),
        posture: state.posture(),
        allowed_suites: state.allowed_suites(),
    })
    .map_err(|error| error.to_string())?;
    let certificate = sign_test_state(
        StateCertificateKind::Advance,
        next,
        AUTHORITY_KEY,
        SigAlg::MlDsa65,
    )?;
    let advance = fixture
        .owner
        .prepare_advance(&certificate, &TestSignature(SigAlg::MlDsa65), AUTHORITY_KEY)
        .map_err(|error| error.to_string())?;
    fixture
        .owner
        .commit(advance)
        .map_err(|error| error.to_string())?;

    assert_eq!(
        responder
            .verify_accept_and_issue_finished(
                &fixture.owner,
                &InitiatorFinishedV1::from_bytes([0u8; 32]),
            )
            .err(),
        Some(ConfirmationError::StaleState)
    );
    assert_eq!(
        initiator
            .verify_and_accept(&fixture.owner, &ResponderFinishedV1::from_bytes([0u8; 32]),)
            .err(),
        Some(ConfirmationError::StaleState)
    );
    Ok(())
}
