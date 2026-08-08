//! Canonical migration-context construction and encoding controls.

use q_periapt_core::Error as CoreError;
use q_periapt_migration::{
    Abi2MigrationApplicationContextV1, AuthenticatedEndpointPolicy, CapabilityTranscriptHash,
    EndpointRole, MigrationCommitmentField, MigrationCommitmentsV1, MigrationContextError,
    MigrationContextV1, MigrationEpoch, MigrationProtocolId, MigrationScopeV1,
    PreKemTranscriptHash, RoleOrderedEndpointPolicies, SecurityFloor, TransitionStateHash,
    MIGRATION_CONTEXT_DOMAIN, MIGRATION_CONTEXT_SCHEMA_VERSION, MIGRATION_CONTEXT_V1_ENCODED_LEN,
};
use q_periapt_policy::{AuthenticatedPolicy, AuthenticatedResolvedSuite, HybridSuite, Policy};
use q_periapt_sig::{SigAlg, Verifier};

struct AcceptingVerifier(SigAlg);

impl Verifier for AcceptingVerifier {
    fn algorithm(&self) -> SigAlg {
        self.0
    }

    fn verify(&self, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<(), CoreError> {
        Ok(())
    }
}

fn authenticated_policy(
    version: u32,
    floor: u8,
    profile: &str,
    pq_kem: &str,
    signature: &str,
    verifier: SigAlg,
) -> Result<AuthenticatedPolicy, String> {
    let toml = format!(
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
        b"test-key",
        toml.as_bytes(),
        b"test-sig",
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

fn commitments(
    capability: u8,
    transition: u8,
    pre_kem: u8,
) -> Result<MigrationCommitmentsV1, MigrationContextError> {
    MigrationCommitmentsV1::new(
        CapabilityTranscriptHash::from_bytes([capability; 32]),
        TransitionStateHash::from_bytes([transition; 32]),
        PreKemTranscriptHash::from_bytes([pre_kem; 32]),
    )
}

fn scope(
    protocol: u8,
    encapsulator_role: EndpointRole,
    epoch: u64,
) -> Result<MigrationScopeV1, MigrationContextError> {
    MigrationScopeV1::new(
        MigrationProtocolId::from_bytes([protocol; 16]),
        encapsulator_role,
        MigrationEpoch::new(epoch)?,
    )
}

fn context(
    scope: MigrationScopeV1,
    local_role: EndpointRole,
    execution: AuthenticatedResolvedSuite,
    local_policy: &AuthenticatedPolicy,
    peer_policy: &AuthenticatedPolicy,
    commitments: MigrationCommitmentsV1,
) -> Result<MigrationContextV1, String> {
    MigrationContextV1::from_authenticated_policies(
        scope,
        local_role,
        execution,
        local_policy,
        peer_policy,
        commitments,
    )
    .map_err(|error| error.to_string())
}

fn encode(context: &MigrationContextV1) -> Result<[u8; MIGRATION_CONTEXT_V1_ENCODED_LEN], String> {
    let mut encoded = [0u8; MIGRATION_CONTEXT_V1_ENCODED_LEN];
    context
        .encode_into(&mut encoded)
        .map_err(|error| error.to_string())?;
    Ok(encoded)
}

fn lp8_fields(mut encoded: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut fields = Vec::new();
    while !encoded.is_empty() {
        let length_bytes = encoded
            .get(..8)
            .ok_or_else(|| "truncated LP8 length".to_owned())?;
        let length: [u8; 8] = length_bytes
            .try_into()
            .map_err(|_| "LP8 length was not eight bytes".to_owned())?;
        let field_len = usize::try_from(u64::from_be_bytes(length))
            .map_err(|_| "LP8 field length does not fit usize".to_owned())?;
        let field_end = 8usize
            .checked_add(field_len)
            .ok_or_else(|| "LP8 field length overflow".to_owned())?;
        let field = encoded
            .get(8..field_end)
            .ok_or_else(|| "truncated LP8 field".to_owned())?;
        fields.push(field);
        encoded = encoded
            .get(field_end..)
            .ok_or_else(|| "truncated LP8 tail".to_owned())?;
    }
    Ok(fields)
}

fn field<'a>(fields: &'a [&[u8]], index: usize) -> Result<&'a [u8], String> {
    fields
        .get(index)
        .copied()
        .ok_or_else(|| format!("missing LP8 field {index}"))
}

#[test]
fn local_peer_views_normalize_to_identical_initiator_responder_bytes() -> Result<(), String> {
    let initiator_policy = authenticated_policy(
        1,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let responder_policy = authenticated_policy(
        2,
        2,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let common_execution = execution(&initiator_policy, HybridSuite::MlKem768X25519)?;
    let common_scope =
        scope(0x11, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?;
    let common_commitments = commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?;

    let initiator_view = context(
        common_scope,
        EndpointRole::Initiator,
        common_execution,
        &initiator_policy,
        &responder_policy,
        common_commitments,
    )?;
    let responder_view = context(
        common_scope,
        EndpointRole::Responder,
        common_execution,
        &responder_policy,
        &initiator_policy,
        common_commitments,
    )?;
    assert_eq!(encode(&initiator_view)?, encode(&responder_view)?);

    let reflected_ownership = context(
        common_scope,
        EndpointRole::Initiator,
        common_execution,
        &responder_policy,
        &initiator_policy,
        common_commitments,
    )?;
    assert_ne!(encode(&initiator_view)?, encode(&reflected_ownership)?);
    Ok(())
}

#[test]
fn canonical_body_has_exact_length_field_order_and_big_endian_integers() -> Result<(), String> {
    let policy = authenticated_policy(
        9,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let execution = execution(&policy, HybridSuite::MlKem768X25519)?;
    let context = context(
        scope(0x11, EndpointRole::Responder, 0x0102_0304_0506_0708)
            .map_err(|error| error.to_string())?,
        EndpointRole::Initiator,
        execution,
        &policy,
        &policy,
        commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?,
    )?;
    let encoded = encode(&context)?;
    assert_eq!(encoded.len(), 315);
    let fields = lp8_fields(&encoded)?;
    assert_eq!(fields.len(), 12);
    assert_eq!(field(&fields, 0)?, MIGRATION_CONTEXT_DOMAIN);
    assert_eq!(
        field(&fields, 1)?,
        MIGRATION_CONTEXT_SCHEMA_VERSION.to_be_bytes()
    );
    assert_eq!(field(&fields, 2)?, [0x11; 16]);
    assert_eq!(field(&fields, 3)?, [EndpointRole::Responder as u8]);
    assert_eq!(field(&fields, 4)?, 0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(field(&fields, 5)?, policy.trusted_state().digest());
    assert_eq!(field(&fields, 6)?, policy.trusted_state().digest());
    assert_eq!(field(&fields, 7)?, [0x31; 32]);
    assert_eq!(field(&fields, 8)?, [HybridSuite::MlKem768X25519.to_u8()]);
    assert_eq!(field(&fields, 9)?, [SecurityFloor::Level3.to_u8()]);
    assert_eq!(field(&fields, 10)?, [0x41; 32]);
    assert_eq!(field(&fields, 11)?, [0x51; 32]);
    Ok(())
}

#[test]
fn construction_rejects_reserved_values_and_non_binding_policies() -> Result<(), String> {
    assert_eq!(
        MigrationEpoch::new(0),
        Err(MigrationContextError::InvalidMigrationEpoch)
    );
    assert_eq!(
        MigrationEpoch::new(u64::MAX),
        Err(MigrationContextError::InvalidMigrationEpoch)
    );
    let valid_epoch = MigrationEpoch::new(1).map_err(|error| error.to_string())?;
    assert_eq!(
        MigrationScopeV1::new(
            MigrationProtocolId::from_bytes([0u8; 16]),
            EndpointRole::Initiator,
            valid_epoch,
        ),
        Err(MigrationContextError::InvalidProtocolId)
    );

    for (candidate, expected_field) in [
        (
            (0, 1, 1),
            MigrationCommitmentField::CapabilityTranscriptHash,
        ),
        ((1, 0, 1), MigrationCommitmentField::TransitionStateHash),
        ((1, 1, 0), MigrationCommitmentField::PreKemTranscriptHash),
    ] {
        assert_eq!(
            commitments(candidate.0, candidate.1, candidate.2),
            Err(MigrationContextError::ZeroCommitment(expected_field))
        );
    }

    let common = authenticated_policy(
        10,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let common_execution = execution(&common, HybridSuite::MlKem768X25519)?;
    let compat = authenticated_policy(
        11,
        3,
        "CompatXWing",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    assert_eq!(
        AuthenticatedEndpointPolicy::from_authenticated_policy(&compat, common_execution),
        Err(MigrationContextError::EndpointPolicyNotContextBound)
    );
    let compat_execution = execution(&compat, HybridSuite::MlKem768X25519)?;
    assert_eq!(
        AuthenticatedEndpointPolicy::from_authenticated_policy(&compat, compat_execution),
        Err(MigrationContextError::ExecutionDecisionNotContextBound)
    );

    let l5 = authenticated_policy(
        12,
        5,
        "ContextBound",
        "ML-KEM-1024",
        "ML-DSA-87",
        SigAlg::MlDsa87,
    )?;
    assert_eq!(
        AuthenticatedEndpointPolicy::from_authenticated_policy(&l5, common_execution),
        Err(MigrationContextError::EndpointPolicyDoesNotAuthorizeSuite)
    );
    Ok(())
}

#[test]
fn execution_decision_mismatch_and_abi2_nondefault_suite_fail_closed() -> Result<(), String> {
    let first = authenticated_policy(
        1,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let second = authenticated_policy(
        2,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let first_execution = execution(&first, HybridSuite::MlKem768X25519)?;
    let second_execution = execution(&second, HybridSuite::MlKem768X25519)?;
    let first_endpoint =
        AuthenticatedEndpointPolicy::from_authenticated_policy(&first, first_execution)
            .map_err(|error| error.to_string())?;
    let second_under_first_execution =
        AuthenticatedEndpointPolicy::from_authenticated_policy(&second, first_execution)
            .map_err(|error| error.to_string())?;
    let endpoints_under_first_execution = RoleOrderedEndpointPolicies::from_local_peer(
        EndpointRole::Initiator,
        first_endpoint,
        second_under_first_execution,
    )
    .map_err(|error| error.to_string())?;
    assert_eq!(
        MigrationContextV1::try_new(
            scope(0x11, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?,
            second_execution,
            endpoints_under_first_execution,
            commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?,
        ),
        Err(MigrationContextError::ExecutionDecisionMismatch)
    );

    let second_endpoint =
        AuthenticatedEndpointPolicy::from_authenticated_policy(&second, second_execution)
            .map_err(|error| error.to_string())?;
    assert_eq!(
        RoleOrderedEndpointPolicies::from_local_peer(
            EndpointRole::Initiator,
            first_endpoint,
            second_endpoint,
        ),
        Err(MigrationContextError::ExecutionDecisionMismatch)
    );

    let l5 = authenticated_policy(
        3,
        5,
        "ContextBound",
        "ML-KEM-1024",
        "ML-DSA-87",
        SigAlg::MlDsa87,
    )?;
    let l5_execution = execution(&l5, HybridSuite::MlKem1024X25519)?;
    let l5_context = context(
        scope(0x11, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?,
        EndpointRole::Initiator,
        l5_execution,
        &l5,
        &l5,
        commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?,
    )?;
    assert_eq!(
        Abi2MigrationApplicationContextV1::try_from(&l5_context),
        Err(MigrationContextError::Abi2IncompatibleSuite)
    );
    Ok(())
}

#[test]
fn every_externally_supplied_field_is_committed_and_reflection_stays_distinct() -> Result<(), String>
{
    let policy = authenticated_policy(
        1,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let execution = execution(&policy, HybridSuite::MlKem768X25519)?;
    let baseline = context(
        scope(0x11, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?,
        EndpointRole::Initiator,
        execution,
        &policy,
        &policy,
        commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?,
    )?;
    let baseline_bytes = encode(&baseline)?;
    let changed = [
        context(
            scope(0x12, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?,
            EndpointRole::Initiator,
            execution,
            &policy,
            &policy,
            commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?,
        )?,
        context(
            scope(0x11, EndpointRole::Responder, 7).map_err(|error| error.to_string())?,
            EndpointRole::Initiator,
            execution,
            &policy,
            &policy,
            commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?,
        )?,
        context(
            scope(0x11, EndpointRole::Initiator, 8).map_err(|error| error.to_string())?,
            EndpointRole::Initiator,
            execution,
            &policy,
            &policy,
            commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?,
        )?,
        context(
            scope(0x11, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?,
            EndpointRole::Initiator,
            execution,
            &policy,
            &policy,
            commitments(0x32, 0x41, 0x51).map_err(|error| error.to_string())?,
        )?,
        context(
            scope(0x11, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?,
            EndpointRole::Initiator,
            execution,
            &policy,
            &policy,
            commitments(0x31, 0x42, 0x51).map_err(|error| error.to_string())?,
        )?,
        context(
            scope(0x11, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?,
            EndpointRole::Initiator,
            execution,
            &policy,
            &policy,
            commitments(0x31, 0x41, 0x52).map_err(|error| error.to_string())?,
        )?,
    ];
    for candidate in changed {
        assert_ne!(baseline_bytes, encode(&candidate)?);
    }
    Ok(())
}

#[test]
fn encode_into_is_exact_extent_atomic_and_carries_expected_execution_state() -> Result<(), String> {
    let policy = authenticated_policy(
        1,
        3,
        "ContextBound",
        "ML-KEM-768",
        "ML-DSA-65",
        SigAlg::MlDsa65,
    )?;
    let execution = execution(&policy, HybridSuite::MlKem768X25519)?;
    let context = context(
        scope(0x11, EndpointRole::Initiator, 7).map_err(|error| error.to_string())?,
        EndpointRole::Initiator,
        execution,
        &policy,
        &policy,
        commitments(0x31, 0x41, 0x51).map_err(|error| error.to_string())?,
    )?;

    let mut short = [0xa5; MIGRATION_CONTEXT_V1_ENCODED_LEN - 1];
    assert_eq!(
        context.encode_into(&mut short),
        Err(MigrationContextError::InvalidOutputLength)
    );
    assert!(short.iter().all(|byte| *byte == 0xa5));

    let mut long = [0x5a; MIGRATION_CONTEXT_V1_ENCODED_LEN + 1];
    assert_eq!(
        context.encode_into(&mut long),
        Err(MigrationContextError::InvalidOutputLength)
    );
    assert!(long.iter().all(|byte| *byte == 0x5a));

    let adapter =
        Abi2MigrationApplicationContextV1::try_from(&context).map_err(|error| error.to_string())?;
    assert_eq!(adapter.as_bytes(), &encode(&context)?);
    assert_eq!(adapter.expected_execution_state(), policy.trusted_state());
    assert_eq!(
        format!("{adapter:?}"),
        "Abi2MigrationApplicationContextV1([redacted])"
    );
    Ok(())
}
