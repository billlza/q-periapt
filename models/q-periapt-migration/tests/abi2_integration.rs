//! End-to-end check that canonical migration bytes pass unchanged through frozen ABI 2.

use q_periapt_backends::MlDsa65;
use q_periapt_core::ZeroizingBytes;
use q_periapt_ffi_abi2::{
    q_periapt_decapsulate, q_periapt_decision_from_signed_policy, q_periapt_encapsulate,
    q_periapt_generate_keypair, Q_PERIAPT_MLKEM768_CT_LEN, Q_PERIAPT_MLKEM768_PK_LEN,
    Q_PERIAPT_MLKEM768_SK_LEN, Q_PERIAPT_OK, Q_PERIAPT_POLICY_DECISION_LEN, Q_PERIAPT_SECRET_LEN,
    Q_PERIAPT_X25519_LEN,
};
use q_periapt_migration::{
    Abi2MigrationApplicationContextV1, CapabilityTranscriptHash, EndpointRole,
    MigrationCommitmentsV1, MigrationContextV1, MigrationEpoch, MigrationProtocolId,
    MigrationScopeV1, PreKemTranscriptHash, TransitionStateHash,
};
use q_periapt_policy::{HybridSuite, Policy};

fn fixture_string<'a>(fixture: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    fixture
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("signed-policy fixture lacks string field {name}"))
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.len() % 2 != 0 {
        return Err("hex input has odd length".to_owned());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(
                *pair
                    .first()
                    .ok_or_else(|| "hex pair lacks first nibble".to_owned())?,
            )?;
            let low = decode_nibble(
                *pair
                    .get(1)
                    .ok_or_else(|| "hex pair lacks second nibble".to_owned())?,
            )?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid hex digit".to_owned()),
    }
}

#[test]
fn abi2_roundtrip_binds_migration_context_and_common_execution_decision() -> Result<(), String> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../bindings/signed-policy-vectors.json"))
            .map_err(|error| error.to_string())?;
    let policy_toml = fixture_string(&fixture, "policy_toml")?.as_bytes();
    let signature = decode_hex(fixture_string(&fixture, "signature")?)?;
    let verification_key = decode_hex(fixture_string(&fixture, "verification_key")?)?;

    let authenticated_policy =
        Policy::load_signed(&MlDsa65, &verification_key, policy_toml, &signature)
            .map_err(|error| error.to_string())?;
    let execution_decision = authenticated_policy
        .resolve_suite(&[HybridSuite::MlKem768X25519])
        .map_err(|error| error.to_string())?;
    let scope = MigrationScopeV1::new(
        MigrationProtocolId::from_bytes([0x71; 16]),
        EndpointRole::Initiator,
        MigrationEpoch::new(4).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let commitments = MigrationCommitmentsV1::new(
        CapabilityTranscriptHash::from_bytes([0x72; 32]),
        TransitionStateHash::from_bytes([0x73; 32]),
        PreKemTranscriptHash::from_bytes([0x74; 32]),
    )
    .map_err(|error| error.to_string())?;
    let migration_context = MigrationContextV1::from_authenticated_policies(
        scope,
        EndpointRole::Initiator,
        execution_decision,
        &authenticated_policy,
        &authenticated_policy,
        commitments,
    )
    .map_err(|error| error.to_string())?;
    let application_context = Abi2MigrationApplicationContextV1::try_from(&migration_context)
        .map_err(|error| error.to_string())?;

    let mut decision = [0u8; Q_PERIAPT_POLICY_DECISION_LEN];
    // SAFETY: every input is backed by a live slice for the supplied length; the
    // fixed decision output is writable, exact-sized, and disjoint from all inputs.
    let decision_rc = unsafe {
        q_periapt_decision_from_signed_policy(
            policy_toml.as_ptr(),
            policy_toml.len(),
            signature.as_ptr(),
            signature.len(),
            verification_key.as_ptr(),
            verification_key.len(),
            core::ptr::null(),
            0,
            decision.as_mut_ptr(),
            decision.len(),
        )
    };
    if decision_rc != Q_PERIAPT_OK {
        return Err(format!("ABI2 signed-policy decision failed: {decision_rc}"));
    }
    let decision_state = decision
        .get(4..)
        .ok_or_else(|| "ABI2 decision lacks its trusted-state suffix".to_owned())?;
    assert_eq!(
        decision_state,
        application_context.expected_execution_state().encode()
    );

    let mut sk_pq = ZeroizingBytes::<Q_PERIAPT_MLKEM768_SK_LEN>::zeroed();
    let mut pk_pq = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
    let mut sk_trad = ZeroizingBytes::<Q_PERIAPT_X25519_LEN>::zeroed();
    let mut pk_trad = [0u8; Q_PERIAPT_X25519_LEN];
    // SAFETY: the decision is readable; all exact-sized output arrays are live,
    // writable, and pairwise disjoint.
    let keypair_rc = unsafe {
        q_periapt_generate_keypair(
            decision.as_ptr(),
            decision.len(),
            sk_pq.as_mut_bytes().as_mut_ptr(),
            sk_pq.as_bytes().len(),
            pk_pq.as_mut_ptr(),
            pk_pq.len(),
            sk_trad.as_mut_bytes().as_mut_ptr(),
            sk_trad.as_bytes().len(),
            pk_trad.as_mut_ptr(),
            pk_trad.len(),
        )
    };
    if keypair_rc != Q_PERIAPT_OK {
        return Err(format!("ABI2 key generation failed: {keypair_rc}"));
    }

    let mut ct_pq = [0u8; Q_PERIAPT_MLKEM768_CT_LEN];
    let mut ct_trad = [0u8; Q_PERIAPT_X25519_LEN];
    let mut enc_secret = ZeroizingBytes::<Q_PERIAPT_SECRET_LEN>::zeroed();
    // SAFETY: all input slices are live for their supplied lengths; all outputs
    // are exact-sized, writable, and disjoint from the inputs and one another.
    let encapsulate_rc = unsafe {
        q_periapt_encapsulate(
            decision.as_ptr(),
            decision.len(),
            pk_pq.as_ptr(),
            pk_pq.len(),
            pk_trad.as_ptr(),
            pk_trad.len(),
            application_context.as_bytes().as_ptr(),
            application_context.as_bytes().len(),
            ct_pq.as_mut_ptr(),
            ct_pq.len(),
            ct_trad.as_mut_ptr(),
            ct_trad.len(),
            enc_secret.as_mut_bytes().as_mut_ptr(),
            enc_secret.as_bytes().len(),
        )
    };
    if encapsulate_rc != Q_PERIAPT_OK {
        return Err(format!("ABI2 encapsulation failed: {encapsulate_rc}"));
    }

    let mut dec_secret = ZeroizingBytes::<Q_PERIAPT_SECRET_LEN>::zeroed();
    // SAFETY: all inputs are live for their supplied lengths and the exact-sized
    // secret output is writable and disjoint from every input.
    let decapsulate_rc = unsafe {
        q_periapt_decapsulate(
            decision.as_ptr(),
            decision.len(),
            sk_pq.as_bytes().as_ptr(),
            sk_pq.as_bytes().len(),
            ct_pq.as_ptr(),
            ct_pq.len(),
            pk_pq.as_ptr(),
            pk_pq.len(),
            sk_trad.as_bytes().as_ptr(),
            sk_trad.as_bytes().len(),
            ct_trad.as_ptr(),
            ct_trad.len(),
            pk_trad.as_ptr(),
            pk_trad.len(),
            application_context.as_bytes().as_ptr(),
            application_context.as_bytes().len(),
            dec_secret.as_mut_bytes().as_mut_ptr(),
            dec_secret.as_bytes().len(),
        )
    };
    assert_eq!(decapsulate_rc, Q_PERIAPT_OK);
    assert_eq!(enc_secret.as_bytes(), dec_secret.as_bytes());

    let mut changed_context = *application_context.as_bytes();
    let last = changed_context
        .last_mut()
        .ok_or_else(|| "migration context unexpectedly empty".to_owned())?;
    *last ^= 1;
    // SAFETY: same valid, disjoint regions as the successful decapsulation; only
    // the public application-context bytes differ.
    let changed_context_rc = unsafe {
        q_periapt_decapsulate(
            decision.as_ptr(),
            decision.len(),
            sk_pq.as_bytes().as_ptr(),
            sk_pq.as_bytes().len(),
            ct_pq.as_ptr(),
            ct_pq.len(),
            pk_pq.as_ptr(),
            pk_pq.len(),
            sk_trad.as_bytes().as_ptr(),
            sk_trad.as_bytes().len(),
            ct_trad.as_ptr(),
            ct_trad.len(),
            pk_trad.as_ptr(),
            pk_trad.len(),
            changed_context.as_ptr(),
            changed_context.len(),
            dec_secret.as_mut_bytes().as_mut_ptr(),
            dec_secret.as_bytes().len(),
        )
    };
    assert_eq!(changed_context_rc, Q_PERIAPT_OK);
    assert_ne!(enc_secret.as_bytes(), dec_secret.as_bytes());

    let mut changed_decision = decision;
    let digest_byte = changed_decision
        .get_mut(8)
        .ok_or_else(|| "ABI2 decision unexpectedly short".to_owned())?;
    *digest_byte ^= 1;
    // SAFETY: same valid, disjoint regions as the successful decapsulation; only
    // the structurally valid public execution-decision digest differs.
    let changed_decision_rc = unsafe {
        q_periapt_decapsulate(
            changed_decision.as_ptr(),
            changed_decision.len(),
            sk_pq.as_bytes().as_ptr(),
            sk_pq.as_bytes().len(),
            ct_pq.as_ptr(),
            ct_pq.len(),
            pk_pq.as_ptr(),
            pk_pq.len(),
            sk_trad.as_bytes().as_ptr(),
            sk_trad.as_bytes().len(),
            ct_trad.as_ptr(),
            ct_trad.len(),
            pk_trad.as_ptr(),
            pk_trad.len(),
            application_context.as_bytes().as_ptr(),
            application_context.as_bytes().len(),
            dec_secret.as_mut_bytes().as_mut_ptr(),
            dec_secret.as_bytes().len(),
        )
    };
    assert_eq!(changed_decision_rc, Q_PERIAPT_OK);
    assert_ne!(enc_secret.as_bytes(), dec_secret.as_bytes());
    Ok(())
}
