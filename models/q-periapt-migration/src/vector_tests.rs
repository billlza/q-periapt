//! Private full-byte correspondence with the independent Python vectors.

use super::*;

use serde_json::Value;

fn require_exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    let mut actual_keys: Vec<&str> = object.keys().map(String::as_str).collect();
    actual_keys.sort_unstable();
    let mut expected_keys = expected.to_vec();
    expected_keys.sort_unstable();
    if actual_keys == expected_keys {
        Ok(())
    } else {
        Err(format!(
            "{label} keys differ: expected {expected_keys:?}, got {actual_keys:?}"
        ))
    }
}

fn required<'a>(object: &'a Value, key: &str) -> Result<&'a Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("vector value lacks {key}"))
}

fn required_str<'a>(object: &'a Value, key: &str) -> Result<&'a str, String> {
    required(object, key)?
        .as_str()
        .ok_or_else(|| format!("vector {key} is not a string"))
}

fn required_u64(object: &Value, key: &str) -> Result<u64, String> {
    required(object, key)?
        .as_u64()
        .ok_or_else(|| format!("vector {key} is not an unsigned integer"))
}

fn required_u8(object: &Value, key: &str) -> Result<u8, String> {
    u8::try_from(required_u64(object, key)?)
        .map_err(|_| format!("vector {key} does not fit one byte"))
}

fn decode_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("vector hex is not canonical lowercase hex".to_owned()),
    }
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("vector hex must contain exactly {N} bytes"));
    }
    let decoded: Vec<u8> = value
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
        .collect::<Result<_, String>>()?;
    decoded
        .try_into()
        .map_err(|_| format!("decoded vector hex must contain exactly {N} bytes"))
}

fn field_hex<const N: usize>(input: &Value, key: &str) -> Result<[u8; N], String> {
    decode_hex(required_str(input, key)?)
}

#[test]
fn rust_encoder_matches_every_independent_python_full_byte_vector() -> Result<(), String> {
    let document: Value =
        serde_json::from_str(include_str!("../vectors/migration-context-v1.json"))
            .map_err(|error| error.to_string())?;
    require_exact_keys(&document, &["schema_version", "vectors"], "vector document")?;
    if required_u64(&document, "schema_version")? != 1 {
        return Err("vector document schema_version must be 1".to_owned());
    }
    let vectors = required(&document, "vectors")?
        .as_array()
        .ok_or_else(|| "vectors must be an array".to_owned())?;
    if vectors.is_empty() {
        return Err("vectors must not be empty".to_owned());
    }

    for vector in vectors {
        require_exact_keys(vector, &["expected", "input", "name"], "vector")?;
        if required_str(vector, "name")?.is_empty() {
            return Err("vector name must not be empty".to_owned());
        }
        let input = required(vector, "input")?;
        let expected = required(vector, "expected")?;
        require_exact_keys(
            input,
            &[
                "capability_transcript_hash",
                "encapsulator_role",
                "initiator_policy_digest",
                "migration_epoch",
                "pre_kem_transcript_hash",
                "protocol_id",
                "responder_policy_digest",
                "security_floor",
                "selected_suite",
                "transition_state_hash",
            ],
            "vector input",
        )?;
        require_exact_keys(
            expected,
            &["encoded_hex", "length", "sha256", "sha3_256"],
            "vector expected",
        )?;
        if required_u64(expected, "length")?
            != u64::try_from(MIGRATION_CONTEXT_V1_ENCODED_LEN)
                .map_err(|_| "encoded length does not fit u64".to_owned())?
        {
            return Err("vector expected length must be 315".to_owned());
        }
        let _: [u8; 32] = decode_hex(required_str(expected, "sha256")?)?;
        let _: [u8; 32] = decode_hex(required_str(expected, "sha3_256")?)?;
        let encapsulator_role = match required_str(input, "encapsulator_role")? {
            "initiator" => EndpointRole::Initiator,
            "responder" => EndpointRole::Responder,
            other => return Err(format!("unknown vector encapsulator role {other}")),
        };
        let selected_suite_code = required_u8(input, "selected_suite")?;
        let selected_suite = HybridSuite::from_u8(selected_suite_code)
            .ok_or_else(|| format!("unknown vector suite {selected_suite_code}"))?;
        let floor_code = required_u8(input, "security_floor")?;
        let effective_floor =
            SecurityFloor::from_nist_level(floor_code).map_err(|error| error.to_string())?;
        let scope = MigrationScopeV1::new(
            MigrationProtocolId::from_bytes(field_hex(input, "protocol_id")?),
            encapsulator_role,
            MigrationEpoch::new(required_u64(input, "migration_epoch")?)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let fields = CanonicalMigrationFieldsV1 {
            scope,
            initiator_policy_digest: PolicyDigest::from_authenticated_bytes(field_hex(
                input,
                "initiator_policy_digest",
            )?),
            responder_policy_digest: PolicyDigest::from_authenticated_bytes(field_hex(
                input,
                "responder_policy_digest",
            )?),
            capability_transcript_hash: CapabilityTranscriptHash::from_bytes(field_hex(
                input,
                "capability_transcript_hash",
            )?),
            selected_suite,
            effective_floor,
            transition_state_hash: TransitionStateHash::from_bytes(field_hex(
                input,
                "transition_state_hash",
            )?),
            pre_kem_transcript_hash: PreKemTranscriptHash::from_bytes(field_hex(
                input,
                "pre_kem_transcript_hash",
            )?),
        };
        let mut actual = [0u8; MIGRATION_CONTEXT_V1_ENCODED_LEN];
        fields
            .encode_into(&mut actual)
            .map_err(|error| error.to_string())?;
        let expected_bytes: [u8; MIGRATION_CONTEXT_V1_ENCODED_LEN] =
            decode_hex(required_str(expected, "encoded_hex")?)?;
        assert_eq!(actual, expected_bytes);
    }
    Ok(())
}
