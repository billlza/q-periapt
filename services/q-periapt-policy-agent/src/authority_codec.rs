//! Canonical codecs for Witness V2 authority values.
//!
//! This module is the single byte-level definition shared by durable Store V2
//! records and the authenticated Authority Wire V2 protocol. Protocol modules
//! may restrict which domain values they admit, but must not define a parallel
//! representation for those values.

use core::fmt;

use crate::authority::{
    AcceptedKeyIdV2, AcceptedKeyRecordV2, AcceptedKeyStatusV2, AuthorityDispositionV2,
    AuthorityIntentV2, AuthorityLimitsV2, AuthorityMutationV2, AuthorityReceiptV2,
    AuthorityRejectionV2, AuthorityRestoreErrorV2, AuthoritySnapshotV2, CapabilityIdV2,
    CapabilityRecordV2, ConfigAdvanceV2, DeploymentConfigRevisionV2, InstanceFenceV2,
    InstanceLeaseV2, OperationIdV2, ProcessInstanceIdV2, ReceiptLocatorV2, StateAdvanceV2,
    StateFenceV2, StateHeadV2, StateRevisionV2, StateTransitionKindV2,
};
use crate::codec::{encode_domain, require_domain, CodecError, Decoder, Encoder, MAX_FRAME_BYTES};

pub(crate) const STORE_SCHEMA_VERSION: u16 = 2;
pub(crate) const RECEIPT_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-RECEIPT/v2";
pub(crate) const CAPABILITY_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-CAPABILITY/v2";
pub(crate) const KEY_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-KEY/v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityCodecError {
    Allocation,
    Invalid,
}

impl fmt::Display for AuthorityCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "authority codec allocation failed",
            Self::Invalid => "authority codec value is not canonical",
        })
    }
}

impl std::error::Error for AuthorityCodecError {}

pub(crate) fn encode_operation_id(value: OperationIdV2) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[..8].copy_from_slice(&value.expected_authority_version().to_be_bytes());
    bytes[8..].copy_from_slice(value.random_id());
    bytes
}

pub(crate) fn decode_operation_id(bytes: &[u8]) -> Result<OperationIdV2, AuthorityCodecError> {
    if bytes.len() != 40 {
        return Err(AuthorityCodecError::Invalid);
    }
    OperationIdV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        suffix(bytes, 8)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_accepted_key_id(value: AcceptedKeyIdV2) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[..8].copy_from_slice(&value.state_global_generation().to_be_bytes());
    bytes[8..16].copy_from_slice(&value.lease_generation().to_be_bytes());
    bytes[16..].copy_from_slice(value.random_id());
    bytes
}

pub(crate) fn decode_accepted_key_id(bytes: &[u8]) -> Result<AcceptedKeyIdV2, AuthorityCodecError> {
    if bytes.len() != 48 {
        return Err(AuthorityCodecError::Invalid);
    }
    AcceptedKeyIdV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        decode_u64(field(bytes, 8, 16)?)?,
        suffix(bytes, 16)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_state_revision(value: StateRevisionV2) -> [u8; 80] {
    let mut bytes = [0u8; 80];
    bytes[..8].copy_from_slice(&value.global_generation().to_be_bytes());
    bytes[8..40].copy_from_slice(value.chain_id());
    bytes[40..48].copy_from_slice(&value.epoch().to_be_bytes());
    bytes[48..].copy_from_slice(value.digest());
    bytes
}

pub(crate) fn decode_state_revision(bytes: &[u8]) -> Result<StateRevisionV2, AuthorityCodecError> {
    if bytes.len() != 80 {
        return Err(AuthorityCodecError::Invalid);
    }
    StateRevisionV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        field(bytes, 8, 40)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
        decode_u64(field(bytes, 40, 48)?)?,
        suffix(bytes, 48)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_state_head(value: StateHeadV2) -> [u8; 112] {
    let mut bytes = [0u8; 112];
    bytes[..80].copy_from_slice(&encode_state_revision(value.revision()));
    bytes[80..].copy_from_slice(value.fence().as_bytes());
    bytes
}

pub(crate) fn decode_state_head(bytes: &[u8]) -> Result<StateHeadV2, AuthorityCodecError> {
    if bytes.len() != 112 {
        return Err(AuthorityCodecError::Invalid);
    }
    Ok(StateHeadV2::new(
        decode_state_revision(field(bytes, 0, 80)?)?,
        StateFenceV2::from_bytes(
            suffix(bytes, 80)?
                .try_into()
                .map_err(|_| AuthorityCodecError::Invalid)?,
        )
        .map_err(|_| AuthorityCodecError::Invalid)?,
    ))
}

pub(crate) fn encode_config(value: DeploymentConfigRevisionV2) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[..8].copy_from_slice(&value.generation().to_be_bytes());
    bytes[8..].copy_from_slice(value.digest());
    bytes
}

pub(crate) fn decode_config(
    bytes: &[u8],
) -> Result<DeploymentConfigRevisionV2, AuthorityCodecError> {
    if bytes.len() != 40 {
        return Err(AuthorityCodecError::Invalid);
    }
    DeploymentConfigRevisionV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        suffix(bytes, 8)?
            .try_into()
            .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_instance_fence(value: InstanceFenceV2) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[..8].copy_from_slice(&value.generation().to_be_bytes());
    bytes[8..].copy_from_slice(value.instance_id().as_bytes());
    bytes
}

pub(crate) fn decode_instance_fence(bytes: &[u8]) -> Result<InstanceFenceV2, AuthorityCodecError> {
    if bytes.len() != 40 {
        return Err(AuthorityCodecError::Invalid);
    }
    InstanceFenceV2::new(
        decode_u64(field(bytes, 0, 8)?)?,
        ProcessInstanceIdV2::from_bytes(
            suffix(bytes, 8)?
                .try_into()
                .map_err(|_| AuthorityCodecError::Invalid)?,
        )
        .map_err(|_| AuthorityCodecError::Invalid)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_lease(value: Option<InstanceLeaseV2>) -> Result<Vec<u8>, AuthorityCodecError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(if value.is_some() { 49 } else { 1 })
        .map_err(|_| AuthorityCodecError::Allocation)?;
    match value {
        None => bytes.push(0),
        Some(lease) => {
            bytes.push(1);
            bytes.extend_from_slice(&encode_instance_fence(lease.fence()));
            bytes.extend_from_slice(&lease.expires_at_millis().to_be_bytes());
        }
    }
    Ok(bytes)
}

pub(crate) fn decode_lease(bytes: &[u8]) -> Result<Option<InstanceLeaseV2>, AuthorityCodecError> {
    match bytes {
        [0] => Ok(None),
        [1, rest @ ..] if rest.len() == 48 => Ok(Some(InstanceLeaseV2::restore(
            decode_instance_fence(field(rest, 0, 40)?)?,
            decode_u64(suffix(rest, 40)?)?,
        ))),
        _ => Err(AuthorityCodecError::Invalid),
    }
}

pub(crate) fn encode_limits(value: AuthorityLimitsV2) -> Result<[u8; 32], AuthorityCodecError> {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(
        &u64::try_from(value.max_receipts())
            .map_err(|_| AuthorityCodecError::Invalid)?
            .to_be_bytes(),
    );
    bytes[8..16].copy_from_slice(
        &u64::try_from(value.max_capabilities())
            .map_err(|_| AuthorityCodecError::Invalid)?
            .to_be_bytes(),
    );
    bytes[16..24].copy_from_slice(
        &u64::try_from(value.max_keys())
            .map_err(|_| AuthorityCodecError::Invalid)?
            .to_be_bytes(),
    );
    bytes[24..].copy_from_slice(&value.lease_ttl_millis().to_be_bytes());
    Ok(bytes)
}

pub(crate) fn decode_limits(bytes: &[u8]) -> Result<AuthorityLimitsV2, AuthorityCodecError> {
    if bytes.len() != 32 {
        return Err(AuthorityCodecError::Invalid);
    }
    AuthorityLimitsV2::new(
        usize::try_from(decode_u64(field(bytes, 0, 8)?)?)
            .map_err(|_| AuthorityCodecError::Invalid)?,
        usize::try_from(decode_u64(field(bytes, 8, 16)?)?)
            .map_err(|_| AuthorityCodecError::Invalid)?,
        usize::try_from(decode_u64(field(bytes, 16, 24)?)?)
            .map_err(|_| AuthorityCodecError::Invalid)?,
        decode_u64(suffix(bytes, 24)?)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_receipt(value: AuthorityReceiptV2) -> Result<Vec<u8>, AuthorityCodecError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, RECEIPT_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    encode_intent(&mut encoder, value.intent())?;
    match value.disposition() {
        AuthorityDispositionV2::Applied => encoder.byte(1).map_err(map_codec)?,
        AuthorityDispositionV2::Rejected(rejection) => {
            encoder.byte(2).map_err(map_codec)?;
            encoder
                .byte(encode_rejection(rejection))
                .map_err(map_codec)?;
        }
    }
    encoder
        .u64(value.resulting_authority_version())
        .map_err(map_codec)?;
    Ok(encoder.finish())
}

pub(crate) fn decode_receipt(bytes: &[u8]) -> Result<AuthorityReceiptV2, AuthorityCodecError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, RECEIPT_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    let intent = decode_intent(&mut decoder)?;
    let disposition = match decoder.byte().map_err(map_codec)? {
        1 => AuthorityDispositionV2::Applied,
        2 => {
            AuthorityDispositionV2::Rejected(decode_rejection(decoder.byte().map_err(map_codec)?)?)
        }
        _ => return Err(AuthorityCodecError::Invalid),
    };
    let resulting_authority_version = decoder.u64().map_err(map_codec)?;
    decoder.finish().map_err(map_codec)?;
    AuthorityReceiptV2::restore(intent, disposition, resulting_authority_version)
        .map_err(map_restore)
}

pub(crate) fn encode_intent(
    encoder: &mut Encoder,
    value: AuthorityIntentV2,
) -> Result<(), AuthorityCodecError> {
    encoder
        .fixed(&encode_operation_id(value.operation_id()))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_config(value.expected_config()))
        .map_err(map_codec)?;
    match value.mutation() {
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation,
            instance_id,
        } => {
            encoder.byte(1).map_err(map_codec)?;
            encoder.u64(expected_lease_generation).map_err(map_codec)?;
            encoder.fixed(instance_id.as_bytes()).map_err(map_codec)
        }
        AuthorityMutationV2::RenewLease { fence } => {
            encoder.byte(2).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)
        }
        AuthorityMutationV2::ReleaseLease { fence } => {
            encoder.byte(3).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)
        }
        AuthorityMutationV2::AdvanceState { fence, advance } => {
            encoder.byte(4).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder
                .byte(match advance.kind() {
                    StateTransitionKindV2::Advance => 1,
                    StateTransitionKindV2::AuthorizedReset => 2,
                })
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_state_head(advance.expected()))
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_state_head(advance.next()))
                .map_err(map_codec)
        }
        AuthorityMutationV2::AdvanceConfig { fence, advance } => {
            encoder.byte(5).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_config(advance.expected()))
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_config(advance.next()))
                .map_err(map_codec)
        }
        AuthorityMutationV2::ConsumeCapability {
            fence,
            capability_id,
        } => {
            encoder.byte(6).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder.fixed(capability_id.as_bytes()).map_err(map_codec)
        }
        AuthorityMutationV2::RegisterKey {
            fence,
            capability_id,
            key_id,
        } => {
            encoder.byte(7).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder.fixed(capability_id.as_bytes()).map_err(map_codec)?;
            encoder
                .fixed(&encode_accepted_key_id(key_id))
                .map_err(map_codec)
        }
        AuthorityMutationV2::RevokeKey { fence, key_id } => {
            encoder.byte(8).map_err(map_codec)?;
            encoder
                .fixed(&encode_instance_fence(fence))
                .map_err(map_codec)?;
            encoder
                .fixed(&encode_accepted_key_id(key_id))
                .map_err(map_codec)
        }
    }
}

pub(crate) fn decode_intent(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityIntentV2, AuthorityCodecError> {
    let operation_id = decode_operation_id(decoder.fixed(40).map_err(map_codec)?)?;
    let expected_config = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
    let mutation = match decoder.byte().map_err(map_codec)? {
        1 => AuthorityMutationV2::AcquireLease {
            expected_lease_generation: decoder.u64().map_err(map_codec)?,
            instance_id: ProcessInstanceIdV2::from_bytes(decoder.array().map_err(map_codec)?)
                .map_err(|_| AuthorityCodecError::Invalid)?,
        },
        2 => AuthorityMutationV2::RenewLease {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
        },
        3 => AuthorityMutationV2::ReleaseLease {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
        },
        4 => {
            let fence = decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?;
            let kind = match decoder.byte().map_err(map_codec)? {
                1 => StateTransitionKindV2::Advance,
                2 => StateTransitionKindV2::AuthorizedReset,
                _ => return Err(AuthorityCodecError::Invalid),
            };
            let expected = decode_state_head(decoder.fixed(112).map_err(map_codec)?)?;
            let next = decode_state_head(decoder.fixed(112).map_err(map_codec)?)?;
            AuthorityMutationV2::AdvanceState {
                fence,
                advance: StateAdvanceV2::new(kind, expected, next)
                    .map_err(|_| AuthorityCodecError::Invalid)?,
            }
        }
        5 => {
            let fence = decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?;
            let expected = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
            let next = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
            AuthorityMutationV2::AdvanceConfig {
                fence,
                advance: ConfigAdvanceV2::new(expected, next)
                    .map_err(|_| AuthorityCodecError::Invalid)?,
            }
        }
        6 => AuthorityMutationV2::ConsumeCapability {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
            capability_id: CapabilityIdV2::from_bytes(decoder.array().map_err(map_codec)?)
                .map_err(|_| AuthorityCodecError::Invalid)?,
        },
        7 => AuthorityMutationV2::RegisterKey {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
            capability_id: CapabilityIdV2::from_bytes(decoder.array().map_err(map_codec)?)
                .map_err(|_| AuthorityCodecError::Invalid)?,
            key_id: decode_accepted_key_id(decoder.fixed(48).map_err(map_codec)?)?,
        },
        8 => AuthorityMutationV2::RevokeKey {
            fence: decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?,
            key_id: decode_accepted_key_id(decoder.fixed(48).map_err(map_codec)?)?,
        },
        _ => return Err(AuthorityCodecError::Invalid),
    };
    AuthorityIntentV2::new(
        operation_id,
        operation_id.expected_authority_version(),
        expected_config,
        mutation,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) const fn encode_rejection(value: AuthorityRejectionV2) -> u8 {
    match value {
        AuthorityRejectionV2::ConfigurationMismatch => 1,
        AuthorityRejectionV2::LeaseHeld => 2,
        AuthorityRejectionV2::LeaseGenerationMismatch => 3,
        AuthorityRejectionV2::LeaseAbsent => 4,
        AuthorityRejectionV2::LeaseExpired => 5,
        AuthorityRejectionV2::FenceMismatch => 6,
        AuthorityRejectionV2::LeaseRenewalNotExtended => 7,
        AuthorityRejectionV2::MutationOverflow => 8,
        AuthorityRejectionV2::StateMismatch => 9,
        AuthorityRejectionV2::ConfigTransitionMismatch => 10,
        AuthorityRejectionV2::CapabilityReplay => 11,
        AuthorityRejectionV2::CapabilityUnknown => 12,
        AuthorityRejectionV2::CapabilityStale => 13,
        AuthorityRejectionV2::CapabilityAlreadyBound => 14,
        AuthorityRejectionV2::KeyAlreadyRegistered => 15,
        AuthorityRejectionV2::KeyStateGenerationMismatch => 16,
        AuthorityRejectionV2::KeyLeaseGenerationMismatch => 17,
        AuthorityRejectionV2::KeyUnknown => 18,
        AuthorityRejectionV2::KeyRevoked => 19,
        AuthorityRejectionV2::CapabilityCapacityExceeded => 20,
        AuthorityRejectionV2::KeyCapacityExceeded => 21,
    }
}

pub(crate) fn decode_rejection(value: u8) -> Result<AuthorityRejectionV2, AuthorityCodecError> {
    match value {
        1 => Ok(AuthorityRejectionV2::ConfigurationMismatch),
        2 => Ok(AuthorityRejectionV2::LeaseHeld),
        3 => Ok(AuthorityRejectionV2::LeaseGenerationMismatch),
        4 => Ok(AuthorityRejectionV2::LeaseAbsent),
        5 => Ok(AuthorityRejectionV2::LeaseExpired),
        6 => Ok(AuthorityRejectionV2::FenceMismatch),
        7 => Ok(AuthorityRejectionV2::LeaseRenewalNotExtended),
        8 => Ok(AuthorityRejectionV2::MutationOverflow),
        9 => Ok(AuthorityRejectionV2::StateMismatch),
        10 => Ok(AuthorityRejectionV2::ConfigTransitionMismatch),
        11 => Ok(AuthorityRejectionV2::CapabilityReplay),
        12 => Ok(AuthorityRejectionV2::CapabilityUnknown),
        13 => Ok(AuthorityRejectionV2::CapabilityStale),
        14 => Ok(AuthorityRejectionV2::CapabilityAlreadyBound),
        15 => Ok(AuthorityRejectionV2::KeyAlreadyRegistered),
        16 => Ok(AuthorityRejectionV2::KeyStateGenerationMismatch),
        17 => Ok(AuthorityRejectionV2::KeyLeaseGenerationMismatch),
        18 => Ok(AuthorityRejectionV2::KeyUnknown),
        19 => Ok(AuthorityRejectionV2::KeyRevoked),
        20 => Ok(AuthorityRejectionV2::CapabilityCapacityExceeded),
        21 => Ok(AuthorityRejectionV2::KeyCapacityExceeded),
        _ => Err(AuthorityCodecError::Invalid),
    }
}

pub(crate) fn encode_capability_record(
    value: CapabilityRecordV2,
) -> Result<Vec<u8>, AuthorityCodecError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, CAPABILITY_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    encoder
        .fixed(&encode_state_head(value.state_head))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_config(value.config))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_instance_fence(value.consumed_by))
        .map_err(map_codec)?;
    match value.key_id {
        None => encoder.byte(0).map_err(map_codec)?,
        Some(key_id) => {
            encoder.byte(1).map_err(map_codec)?;
            encoder
                .fixed(&encode_accepted_key_id(key_id))
                .map_err(map_codec)?;
        }
    }
    Ok(encoder.finish())
}

pub(crate) fn decode_capability_record(
    bytes: &[u8],
) -> Result<CapabilityRecordV2, AuthorityCodecError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, CAPABILITY_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    let state_head = decode_state_head(decoder.fixed(112).map_err(map_codec)?)?;
    let config = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
    let consumed_by = decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?;
    let key_id = match decoder.byte().map_err(map_codec)? {
        0 => None,
        1 => Some(decode_accepted_key_id(
            decoder.fixed(48).map_err(map_codec)?,
        )?),
        _ => return Err(AuthorityCodecError::Invalid),
    };
    decoder.finish().map_err(map_codec)?;
    Ok(CapabilityRecordV2 {
        state_head,
        config,
        consumed_by,
        key_id,
    })
}

pub(crate) fn encode_key_record(
    value: AcceptedKeyRecordV2,
) -> Result<Vec<u8>, AuthorityCodecError> {
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut encoder, KEY_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    encoder
        .fixed(value.capability_id.as_bytes())
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_state_head(value.state_head))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_config(value.config))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_instance_fence(value.registered_by))
        .map_err(map_codec)?;
    encoder
        .byte(match value.status {
            AcceptedKeyStatusV2::Registered => 1,
            AcceptedKeyStatusV2::Revoked => 2,
        })
        .map_err(map_codec)?;
    Ok(encoder.finish())
}

pub(crate) fn decode_key_record(bytes: &[u8]) -> Result<AcceptedKeyRecordV2, AuthorityCodecError> {
    let mut decoder = Decoder::new(bytes);
    require_domain(&mut decoder, KEY_DOMAIN, STORE_SCHEMA_VERSION).map_err(map_codec)?;
    let capability_id = CapabilityIdV2::from_bytes(decoder.array().map_err(map_codec)?)
        .map_err(|_| AuthorityCodecError::Invalid)?;
    let state_head = decode_state_head(decoder.fixed(112).map_err(map_codec)?)?;
    let config = decode_config(decoder.fixed(40).map_err(map_codec)?)?;
    let registered_by = decode_instance_fence(decoder.fixed(40).map_err(map_codec)?)?;
    let status = match decoder.byte().map_err(map_codec)? {
        1 => AcceptedKeyStatusV2::Registered,
        2 => AcceptedKeyStatusV2::Revoked,
        _ => return Err(AuthorityCodecError::Invalid),
    };
    decoder.finish().map_err(map_codec)?;
    Ok(AcceptedKeyRecordV2 {
        capability_id,
        state_head,
        config,
        registered_by,
        status,
    })
}

pub(crate) fn encode_receipt_locator(value: ReceiptLocatorV2) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes[..40].copy_from_slice(&encode_operation_id(value.operation_id()));
    bytes[40..].copy_from_slice(&value.resulting_authority_version().to_be_bytes());
    bytes
}

pub(crate) fn decode_receipt_locator(
    bytes: &[u8],
) -> Result<ReceiptLocatorV2, AuthorityCodecError> {
    if bytes.len() != 48 {
        return Err(AuthorityCodecError::Invalid);
    }
    ReceiptLocatorV2::new(
        decode_operation_id(field(bytes, 0, 40)?)?,
        decode_u64(suffix(bytes, 40)?)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

pub(crate) fn encode_snapshot(
    encoder: &mut Encoder,
    value: AuthoritySnapshotV2,
) -> Result<(), AuthorityCodecError> {
    encoder.u64(value.authority_version()).map_err(map_codec)?;
    encoder.u64(value.clock_floor_millis()).map_err(map_codec)?;
    encoder
        .fixed(&encode_config(value.config()))
        .map_err(map_codec)?;
    encoder
        .fixed(&encode_state_head(value.state_head()))
        .map_err(map_codec)?;
    encoder.u64(value.lease_generation()).map_err(map_codec)?;
    encoder
        .lp16(&encode_lease(value.active_lease())?)
        .map_err(map_codec)?;
    for count in [
        value.receipt_count(),
        value.capability_count(),
        value.retained_key_count(),
        value.active_key_count(),
    ] {
        encoder
            .u64(u64::try_from(count).map_err(|_| AuthorityCodecError::Invalid)?)
            .map_err(map_codec)?;
    }
    Ok(())
}

pub(crate) fn decode_snapshot(
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritySnapshotV2, AuthorityCodecError> {
    AuthoritySnapshotV2::restore_wire(
        decoder.u64().map_err(map_codec)?,
        decoder.u64().map_err(map_codec)?,
        decode_config(decoder.fixed(40).map_err(map_codec)?)?,
        decode_state_head(decoder.fixed(112).map_err(map_codec)?)?,
        decoder.u64().map_err(map_codec)?,
        decode_lease(decoder.lp16(49).map_err(map_codec)?)?,
        decode_count(decoder.u64().map_err(map_codec)?)?,
        decode_count(decoder.u64().map_err(map_codec)?)?,
        decode_count(decoder.u64().map_err(map_codec)?)?,
        decode_count(decoder.u64().map_err(map_codec)?)?,
    )
    .map_err(|_| AuthorityCodecError::Invalid)
}

fn decode_count(value: u64) -> Result<usize, AuthorityCodecError> {
    usize::try_from(value).map_err(|_| AuthorityCodecError::Invalid)
}

fn decode_u64(bytes: &[u8]) -> Result<u64, AuthorityCodecError> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| AuthorityCodecError::Invalid)?,
    ))
}

fn field(bytes: &[u8], start: usize, end: usize) -> Result<&[u8], AuthorityCodecError> {
    bytes.get(start..end).ok_or(AuthorityCodecError::Invalid)
}

fn suffix(bytes: &[u8], start: usize) -> Result<&[u8], AuthorityCodecError> {
    bytes.get(start..).ok_or(AuthorityCodecError::Invalid)
}

fn map_codec(error: CodecError) -> AuthorityCodecError {
    match error {
        CodecError::Allocation => AuthorityCodecError::Allocation,
        CodecError::InvalidLength
        | CodecError::InvalidValue
        | CodecError::Io
        | CodecError::Oversized
        | CodecError::TrailingBytes
        | CodecError::Truncated => AuthorityCodecError::Invalid,
    }
}

fn map_restore(error: AuthorityRestoreErrorV2) -> AuthorityCodecError {
    match error {
        AuthorityRestoreErrorV2::Allocation => AuthorityCodecError::Allocation,
        AuthorityRestoreErrorV2::Invalid => AuthorityCodecError::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use q_periapt_backends::Sha3_256Xof;
    use q_periapt_core::Xof256;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn append_record(corpus: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AuthorityCodecError> {
        let length = u64::try_from(bytes.len()).map_err(|_| AuthorityCodecError::Invalid)?;
        let additional = 8usize
            .checked_add(bytes.len())
            .ok_or(AuthorityCodecError::Invalid)?;
        corpus
            .try_reserve_exact(additional)
            .map_err(|_| AuthorityCodecError::Allocation)?;
        corpus.extend_from_slice(&length.to_be_bytes());
        corpus.extend_from_slice(bytes);
        Ok(())
    }

    fn config(
        generation: u64,
        byte: u8,
    ) -> Result<DeploymentConfigRevisionV2, AuthorityCodecError> {
        DeploymentConfigRevisionV2::new(generation, [byte; 32])
            .map_err(|_| AuthorityCodecError::Invalid)
    }

    fn head(
        generation: u64,
        chain: u8,
        epoch: u64,
        digest: u8,
        fence: u8,
    ) -> Result<StateHeadV2, AuthorityCodecError> {
        Ok(StateHeadV2::new(
            StateRevisionV2::new(generation, [chain; 32], epoch, [digest; 32])
                .map_err(|_| AuthorityCodecError::Invalid)?,
            StateFenceV2::from_bytes([fence; 32]).map_err(|_| AuthorityCodecError::Invalid)?,
        ))
    }

    fn instance_fence(generation: u64, byte: u8) -> Result<InstanceFenceV2, AuthorityCodecError> {
        InstanceFenceV2::new(
            generation,
            ProcessInstanceIdV2::from_bytes([byte; 32])
                .map_err(|_| AuthorityCodecError::Invalid)?,
        )
        .map_err(|_| AuthorityCodecError::Invalid)
    }

    fn intent(
        version: u64,
        byte: u8,
        config: DeploymentConfigRevisionV2,
        mutation: AuthorityMutationV2,
    ) -> Result<AuthorityIntentV2, AuthorityCodecError> {
        AuthorityIntentV2::new(
            OperationIdV2::new(version, [byte; 32]).map_err(|_| AuthorityCodecError::Invalid)?,
            version,
            config,
            mutation,
        )
        .map_err(|_| AuthorityCodecError::Invalid)
    }

    fn receipt(
        intent: AuthorityIntentV2,
        disposition: AuthorityDispositionV2,
    ) -> Result<AuthorityReceiptV2, AuthorityCodecError> {
        AuthorityReceiptV2::restore(
            intent,
            disposition,
            intent
                .expected_authority_version()
                .checked_add(1)
                .ok_or(AuthorityCodecError::Invalid)?,
        )
        .map_err(map_restore)
    }

    #[test]
    fn store_v2_canonical_bytes_match_the_frozen_stage2a1_corpus() -> TestResult {
        // Level 1 reliability guard: detect accidental changes to already-persisted
        // Store V2 bytes. This digest is not a malicious-tamper authenticity claim.
        let mut corpus = Vec::new();
        let config_one = config(1, 0x31)?;
        let config_two = config(2, 0x32)?;
        let head_one = head(1, 0x41, 1, 0x51, 0x61)?;
        let head_two = head(2, 0x41, 2, 0x52, 0x62)?;
        let fence = instance_fence(1, 0x71)?;
        let capability_id = CapabilityIdV2::from_bytes([0x81; 32])?;
        let key_id = AcceptedKeyIdV2::new(1, 1, [0x91; 32])?;
        let limits = AuthorityLimitsV2::new(64, 32, 16, 10_000)?;

        // Store V2 meta and key primitives, in the persisted field order.
        append_record(&mut corpus, &1u64.to_be_bytes())?;
        append_record(&mut corpus, &10_000u64.to_be_bytes())?;
        append_record(&mut corpus, &encode_config(config_one))?;
        append_record(&mut corpus, &encode_state_head(head_one))?;
        append_record(&mut corpus, &1u64.to_be_bytes())?;
        append_record(
            &mut corpus,
            &encode_lease(Some(InstanceLeaseV2::restore(fence, 20_000)))?,
        )?;
        append_record(&mut corpus, &encode_limits(limits)?)?;
        append_record(
            &mut corpus,
            &encode_operation_id(OperationIdV2::new(1, [0x11; 32])?),
        )?;
        append_record(&mut corpus, &encode_accepted_key_id(key_id))?;
        append_record(&mut corpus, &encode_state_revision(head_one.revision()))?;
        append_record(&mut corpus, &encode_instance_fence(fence))?;

        let state_advance =
            StateAdvanceV2::new(StateTransitionKindV2::Advance, head_one, head_two)?;
        let config_advance = ConfigAdvanceV2::new(config_one, config_two)?;
        let mutations = [
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([0xa1; 32])?,
            },
            AuthorityMutationV2::RenewLease { fence },
            AuthorityMutationV2::ReleaseLease { fence },
            AuthorityMutationV2::AdvanceState {
                fence,
                advance: state_advance,
            },
            AuthorityMutationV2::AdvanceConfig {
                fence,
                advance: config_advance,
            },
            AuthorityMutationV2::ConsumeCapability {
                fence,
                capability_id,
            },
            AuthorityMutationV2::RegisterKey {
                fence,
                capability_id,
                key_id,
            },
            AuthorityMutationV2::RevokeKey { fence, key_id },
        ];
        for (index, mutation) in mutations.into_iter().enumerate() {
            let tag = u8::try_from(index + 1)?;
            let intent = intent(u64::from(tag), tag, config_one, mutation)?;
            let mut encoded_intent = Encoder::new(MAX_FRAME_BYTES);
            encode_intent(&mut encoded_intent, intent)?;
            append_record(&mut corpus, &encoded_intent.finish())?;
            append_record(
                &mut corpus,
                &encode_receipt(receipt(intent, AuthorityDispositionV2::Applied)?)?,
            )?;
        }
        let rejections = [
            AuthorityRejectionV2::ConfigurationMismatch,
            AuthorityRejectionV2::LeaseHeld,
            AuthorityRejectionV2::LeaseGenerationMismatch,
            AuthorityRejectionV2::LeaseAbsent,
            AuthorityRejectionV2::LeaseExpired,
            AuthorityRejectionV2::FenceMismatch,
            AuthorityRejectionV2::LeaseRenewalNotExtended,
            AuthorityRejectionV2::MutationOverflow,
            AuthorityRejectionV2::StateMismatch,
            AuthorityRejectionV2::ConfigTransitionMismatch,
            AuthorityRejectionV2::CapabilityReplay,
            AuthorityRejectionV2::CapabilityUnknown,
            AuthorityRejectionV2::CapabilityStale,
            AuthorityRejectionV2::CapabilityAlreadyBound,
            AuthorityRejectionV2::KeyAlreadyRegistered,
            AuthorityRejectionV2::KeyStateGenerationMismatch,
            AuthorityRejectionV2::KeyLeaseGenerationMismatch,
            AuthorityRejectionV2::KeyUnknown,
            AuthorityRejectionV2::KeyRevoked,
            AuthorityRejectionV2::CapabilityCapacityExceeded,
            AuthorityRejectionV2::KeyCapacityExceeded,
        ];
        for (index, rejection) in rejections.into_iter().enumerate() {
            let tag = u8::try_from(index + 1)?;
            append_record(&mut corpus, &[encode_rejection(rejection)])?;
            let intent = intent(
                u64::from(tag),
                tag,
                config_one,
                AuthorityMutationV2::AcquireLease {
                    expected_lease_generation: 0,
                    instance_id: ProcessInstanceIdV2::from_bytes([tag; 32])?,
                },
            )?;
            append_record(
                &mut corpus,
                &encode_receipt(receipt(
                    intent,
                    AuthorityDispositionV2::Rejected(rejection),
                )?)?,
            )?;
        }

        append_record(
            &mut corpus,
            &encode_capability_record(CapabilityRecordV2 {
                state_head: head_one,
                config: config_one,
                consumed_by: fence,
                key_id: Some(key_id),
            })?,
        )?;
        for status in [
            AcceptedKeyStatusV2::Registered,
            AcceptedKeyStatusV2::Revoked,
        ] {
            append_record(
                &mut corpus,
                &encode_key_record(AcceptedKeyRecordV2 {
                    capability_id,
                    state_head: head_one,
                    config: config_one,
                    registered_by: fence,
                    status,
                })?,
            )?;
        }

        let mut hash = Sha3_256Xof::new();
        hash.reserve(corpus.len());
        hash.absorb_public(&corpus);
        let digest = hash.squeeze32();
        assert_eq!(corpus.len(), 8_525);
        assert_eq!(
            digest,
            [
                0x12, 0x18, 0x70, 0xa6, 0xdb, 0x43, 0x1b, 0x26, 0x5b, 0xad, 0x6c, 0x76, 0xf9, 0xfe,
                0x20, 0xf3, 0xdb, 0x0d, 0x01, 0x90, 0x2f, 0x2d, 0xca, 0x5e, 0x1a, 0x3e, 0xd4, 0x27,
                0x5c, 0x9e, 0x63, 0x7b,
            ]
        );
        Ok(())
    }
}
