//! Closed authenticated Authority Wire V2 message grammar.

use core::fmt;

use crate::authority::{
    reachable_lease_receipt_kind, AuthorityEpochV2, AuthorityIntentV2, AuthorityMutationV2,
    AuthorityQueryResultV2, AuthorityReceiptV2, AuthoritySnapshotV2, AuthorityValueErrorV2,
    DeploymentConfigRevisionV2, LeaseMutationKindV2, OperationIdV2, ReceiptAckDispositionV2,
    ReceiptLocatorV2, StateHeadV2,
};
use crate::authority_codec::{
    decode_config, decode_intent, decode_operation_id, decode_receipt, decode_receipt_locator,
    decode_snapshot, encode_config, encode_intent, encode_operation_id, encode_receipt,
    encode_receipt_locator, encode_snapshot, encode_state_head, AuthorityCodecError,
};
use crate::codec::{encode_domain, require_domain, CodecError, Decoder, Encoder, MAX_FRAME_BYTES};

pub(crate) const AUTHORITY_REQUEST_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-WIRE-REQUEST/v2";
pub(crate) const AUTHORITY_RESPONSE_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-WIRE-RESPONSE/v2";
pub(crate) const AUTHORITY_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"Q-PERIAPT-AUTHORITY-WIRE-REQUEST-DIGEST/v2";
pub(crate) const AUTHORITY_WIRE_SCHEMA: u16 = 2;

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

macro_rules! wire_identifier {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Construct an identifier from exact nonzero bytes.
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, AuthorityValueErrorV2> {
                nonzero(&bytes)
                    .then_some(Self(bytes))
                    .ok_or(AuthorityValueErrorV2::InvalidIdentifier)
            }

            /// Borrow the exact opaque bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

wire_identifier!(
    AuthorityClientIdV2,
    "Pinned identity of the sole authenticated Authority Wire V2 client principal."
);
wire_identifier!(
    AuthorityServerIdV2,
    "Pinned identity of one authenticated Authority Wire V2 server."
);

/// Exact endpoint and authority-state binding shared by one client and server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityWireIdentityV2 {
    client_id: AuthorityClientIdV2,
    server_id: AuthorityServerIdV2,
    authority_epoch: AuthorityEpochV2,
    state_head: StateHeadV2,
    config: DeploymentConfigRevisionV2,
}

impl AuthorityWireIdentityV2 {
    /// Bind distinct endpoint identities to one exact authority epoch, state, and config.
    pub fn new(
        client_id: AuthorityClientIdV2,
        server_id: AuthorityServerIdV2,
        authority_epoch: AuthorityEpochV2,
        state_head: StateHeadV2,
        config: DeploymentConfigRevisionV2,
    ) -> Result<Self, AuthorityValueErrorV2> {
        if client_id.as_bytes() == server_id.as_bytes() {
            return Err(AuthorityValueErrorV2::InvalidIdentifier);
        }
        Ok(Self {
            client_id,
            server_id,
            authority_epoch,
            state_head,
            config,
        })
    }

    /// Return the sole authorized client identity.
    #[must_use]
    pub const fn client_id(self) -> AuthorityClientIdV2 {
        self.client_id
    }

    /// Return the expected server identity.
    #[must_use]
    pub const fn server_id(self) -> AuthorityServerIdV2 {
        self.server_id
    }

    /// Return the exact provisioned authority-store epoch.
    #[must_use]
    pub const fn authority_epoch(self) -> AuthorityEpochV2 {
        self.authority_epoch
    }

    /// Return the exact pinned migration-state head.
    #[must_use]
    pub const fn state_head(self) -> StateHeadV2 {
        self.state_head
    }

    /// Return the exact pinned deployment configuration.
    #[must_use]
    pub const fn config(self) -> DeploymentConfigRevisionV2 {
        self.config
    }
}

/// Closed, pre-dispatch or deterministic authority-service failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityKnownFailureV2 {
    /// The bounded authenticated nonce table is full; the request was not dispatched.
    RateLimited,
    /// A bounded allocation failed before a known store result could be returned.
    AllocationFailed,
    /// The trusted authority clock was unavailable.
    ClockUnavailable,
    /// An operation identifier was reused for a different lease intent.
    OperationConflict,
    /// The expected authority version was not current.
    AuthorityVersionMismatch,
    /// The authority version cannot advance further.
    AuthorityVersionExhausted,
    /// The retained receipt table is full.
    ReceiptCapacityExceeded,
    /// The exact receipt locator did not match retained state.
    ReceiptAcknowledgementMismatch,
}

/// Low-cardinality uncertainty after a request may have reached dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityUnknownV2 {
    /// A request write failed after at least one byte was accepted by the socket.
    RequestWriteIndeterminate,
    /// No complete response arrived before the absolute operation deadline.
    ResponseUnavailable,
    /// The response signature could not be authenticated.
    ResponseAuthenticationFailed,
    /// An authenticated response was malformed or did not match the request binding.
    ResponseInvalid,
    /// The server reported a fatal store quarantine and stopped serving.
    ServerQuarantined,
    /// The server observed this nonce before; the earlier request may have dispatched.
    ReplayDetected,
}

/// Exact known result, known failure, or explicit uncertain result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityOutcomeV2<T> {
    /// An authenticated exact command result.
    Known(T),
    /// An authenticated closed failure that proves no ambiguous store result.
    KnownFailure(AuthorityKnownFailureV2),
    /// The request may have reached dispatch or cannot be safely classified.
    Unknown(AuthorityUnknownV2),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum AuthorityCommandV2 {
    Snapshot = 1,
    Acquire = 2,
    Renew = 3,
    Release = 4,
    Query = 5,
    Ack = 6,
}

impl AuthorityCommandV2 {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Snapshot),
            2 => Some(Self::Acquire),
            3 => Some(Self::Renew),
            4 => Some(Self::Release),
            5 => Some(Self::Query),
            6 => Some(Self::Ack),
            _ => None,
        }
    }
}

// Payloads stay `Copy` so requests can be rebuilt and compared without heap
// allocation; the one large lease-intent variant is a short-lived stack value.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityRequestPayloadV2 {
    Snapshot,
    LeaseIntent(AuthorityIntentV2),
    Query(OperationIdV2),
    Ack(ReceiptLocatorV2),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityRequestV2 {
    pub(crate) client_id: AuthorityClientIdV2,
    pub(crate) server_id: AuthorityServerIdV2,
    pub(crate) authority_epoch: AuthorityEpochV2,
    pub(crate) expected_state_head: StateHeadV2,
    pub(crate) expected_config: DeploymentConfigRevisionV2,
    pub(crate) nonce: [u8; 32],
    pub(crate) command: AuthorityCommandV2,
    pub(crate) payload: AuthorityRequestPayloadV2,
}

impl AuthorityRequestV2 {
    pub(crate) fn new(
        identity: AuthorityWireIdentityV2,
        nonce: [u8; 32],
        command: AuthorityCommandV2,
        payload: AuthorityRequestPayloadV2,
    ) -> Result<Self, AuthorityProtocolErrorV2> {
        if !nonzero(&nonce) || !request_shape_is_valid(command, payload) {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        if matches!(payload, AuthorityRequestPayloadV2::LeaseIntent(intent)
            if intent.expected_config() != identity.config)
        {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        Ok(Self {
            client_id: identity.client_id,
            server_id: identity.server_id,
            authority_epoch: identity.authority_epoch,
            expected_state_head: identity.state_head,
            expected_config: identity.config,
            nonce,
            command,
            payload,
        })
    }

    pub(crate) fn body(&self) -> Result<Vec<u8>, AuthorityProtocolErrorV2> {
        if !nonzero(&self.nonce)
            || self.client_id.as_bytes() == self.server_id.as_bytes()
            || !request_shape_is_valid(self.command, self.payload)
            || matches!(self.payload, AuthorityRequestPayloadV2::LeaseIntent(intent)
                if intent.expected_config() != self.expected_config)
        {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(
            &mut encoder,
            AUTHORITY_REQUEST_DOMAIN,
            AUTHORITY_WIRE_SCHEMA,
        )
        .map_err(map_codec)?;
        encoder
            .fixed(self.client_id.as_bytes())
            .map_err(map_codec)?;
        encoder
            .fixed(self.server_id.as_bytes())
            .map_err(map_codec)?;
        encoder
            .fixed(self.authority_epoch.as_bytes())
            .map_err(map_codec)?;
        encoder
            .fixed(&encode_state_head(self.expected_state_head))
            .map_err(map_codec)?;
        encoder
            .fixed(&encode_config(self.expected_config))
            .map_err(map_codec)?;
        encoder.fixed(&self.nonce).map_err(map_codec)?;
        encoder.byte(self.command as u8).map_err(map_codec)?;
        match self.payload {
            AuthorityRequestPayloadV2::Snapshot => {}
            AuthorityRequestPayloadV2::LeaseIntent(intent) => {
                encode_intent(&mut encoder, intent).map_err(map_authority_codec)?;
            }
            AuthorityRequestPayloadV2::Query(operation_id) => encoder
                .fixed(&encode_operation_id(operation_id))
                .map_err(map_codec)?,
            AuthorityRequestPayloadV2::Ack(locator) => encoder
                .fixed(&encode_receipt_locator(locator))
                .map_err(map_codec)?,
        }
        Ok(encoder.finish())
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Self, AuthorityProtocolErrorV2> {
        let mut decoder = Decoder::new(body);
        require_domain(
            &mut decoder,
            AUTHORITY_REQUEST_DOMAIN,
            AUTHORITY_WIRE_SCHEMA,
        )
        .map_err(map_codec)?;
        let client_id = AuthorityClientIdV2::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV2::Invalid)?;
        let server_id = AuthorityServerIdV2::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV2::Invalid)?;
        if client_id.as_bytes() == server_id.as_bytes() {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        let authority_epoch = AuthorityEpochV2::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV2::Invalid)?;
        let expected_state_head =
            crate::authority_codec::decode_state_head(decoder.fixed(112).map_err(map_codec)?)
                .map_err(map_authority_codec)?;
        let expected_config =
            decode_config(decoder.fixed(40).map_err(map_codec)?).map_err(map_authority_codec)?;
        let nonce = decoder.array().map_err(map_codec)?;
        if !nonzero(&nonce) {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        let command = AuthorityCommandV2::from_u8(decoder.byte().map_err(map_codec)?)
            .ok_or(AuthorityProtocolErrorV2::Invalid)?;
        let payload = match command {
            AuthorityCommandV2::Snapshot => AuthorityRequestPayloadV2::Snapshot,
            AuthorityCommandV2::Acquire
            | AuthorityCommandV2::Renew
            | AuthorityCommandV2::Release => {
                let intent = decode_intent(&mut decoder).map_err(map_authority_codec)?;
                AuthorityRequestPayloadV2::LeaseIntent(intent)
            }
            AuthorityCommandV2::Query => AuthorityRequestPayloadV2::Query(
                decode_operation_id(decoder.fixed(40).map_err(map_codec)?)
                    .map_err(map_authority_codec)?,
            ),
            AuthorityCommandV2::Ack => AuthorityRequestPayloadV2::Ack(
                decode_receipt_locator(decoder.fixed(48).map_err(map_codec)?)
                    .map_err(map_authority_codec)?,
            ),
        };
        decoder.finish().map_err(map_codec)?;
        if !request_shape_is_valid(command, payload)
            || matches!(payload, AuthorityRequestPayloadV2::LeaseIntent(intent)
                if intent.expected_config() != expected_config)
        {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        Ok(Self {
            client_id,
            server_id,
            authority_epoch,
            expected_state_head,
            expected_config,
            nonce,
            command,
            payload,
        })
    }
}

fn request_shape_is_valid(command: AuthorityCommandV2, payload: AuthorityRequestPayloadV2) -> bool {
    match (command, payload) {
        (AuthorityCommandV2::Snapshot, AuthorityRequestPayloadV2::Snapshot)
        | (AuthorityCommandV2::Query, AuthorityRequestPayloadV2::Query(_))
        | (AuthorityCommandV2::Ack, AuthorityRequestPayloadV2::Ack(_)) => true,
        (
            AuthorityCommandV2::Acquire | AuthorityCommandV2::Renew | AuthorityCommandV2::Release,
            AuthorityRequestPayloadV2::LeaseIntent(intent),
        ) => lease_command(intent.mutation()) == Some(command),
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuthoritySuccessV2 {
    Snapshot(Box<AuthoritySnapshotV2>),
    Receipt(Box<AuthorityReceiptV2>),
    Query(AuthorityQueryResultV2),
    Ack(ReceiptAckDispositionV2),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityResponseDispositionV2 {
    Success(AuthoritySuccessV2),
    KnownFailure(AuthorityKnownFailureV2),
    ReplayDetected,
    ServerQuarantined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityResponseV2 {
    pub(crate) server_id: AuthorityServerIdV2,
    pub(crate) client_id: AuthorityClientIdV2,
    pub(crate) authority_epoch: AuthorityEpochV2,
    pub(crate) nonce: [u8; 32],
    pub(crate) command: AuthorityCommandV2,
    pub(crate) request_digest: [u8; 32],
    pub(crate) disposition: AuthorityResponseDispositionV2,
}

impl AuthorityResponseV2 {
    pub(crate) fn body(&self) -> Result<Vec<u8>, AuthorityProtocolErrorV2> {
        if !nonzero(&self.nonce) || self.client_id.as_bytes() == self.server_id.as_bytes() {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(
            &mut encoder,
            AUTHORITY_RESPONSE_DOMAIN,
            AUTHORITY_WIRE_SCHEMA,
        )
        .map_err(map_codec)?;
        encoder
            .fixed(self.server_id.as_bytes())
            .map_err(map_codec)?;
        encoder
            .fixed(self.client_id.as_bytes())
            .map_err(map_codec)?;
        encoder
            .fixed(self.authority_epoch.as_bytes())
            .map_err(map_codec)?;
        encoder.fixed(&self.nonce).map_err(map_codec)?;
        encoder.byte(self.command as u8).map_err(map_codec)?;
        encoder.fixed(&self.request_digest).map_err(map_codec)?;
        match &self.disposition {
            AuthorityResponseDispositionV2::Success(success) => {
                encoder.byte(1).map_err(map_codec)?;
                encode_success(&mut encoder, self.command, success)?;
            }
            AuthorityResponseDispositionV2::KnownFailure(failure)
                if failure_is_valid_for_command(self.command, *failure) =>
            {
                encoder.byte(2).map_err(map_codec)?;
                encoder.byte(encode_failure(*failure)).map_err(map_codec)?;
            }
            AuthorityResponseDispositionV2::KnownFailure(_) => {
                return Err(AuthorityProtocolErrorV2::Invalid);
            }
            AuthorityResponseDispositionV2::ReplayDetected => {
                encoder.byte(3).map_err(map_codec)?;
            }
            AuthorityResponseDispositionV2::ServerQuarantined => {
                encoder.byte(4).map_err(map_codec)?;
            }
        }
        Ok(encoder.finish())
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Self, AuthorityProtocolErrorV2> {
        let mut decoder = Decoder::new(body);
        require_domain(
            &mut decoder,
            AUTHORITY_RESPONSE_DOMAIN,
            AUTHORITY_WIRE_SCHEMA,
        )
        .map_err(map_codec)?;
        let server_id = AuthorityServerIdV2::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV2::Invalid)?;
        let client_id = AuthorityClientIdV2::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV2::Invalid)?;
        if client_id.as_bytes() == server_id.as_bytes() {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        let authority_epoch = AuthorityEpochV2::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV2::Invalid)?;
        let nonce = decoder.array().map_err(map_codec)?;
        if !nonzero(&nonce) {
            return Err(AuthorityProtocolErrorV2::Invalid);
        }
        let command = AuthorityCommandV2::from_u8(decoder.byte().map_err(map_codec)?)
            .ok_or(AuthorityProtocolErrorV2::Invalid)?;
        let request_digest = decoder.array().map_err(map_codec)?;
        let disposition = match decoder.byte().map_err(map_codec)? {
            1 => AuthorityResponseDispositionV2::Success(decode_success(&mut decoder, command)?),
            2 => {
                let failure = decode_failure(decoder.byte().map_err(map_codec)?)?;
                if !failure_is_valid_for_command(command, failure) {
                    return Err(AuthorityProtocolErrorV2::Invalid);
                }
                AuthorityResponseDispositionV2::KnownFailure(failure)
            }
            3 => AuthorityResponseDispositionV2::ReplayDetected,
            4 => AuthorityResponseDispositionV2::ServerQuarantined,
            _ => return Err(AuthorityProtocolErrorV2::Invalid),
        };
        decoder.finish().map_err(map_codec)?;
        Ok(Self {
            server_id,
            client_id,
            authority_epoch,
            nonce,
            command,
            request_digest,
            disposition,
        })
    }
}

fn encode_success(
    encoder: &mut Encoder,
    command: AuthorityCommandV2,
    success: &AuthoritySuccessV2,
) -> Result<(), AuthorityProtocolErrorV2> {
    match (command, success) {
        (AuthorityCommandV2::Snapshot, AuthoritySuccessV2::Snapshot(snapshot))
            if snapshot_is_wire_safe(**snapshot) =>
        {
            encode_snapshot(encoder, **snapshot).map_err(map_authority_codec)
        }
        (
            AuthorityCommandV2::Acquire | AuthorityCommandV2::Renew | AuthorityCommandV2::Release,
            AuthoritySuccessV2::Receipt(receipt),
        ) if receipt_command(receipt) == Some(command) => encoder
            .lp16(&encode_receipt(**receipt).map_err(map_authority_codec)?)
            .map_err(map_codec),
        (AuthorityCommandV2::Query, AuthoritySuccessV2::Query(result)) => {
            encode_query_result(encoder, result)
        }
        (AuthorityCommandV2::Ack, AuthoritySuccessV2::Ack(disposition)) => encoder
            .byte(match disposition {
                ReceiptAckDispositionV2::Removed => 1,
                ReceiptAckDispositionV2::AlreadyAbsent => 2,
            })
            .map_err(map_codec),
        _ => Err(AuthorityProtocolErrorV2::Invalid),
    }
}

fn decode_success(
    decoder: &mut Decoder<'_>,
    command: AuthorityCommandV2,
) -> Result<AuthoritySuccessV2, AuthorityProtocolErrorV2> {
    match command {
        AuthorityCommandV2::Snapshot => {
            let snapshot = decode_snapshot(decoder).map_err(map_authority_codec)?;
            if !snapshot_is_wire_safe(snapshot) {
                return Err(AuthorityProtocolErrorV2::Invalid);
            }
            Ok(AuthoritySuccessV2::Snapshot(Box::new(snapshot)))
        }
        AuthorityCommandV2::Acquire | AuthorityCommandV2::Renew | AuthorityCommandV2::Release => {
            let receipt = decode_receipt(decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?)
                .map_err(map_authority_codec)?;
            if receipt_command(&receipt) != Some(command) {
                return Err(AuthorityProtocolErrorV2::Invalid);
            }
            Ok(AuthoritySuccessV2::Receipt(Box::new(receipt)))
        }
        AuthorityCommandV2::Query => Ok(AuthoritySuccessV2::Query(decode_query_result(decoder)?)),
        AuthorityCommandV2::Ack => Ok(AuthoritySuccessV2::Ack(
            match decoder.byte().map_err(map_codec)? {
                1 => ReceiptAckDispositionV2::Removed,
                2 => ReceiptAckDispositionV2::AlreadyAbsent,
                _ => return Err(AuthorityProtocolErrorV2::Invalid),
            },
        )),
    }
}

fn encode_query_result(
    encoder: &mut Encoder,
    result: &AuthorityQueryResultV2,
) -> Result<(), AuthorityProtocolErrorV2> {
    match result {
        AuthorityQueryResultV2::Found(receipt) if receipt_command(receipt).is_some() => {
            encoder.byte(1).map_err(map_codec)?;
            encoder
                .lp16(&encode_receipt(**receipt).map_err(map_authority_codec)?)
                .map_err(map_codec)
        }
        AuthorityQueryResultV2::AbsentAtVersion { authority_version }
            if *authority_version != 0 =>
        {
            encoder.byte(2).map_err(map_codec)?;
            encoder.u64(*authority_version).map_err(map_codec)
        }
        _ => Err(AuthorityProtocolErrorV2::Invalid),
    }
}

fn decode_query_result(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityQueryResultV2, AuthorityProtocolErrorV2> {
    match decoder.byte().map_err(map_codec)? {
        1 => {
            let receipt = decode_receipt(decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?)
                .map_err(map_authority_codec)?;
            if receipt_command(&receipt).is_none() {
                return Err(AuthorityProtocolErrorV2::Invalid);
            }
            Ok(AuthorityQueryResultV2::Found(Box::new(receipt)))
        }
        2 => {
            let authority_version = decoder.u64().map_err(map_codec)?;
            if authority_version == 0 {
                return Err(AuthorityProtocolErrorV2::Invalid);
            }
            Ok(AuthorityQueryResultV2::AbsentAtVersion { authority_version })
        }
        _ => Err(AuthorityProtocolErrorV2::Invalid),
    }
}

const fn encode_failure(failure: AuthorityKnownFailureV2) -> u8 {
    match failure {
        AuthorityKnownFailureV2::RateLimited => 1,
        AuthorityKnownFailureV2::AllocationFailed => 2,
        AuthorityKnownFailureV2::ClockUnavailable => 3,
        AuthorityKnownFailureV2::OperationConflict => 4,
        AuthorityKnownFailureV2::AuthorityVersionMismatch => 5,
        AuthorityKnownFailureV2::AuthorityVersionExhausted => 6,
        AuthorityKnownFailureV2::ReceiptCapacityExceeded => 7,
        AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch => 8,
    }
}

fn decode_failure(value: u8) -> Result<AuthorityKnownFailureV2, AuthorityProtocolErrorV2> {
    match value {
        1 => Ok(AuthorityKnownFailureV2::RateLimited),
        2 => Ok(AuthorityKnownFailureV2::AllocationFailed),
        3 => Ok(AuthorityKnownFailureV2::ClockUnavailable),
        4 => Ok(AuthorityKnownFailureV2::OperationConflict),
        5 => Ok(AuthorityKnownFailureV2::AuthorityVersionMismatch),
        6 => Ok(AuthorityKnownFailureV2::AuthorityVersionExhausted),
        7 => Ok(AuthorityKnownFailureV2::ReceiptCapacityExceeded),
        8 => Ok(AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch),
        _ => Err(AuthorityProtocolErrorV2::Invalid),
    }
}

pub(crate) fn lease_command(mutation: AuthorityMutationV2) -> Option<AuthorityCommandV2> {
    match mutation {
        AuthorityMutationV2::AcquireLease { .. } => Some(AuthorityCommandV2::Acquire),
        AuthorityMutationV2::RenewLease { .. } => Some(AuthorityCommandV2::Renew),
        AuthorityMutationV2::ReleaseLease { .. } => Some(AuthorityCommandV2::Release),
        AuthorityMutationV2::AdvanceState { .. }
        | AuthorityMutationV2::AdvanceConfig { .. }
        | AuthorityMutationV2::ConsumeCapability { .. }
        | AuthorityMutationV2::RegisterKey { .. }
        | AuthorityMutationV2::RevokeKey { .. } => None,
    }
}

pub(crate) fn receipt_command(receipt: &AuthorityReceiptV2) -> Option<AuthorityCommandV2> {
    match reachable_lease_receipt_kind(receipt)? {
        LeaseMutationKindV2::Acquire => Some(AuthorityCommandV2::Acquire),
        LeaseMutationKindV2::Renew => Some(AuthorityCommandV2::Renew),
        LeaseMutationKindV2::Release => Some(AuthorityCommandV2::Release),
    }
}

fn failure_is_valid_for_command(
    command: AuthorityCommandV2,
    failure: AuthorityKnownFailureV2,
) -> bool {
    match failure {
        AuthorityKnownFailureV2::RateLimited | AuthorityKnownFailureV2::AllocationFailed => true,
        AuthorityKnownFailureV2::ClockUnavailable => matches!(
            command,
            AuthorityCommandV2::Snapshot
                | AuthorityCommandV2::Acquire
                | AuthorityCommandV2::Renew
                | AuthorityCommandV2::Release
        ),
        AuthorityKnownFailureV2::OperationConflict
        | AuthorityKnownFailureV2::AuthorityVersionMismatch
        | AuthorityKnownFailureV2::AuthorityVersionExhausted
        | AuthorityKnownFailureV2::ReceiptCapacityExceeded => matches!(
            command,
            AuthorityCommandV2::Acquire | AuthorityCommandV2::Renew | AuthorityCommandV2::Release
        ),
        AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch => {
            command == AuthorityCommandV2::Ack
        }
    }
}

fn snapshot_is_wire_safe(snapshot: AuthoritySnapshotV2) -> bool {
    snapshot.capability_count() == 0
        && snapshot.retained_key_count() == 0
        && snapshot.active_key_count() == 0
}

/// One wire lease receipt whose caller asserts a durable record of the operation.
///
/// Acknowledgement lets the authority server prune its bounded retained-receipt
/// table. The wrapper cannot observe the caller's storage; constructing it is the
/// caller's explicit statement that it has already committed, with its own
/// durability, whatever it needs to settle this operation without the server's
/// copy, so a later crash cannot lose an outcome the server is now allowed to
/// forget.
///
/// For the policy agent that record is the operation id, journaled in its
/// repository before the intent is dispatched (`StateRepository::journal_lease_intent`),
/// not the receipt bytes: a successor process queries every journaled id,
/// acknowledges the receipt it finds still retained, and forgets the row. The
/// server therefore keeps a receipt exactly until it is acknowledged, and an
/// acknowledgement lost with the process is repeated at the next start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurablyRetainedAuthorityReceiptV2(AuthorityReceiptV2);

impl DurablyRetainedAuthorityReceiptV2 {
    /// Wrap one acknowledgeable wire lease receipt whose operation the caller
    /// has durably recorded.
    ///
    /// Non-lease or wire-unreachable receipts are rejected instead of being
    /// silently acknowledged.
    pub fn after_durable_commit(
        receipt: AuthorityReceiptV2,
    ) -> Result<Self, AuthorityValueErrorV2> {
        receipt_command(&receipt)
            .map(|_| Self(receipt))
            .ok_or(AuthorityValueErrorV2::InvalidTransition)
    }

    /// Return the exact locator that identifies the retained receipt.
    #[must_use]
    pub const fn locator(&self) -> ReceiptLocatorV2 {
        self.0.locator()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityProtocolErrorV2 {
    Allocation,
    Invalid,
}

impl fmt::Display for AuthorityProtocolErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "authority wire bounded allocation failed",
            Self::Invalid => "authority wire message is invalid",
        })
    }
}

impl std::error::Error for AuthorityProtocolErrorV2 {}

fn map_codec(error: CodecError) -> AuthorityProtocolErrorV2 {
    match error {
        CodecError::Allocation => AuthorityProtocolErrorV2::Allocation,
        CodecError::InvalidLength
        | CodecError::InvalidValue
        | CodecError::Io
        | CodecError::Oversized
        | CodecError::TrailingBytes
        | CodecError::Truncated => AuthorityProtocolErrorV2::Invalid,
    }
}

fn map_authority_codec(error: AuthorityCodecError) -> AuthorityProtocolErrorV2 {
    match error {
        AuthorityCodecError::Allocation => AuthorityProtocolErrorV2::Allocation,
        AuthorityCodecError::Invalid => AuthorityProtocolErrorV2::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use q_periapt_backends::Sha3_256Xof;
    use q_periapt_core::Xof256;

    use super::*;
    use crate::authority::{
        AuthorityDispositionV2, AuthorityLimitsV2, AuthorityRejectionV2, InstanceFenceV2,
        ProcessInstanceIdV2, StateAdvanceV2, StateFenceV2, StateRevisionV2, StateTransitionKindV2,
    };
    use crate::codec::hash_fields;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn config(
        generation: u64,
        byte: u8,
    ) -> Result<DeploymentConfigRevisionV2, AuthorityValueErrorV2> {
        DeploymentConfigRevisionV2::new(generation, [byte; 32])
    }

    fn head(
        generation: u64,
        chain: u8,
        epoch: u64,
        digest: u8,
        fence: u8,
    ) -> Result<StateHeadV2, AuthorityValueErrorV2> {
        Ok(StateHeadV2::new(
            StateRevisionV2::new(generation, [chain; 32], epoch, [digest; 32])?,
            StateFenceV2::from_bytes([fence; 32])?,
        ))
    }

    fn identity() -> Result<AuthorityWireIdentityV2, AuthorityValueErrorV2> {
        AuthorityWireIdentityV2::new(
            AuthorityClientIdV2::from_bytes([0x11; 32])?,
            AuthorityServerIdV2::from_bytes([0x12; 32])?,
            AuthorityEpochV2::from_bytes([0x13; 32])?,
            head(1, 0x21, 1, 0x22, 0x23)?,
            config(1, 0x31)?,
        )
    }

    fn operation(version: u64, byte: u8) -> Result<OperationIdV2, AuthorityValueErrorV2> {
        OperationIdV2::new(version, [byte; 32])
    }

    fn fence() -> Result<InstanceFenceV2, AuthorityValueErrorV2> {
        InstanceFenceV2::new(1, ProcessInstanceIdV2::from_bytes([0x41; 32])?)
    }

    fn acquire_intent() -> Result<AuthorityIntentV2, AuthorityValueErrorV2> {
        AuthorityIntentV2::new(
            operation(1, 0x51)?,
            1,
            config(1, 0x31)?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([0x42; 32])?,
            },
        )
    }

    fn renew_intent() -> Result<AuthorityIntentV2, AuthorityValueErrorV2> {
        AuthorityIntentV2::new(
            operation(2, 0x52)?,
            2,
            config(1, 0x31)?,
            AuthorityMutationV2::RenewLease { fence: fence()? },
        )
    }

    fn release_intent() -> Result<AuthorityIntentV2, AuthorityValueErrorV2> {
        AuthorityIntentV2::new(
            operation(3, 0x53)?,
            3,
            config(1, 0x31)?,
            AuthorityMutationV2::ReleaseLease { fence: fence()? },
        )
    }

    fn receipt(
        intent: AuthorityIntentV2,
        disposition: AuthorityDispositionV2,
    ) -> Result<AuthorityReceiptV2, AuthorityProtocolErrorV2> {
        AuthorityReceiptV2::restore(
            intent,
            disposition,
            intent
                .expected_authority_version()
                .checked_add(1)
                .ok_or(AuthorityProtocolErrorV2::Invalid)?,
        )
        .map_err(|_| AuthorityProtocolErrorV2::Invalid)
    }

    fn snapshot() -> Result<AuthoritySnapshotV2, AuthorityValueErrorV2> {
        AuthoritySnapshotV2::restore_wire(
            1,
            10_000,
            config(1, 0x31)?,
            head(1, 0x21, 1, 0x22, 0x23)?,
            0,
            None,
            0,
            0,
            0,
            0,
        )
    }

    fn append(corpus: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AuthorityProtocolErrorV2> {
        let length = u64::try_from(bytes.len()).map_err(|_| AuthorityProtocolErrorV2::Invalid)?;
        let additional = 8usize
            .checked_add(bytes.len())
            .ok_or(AuthorityProtocolErrorV2::Invalid)?;
        corpus
            .try_reserve_exact(additional)
            .map_err(|_| AuthorityProtocolErrorV2::Allocation)?;
        corpus.extend_from_slice(&length.to_be_bytes());
        corpus.extend_from_slice(bytes);
        Ok(())
    }

    fn fixture_digest(bytes: &[u8]) -> [u8; 32] {
        let mut hash = Sha3_256Xof::new();
        hash.reserve(bytes.len());
        hash.absorb_public(bytes);
        hash.squeeze32()
    }

    fn response_prefix(
        identity: AuthorityWireIdentityV2,
        nonce: [u8; 32],
        command: AuthorityCommandV2,
        request_digest: [u8; 32],
    ) -> Result<Encoder, AuthorityProtocolErrorV2> {
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(
            &mut encoder,
            AUTHORITY_RESPONSE_DOMAIN,
            AUTHORITY_WIRE_SCHEMA,
        )
        .map_err(map_codec)?;
        encoder
            .fixed(identity.server_id().as_bytes())
            .map_err(map_codec)?;
        encoder
            .fixed(identity.client_id().as_bytes())
            .map_err(map_codec)?;
        encoder
            .fixed(identity.authority_epoch().as_bytes())
            .map_err(map_codec)?;
        encoder.fixed(&nonce).map_err(map_codec)?;
        encoder.byte(command as u8).map_err(map_codec)?;
        encoder.fixed(&request_digest).map_err(map_codec)?;
        Ok(encoder)
    }

    #[test]
    fn six_command_request_and_response_bytes_are_frozen() -> TestResult {
        let identity = identity()?;
        let acquire = acquire_intent()?;
        let renew = renew_intent()?;
        let release = release_intent()?;
        let acquire_receipt = receipt(acquire, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        let renew_receipt = receipt(renew, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        let release_receipt = receipt(release, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        let requests = [
            AuthorityRequestV2::new(
                identity,
                [1; 32],
                AuthorityCommandV2::Snapshot,
                AuthorityRequestPayloadV2::Snapshot,
            )?,
            AuthorityRequestV2::new(
                identity,
                [2; 32],
                AuthorityCommandV2::Acquire,
                AuthorityRequestPayloadV2::LeaseIntent(acquire),
            )?,
            AuthorityRequestV2::new(
                identity,
                [3; 32],
                AuthorityCommandV2::Renew,
                AuthorityRequestPayloadV2::LeaseIntent(renew),
            )?,
            AuthorityRequestV2::new(
                identity,
                [4; 32],
                AuthorityCommandV2::Release,
                AuthorityRequestPayloadV2::LeaseIntent(release),
            )?,
            AuthorityRequestV2::new(
                identity,
                [5; 32],
                AuthorityCommandV2::Query,
                AuthorityRequestPayloadV2::Query(acquire.operation_id()),
            )?,
            AuthorityRequestV2::new(
                identity,
                [6; 32],
                AuthorityCommandV2::Ack,
                AuthorityRequestPayloadV2::Ack(acquire_receipt.locator()),
            )?,
        ];
        let successes = [
            AuthoritySuccessV2::Snapshot(Box::new(snapshot()?)),
            AuthoritySuccessV2::Receipt(Box::new(acquire_receipt)),
            AuthoritySuccessV2::Receipt(Box::new(renew_receipt)),
            AuthoritySuccessV2::Receipt(Box::new(release_receipt)),
            AuthoritySuccessV2::Query(AuthorityQueryResultV2::Found(Box::new(acquire_receipt))),
            AuthoritySuccessV2::Ack(ReceiptAckDispositionV2::Removed),
        ];
        let mut corpus = Vec::new();
        let mut request_vectors = Vec::new();
        let mut request_digests = Vec::new();
        let mut response_vectors = Vec::new();
        for (request, success) in requests.into_iter().zip(successes) {
            let request_body = request.body()?;
            assert_eq!(AuthorityRequestV2::decode(&request_body)?, request);
            let identity_offset = 2usize
                .checked_add(AUTHORITY_REQUEST_DOMAIN.len())
                .and_then(|offset| offset.checked_add(2))
                .ok_or(AuthorityProtocolErrorV2::Invalid)?;
            assert_eq!(
                request_body.get(identity_offset..identity_offset + 32),
                Some(identity.client_id().as_bytes().as_slice())
            );
            assert_eq!(
                request_body.get(identity_offset + 32..identity_offset + 64),
                Some(identity.server_id().as_bytes().as_slice())
            );
            assert_eq!(
                request_body.get(identity_offset + 64..identity_offset + 96),
                Some(identity.authority_epoch().as_bytes().as_slice())
            );
            assert_eq!(
                request_body.get(identity_offset + 96..identity_offset + 208),
                Some(encode_state_head(identity.state_head()).as_slice())
            );
            assert_eq!(
                request_body.get(identity_offset + 208..identity_offset + 248),
                Some(encode_config(identity.config()).as_slice())
            );
            assert_eq!(
                request_body.get(identity_offset + 248..identity_offset + 280),
                Some(request.nonce.as_slice())
            );
            assert_eq!(
                request_body.get(identity_offset + 280),
                Some(&(request.command as u8))
            );
            request_vectors.push((request_body.len(), fixture_digest(&request_body)));
            let request_digest = hash_fields(AUTHORITY_REQUEST_DIGEST_DOMAIN, &[&request_body])
                .map_err(map_codec)?;
            request_digests.push(request_digest);
            append(&mut corpus, &request_body)?;
            let response = AuthorityResponseV2 {
                server_id: identity.server_id(),
                client_id: identity.client_id(),
                authority_epoch: identity.authority_epoch(),
                nonce: request.nonce,
                command: request.command,
                request_digest,
                disposition: AuthorityResponseDispositionV2::Success(success),
            };
            let response_body = response.body()?;
            assert_eq!(AuthorityResponseV2::decode(&response_body)?, response);
            response_vectors.push((response_body.len(), fixture_digest(&response_body)));
            append(&mut corpus, &response_body)?;
        }
        assert_eq!(
            request_vectors,
            vec![
                (
                    320,
                    [
                        59, 56, 29, 212, 145, 181, 23, 24, 156, 137, 62, 216, 182, 122, 114, 99,
                        255, 82, 45, 77, 255, 10, 162, 162, 21, 194, 229, 130, 237, 74, 74, 105
                    ]
                ),
                (
                    441,
                    [
                        187, 88, 190, 203, 172, 70, 19, 11, 3, 31, 59, 107, 239, 21, 239, 190, 40,
                        192, 90, 118, 88, 91, 234, 226, 239, 140, 137, 3, 252, 141, 220, 155
                    ]
                ),
                (
                    441,
                    [
                        210, 172, 100, 156, 129, 83, 25, 90, 46, 8, 162, 218, 11, 84, 226, 212,
                        245, 109, 217, 13, 92, 204, 235, 235, 48, 190, 35, 196, 145, 12, 79, 190
                    ]
                ),
                (
                    441,
                    [
                        188, 201, 50, 198, 185, 132, 118, 224, 210, 234, 171, 31, 134, 92, 32, 210,
                        64, 231, 9, 100, 77, 179, 236, 245, 115, 60, 178, 41, 216, 249, 87, 111
                    ]
                ),
                (
                    360,
                    [
                        87, 152, 51, 8, 41, 155, 203, 41, 87, 184, 160, 122, 11, 239, 41, 112, 123,
                        198, 62, 247, 142, 52, 203, 177, 56, 52, 250, 30, 163, 55, 250, 162
                    ]
                ),
                (
                    368,
                    [
                        109, 64, 78, 216, 141, 139, 191, 98, 99, 31, 213, 63, 75, 127, 251, 181,
                        42, 142, 202, 3, 225, 42, 27, 145, 194, 108, 243, 24, 237, 32, 170, 183
                    ]
                ),
            ]
        );
        assert_eq!(
            request_digests,
            vec![
                [
                    199, 128, 238, 255, 5, 225, 111, 50, 173, 131, 241, 142, 92, 157, 226, 125, 58,
                    41, 64, 10, 88, 248, 216, 226, 134, 113, 51, 240, 193, 83, 249, 0
                ],
                [
                    49, 138, 204, 182, 84, 213, 157, 115, 79, 133, 7, 247, 214, 52, 245, 32, 54,
                    24, 18, 15, 89, 107, 115, 115, 9, 59, 121, 148, 25, 7, 234, 103
                ],
                [
                    34, 97, 23, 75, 104, 162, 191, 251, 99, 40, 122, 43, 162, 70, 75, 6, 161, 56,
                    42, 119, 85, 132, 151, 62, 170, 216, 53, 22, 145, 196, 137, 33
                ],
                [
                    19, 138, 209, 66, 123, 178, 177, 123, 98, 5, 180, 104, 139, 68, 5, 103, 121,
                    39, 200, 3, 250, 113, 79, 107, 67, 22, 128, 45, 7, 94, 148, 207
                ],
                [
                    140, 254, 78, 63, 15, 220, 176, 206, 115, 56, 237, 249, 214, 198, 2, 0, 207,
                    222, 213, 55, 144, 38, 73, 144, 13, 180, 166, 225, 29, 35, 132, 117
                ],
                [
                    154, 243, 2, 181, 220, 73, 151, 151, 113, 115, 77, 129, 102, 202, 252, 234, 40,
                    125, 247, 229, 137, 157, 135, 24, 113, 220, 18, 30, 135, 34, 238, 248
                ],
            ]
        );
        assert_eq!(
            response_vectors,
            vec![
                (
                    413,
                    [
                        188, 179, 127, 214, 121, 102, 87, 228, 177, 236, 102, 189, 144, 92, 196,
                        169, 17, 197, 36, 230, 48, 227, 68, 24, 216, 176, 227, 215, 71, 104, 243,
                        135
                    ]
                ),
                (
                    368,
                    [
                        214, 204, 210, 148, 94, 187, 88, 159, 118, 208, 53, 126, 201, 155, 15, 20,
                        15, 103, 46, 169, 78, 209, 114, 172, 62, 12, 89, 4, 249, 216, 182, 40
                    ]
                ),
                (
                    368,
                    [
                        239, 204, 124, 160, 216, 181, 58, 102, 20, 209, 189, 245, 170, 152, 165,
                        99, 98, 42, 23, 77, 231, 14, 18, 104, 122, 204, 113, 190, 145, 239, 61, 83
                    ]
                ),
                (
                    368,
                    [
                        218, 137, 147, 13, 20, 161, 182, 127, 77, 160, 182, 170, 250, 171, 164, 75,
                        37, 111, 51, 20, 27, 244, 245, 52, 49, 39, 57, 213, 139, 221, 175, 23
                    ]
                ),
                (
                    369,
                    [
                        31, 34, 204, 184, 216, 22, 52, 76, 216, 150, 135, 132, 177, 190, 43, 123,
                        220, 161, 241, 160, 186, 174, 93, 184, 125, 145, 130, 122, 4, 115, 114, 48
                    ]
                ),
                (
                    203,
                    [
                        176, 42, 197, 194, 219, 204, 189, 100, 100, 66, 174, 160, 30, 212, 255,
                        238, 24, 96, 185, 91, 49, 29, 28, 57, 167, 102, 119, 17, 65, 124, 76, 137
                    ]
                ),
            ]
        );
        let mut hash = Sha3_256Xof::new();
        hash.reserve(corpus.len());
        hash.absorb_public(&corpus);
        assert_eq!(corpus.len(), 4_556);
        // Level 1 reliability guard: detect accidental changes to the closed six-command
        // wire grammar. This digest is not a malicious-tamper authenticity claim.
        assert_eq!(
            hash.squeeze32(),
            [
                0x12, 0xe9, 0xac, 0x09, 0x5e, 0xd6, 0xfd, 0x76, 0x7b, 0xff, 0x94, 0xa4, 0xa1, 0x95,
                0xae, 0xcf, 0x65, 0x93, 0x62, 0x2f, 0x23, 0x4c, 0x07, 0x97, 0x54, 0x94, 0xde, 0x98,
                0x76, 0xae, 0xa9, 0xab,
            ]
        );
        Ok(())
    }

    #[test]
    fn impossible_receipts_fail_closed_at_every_wire_boundary() -> TestResult {
        let identity = identity()?;
        let acquire = acquire_intent()?;
        let impossible = receipt(
            acquire,
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::CapabilityReplay),
        )
        .map_err(|_| AuthorityCodecError::Invalid)?;
        assert_eq!(receipt_command(&impossible), None);
        let response = AuthorityResponseV2 {
            server_id: identity.server_id(),
            client_id: identity.client_id(),
            authority_epoch: identity.authority_epoch(),
            nonce: [1; 32],
            command: AuthorityCommandV2::Acquire,
            request_digest: [2; 32],
            disposition: AuthorityResponseDispositionV2::Success(AuthoritySuccessV2::Receipt(
                Box::new(impossible),
            )),
        };
        assert_eq!(response.body(), Err(AuthorityProtocolErrorV2::Invalid));
        let mut impossible_acquire_bytes = response_prefix(
            identity,
            response.nonce,
            response.command,
            response.request_digest,
        )?;
        impossible_acquire_bytes.byte(1).map_err(map_codec)?;
        impossible_acquire_bytes
            .lp16(&encode_receipt(impossible)?)
            .map_err(map_codec)?;
        assert_eq!(
            AuthorityResponseV2::decode(&impossible_acquire_bytes.finish()),
            Err(AuthorityProtocolErrorV2::Invalid)
        );

        let next_head = head(2, 0x21, 2, 0x24, 0x25)?;
        let advance = StateAdvanceV2::new(
            StateTransitionKindV2::Advance,
            identity.state_head(),
            next_head,
        )?;
        let foreign_intent = AuthorityIntentV2::new(
            operation(4, 0x54)?,
            4,
            identity.config(),
            AuthorityMutationV2::AdvanceState {
                fence: fence()?,
                advance,
            },
        )?;
        let foreign = receipt(foreign_intent, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        assert_eq!(receipt_command(&foreign), None);
        let query = AuthorityResponseV2 {
            server_id: identity.server_id(),
            client_id: identity.client_id(),
            authority_epoch: identity.authority_epoch(),
            nonce: [3; 32],
            command: AuthorityCommandV2::Query,
            request_digest: [4; 32],
            disposition: AuthorityResponseDispositionV2::Success(AuthoritySuccessV2::Query(
                AuthorityQueryResultV2::Found(Box::new(foreign)),
            )),
        };
        assert_eq!(query.body(), Err(AuthorityProtocolErrorV2::Invalid));
        let mut foreign_query_bytes =
            response_prefix(identity, query.nonce, query.command, query.request_digest)?;
        foreign_query_bytes.byte(1).map_err(map_codec)?;
        foreign_query_bytes.byte(1).map_err(map_codec)?;
        foreign_query_bytes
            .lp16(&encode_receipt(foreign)?)
            .map_err(map_codec)?;
        assert_eq!(
            AuthorityResponseV2::decode(&foreign_query_bytes.finish()),
            Err(AuthorityProtocolErrorV2::Invalid)
        );
        Ok(())
    }

    #[test]
    fn encoders_revalidate_inner_config_nonce_shape_and_failure_reachability() -> TestResult {
        let identity = identity()?;
        let wrong_config = config(2, 0x32)?;
        let intent = AuthorityIntentV2::new(
            operation(1, 0x61)?,
            1,
            wrong_config,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: 0,
                instance_id: ProcessInstanceIdV2::from_bytes([0x62; 32])?,
            },
        )?;
        assert_eq!(
            AuthorityRequestV2::new(
                identity,
                [1; 32],
                AuthorityCommandV2::Acquire,
                AuthorityRequestPayloadV2::LeaseIntent(intent),
            ),
            Err(AuthorityProtocolErrorV2::Invalid)
        );
        let invalid = AuthorityRequestV2 {
            client_id: identity.client_id(),
            server_id: identity.server_id(),
            authority_epoch: identity.authority_epoch(),
            expected_state_head: identity.state_head(),
            expected_config: identity.config(),
            nonce: [0; 32],
            command: AuthorityCommandV2::Snapshot,
            payload: AuthorityRequestPayloadV2::Snapshot,
        };
        assert_eq!(invalid.body(), Err(AuthorityProtocolErrorV2::Invalid));
        let impossible_failure = AuthorityResponseV2 {
            server_id: identity.server_id(),
            client_id: identity.client_id(),
            authority_epoch: identity.authority_epoch(),
            nonce: [1; 32],
            command: AuthorityCommandV2::Query,
            request_digest: [0; 32],
            disposition: AuthorityResponseDispositionV2::KnownFailure(
                AuthorityKnownFailureV2::ClockUnavailable,
            ),
        };
        assert_eq!(
            impossible_failure.body(),
            Err(AuthorityProtocolErrorV2::Invalid)
        );
        let mut impossible_failure_bytes = response_prefix(
            identity,
            impossible_failure.nonce,
            impossible_failure.command,
            impossible_failure.request_digest,
        )?;
        impossible_failure_bytes.byte(2).map_err(map_codec)?;
        impossible_failure_bytes
            .byte(encode_failure(AuthorityKnownFailureV2::ClockUnavailable))
            .map_err(map_codec)?;
        assert_eq!(
            AuthorityResponseV2::decode(&impossible_failure_bytes.finish()),
            Err(AuthorityProtocolErrorV2::Invalid)
        );

        let zero_digest = AuthorityResponseV2 {
            server_id: identity.server_id(),
            client_id: identity.client_id(),
            authority_epoch: identity.authority_epoch(),
            nonce: [2; 32],
            command: AuthorityCommandV2::Snapshot,
            request_digest: [0; 32],
            disposition: AuthorityResponseDispositionV2::KnownFailure(
                AuthorityKnownFailureV2::AllocationFailed,
            ),
        };
        let zero_digest_body = zero_digest.body()?;
        assert_eq!(AuthorityResponseV2::decode(&zero_digest_body)?, zero_digest);
        let _ = AuthorityLimitsV2::new(8, 4, 4, 10_000)?;
        Ok(())
    }
}
