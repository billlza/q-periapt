//! Closed authenticated Authority Wire V3 message grammar.

use core::fmt;

use crate::authority::{
    reachable_product_receipt_kind, AuthorityEpochV2, AuthorityIntentV2, AuthorityMutationV2,
    AuthorityQueryResultV2, AuthorityReceiptV2, AuthoritySnapshotV2, AuthorityValueErrorV2,
    DeploymentConfigRevisionV2, OperationIdV2, ProductAuthorityMutationKindV2,
    ReceiptAckDispositionV2, ReceiptLocatorV2, StateHeadV2,
};
use crate::authority_codec::{
    decode_config, decode_intent, decode_operation_id, decode_receipt, decode_receipt_locator,
    decode_snapshot, encode_config, encode_intent, encode_operation_id, encode_receipt,
    encode_receipt_locator, encode_snapshot, encode_state_head, AuthorityCodecError,
};
use crate::codec::{encode_domain, require_domain, CodecError, Decoder, Encoder, MAX_FRAME_BYTES};

pub(crate) const AUTHORITY_REQUEST_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-WIRE-REQUEST/v3";
pub(crate) const AUTHORITY_RESPONSE_DOMAIN: &[u8] = b"Q-PERIAPT-AUTHORITY-WIRE-RESPONSE/v3";
pub(crate) const AUTHORITY_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"Q-PERIAPT-AUTHORITY-WIRE-REQUEST-DIGEST/v3";
pub(crate) const AUTHORITY_WIRE_SCHEMA: u16 = 3;

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
    AuthorityClientIdV3,
    "Pinned identity of the sole authenticated Authority Wire V3 client principal."
);
wire_identifier!(
    AuthorityServerIdV3,
    "Pinned identity of one authenticated Authority Wire V3 server."
);

/// Exact endpoint and authority-state binding shared by one client and server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityWireIdentityV3 {
    client_id: AuthorityClientIdV3,
    server_id: AuthorityServerIdV3,
    authority_epoch: AuthorityEpochV2,
    state_head: StateHeadV2,
    config: DeploymentConfigRevisionV2,
}

impl AuthorityWireIdentityV3 {
    /// Bind distinct endpoint identities to one exact authority epoch, state, and config.
    pub fn new(
        client_id: AuthorityClientIdV3,
        server_id: AuthorityServerIdV3,
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
    pub const fn client_id(self) -> AuthorityClientIdV3 {
        self.client_id
    }

    /// Return the expected server identity.
    #[must_use]
    pub const fn server_id(self) -> AuthorityServerIdV3 {
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

    /// Return the same immutable endpoint/epoch/config binding at a new state head.
    ///
    /// Callers must separately prove the exact predecessor/successor transition;
    /// this helper cannot weaken endpoint or authority-epoch identity.
    #[must_use]
    pub(crate) const fn at_state_head(self, state_head: StateHeadV2) -> Self {
        Self { state_head, ..self }
    }
}

/// Closed, pre-dispatch or deterministic authority-service failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityKnownFailureV3 {
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
pub enum AuthorityUnknownV3 {
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
pub enum AuthorityOutcomeV3<T> {
    /// An authenticated exact command result.
    Known(T),
    /// An authenticated closed failure that proves no ambiguous store result.
    KnownFailure(AuthorityKnownFailureV3),
    /// The request may have reached dispatch or cannot be safely classified.
    Unknown(AuthorityUnknownV3),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum AuthorityCommandV3 {
    Snapshot = 1,
    Acquire = 2,
    Renew = 3,
    Release = 4,
    Query = 5,
    Ack = 6,
    AdvanceState = 7,
}

impl AuthorityCommandV3 {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Snapshot),
            2 => Some(Self::Acquire),
            3 => Some(Self::Renew),
            4 => Some(Self::Release),
            5 => Some(Self::Query),
            6 => Some(Self::Ack),
            7 => Some(Self::AdvanceState),
            _ => None,
        }
    }
}

// Payloads stay `Copy` so requests can be rebuilt and compared without heap
// allocation; the one large mutation-intent variant is a short-lived stack value.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityRequestPayloadV3 {
    Snapshot,
    MutationIntent(AuthorityIntentV2),
    Query(OperationIdV2),
    Ack(ReceiptLocatorV2),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityRequestV3 {
    pub(crate) client_id: AuthorityClientIdV3,
    pub(crate) server_id: AuthorityServerIdV3,
    pub(crate) authority_epoch: AuthorityEpochV2,
    pub(crate) expected_state_head: StateHeadV2,
    pub(crate) expected_config: DeploymentConfigRevisionV2,
    pub(crate) nonce: [u8; 32],
    pub(crate) command: AuthorityCommandV3,
    pub(crate) payload: AuthorityRequestPayloadV3,
}

impl AuthorityRequestV3 {
    pub(crate) fn new(
        identity: AuthorityWireIdentityV3,
        nonce: [u8; 32],
        command: AuthorityCommandV3,
        payload: AuthorityRequestPayloadV3,
    ) -> Result<Self, AuthorityProtocolErrorV3> {
        if !nonzero(&nonce) || !request_shape_is_valid(command, payload) {
            return Err(AuthorityProtocolErrorV3::Invalid);
        }
        if matches!(payload, AuthorityRequestPayloadV3::MutationIntent(intent)
            if intent.expected_config() != identity.config)
        {
            return Err(AuthorityProtocolErrorV3::Invalid);
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

    pub(crate) fn body(&self) -> Result<Vec<u8>, AuthorityProtocolErrorV3> {
        if !nonzero(&self.nonce)
            || self.client_id.as_bytes() == self.server_id.as_bytes()
            || !request_shape_is_valid(self.command, self.payload)
            || matches!(self.payload, AuthorityRequestPayloadV3::MutationIntent(intent)
                if intent.expected_config() != self.expected_config)
        {
            return Err(AuthorityProtocolErrorV3::Invalid);
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
            AuthorityRequestPayloadV3::Snapshot => {}
            AuthorityRequestPayloadV3::MutationIntent(intent) => {
                encode_intent(&mut encoder, intent).map_err(map_authority_codec)?;
            }
            AuthorityRequestPayloadV3::Query(operation_id) => encoder
                .fixed(&encode_operation_id(operation_id))
                .map_err(map_codec)?,
            AuthorityRequestPayloadV3::Ack(locator) => encoder
                .fixed(&encode_receipt_locator(locator))
                .map_err(map_codec)?,
        }
        Ok(encoder.finish())
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Self, AuthorityProtocolErrorV3> {
        let mut decoder = Decoder::new(body);
        require_domain(
            &mut decoder,
            AUTHORITY_REQUEST_DOMAIN,
            AUTHORITY_WIRE_SCHEMA,
        )
        .map_err(map_codec)?;
        let client_id = AuthorityClientIdV3::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV3::Invalid)?;
        let server_id = AuthorityServerIdV3::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV3::Invalid)?;
        if client_id.as_bytes() == server_id.as_bytes() {
            return Err(AuthorityProtocolErrorV3::Invalid);
        }
        let authority_epoch = AuthorityEpochV2::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV3::Invalid)?;
        let expected_state_head =
            crate::authority_codec::decode_state_head(decoder.fixed(112).map_err(map_codec)?)
                .map_err(map_authority_codec)?;
        let expected_config =
            decode_config(decoder.fixed(40).map_err(map_codec)?).map_err(map_authority_codec)?;
        let nonce = decoder.array().map_err(map_codec)?;
        if !nonzero(&nonce) {
            return Err(AuthorityProtocolErrorV3::Invalid);
        }
        let command = AuthorityCommandV3::from_u8(decoder.byte().map_err(map_codec)?)
            .ok_or(AuthorityProtocolErrorV3::Invalid)?;
        let payload = match command {
            AuthorityCommandV3::Snapshot => AuthorityRequestPayloadV3::Snapshot,
            AuthorityCommandV3::Acquire
            | AuthorityCommandV3::Renew
            | AuthorityCommandV3::Release
            | AuthorityCommandV3::AdvanceState => {
                let intent = decode_intent(&mut decoder).map_err(map_authority_codec)?;
                AuthorityRequestPayloadV3::MutationIntent(intent)
            }
            AuthorityCommandV3::Query => AuthorityRequestPayloadV3::Query(
                decode_operation_id(decoder.fixed(40).map_err(map_codec)?)
                    .map_err(map_authority_codec)?,
            ),
            AuthorityCommandV3::Ack => AuthorityRequestPayloadV3::Ack(
                decode_receipt_locator(decoder.fixed(48).map_err(map_codec)?)
                    .map_err(map_authority_codec)?,
            ),
        };
        decoder.finish().map_err(map_codec)?;
        if !request_shape_is_valid(command, payload)
            || matches!(payload, AuthorityRequestPayloadV3::MutationIntent(intent)
                if intent.expected_config() != expected_config)
        {
            return Err(AuthorityProtocolErrorV3::Invalid);
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

fn request_shape_is_valid(command: AuthorityCommandV3, payload: AuthorityRequestPayloadV3) -> bool {
    match (command, payload) {
        (AuthorityCommandV3::Snapshot, AuthorityRequestPayloadV3::Snapshot)
        | (AuthorityCommandV3::Query, AuthorityRequestPayloadV3::Query(_))
        | (AuthorityCommandV3::Ack, AuthorityRequestPayloadV3::Ack(_)) => true,
        (
            AuthorityCommandV3::Acquire
            | AuthorityCommandV3::Renew
            | AuthorityCommandV3::Release
            | AuthorityCommandV3::AdvanceState,
            AuthorityRequestPayloadV3::MutationIntent(intent),
        ) => mutation_command(intent.mutation()) == Some(command),
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuthoritySuccessV3 {
    Snapshot(Box<AuthoritySnapshotV2>),
    Receipt(Box<AuthorityReceiptV2>),
    Query(AuthorityQueryResultV2),
    Ack(ReceiptAckDispositionV2),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityResponseDispositionV3 {
    Success(AuthoritySuccessV3),
    KnownFailure(AuthorityKnownFailureV3),
    ReplayDetected,
    ServerQuarantined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorityResponseV3 {
    pub(crate) server_id: AuthorityServerIdV3,
    pub(crate) client_id: AuthorityClientIdV3,
    pub(crate) authority_epoch: AuthorityEpochV2,
    pub(crate) nonce: [u8; 32],
    pub(crate) command: AuthorityCommandV3,
    pub(crate) request_digest: [u8; 32],
    pub(crate) disposition: AuthorityResponseDispositionV3,
}

impl AuthorityResponseV3 {
    pub(crate) fn body(&self) -> Result<Vec<u8>, AuthorityProtocolErrorV3> {
        if !nonzero(&self.nonce) || self.client_id.as_bytes() == self.server_id.as_bytes() {
            return Err(AuthorityProtocolErrorV3::Invalid);
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
            AuthorityResponseDispositionV3::Success(success) => {
                encoder.byte(1).map_err(map_codec)?;
                encode_success(&mut encoder, self.command, success)?;
            }
            AuthorityResponseDispositionV3::KnownFailure(failure)
                if failure_is_valid_for_command(self.command, *failure) =>
            {
                encoder.byte(2).map_err(map_codec)?;
                encoder.byte(encode_failure(*failure)).map_err(map_codec)?;
            }
            AuthorityResponseDispositionV3::KnownFailure(_) => {
                return Err(AuthorityProtocolErrorV3::Invalid);
            }
            AuthorityResponseDispositionV3::ReplayDetected => {
                encoder.byte(3).map_err(map_codec)?;
            }
            AuthorityResponseDispositionV3::ServerQuarantined => {
                encoder.byte(4).map_err(map_codec)?;
            }
        }
        Ok(encoder.finish())
    }

    pub(crate) fn decode(body: &[u8]) -> Result<Self, AuthorityProtocolErrorV3> {
        let mut decoder = Decoder::new(body);
        require_domain(
            &mut decoder,
            AUTHORITY_RESPONSE_DOMAIN,
            AUTHORITY_WIRE_SCHEMA,
        )
        .map_err(map_codec)?;
        let server_id = AuthorityServerIdV3::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV3::Invalid)?;
        let client_id = AuthorityClientIdV3::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV3::Invalid)?;
        if client_id.as_bytes() == server_id.as_bytes() {
            return Err(AuthorityProtocolErrorV3::Invalid);
        }
        let authority_epoch = AuthorityEpochV2::from_bytes(decoder.array().map_err(map_codec)?)
            .map_err(|_| AuthorityProtocolErrorV3::Invalid)?;
        let nonce = decoder.array().map_err(map_codec)?;
        if !nonzero(&nonce) {
            return Err(AuthorityProtocolErrorV3::Invalid);
        }
        let command = AuthorityCommandV3::from_u8(decoder.byte().map_err(map_codec)?)
            .ok_or(AuthorityProtocolErrorV3::Invalid)?;
        let request_digest = decoder.array().map_err(map_codec)?;
        let disposition = match decoder.byte().map_err(map_codec)? {
            1 => AuthorityResponseDispositionV3::Success(decode_success(&mut decoder, command)?),
            2 => {
                let failure = decode_failure(decoder.byte().map_err(map_codec)?)?;
                if !failure_is_valid_for_command(command, failure) {
                    return Err(AuthorityProtocolErrorV3::Invalid);
                }
                AuthorityResponseDispositionV3::KnownFailure(failure)
            }
            3 => AuthorityResponseDispositionV3::ReplayDetected,
            4 => AuthorityResponseDispositionV3::ServerQuarantined,
            _ => return Err(AuthorityProtocolErrorV3::Invalid),
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
    command: AuthorityCommandV3,
    success: &AuthoritySuccessV3,
) -> Result<(), AuthorityProtocolErrorV3> {
    match (command, success) {
        (AuthorityCommandV3::Snapshot, AuthoritySuccessV3::Snapshot(snapshot))
            if snapshot_is_wire_safe(**snapshot) =>
        {
            encode_snapshot(encoder, **snapshot).map_err(map_authority_codec)
        }
        (
            AuthorityCommandV3::Acquire
            | AuthorityCommandV3::Renew
            | AuthorityCommandV3::Release
            | AuthorityCommandV3::AdvanceState,
            AuthoritySuccessV3::Receipt(receipt),
        ) if receipt_command(receipt) == Some(command) => encoder
            .lp16(&encode_receipt(**receipt).map_err(map_authority_codec)?)
            .map_err(map_codec),
        (AuthorityCommandV3::Query, AuthoritySuccessV3::Query(result)) => {
            encode_query_result(encoder, result)
        }
        (AuthorityCommandV3::Ack, AuthoritySuccessV3::Ack(disposition)) => encoder
            .byte(match disposition {
                ReceiptAckDispositionV2::Removed => 1,
                ReceiptAckDispositionV2::AlreadyAbsent => 2,
            })
            .map_err(map_codec),
        _ => Err(AuthorityProtocolErrorV3::Invalid),
    }
}

fn decode_success(
    decoder: &mut Decoder<'_>,
    command: AuthorityCommandV3,
) -> Result<AuthoritySuccessV3, AuthorityProtocolErrorV3> {
    match command {
        AuthorityCommandV3::Snapshot => {
            let snapshot = decode_snapshot(decoder).map_err(map_authority_codec)?;
            if !snapshot_is_wire_safe(snapshot) {
                return Err(AuthorityProtocolErrorV3::Invalid);
            }
            Ok(AuthoritySuccessV3::Snapshot(Box::new(snapshot)))
        }
        AuthorityCommandV3::Acquire
        | AuthorityCommandV3::Renew
        | AuthorityCommandV3::Release
        | AuthorityCommandV3::AdvanceState => {
            let receipt = decode_receipt(decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?)
                .map_err(map_authority_codec)?;
            if receipt_command(&receipt) != Some(command) {
                return Err(AuthorityProtocolErrorV3::Invalid);
            }
            Ok(AuthoritySuccessV3::Receipt(Box::new(receipt)))
        }
        AuthorityCommandV3::Query => Ok(AuthoritySuccessV3::Query(decode_query_result(decoder)?)),
        AuthorityCommandV3::Ack => Ok(AuthoritySuccessV3::Ack(
            match decoder.byte().map_err(map_codec)? {
                1 => ReceiptAckDispositionV2::Removed,
                2 => ReceiptAckDispositionV2::AlreadyAbsent,
                _ => return Err(AuthorityProtocolErrorV3::Invalid),
            },
        )),
    }
}

fn encode_query_result(
    encoder: &mut Encoder,
    result: &AuthorityQueryResultV2,
) -> Result<(), AuthorityProtocolErrorV3> {
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
        _ => Err(AuthorityProtocolErrorV3::Invalid),
    }
}

fn decode_query_result(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityQueryResultV2, AuthorityProtocolErrorV3> {
    match decoder.byte().map_err(map_codec)? {
        1 => {
            let receipt = decode_receipt(decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?)
                .map_err(map_authority_codec)?;
            if receipt_command(&receipt).is_none() {
                return Err(AuthorityProtocolErrorV3::Invalid);
            }
            Ok(AuthorityQueryResultV2::Found(Box::new(receipt)))
        }
        2 => {
            let authority_version = decoder.u64().map_err(map_codec)?;
            if authority_version == 0 {
                return Err(AuthorityProtocolErrorV3::Invalid);
            }
            Ok(AuthorityQueryResultV2::AbsentAtVersion { authority_version })
        }
        _ => Err(AuthorityProtocolErrorV3::Invalid),
    }
}

const fn encode_failure(failure: AuthorityKnownFailureV3) -> u8 {
    match failure {
        AuthorityKnownFailureV3::RateLimited => 1,
        AuthorityKnownFailureV3::AllocationFailed => 2,
        AuthorityKnownFailureV3::ClockUnavailable => 3,
        AuthorityKnownFailureV3::OperationConflict => 4,
        AuthorityKnownFailureV3::AuthorityVersionMismatch => 5,
        AuthorityKnownFailureV3::AuthorityVersionExhausted => 6,
        AuthorityKnownFailureV3::ReceiptCapacityExceeded => 7,
        AuthorityKnownFailureV3::ReceiptAcknowledgementMismatch => 8,
    }
}

fn decode_failure(value: u8) -> Result<AuthorityKnownFailureV3, AuthorityProtocolErrorV3> {
    match value {
        1 => Ok(AuthorityKnownFailureV3::RateLimited),
        2 => Ok(AuthorityKnownFailureV3::AllocationFailed),
        3 => Ok(AuthorityKnownFailureV3::ClockUnavailable),
        4 => Ok(AuthorityKnownFailureV3::OperationConflict),
        5 => Ok(AuthorityKnownFailureV3::AuthorityVersionMismatch),
        6 => Ok(AuthorityKnownFailureV3::AuthorityVersionExhausted),
        7 => Ok(AuthorityKnownFailureV3::ReceiptCapacityExceeded),
        8 => Ok(AuthorityKnownFailureV3::ReceiptAcknowledgementMismatch),
        _ => Err(AuthorityProtocolErrorV3::Invalid),
    }
}

pub(crate) fn mutation_command(mutation: AuthorityMutationV2) -> Option<AuthorityCommandV3> {
    match mutation {
        AuthorityMutationV2::AcquireLease { .. } => Some(AuthorityCommandV3::Acquire),
        AuthorityMutationV2::RenewLease { .. } => Some(AuthorityCommandV3::Renew),
        AuthorityMutationV2::ReleaseLease { .. } => Some(AuthorityCommandV3::Release),
        AuthorityMutationV2::AdvanceState { .. } => Some(AuthorityCommandV3::AdvanceState),
        AuthorityMutationV2::AdvanceConfig { .. }
        | AuthorityMutationV2::ConsumeCapability { .. }
        | AuthorityMutationV2::RegisterKey { .. }
        | AuthorityMutationV2::RevokeKey { .. } => None,
    }
}

pub(crate) fn receipt_command(receipt: &AuthorityReceiptV2) -> Option<AuthorityCommandV3> {
    match reachable_product_receipt_kind(receipt)? {
        ProductAuthorityMutationKindV2::AcquireLease => Some(AuthorityCommandV3::Acquire),
        ProductAuthorityMutationKindV2::RenewLease => Some(AuthorityCommandV3::Renew),
        ProductAuthorityMutationKindV2::ReleaseLease => Some(AuthorityCommandV3::Release),
        ProductAuthorityMutationKindV2::AdvanceState => Some(AuthorityCommandV3::AdvanceState),
    }
}

fn failure_is_valid_for_command(
    command: AuthorityCommandV3,
    failure: AuthorityKnownFailureV3,
) -> bool {
    match failure {
        AuthorityKnownFailureV3::RateLimited | AuthorityKnownFailureV3::AllocationFailed => true,
        AuthorityKnownFailureV3::ClockUnavailable => matches!(
            command,
            AuthorityCommandV3::Snapshot
                | AuthorityCommandV3::Acquire
                | AuthorityCommandV3::Renew
                | AuthorityCommandV3::Release
                | AuthorityCommandV3::AdvanceState
        ),
        AuthorityKnownFailureV3::OperationConflict
        | AuthorityKnownFailureV3::AuthorityVersionMismatch
        | AuthorityKnownFailureV3::AuthorityVersionExhausted
        | AuthorityKnownFailureV3::ReceiptCapacityExceeded => matches!(
            command,
            AuthorityCommandV3::Acquire
                | AuthorityCommandV3::Renew
                | AuthorityCommandV3::Release
                | AuthorityCommandV3::AdvanceState
        ),
        AuthorityKnownFailureV3::ReceiptAcknowledgementMismatch => {
            command == AuthorityCommandV3::Ack
        }
    }
}

fn snapshot_is_wire_safe(snapshot: AuthoritySnapshotV2) -> bool {
    snapshot.capability_count() == 0
        && snapshot.retained_key_count() == 0
        && snapshot.active_key_count() == 0
}

/// One wire lease receipt whose exact bytes were durably retained by the client journal.
///
/// Acknowledgement lets the authority server prune its bounded retained-receipt
/// table. Construction is crate-private so the product service can obtain this
/// capability only after its repository transaction commits the exact receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurablyRetainedAuthorityReceiptV3(AuthorityReceiptV2);

impl DurablyRetainedAuthorityReceiptV3 {
    /// Seal one acknowledgeable receipt after the repository's durable commit.
    ///
    /// Non-lease or wire-unreachable receipts are rejected instead of being
    /// silently acknowledged.
    pub(crate) fn after_repository_commit(
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

    /// Return the exact durably retained receipt for repository verification.
    #[must_use]
    pub(crate) const fn receipt(&self) -> AuthorityReceiptV2 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityProtocolErrorV3 {
    Allocation,
    Invalid,
}

impl fmt::Display for AuthorityProtocolErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allocation => "authority wire bounded allocation failed",
            Self::Invalid => "authority wire message is invalid",
        })
    }
}

impl std::error::Error for AuthorityProtocolErrorV3 {}

fn map_codec(error: CodecError) -> AuthorityProtocolErrorV3 {
    match error {
        CodecError::Allocation => AuthorityProtocolErrorV3::Allocation,
        CodecError::InvalidLength
        | CodecError::InvalidValue
        | CodecError::Io
        | CodecError::Oversized
        | CodecError::TrailingBytes
        | CodecError::Truncated => AuthorityProtocolErrorV3::Invalid,
    }
}

fn map_authority_codec(error: AuthorityCodecError) -> AuthorityProtocolErrorV3 {
    match error {
        AuthorityCodecError::Allocation => AuthorityProtocolErrorV3::Allocation,
        AuthorityCodecError::Invalid => AuthorityProtocolErrorV3::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use q_periapt_backends::Sha3_256Xof;
    use q_periapt_core::Xof256;

    use super::*;
    use crate::authority::{
        AuthorityDispositionV2, AuthorityLimitsV2, AuthorityRejectionV2, ConfigAdvanceV2,
        InstanceFenceV2, ProcessInstanceIdV2, StateAdvanceV2, StateFenceV2, StateRevisionV2,
        StateTransitionKindV2,
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

    fn identity() -> Result<AuthorityWireIdentityV3, AuthorityValueErrorV2> {
        AuthorityWireIdentityV3::new(
            AuthorityClientIdV3::from_bytes([0x11; 32])?,
            AuthorityServerIdV3::from_bytes([0x12; 32])?,
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
    ) -> Result<AuthorityReceiptV2, AuthorityProtocolErrorV3> {
        AuthorityReceiptV2::restore(
            intent,
            disposition,
            intent
                .expected_authority_version()
                .checked_add(1)
                .ok_or(AuthorityProtocolErrorV3::Invalid)?,
        )
        .map_err(|_| AuthorityProtocolErrorV3::Invalid)
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

    fn append(corpus: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AuthorityProtocolErrorV3> {
        let length = u64::try_from(bytes.len()).map_err(|_| AuthorityProtocolErrorV3::Invalid)?;
        let additional = 8usize
            .checked_add(bytes.len())
            .ok_or(AuthorityProtocolErrorV3::Invalid)?;
        corpus
            .try_reserve_exact(additional)
            .map_err(|_| AuthorityProtocolErrorV3::Allocation)?;
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
        identity: AuthorityWireIdentityV3,
        nonce: [u8; 32],
        command: AuthorityCommandV3,
        request_digest: [u8; 32],
    ) -> Result<Encoder, AuthorityProtocolErrorV3> {
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
    fn seven_command_request_and_response_bytes_are_frozen() -> TestResult {
        let identity = identity()?;
        let acquire = acquire_intent()?;
        let renew = renew_intent()?;
        let release = release_intent()?;
        let state_advance = StateAdvanceV2::new(
            StateTransitionKindV2::Advance,
            identity.state_head(),
            head(2, 0x21, 2, 0x24, 0x25)?,
        )?;
        let advance = AuthorityIntentV2::new(
            operation(4, 0x54)?,
            4,
            identity.config(),
            AuthorityMutationV2::AdvanceState {
                fence: fence()?,
                advance: state_advance,
            },
        )?;
        let acquire_receipt = receipt(acquire, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        let renew_receipt = receipt(renew, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        let release_receipt = receipt(release, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        let advance_receipt = receipt(advance, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        let requests = [
            AuthorityRequestV3::new(
                identity,
                [1; 32],
                AuthorityCommandV3::Snapshot,
                AuthorityRequestPayloadV3::Snapshot,
            )?,
            AuthorityRequestV3::new(
                identity,
                [2; 32],
                AuthorityCommandV3::Acquire,
                AuthorityRequestPayloadV3::MutationIntent(acquire),
            )?,
            AuthorityRequestV3::new(
                identity,
                [3; 32],
                AuthorityCommandV3::Renew,
                AuthorityRequestPayloadV3::MutationIntent(renew),
            )?,
            AuthorityRequestV3::new(
                identity,
                [4; 32],
                AuthorityCommandV3::Release,
                AuthorityRequestPayloadV3::MutationIntent(release),
            )?,
            AuthorityRequestV3::new(
                identity,
                [5; 32],
                AuthorityCommandV3::Query,
                AuthorityRequestPayloadV3::Query(acquire.operation_id()),
            )?,
            AuthorityRequestV3::new(
                identity,
                [6; 32],
                AuthorityCommandV3::Ack,
                AuthorityRequestPayloadV3::Ack(acquire_receipt.locator()),
            )?,
            AuthorityRequestV3::new(
                identity,
                [7; 32],
                AuthorityCommandV3::AdvanceState,
                AuthorityRequestPayloadV3::MutationIntent(advance),
            )?,
        ];
        let successes = [
            AuthoritySuccessV3::Snapshot(Box::new(snapshot()?)),
            AuthoritySuccessV3::Receipt(Box::new(acquire_receipt)),
            AuthoritySuccessV3::Receipt(Box::new(renew_receipt)),
            AuthoritySuccessV3::Receipt(Box::new(release_receipt)),
            AuthoritySuccessV3::Query(AuthorityQueryResultV2::Found(Box::new(acquire_receipt))),
            AuthoritySuccessV3::Ack(ReceiptAckDispositionV2::Removed),
            AuthoritySuccessV3::Receipt(Box::new(advance_receipt)),
        ];
        let mut corpus = Vec::new();
        let mut request_vectors = Vec::new();
        let mut request_digests = Vec::new();
        let mut response_vectors = Vec::new();
        for (request, success) in requests.into_iter().zip(successes) {
            let request_body = request.body()?;
            assert_eq!(AuthorityRequestV3::decode(&request_body)?, request);
            let identity_offset = 2usize
                .checked_add(AUTHORITY_REQUEST_DOMAIN.len())
                .and_then(|offset| offset.checked_add(2))
                .ok_or(AuthorityProtocolErrorV3::Invalid)?;
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
            let response = AuthorityResponseV3 {
                server_id: identity.server_id(),
                client_id: identity.client_id(),
                authority_epoch: identity.authority_epoch(),
                nonce: request.nonce,
                command: request.command,
                request_digest,
                disposition: AuthorityResponseDispositionV3::Success(success),
            };
            let response_body = response.body()?;
            assert_eq!(AuthorityResponseV3::decode(&response_body)?, response);
            response_vectors.push((response_body.len(), fixture_digest(&response_body)));
            append(&mut corpus, &response_body)?;
        }
        assert_eq!(
            request_vectors,
            vec![
                (
                    320,
                    [
                        19, 26, 26, 194, 6, 240, 190, 180, 44, 202, 216, 234, 241, 183, 40, 246,
                        100, 194, 77, 116, 11, 40, 203, 107, 130, 126, 115, 17, 136, 39, 84, 217
                    ]
                ),
                (
                    441,
                    [
                        120, 66, 201, 228, 5, 154, 97, 83, 104, 185, 49, 128, 15, 185, 131, 73,
                        154, 213, 51, 79, 207, 195, 46, 64, 144, 165, 9, 133, 110, 87, 225, 158
                    ]
                ),
                (
                    441,
                    [
                        62, 169, 27, 127, 201, 107, 83, 156, 85, 237, 7, 26, 114, 120, 0, 25, 126,
                        11, 198, 228, 42, 177, 242, 101, 87, 169, 39, 74, 180, 58, 58, 167
                    ]
                ),
                (
                    441,
                    [
                        47, 125, 128, 194, 161, 8, 186, 13, 1, 59, 253, 231, 22, 107, 136, 129, 55,
                        147, 54, 132, 129, 96, 200, 14, 29, 69, 191, 53, 165, 108, 142, 129
                    ]
                ),
                (
                    360,
                    [
                        29, 90, 85, 36, 76, 39, 132, 233, 224, 102, 243, 122, 201, 115, 8, 9, 195,
                        193, 92, 83, 157, 124, 104, 217, 1, 76, 4, 196, 7, 206, 103, 52
                    ]
                ),
                (
                    368,
                    [
                        109, 89, 217, 40, 229, 46, 131, 71, 15, 16, 242, 225, 253, 159, 14, 3, 208,
                        174, 134, 133, 175, 16, 86, 41, 185, 186, 200, 199, 253, 95, 163, 54
                    ]
                ),
                (
                    666,
                    [
                        52, 65, 85, 35, 190, 0, 53, 73, 219, 138, 112, 205, 43, 190, 73, 222, 40,
                        45, 55, 180, 203, 3, 173, 229, 168, 234, 176, 75, 75, 6, 226, 215
                    ]
                ),
            ]
        );
        assert_eq!(
            request_digests,
            vec![
                [
                    90, 163, 176, 95, 229, 90, 238, 81, 245, 63, 10, 170, 219, 139, 122, 246, 94,
                    111, 77, 32, 164, 120, 184, 30, 154, 219, 76, 238, 107, 52, 25, 154
                ],
                [
                    0, 173, 15, 93, 208, 31, 61, 194, 198, 76, 96, 148, 34, 190, 80, 249, 83, 128,
                    1, 77, 82, 142, 116, 179, 247, 95, 55, 61, 110, 35, 99, 240
                ],
                [
                    233, 163, 99, 133, 254, 83, 143, 121, 75, 226, 254, 229, 123, 233, 77, 234,
                    184, 229, 45, 113, 67, 96, 120, 221, 40, 157, 4, 29, 252, 172, 104, 172
                ],
                [
                    166, 136, 129, 124, 189, 152, 174, 248, 33, 9, 87, 247, 243, 220, 122, 23, 14,
                    90, 4, 178, 18, 212, 91, 177, 135, 22, 80, 208, 177, 42, 235, 178
                ],
                [
                    225, 121, 238, 72, 17, 148, 209, 39, 79, 70, 153, 220, 176, 220, 136, 255, 71,
                    50, 190, 9, 79, 22, 250, 52, 55, 222, 165, 73, 228, 61, 250, 217
                ],
                [
                    163, 224, 156, 230, 126, 140, 113, 0, 43, 217, 235, 227, 92, 250, 234, 249,
                    149, 184, 153, 147, 116, 0, 4, 100, 201, 208, 195, 211, 16, 159, 55, 239
                ],
                [
                    32, 33, 97, 174, 5, 205, 186, 211, 111, 196, 145, 167, 99, 101, 98, 146, 16,
                    185, 44, 209, 254, 10, 153, 33, 93, 160, 185, 205, 87, 196, 29, 19
                ],
            ]
        );
        assert_eq!(
            response_vectors,
            vec![
                (
                    413,
                    [
                        145, 77, 63, 190, 58, 29, 187, 210, 167, 97, 181, 210, 65, 122, 210, 243,
                        122, 45, 23, 15, 14, 96, 72, 134, 73, 213, 135, 142, 144, 182, 149, 223
                    ]
                ),
                (
                    368,
                    [
                        89, 48, 95, 115, 148, 211, 233, 107, 134, 158, 3, 102, 67, 63, 44, 158,
                        223, 67, 219, 103, 12, 31, 57, 251, 81, 169, 48, 99, 234, 122, 59, 83
                    ]
                ),
                (
                    368,
                    [
                        95, 192, 168, 52, 217, 63, 133, 68, 5, 244, 211, 97, 34, 115, 109, 121,
                        156, 139, 101, 169, 230, 161, 240, 29, 112, 137, 44, 24, 208, 98, 144, 46
                    ]
                ),
                (
                    368,
                    [
                        45, 17, 114, 76, 55, 144, 252, 131, 112, 85, 225, 170, 91, 109, 248, 103,
                        140, 79, 19, 116, 37, 204, 227, 191, 196, 68, 34, 255, 78, 242, 152, 124
                    ]
                ),
                (
                    369,
                    [
                        240, 196, 223, 240, 241, 79, 88, 114, 43, 26, 63, 113, 54, 70, 167, 104,
                        23, 252, 183, 131, 202, 80, 167, 58, 22, 188, 64, 187, 8, 228, 32, 35
                    ]
                ),
                (
                    203,
                    [
                        224, 43, 227, 52, 209, 1, 68, 168, 212, 14, 247, 233, 99, 85, 50, 254, 189,
                        198, 114, 130, 41, 21, 245, 82, 122, 208, 99, 240, 124, 37, 130, 154
                    ]
                ),
                (
                    593,
                    [
                        163, 242, 63, 25, 81, 101, 63, 80, 133, 162, 250, 187, 171, 8, 12, 96, 26,
                        33, 140, 86, 55, 209, 183, 138, 74, 25, 36, 163, 164, 22, 55, 10
                    ]
                ),
            ]
        );
        let mut hash = Sha3_256Xof::new();
        hash.reserve(corpus.len());
        hash.absorb_public(&corpus);
        assert_eq!(corpus.len(), 5_831);
        // Level 1 reliability guard: detect accidental changes to the closed seven-command
        // wire grammar. This digest is not a malicious-tamper authenticity claim.
        assert_eq!(
            hash.squeeze32(),
            [
                177, 100, 207, 67, 180, 29, 63, 169, 113, 96, 181, 3, 97, 129, 105, 75, 164, 168,
                119, 22, 145, 215, 172, 198, 9, 44, 213, 151, 242, 136, 150, 160,
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
        let response = AuthorityResponseV3 {
            server_id: identity.server_id(),
            client_id: identity.client_id(),
            authority_epoch: identity.authority_epoch(),
            nonce: [1; 32],
            command: AuthorityCommandV3::Acquire,
            request_digest: [2; 32],
            disposition: AuthorityResponseDispositionV3::Success(AuthoritySuccessV3::Receipt(
                Box::new(impossible),
            )),
        };
        assert_eq!(response.body(), Err(AuthorityProtocolErrorV3::Invalid));
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
            AuthorityResponseV3::decode(&impossible_acquire_bytes.finish()),
            Err(AuthorityProtocolErrorV3::Invalid)
        );

        let foreign_intent = AuthorityIntentV2::new(
            operation(4, 0x54)?,
            4,
            identity.config(),
            AuthorityMutationV2::AdvanceConfig {
                fence: fence()?,
                advance: ConfigAdvanceV2::new(identity.config(), config(2, 0x32)?)?,
            },
        )?;
        let foreign = receipt(foreign_intent, AuthorityDispositionV2::Applied)
            .map_err(|_| AuthorityCodecError::Invalid)?;
        assert_eq!(receipt_command(&foreign), None);
        let query = AuthorityResponseV3 {
            server_id: identity.server_id(),
            client_id: identity.client_id(),
            authority_epoch: identity.authority_epoch(),
            nonce: [3; 32],
            command: AuthorityCommandV3::Query,
            request_digest: [4; 32],
            disposition: AuthorityResponseDispositionV3::Success(AuthoritySuccessV3::Query(
                AuthorityQueryResultV2::Found(Box::new(foreign)),
            )),
        };
        assert_eq!(query.body(), Err(AuthorityProtocolErrorV3::Invalid));
        let mut foreign_query_bytes =
            response_prefix(identity, query.nonce, query.command, query.request_digest)?;
        foreign_query_bytes.byte(1).map_err(map_codec)?;
        foreign_query_bytes.byte(1).map_err(map_codec)?;
        foreign_query_bytes
            .lp16(&encode_receipt(foreign)?)
            .map_err(map_codec)?;
        assert_eq!(
            AuthorityResponseV3::decode(&foreign_query_bytes.finish()),
            Err(AuthorityProtocolErrorV3::Invalid)
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
            AuthorityRequestV3::new(
                identity,
                [1; 32],
                AuthorityCommandV3::Acquire,
                AuthorityRequestPayloadV3::MutationIntent(intent),
            ),
            Err(AuthorityProtocolErrorV3::Invalid)
        );
        let invalid = AuthorityRequestV3 {
            client_id: identity.client_id(),
            server_id: identity.server_id(),
            authority_epoch: identity.authority_epoch(),
            expected_state_head: identity.state_head(),
            expected_config: identity.config(),
            nonce: [0; 32],
            command: AuthorityCommandV3::Snapshot,
            payload: AuthorityRequestPayloadV3::Snapshot,
        };
        assert_eq!(invalid.body(), Err(AuthorityProtocolErrorV3::Invalid));
        let impossible_failure = AuthorityResponseV3 {
            server_id: identity.server_id(),
            client_id: identity.client_id(),
            authority_epoch: identity.authority_epoch(),
            nonce: [1; 32],
            command: AuthorityCommandV3::Query,
            request_digest: [0; 32],
            disposition: AuthorityResponseDispositionV3::KnownFailure(
                AuthorityKnownFailureV3::ClockUnavailable,
            ),
        };
        assert_eq!(
            impossible_failure.body(),
            Err(AuthorityProtocolErrorV3::Invalid)
        );
        let mut impossible_failure_bytes = response_prefix(
            identity,
            impossible_failure.nonce,
            impossible_failure.command,
            impossible_failure.request_digest,
        )?;
        impossible_failure_bytes.byte(2).map_err(map_codec)?;
        impossible_failure_bytes
            .byte(encode_failure(AuthorityKnownFailureV3::ClockUnavailable))
            .map_err(map_codec)?;
        assert_eq!(
            AuthorityResponseV3::decode(&impossible_failure_bytes.finish()),
            Err(AuthorityProtocolErrorV3::Invalid)
        );

        let zero_digest = AuthorityResponseV3 {
            server_id: identity.server_id(),
            client_id: identity.client_id(),
            authority_epoch: identity.authority_epoch(),
            nonce: [2; 32],
            command: AuthorityCommandV3::Snapshot,
            request_digest: [0; 32],
            disposition: AuthorityResponseDispositionV3::KnownFailure(
                AuthorityKnownFailureV3::AllocationFailed,
            ),
        };
        let zero_digest_body = zero_digest.body()?;
        assert_eq!(AuthorityResponseV3::decode(&zero_digest_body)?, zero_digest);
        let _ = AuthorityLimitsV2::new(8, 4, 4, 10_000)?;
        Ok(())
    }
}
