//! Mandatory authenticated external witness protocol and reference server.

use core::fmt;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use q_periapt_backends::{ML_DSA_65_SK_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::ZeroizingBytes;
use redb::{Database, Durability, ReadableTable, TableDefinition};

use crate::authentication::{
    sign_envelope, verify_envelope as verify_signed_envelope, AuthenticationError,
};
use crate::codec::{
    accept_error_is_transient, encode_domain, hash_fields, read_frame, read_frame_until,
    require_domain, write_frame, write_frame_until, CodecError, Decoder, Encoder, MAX_FRAME_BYTES,
};
use crate::filesystem::open_private_file;
use crate::types::{FenceToken, OperationId, StateAdvance, StateHead};

const WITNESS_REQUEST_DOMAIN: &[u8] = b"Q-PERIAPT-WITNESS-REQUEST/v1";
const WITNESS_RESPONSE_DOMAIN: &[u8] = b"Q-PERIAPT-WITNESS-RESPONSE/v1";
const WITNESS_REQUEST_DIGEST_DOMAIN: &[u8] = b"Q-PERIAPT-WITNESS-REQUEST-DIGEST/v1";
const WITNESS_SCHEMA_VERSION: u16 = 1;
const WITNESS_STORE_SCHEMA: [u8; 2] = WITNESS_SCHEMA_VERSION.to_be_bytes();
const WITNESS_MAX_OPERATIONS: u64 = 4096;
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("witness_meta_v1");
const OPERATION_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("witness_operations_v1");
const META_SCHEMA: &str = "schema";
const META_HEAD: &str = "head";
const META_OPERATION_COUNT: &str = "operation_count";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum RequestKind {
    ReadHead = 1,
    CompareAndAdvance = 2,
    QueryOperation = 3,
}

impl RequestKind {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ReadHead),
            2 => Some(Self::CompareAndAdvance),
            3 => Some(Self::QueryOperation),
            _ => None,
        }
    }
}

/// Exact external-witness CAS operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessIntent {
    operation_id: OperationId,
    advance: StateAdvance,
    expected: StateHead,
    next: StateHead,
}

impl WitnessIntent {
    /// Construct an intent whose heads exactly match the authorized state advance.
    pub fn new(
        operation_id: OperationId,
        advance: StateAdvance,
        expected_fence: FenceToken,
        next_fence: FenceToken,
    ) -> Result<Self, WitnessError> {
        if expected_fence == next_fence {
            return Err(WitnessError::InvalidIntent);
        }
        Ok(Self {
            operation_id,
            advance,
            expected: StateHead::new(advance.expected(), expected_fence),
            next: StateHead::new(advance.next(), next_fence),
        })
    }

    /// Return the operation identifier.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }

    /// Return the authenticated transition semantics.
    #[must_use]
    pub const fn advance(self) -> StateAdvance {
        self.advance
    }

    /// Return the exact expected witness head.
    #[must_use]
    pub const fn expected(self) -> StateHead {
        self.expected
    }

    /// Return the exact successor witness head.
    #[must_use]
    pub const fn next(self) -> StateHead {
        self.next
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder) -> Result<(), CodecError> {
        encoder.fixed(self.operation_id.as_bytes())?;
        self.advance.encode(encoder)?;
        self.expected.encode(encoder)?;
        self.next.encode(encoder)
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let operation_id =
            OperationId::decode(decoder.array()?).map_err(|_| CodecError::InvalidValue)?;
        let advance = StateAdvance::decode(decoder)?;
        let expected = StateHead::decode(decoder)?;
        let next = StateHead::decode(decoder)?;
        if advance.expected() != expected.revision()
            || advance.next() != next.revision()
            || expected.fence() == next.fence()
        {
            return Err(CodecError::InvalidValue);
        }
        Ok(Self {
            operation_id,
            advance,
            expected,
            next,
        })
    }
}

/// Authenticated witness disposition for an exact CAS or query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessDisposition {
    /// The exact transition is the authoritative committed operation.
    Applied = 1,
    /// A query proved that no operation exists under the requested identifier.
    NotApplied = 2,
    /// The expected head did not match the authoritative head.
    Conflict = 3,
}

impl WitnessDisposition {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Applied),
            2 => Some(Self::NotApplied),
            3 => Some(Self::Conflict),
            _ => None,
        }
    }
}

/// Verified witness receipt bound to one operation and authoritative head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessReceipt {
    disposition: WitnessDisposition,
    intent: Option<WitnessIntent>,
    authoritative_head: StateHead,
}

impl WitnessReceipt {
    pub(crate) const fn applied(intent: WitnessIntent) -> Self {
        Self {
            disposition: WitnessDisposition::Applied,
            intent: Some(intent),
            authoritative_head: intent.next,
        }
    }

    pub(crate) const fn not_applied(authoritative_head: StateHead) -> Self {
        Self {
            disposition: WitnessDisposition::NotApplied,
            intent: None,
            authoritative_head,
        }
    }

    pub(crate) const fn conflict(intent: WitnessIntent, authoritative_head: StateHead) -> Self {
        Self {
            disposition: WitnessDisposition::Conflict,
            intent: Some(intent),
            authoritative_head,
        }
    }

    /// Return the authenticated outcome.
    #[must_use]
    pub const fn disposition(self) -> WitnessDisposition {
        self.disposition
    }

    /// Return the exact stored intent, when one exists.
    #[must_use]
    pub const fn intent(self) -> Option<WitnessIntent> {
        self.intent
    }

    /// Return the witness's authoritative head at this operation.
    #[must_use]
    pub const fn authoritative_head(self) -> StateHead {
        self.authoritative_head
    }

    /// Verify that this receipt is the exact applied result required by `intent`.
    #[must_use]
    pub fn is_exact_applied(self, intent: WitnessIntent) -> bool {
        matches!(self.disposition, WitnessDisposition::Applied)
            && matches!(self.intent, Some(stored) if stored == intent)
            && self.authoritative_head == intent.next
    }

    fn encode(&self, encoder: &mut Encoder) -> Result<(), CodecError> {
        encoder.byte(self.disposition as u8)?;
        match self.intent {
            Some(intent) => {
                encoder.byte(1)?;
                intent.encode(encoder)?;
            }
            None => encoder.byte(0)?,
        }
        self.authoritative_head.encode(encoder)
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let disposition =
            WitnessDisposition::from_u8(decoder.byte()?).ok_or(CodecError::InvalidValue)?;
        let intent = match decoder.byte()? {
            0 => None,
            1 => Some(WitnessIntent::decode(decoder)?),
            _ => return Err(CodecError::InvalidValue),
        };
        let authoritative_head = StateHead::decode(decoder)?;
        let shape_valid = match disposition {
            WitnessDisposition::Applied => {
                matches!(intent, Some(value) if value.next == authoritative_head)
            }
            WitnessDisposition::Conflict => intent.is_some(),
            WitnessDisposition::NotApplied => intent.is_none(),
        };
        if !shape_valid {
            return Err(CodecError::InvalidValue);
        }
        Ok(Self {
            disposition,
            intent,
            authoritative_head,
        })
    }
}

/// Witness operation result. `Unknown` never aliases failure or absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessOutcome {
    /// An authenticated exact result was received.
    Known(Box<WitnessReceipt>),
    /// The request may or may not have been applied; query the same operation ID.
    Unknown,
}

/// Authentication, persistence, protocol, or availability failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WitnessError {
    /// Static timeout or authentication-key configuration was invalid.
    InvalidConfiguration,
    /// A signed request or response failed verification.
    AuthenticationFailed,
    /// A canonical message was malformed, unknown, oversized, or inconsistent.
    InvalidMessage,
    /// A state advance or receipt did not match its exact operation.
    InvalidIntent,
    /// The witness database was missing, corrupt, or inconsistent.
    Persistence,
    /// The witness was unavailable before an authoritative read completed.
    Unavailable,
    /// The witness operation table reached its explicit capacity.
    CapacityExceeded,
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "witness configuration invalid",
            Self::AuthenticationFailed => "witness authentication failed",
            Self::InvalidMessage => "witness message invalid",
            Self::InvalidIntent => "witness intent or receipt mismatch",
            Self::Persistence => "witness persistent state unavailable or corrupt",
            Self::Unavailable => "witness unavailable",
            Self::CapacityExceeded => "witness operation capacity exceeded",
        })
    }
}

impl std::error::Error for WitnessError {}

fn map_codec(_: CodecError) -> WitnessError {
    WitnessError::InvalidMessage
}

/// Mandatory external rollback-witness boundary.
pub trait WitnessPort: Send + Sync {
    /// Read and authenticate the current external head.
    fn read_head(&self) -> Result<StateHead, WitnessError>;

    /// Attempt one exact CAS. Transport uncertainty returns `Unknown`.
    fn compare_and_advance(&self, intent: WitnessIntent) -> Result<WitnessOutcome, WitnessError>;

    /// Query the same unpredictable operation identifier after an unknown result.
    fn query(&self, operation_id: OperationId) -> Result<WitnessOutcome, WitnessError>;
}

struct Request {
    kind: RequestKind,
    nonce: [u8; 32],
    intent: Option<WitnessIntent>,
    operation_id: Option<OperationId>,
}

impl Request {
    fn read(nonce: [u8; 32]) -> Self {
        Self {
            kind: RequestKind::ReadHead,
            nonce,
            intent: None,
            operation_id: None,
        }
    }

    fn compare(nonce: [u8; 32], intent: WitnessIntent) -> Self {
        Self {
            kind: RequestKind::CompareAndAdvance,
            nonce,
            intent: Some(intent),
            operation_id: Some(intent.operation_id),
        }
    }

    fn query(nonce: [u8; 32], operation_id: OperationId) -> Self {
        Self {
            kind: RequestKind::QueryOperation,
            nonce,
            intent: None,
            operation_id: Some(operation_id),
        }
    }

    fn body(&self) -> Result<Vec<u8>, WitnessError> {
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(&mut encoder, WITNESS_REQUEST_DOMAIN, WITNESS_SCHEMA_VERSION)
            .map_err(map_codec)?;
        encoder.byte(self.kind as u8).map_err(map_codec)?;
        encoder.fixed(&self.nonce).map_err(map_codec)?;
        match self.kind {
            RequestKind::ReadHead => {}
            RequestKind::CompareAndAdvance => self
                .intent
                .ok_or(WitnessError::InvalidMessage)?
                .encode(&mut encoder)
                .map_err(map_codec)?,
            RequestKind::QueryOperation => encoder
                .fixed(
                    self.operation_id
                        .ok_or(WitnessError::InvalidMessage)?
                        .as_bytes(),
                )
                .map_err(map_codec)?,
        }
        Ok(encoder.finish())
    }

    fn decode(body: &[u8]) -> Result<Self, WitnessError> {
        let mut decoder = Decoder::new(body);
        require_domain(&mut decoder, WITNESS_REQUEST_DOMAIN, WITNESS_SCHEMA_VERSION)
            .map_err(map_codec)?;
        let kind = RequestKind::from_u8(decoder.byte().map_err(map_codec)?)
            .ok_or(WitnessError::InvalidMessage)?;
        let nonce = decoder.array().map_err(map_codec)?;
        let (intent, operation_id) = match kind {
            RequestKind::ReadHead => (None, None),
            RequestKind::CompareAndAdvance => {
                let intent = WitnessIntent::decode(&mut decoder).map_err(map_codec)?;
                (Some(intent), Some(intent.operation_id))
            }
            RequestKind::QueryOperation => {
                let operation_id = OperationId::decode(decoder.array().map_err(map_codec)?)
                    .map_err(|_| WitnessError::InvalidMessage)?;
                (None, Some(operation_id))
            }
        };
        decoder.finish().map_err(map_codec)?;
        Ok(Self {
            kind,
            nonce,
            intent,
            operation_id,
        })
    }
}

struct Response {
    kind: RequestKind,
    nonce: [u8; 32],
    request_digest: [u8; 32],
    receipt: WitnessReceipt,
}

impl Response {
    fn body(&self) -> Result<Vec<u8>, WitnessError> {
        let mut encoder = Encoder::new(MAX_FRAME_BYTES);
        encode_domain(
            &mut encoder,
            WITNESS_RESPONSE_DOMAIN,
            WITNESS_SCHEMA_VERSION,
        )
        .map_err(map_codec)?;
        encoder.byte(self.kind as u8).map_err(map_codec)?;
        encoder.fixed(&self.nonce).map_err(map_codec)?;
        encoder.fixed(&self.request_digest).map_err(map_codec)?;
        self.receipt.encode(&mut encoder).map_err(map_codec)?;
        Ok(encoder.finish())
    }

    fn decode(body: &[u8]) -> Result<Self, WitnessError> {
        let mut decoder = Decoder::new(body);
        require_domain(
            &mut decoder,
            WITNESS_RESPONSE_DOMAIN,
            WITNESS_SCHEMA_VERSION,
        )
        .map_err(map_codec)?;
        let kind = RequestKind::from_u8(decoder.byte().map_err(map_codec)?)
            .ok_or(WitnessError::InvalidMessage)?;
        let nonce = decoder.array().map_err(map_codec)?;
        let request_digest = decoder.array().map_err(map_codec)?;
        let receipt = WitnessReceipt::decode(&mut decoder).map_err(map_codec)?;
        decoder.finish().map_err(map_codec)?;
        Ok(Self {
            kind,
            nonce,
            request_digest,
            receipt,
        })
    }
}

fn random_nonce() -> Result<[u8; 32], WitnessError> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| WitnessError::Unavailable)?;
    nonce
        .iter()
        .any(|byte| *byte != 0)
        .then_some(nonce)
        .ok_or(WitnessError::Unavailable)
}

fn signed_envelope(body: &[u8], signing_key: &[u8]) -> Result<Vec<u8>, WitnessError> {
    sign_envelope(body, signing_key).map_err(map_authentication)
}

fn verify_envelope<'a>(
    envelope: &'a [u8],
    verification_key: &[u8],
) -> Result<&'a [u8], WitnessError> {
    verify_signed_envelope(envelope, verification_key).map_err(map_authentication)
}

fn map_authentication(error: AuthenticationError) -> WitnessError {
    match error {
        AuthenticationError::Authentication => WitnessError::AuthenticationFailed,
        AuthenticationError::Entropy => WitnessError::Unavailable,
        AuthenticationError::InvalidEnvelope => WitnessError::InvalidMessage,
    }
}

/// Mutually authenticated TCP witness client.
pub struct AuthenticatedTcpWitness {
    address: SocketAddr,
    client_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
    witness_verification_key: [u8; ML_DSA_65_VK_LEN],
    timeout: Duration,
}

impl fmt::Debug for AuthenticatedTcpWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedTcpWitness([redacted])")
    }
}

impl AuthenticatedTcpWitness {
    /// Configure the external address and independently provisioned request/response keys.
    pub fn new(
        address: SocketAddr,
        client_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        witness_verification_key: [u8; ML_DSA_65_VK_LEN],
        timeout: Duration,
    ) -> Result<Self, WitnessError> {
        validate_authentication_material(
            client_signing_key.as_bytes(),
            &witness_verification_key,
            timeout,
        )?;
        Ok(Self {
            address,
            client_signing_key,
            witness_verification_key,
            timeout,
        })
    }

    fn exchange(&self, request: &Request) -> Result<Response, WitnessError> {
        let request_body = request.body()?;
        let envelope = signed_envelope(&request_body, self.client_signing_key.as_bytes())?;
        let mut stream = TcpStream::connect_timeout(&self.address, self.timeout)
            .map_err(|_| WitnessError::Unavailable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|_| WitnessError::Unavailable)?;
        write_frame(&mut stream, &envelope).map_err(|_| WitnessError::Unavailable)?;
        let response_envelope = read_frame(&mut stream).map_err(|_| WitnessError::Unavailable)?;
        let response_body = verify_envelope(&response_envelope, &self.witness_verification_key)?;
        let response = Response::decode(response_body)?;
        let expected_digest =
            hash_fields(WITNESS_REQUEST_DIGEST_DOMAIN, &[&request_body]).map_err(map_codec)?;
        if response.kind != request.kind
            || response.nonce != request.nonce
            || response.request_digest != expected_digest
        {
            return Err(WitnessError::AuthenticationFailed);
        }
        Ok(response)
    }
}

impl WitnessPort for AuthenticatedTcpWitness {
    fn read_head(&self) -> Result<StateHead, WitnessError> {
        let request = Request::read(random_nonce()?);
        let response = self.exchange(&request)?;
        if response.receipt.disposition != WitnessDisposition::NotApplied
            || response.receipt.intent.is_some()
        {
            return Err(WitnessError::InvalidMessage);
        }
        Ok(response.receipt.authoritative_head)
    }

    fn compare_and_advance(&self, intent: WitnessIntent) -> Result<WitnessOutcome, WitnessError> {
        let request = Request::compare(random_nonce()?, intent);
        // Encode here so a failure to build the request is reported as a
        // definite failure, before anything is transmitted. Past this point the
        // request may reach the witness, and the witness may commit the advance.
        let _ = request.body()?;
        match self.exchange(&request) {
            Ok(response) => {
                let receipt = response.receipt;
                if receipt.intent != Some(intent)
                    || matches!(receipt.disposition, WitnessDisposition::NotApplied)
                {
                    return Err(WitnessError::InvalidIntent);
                }
                Ok(WitnessOutcome::Known(Box::new(receipt)))
            }
            // This is a state-changing request, so every remaining failure is
            // INDETERMINATE, not a definite failure. A response that fails
            // authentication, does not decode, or does not match the request
            // still leaves the possibility that the witness applied the advance
            // and only the answer was lost or tampered with. Reporting those as
            // errors would invite the caller to retry or roll back against a
            // state that actually moved. The caller resolves it the way the
            // protocol intends -- by querying the same unpredictable operation
            // id -- which is exactly what `Unknown` asks it to do. Read-only
            // requests keep reporting definite failures, because no state can
            // have changed underneath them.
            Err(_) => Ok(WitnessOutcome::Unknown),
        }
    }

    fn query(&self, operation_id: OperationId) -> Result<WitnessOutcome, WitnessError> {
        let request = Request::query(random_nonce()?, operation_id);
        match self.exchange(&request) {
            Ok(response) => {
                let receipt = response.receipt;
                if matches!(receipt.intent, Some(intent) if intent.operation_id != operation_id) {
                    return Err(WitnessError::InvalidIntent);
                }
                Ok(WitnessOutcome::Known(Box::new(receipt)))
            }
            Err(WitnessError::Unavailable) => Ok(WitnessOutcome::Unknown),
            Err(error) => Err(error),
        }
    }
}

struct WitnessStore {
    database: Database,
}

impl WitnessStore {
    fn provision(path: &Path, initial_head: StateHead) -> Result<Self, WitnessError> {
        let file = open_private_file(path, true).map_err(|_| WitnessError::Persistence)?;
        let database = Database::builder()
            .create_file(file)
            .map_err(|_| WitnessError::Persistence)?;
        let mut transaction = database
            .begin_write()
            .map_err(|_| WitnessError::Persistence)?;
        transaction.set_durability(Durability::Immediate);
        transaction.set_two_phase_commit(true);
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| WitnessError::Persistence)?;
            meta.insert(META_SCHEMA, WITNESS_STORE_SCHEMA.as_slice())
                .map_err(|_| WitnessError::Persistence)?;
            meta.insert(META_HEAD, initial_head.to_bytes().as_slice())
                .map_err(|_| WitnessError::Persistence)?;
            meta.insert(META_OPERATION_COUNT, 0u64.to_be_bytes().as_slice())
                .map_err(|_| WitnessError::Persistence)?;
            transaction
                .open_table(OPERATION_TABLE)
                .map_err(|_| WitnessError::Persistence)?;
        }
        transaction
            .commit()
            .map_err(|_| WitnessError::Persistence)?;
        Ok(Self { database })
    }

    fn open(path: &Path) -> Result<Self, WitnessError> {
        let file = open_private_file(path, false).map_err(|_| WitnessError::Persistence)?;
        let mut database = Database::builder()
            .create_file(file)
            .map_err(|_| WitnessError::Persistence)?;
        if !database
            .check_integrity()
            .map_err(|_| WitnessError::Persistence)?
        {
            return Err(WitnessError::Persistence);
        }
        let store = Self { database };
        store.head()?;
        store.verify_semantics()?;
        Ok(store)
    }

    /// Validate at open the invariants the request paths already assume.
    ///
    /// `check_integrity` proves only that redb's own structure is sound, and
    /// `head` proves only the schema and head decode. A database that is
    /// structurally valid but semantically damaged would be accepted here and
    /// then fail inside a request instead. One of those cases is worse than a
    /// late failure: capacity is enforced against `META_OPERATION_COUNT`, so a
    /// counter that under-reports the rows actually present would let the
    /// explicit operation limit be exceeded.
    fn verify_semantics(&self) -> Result<(), WitnessError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| WitnessError::Persistence)?;
        let meta = transaction
            .open_table(META_TABLE)
            .map_err(|_| WitnessError::Persistence)?;
        let operations = transaction
            .open_table(OPERATION_TABLE)
            .map_err(|_| WitnessError::Persistence)?;
        let recorded: [u8; 8] = meta
            .get(META_OPERATION_COUNT)
            .map_err(|_| WitnessError::Persistence)?
            .ok_or(WitnessError::Persistence)?
            .value()
            .try_into()
            .map_err(|_| WitnessError::Persistence)?;
        let recorded = u64::from_be_bytes(recorded);
        if recorded > WITNESS_MAX_OPERATIONS {
            return Err(WitnessError::Persistence);
        }
        let mut observed = 0u64;
        for row in operations.iter().map_err(|_| WitnessError::Persistence)? {
            let (key, value) = row.map_err(|_| WitnessError::Persistence)?;
            let mut decoder = Decoder::new(value.value());
            let receipt = WitnessReceipt::decode(&mut decoder).map_err(map_codec)?;
            decoder.finish().map_err(map_codec)?;
            // Every stored receipt is filed under the operation id it records;
            // a row whose key disagrees would make a point lookup answer for a
            // different operation than the caller asked about.
            let filed_correctly = receipt
                .intent
                .is_some_and(|intent| intent.operation_id.as_bytes().as_slice() == key.value());
            if !filed_correctly {
                return Err(WitnessError::Persistence);
            }
            observed = observed.checked_add(1).ok_or(WitnessError::Persistence)?;
        }
        if observed != recorded {
            return Err(WitnessError::Persistence);
        }
        Ok(())
    }

    fn head(&self) -> Result<StateHead, WitnessError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| WitnessError::Persistence)?;
        let meta = transaction
            .open_table(META_TABLE)
            .map_err(|_| WitnessError::Persistence)?;
        let schema = meta
            .get(META_SCHEMA)
            .map_err(|_| WitnessError::Persistence)?
            .ok_or(WitnessError::Persistence)?;
        if schema.value() != WITNESS_STORE_SCHEMA {
            return Err(WitnessError::Persistence);
        }
        let encoded = meta
            .get(META_HEAD)
            .map_err(|_| WitnessError::Persistence)?
            .ok_or(WitnessError::Persistence)?;
        let mut decoder = Decoder::new(encoded.value());
        let head = StateHead::decode(&mut decoder).map_err(map_codec)?;
        decoder.finish().map_err(map_codec)?;
        Ok(head)
    }

    fn query_receipt(&self, operation_id: OperationId) -> Result<WitnessReceipt, WitnessError> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| WitnessError::Persistence)?;
        let operations = transaction
            .open_table(OPERATION_TABLE)
            .map_err(|_| WitnessError::Persistence)?;
        if let Some(encoded) = operations
            .get(operation_id.as_bytes().as_slice())
            .map_err(|_| WitnessError::Persistence)?
        {
            let mut decoder = Decoder::new(encoded.value());
            let receipt = WitnessReceipt::decode(&mut decoder).map_err(map_codec)?;
            decoder.finish().map_err(map_codec)?;
            return Ok(receipt);
        }
        let meta = transaction
            .open_table(META_TABLE)
            .map_err(|_| WitnessError::Persistence)?;
        Ok(WitnessReceipt::not_applied(decode_head_value(&meta)?))
    }

    fn compare(&self, intent: WitnessIntent) -> Result<WitnessReceipt, WitnessError> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| WitnessError::Persistence)?;
        transaction.set_durability(Durability::Immediate);
        transaction.set_two_phase_commit(true);
        let receipt = {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| WitnessError::Persistence)?;
            let mut operations = transaction
                .open_table(OPERATION_TABLE)
                .map_err(|_| WitnessError::Persistence)?;
            let existing_receipt = operations
                .get(intent.operation_id.as_bytes().as_slice())
                .map_err(|_| WitnessError::Persistence)?
                .map(|encoded| {
                    let mut decoder = Decoder::new(encoded.value());
                    let receipt = WitnessReceipt::decode(&mut decoder).map_err(map_codec)?;
                    decoder.finish().map_err(map_codec)?;
                    Ok(receipt)
                })
                .transpose()?;
            if let Some(receipt) = existing_receipt {
                if receipt.intent != Some(intent) {
                    return Err(WitnessError::InvalidIntent);
                }
                return Ok(receipt);
            }
            let count_bytes: [u8; 8] = meta
                .get(META_OPERATION_COUNT)
                .map_err(|_| WitnessError::Persistence)?
                .ok_or(WitnessError::Persistence)?
                .value()
                .try_into()
                .map_err(|_| WitnessError::Persistence)?;
            let count = u64::from_be_bytes(count_bytes);
            if count >= WITNESS_MAX_OPERATIONS {
                return Err(WitnessError::CapacityExceeded);
            }
            let head = decode_head_value(&meta)?;
            let receipt = if head == intent.expected {
                let next_bytes = intent.next.to_bytes();
                meta.insert(META_HEAD, next_bytes.as_slice())
                    .map_err(|_| WitnessError::Persistence)?;
                WitnessReceipt::applied(intent)
            } else {
                WitnessReceipt::conflict(intent, head)
            };
            let mut encoder = Encoder::new(MAX_FRAME_BYTES);
            receipt.encode(&mut encoder).map_err(map_codec)?;
            let encoded = encoder.finish();
            operations
                .insert(
                    intent.operation_id.as_bytes().as_slice(),
                    encoded.as_slice(),
                )
                .map_err(|_| WitnessError::Persistence)?;
            meta.insert(
                META_OPERATION_COUNT,
                count
                    .checked_add(1)
                    .ok_or(WitnessError::CapacityExceeded)?
                    .to_be_bytes()
                    .as_slice(),
            )
            .map_err(|_| WitnessError::Persistence)?;
            receipt
        };
        transaction
            .commit()
            .map_err(|_| WitnessError::Persistence)?;
        Ok(receipt)
    }
}

/// Authenticated reference witness server backed by an independent durable store.
pub struct ReferenceWitnessServer {
    store: WitnessStore,
    client_verification_key: [u8; ML_DSA_65_VK_LEN],
    witness_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
    io_timeout: Duration,
}

impl fmt::Debug for ReferenceWitnessServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReferenceWitnessServer([redacted])")
    }
}

impl ReferenceWitnessServer {
    /// Explicitly provision a new external witness database.
    pub fn provision(
        path: &Path,
        initial_head: StateHead,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        witness_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        io_timeout: Duration,
    ) -> Result<Self, WitnessError> {
        validate_authentication_material(
            witness_signing_key.as_bytes(),
            &client_verification_key,
            io_timeout,
        )?;
        Ok(Self {
            store: WitnessStore::provision(path, initial_head)?,
            client_verification_key,
            witness_signing_key,
            io_timeout,
        })
    }

    /// Open an existing witness database; missing or repaired/corrupt state fails closed.
    pub fn open(
        path: &Path,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        witness_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        io_timeout: Duration,
    ) -> Result<Self, WitnessError> {
        validate_authentication_material(
            witness_signing_key.as_bytes(),
            &client_verification_key,
            io_timeout,
        )?;
        Ok(Self {
            store: WitnessStore::open(path)?,
            client_verification_key,
            witness_signing_key,
            io_timeout,
        })
    }

    fn handle(&self, stream: &mut TcpStream) -> Result<(), WitnessError> {
        // One absolute deadline covers the whole connection: every framed read
        // and write below derives its remaining budget from it, so a trickling
        // client cannot hold the single serving slot past `io_timeout`.
        let deadline = Instant::now()
            .checked_add(self.io_timeout)
            .ok_or(WitnessError::Unavailable)?;
        let envelope = read_frame_until(stream, deadline).map_err(map_codec)?;
        let request_body = verify_envelope(&envelope, &self.client_verification_key)?;
        let request = Request::decode(request_body)?;
        let receipt = match request.kind {
            RequestKind::ReadHead => WitnessReceipt::not_applied(self.store.head()?),
            RequestKind::CompareAndAdvance => self
                .store
                .compare(request.intent.ok_or(WitnessError::InvalidMessage)?)?,
            RequestKind::QueryOperation => {
                let operation_id = request.operation_id.ok_or(WitnessError::InvalidMessage)?;
                self.store.query_receipt(operation_id)?
            }
        };
        let response = Response {
            kind: request.kind,
            nonce: request.nonce,
            request_digest: hash_fields(WITNESS_REQUEST_DIGEST_DOMAIN, &[request_body])
                .map_err(map_codec)?,
            receipt,
        };
        let response_body = response.body()?;
        let response_envelope =
            signed_envelope(&response_body, self.witness_signing_key.as_bytes())?;
        write_frame_until(stream, &response_envelope, deadline).map_err(map_codec)
    }

    /// Serve authenticated single-request TCP connections until `shutdown` is set.
    pub fn serve(&self, listener: TcpListener, shutdown: &AtomicBool) -> Result<(), WitnessError> {
        listener
            .set_nonblocking(true)
            .map_err(|_| WitnessError::Unavailable)?;
        while !shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // A per-connection setsockopt failure is isolated to that
                    // connection, exactly like a malformed request below; it
                    // must not tear down the listener.
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    // A rejected request is isolated to its connection; no
                    // response is produced and no state is changed. That has to
                    // include the request-level rejections a caller can provoke
                    // on purpose: an intent that does not match its operation
                    // id, and a full operation table. Terminating the listener
                    // on those would let one caller -- by replaying a
                    // conflicting intent, or simply by filling the table to its
                    // explicit capacity -- destroy every subsequent read and
                    // query for everyone. Only a broken server is fatal:
                    // Persistence means the database is corrupt or
                    // inconsistent, InvalidConfiguration means the static
                    // configuration is unusable, and Unavailable means an
                    // authoritative read could not complete.
                    match self.handle(&mut stream) {
                        Ok(())
                        | Err(WitnessError::AuthenticationFailed)
                        | Err(WitnessError::InvalidMessage)
                        | Err(WitnessError::InvalidIntent)
                        | Err(WitnessError::CapacityExceeded) => {}
                        Err(error) => return Err(error),
                    }
                }
                Err(error) if accept_error_is_transient(&error) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(WitnessError::Unavailable),
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
pub(crate) mod test_support {
    use super::*;

    /// Desynchronize the recorded operation count from the rows actually
    /// present, leaving a store redb still considers structurally sound.
    pub(crate) fn desynchronize_operation_count(path: &Path) -> Result<(), WitnessError> {
        let file = open_private_file(path, false).map_err(|_| WitnessError::Persistence)?;
        let database = Database::builder()
            .create_file(file)
            .map_err(|_| WitnessError::Persistence)?;
        let transaction = database
            .begin_write()
            .map_err(|_| WitnessError::Persistence)?;
        {
            let mut meta = transaction
                .open_table(META_TABLE)
                .map_err(|_| WitnessError::Persistence)?;
            meta.insert(META_OPERATION_COUNT, 7u64.to_be_bytes().as_slice())
                .map_err(|_| WitnessError::Persistence)?;
        }
        transaction
            .commit()
            .map_err(|_| WitnessError::Persistence)?;
        Ok(())
    }

    pub(crate) fn framed_read_request(
        signing_key: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32]), WitnessError> {
        let nonce = random_nonce()?;
        let body = Request::read(nonce).body()?;
        let envelope = signed_envelope(&body, signing_key)?;
        let mut frame = Vec::new();
        write_frame(&mut frame, &envelope).map_err(map_codec)?;
        Ok((frame, nonce))
    }

    pub(crate) fn read_response_head(
        envelope: &[u8],
        verification_key: &[u8],
        expected_nonce: [u8; 32],
    ) -> Result<StateHead, WitnessError> {
        let body = verify_envelope(envelope, verification_key)?;
        let response = Response::decode(body)?;
        let receipt = response.receipt;
        if response.kind != RequestKind::ReadHead
            || response.nonce != expected_nonce
            || receipt.disposition() != WitnessDisposition::NotApplied
            || receipt.intent().is_some()
        {
            return Err(WitnessError::InvalidMessage);
        }
        Ok(receipt.authoritative_head())
    }
}

/// Domain-separated probe used only to prove, at startup, that the two
/// directions of this protocol are carried by different key pairs.
const DIRECTION_ISOLATION_PROBE: &[u8] = b"Q-PERIAPT-WITNESS-DIRECTION-PROBE/v1";

fn validate_authentication_material(
    signing_key: &[u8],
    verification_key: &[u8],
    timeout: Duration,
) -> Result<(), WitnessError> {
    if timeout.is_zero()
        || signing_key.iter().all(|byte| *byte == 0)
        || verification_key.iter().all(|byte| *byte == 0)
    {
        return Err(WitnessError::InvalidConfiguration);
    }
    // Prove the request and response directions are isolated, the way the
    // authority transport proves it by requiring distinct endpoint identities.
    // Here the two directions are named by different key material rather than
    // by ids: requests are verified under `verification_key`, responses are
    // signed under `signing_key`. If those are one key pair, whoever is
    // authorized to send requests can also forge responses, so the asymmetry
    // the protocol depends on would not exist.
    //
    // Signing the probe also proves the signing key is well-formed enough to
    // produce a signature at startup, rather than discovering it is not after a
    // state change has already been committed and only the response can no
    // longer be produced.
    let probe = sign_envelope(DIRECTION_ISOLATION_PROBE, signing_key)
        .map_err(|_| WitnessError::InvalidConfiguration)?;
    if verify_signed_envelope(&probe, verification_key).is_ok() {
        return Err(WitnessError::InvalidConfiguration);
    }
    Ok(())
}

fn decode_head_value(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<StateHead, WitnessError> {
    let encoded = meta
        .get(META_HEAD)
        .map_err(|_| WitnessError::Persistence)?
        .ok_or(WitnessError::Persistence)?;
    let mut decoder = Decoder::new(encoded.value());
    let head = StateHead::decode(&mut decoder).map_err(map_codec)?;
    decoder.finish().map_err(map_codec)?;
    Ok(head)
}
