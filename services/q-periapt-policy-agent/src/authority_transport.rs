//! Mutually authenticated, deadline-bounded Authority Wire V2 TCP transport.

use core::fmt;
use std::collections::{HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use q_periapt_backends::{ML_DSA_65_SK_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::ZeroizingBytes;

use crate::authentication::{
    sign_envelope, signing_key_matches_verification_key, verify_envelope, AuthenticationError,
};
use crate::authority::{
    AuthorityErrorV2, AuthorityIntentV2, AuthorityLimitsV2, AuthorityQueryResultV2,
    AuthorityReceiptV2, AuthoritySnapshotV2, DeploymentConfigRevisionV2, OperationIdV2,
    ReceiptAckDispositionV2,
};
use crate::authority_protocol::{
    receipt_command, AuthorityClientIdV2, AuthorityCommandV2, AuthorityKnownFailureV2,
    AuthorityOutcomeV2, AuthorityProtocolErrorV2, AuthorityRequestPayloadV2, AuthorityRequestV2,
    AuthorityResponseDispositionV2, AuthorityResponseV2, AuthorityServerIdV2, AuthoritySuccessV2,
    AuthorityUnknownV2, AuthorityWireIdentityV2, DurablyRetainedAuthorityReceiptV2,
    AUTHORITY_REQUEST_DIGEST_DOMAIN,
};
use crate::authority_store::{AuthorityStoreErrorV2, AuthorityStoreV2};
use crate::codec::{accept_error_is_transient, hash_fields, MAX_FRAME_BYTES};

const HARD_MAX_AUTHORITY_NONCES: usize = 4096;
const HARD_MIN_TOTAL_DEADLINE: Duration = Duration::from_millis(1);
const HARD_MAX_TOTAL_DEADLINE: Duration = Duration::from_secs(30);
const HARD_MIN_NONCE_TTL: Duration = Duration::from_millis(1);
const HARD_MAX_NONCE_TTL: Duration = Duration::from_secs(10 * 60);
const ROLE_SEPARATION_CHALLENGE: &[u8] = b"Q-PERIAPT-AUTHORITY-WIRE-ROLE-SEPARATION/v2";

/// Transport failures that prove no request byte was accepted by the socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityTransportErrorV2 {
    /// Endpoint identity, key-role separation, or a resource bound was invalid.
    InvalidConfiguration,
    /// The requested typed method did not match its complete authority intent.
    InvalidRequest,
    /// A fresh nonzero request nonce or randomized request signature was unavailable.
    EntropyUnavailable,
    /// Canonical request construction failed before connecting.
    EncodingFailed,
    /// Connect or request write failed while zero request bytes were known to be sent.
    NotSent,
}

impl fmt::Display for AuthorityTransportErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "authority transport configuration invalid",
            Self::InvalidRequest => "authority transport request invalid",
            Self::EntropyUnavailable => "authority transport entropy unavailable",
            Self::EncodingFailed => "authority transport request encoding failed",
            Self::NotSent => "authority transport request was not sent",
        })
    }
}

impl std::error::Error for AuthorityTransportErrorV2 {}

/// Server-side setup, listener, or fatal-store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityServerErrorV2 {
    /// The pinned identity, keys, deadline, or resource limits were invalid.
    InvalidConfiguration,
    /// The store could not be provisioned, opened, or read before serving.
    StoreUnavailable,
    /// A fatal store result permanently quarantined this server instance.
    Quarantined,
    /// The TCP listener could not continue accepting connections.
    ListenerUnavailable,
}

impl fmt::Display for AuthorityServerErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "authority server configuration invalid",
            Self::StoreUnavailable => "authority server store unavailable",
            Self::Quarantined => "authority server store quarantined",
            Self::ListenerUnavailable => "authority server listener unavailable",
        })
    }
}

impl std::error::Error for AuthorityServerErrorV2 {}

/// Bounded server transport and authenticated replay-window configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityTransportLimitsV2 {
    total_deadline: Duration,
    nonce_ttl: Duration,
    max_nonces: usize,
}

impl AuthorityTransportLimitsV2 {
    /// Construct nonzero bounds with no more than 4096 live authenticated nonces.
    pub fn new(
        total_deadline: Duration,
        nonce_ttl: Duration,
        max_nonces: usize,
    ) -> Result<Self, AuthorityTransportErrorV2> {
        if !(HARD_MIN_TOTAL_DEADLINE..=HARD_MAX_TOTAL_DEADLINE).contains(&total_deadline)
            || !(HARD_MIN_NONCE_TTL..=HARD_MAX_NONCE_TTL).contains(&nonce_ttl)
            || max_nonces == 0
            || max_nonces > HARD_MAX_AUTHORITY_NONCES
            || Instant::now().checked_add(total_deadline).is_none()
            || Instant::now().checked_add(nonce_ttl).is_none()
        {
            return Err(AuthorityTransportErrorV2::InvalidConfiguration);
        }
        Ok(Self {
            total_deadline,
            nonce_ttl,
            max_nonces,
        })
    }

    /// Return the absolute per-connection operation budget.
    #[must_use]
    pub const fn total_deadline(self) -> Duration {
        self.total_deadline
    }

    /// Return the authenticated nonce retention window.
    #[must_use]
    pub const fn nonce_ttl(self) -> Duration {
        self.nonce_ttl
    }

    /// Return the maximum simultaneously retained nonces.
    #[must_use]
    pub const fn max_nonces(self) -> usize {
        self.max_nonces
    }
}

/// Inputs for explicitly provisioning a new Authority Store V2 server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityServerProvisionV2 {
    client_id: AuthorityClientIdV2,
    server_id: AuthorityServerIdV2,
    state_head: crate::authority::StateHeadV2,
    config: DeploymentConfigRevisionV2,
    store_limits: AuthorityLimitsV2,
}

impl AuthorityServerProvisionV2 {
    /// Bind a new store to distinct endpoint identities and exact initial state.
    pub fn new(
        client_id: AuthorityClientIdV2,
        server_id: AuthorityServerIdV2,
        state_head: crate::authority::StateHeadV2,
        config: DeploymentConfigRevisionV2,
        store_limits: AuthorityLimitsV2,
    ) -> Result<Self, AuthorityTransportErrorV2> {
        if client_id.as_bytes() == server_id.as_bytes() {
            return Err(AuthorityTransportErrorV2::InvalidConfiguration);
        }
        Ok(Self {
            client_id,
            server_id,
            state_head,
            config,
            store_limits,
        })
    }
}

/// Typed mutually authenticated client for the six Authority Wire V2 commands.
pub struct AuthenticatedTcpAuthorityV2 {
    address: SocketAddr,
    identity: AuthorityWireIdentityV2,
    client_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
    server_verification_key: [u8; ML_DSA_65_VK_LEN],
    total_deadline: Duration,
}

impl fmt::Debug for AuthenticatedTcpAuthorityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedTcpAuthorityV2([redacted])")
    }
}

impl AuthenticatedTcpAuthorityV2 {
    /// Configure one exact server, client principal, authority state, and key direction.
    pub fn new(
        address: SocketAddr,
        identity: AuthorityWireIdentityV2,
        client_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        server_verification_key: [u8; ML_DSA_65_VK_LEN],
        total_deadline: Duration,
    ) -> Result<Self, AuthorityTransportErrorV2> {
        validate_authentication_material(
            client_signing_key.as_bytes(),
            &server_verification_key,
            total_deadline,
        )?;
        Ok(Self {
            address,
            identity,
            client_signing_key,
            server_verification_key,
            total_deadline,
        })
    }

    /// Read the exact current authority projection.
    pub fn snapshot(
        &self,
    ) -> Result<AuthorityOutcomeV2<AuthoritySnapshotV2>, AuthorityTransportErrorV2> {
        let request = self.request(
            AuthorityCommandV2::Snapshot,
            AuthorityRequestPayloadV2::Snapshot,
        )?;
        match self.exchange(request)? {
            ClientExchangeV2::Unknown(reason) => Ok(AuthorityOutcomeV2::Unknown(reason)),
            ClientExchangeV2::Response(response) => match response.disposition {
                AuthorityResponseDispositionV2::Success(AuthoritySuccessV2::Snapshot(snapshot))
                    if snapshot.config() == self.identity.config()
                        && snapshot.state_head() == self.identity.state_head()
                        && snapshot.capability_count() == 0
                        && snapshot.retained_key_count() == 0
                        && snapshot.active_key_count() == 0 =>
                {
                    Ok(AuthorityOutcomeV2::Known(*snapshot))
                }
                AuthorityResponseDispositionV2::KnownFailure(failure) => {
                    Ok(AuthorityOutcomeV2::KnownFailure(failure))
                }
                AuthorityResponseDispositionV2::ReplayDetected => Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ReplayDetected,
                )),
                AuthorityResponseDispositionV2::ServerQuarantined => Ok(
                    AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ServerQuarantined),
                ),
                _ => Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ResponseInvalid,
                )),
            },
        }
    }

    /// Apply one complete acquire-lease intent.
    pub fn acquire(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_operation(AuthorityCommandV2::Acquire, intent)
    }

    /// Apply one complete renew-lease intent.
    pub fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_operation(AuthorityCommandV2::Renew, intent)
    }

    /// Apply one complete release-lease intent.
    pub fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_operation(AuthorityCommandV2::Release, intent)
    }

    /// Query one exact operation after an uncertain lease result.
    pub fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityQueryResultV2>, AuthorityTransportErrorV2> {
        let request = self.request(
            AuthorityCommandV2::Query,
            AuthorityRequestPayloadV2::Query(operation_id),
        )?;
        match self.exchange(request)? {
            ClientExchangeV2::Unknown(reason) => Ok(AuthorityOutcomeV2::Unknown(reason)),
            ClientExchangeV2::Response(response) => match response.disposition {
                AuthorityResponseDispositionV2::Success(AuthoritySuccessV2::Query(result))
                    if query_result_matches(&result, operation_id, self.identity.config()) =>
                {
                    Ok(AuthorityOutcomeV2::Known(result))
                }
                AuthorityResponseDispositionV2::KnownFailure(failure) => {
                    Ok(AuthorityOutcomeV2::KnownFailure(failure))
                }
                AuthorityResponseDispositionV2::ReplayDetected => Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ReplayDetected,
                )),
                AuthorityResponseDispositionV2::ServerQuarantined => Ok(
                    AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ServerQuarantined),
                ),
                _ => Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ResponseInvalid,
                )),
            },
        }
    }

    /// Let the server prune one receipt this client has already durably retained.
    ///
    /// Repeating an acknowledgement is explicitly idempotent: a receipt the server
    /// no longer retains returns [`ReceiptAckDispositionV2::AlreadyAbsent`].
    pub fn acknowledge(
        &self,
        retained: &DurablyRetainedAuthorityReceiptV2,
    ) -> Result<AuthorityOutcomeV2<ReceiptAckDispositionV2>, AuthorityTransportErrorV2> {
        let request = self.request(
            AuthorityCommandV2::Ack,
            AuthorityRequestPayloadV2::Ack(retained.locator()),
        )?;
        match self.exchange(request)? {
            ClientExchangeV2::Unknown(reason) => Ok(AuthorityOutcomeV2::Unknown(reason)),
            ClientExchangeV2::Response(response) => match response.disposition {
                AuthorityResponseDispositionV2::Success(AuthoritySuccessV2::Ack(disposition)) => {
                    Ok(AuthorityOutcomeV2::Known(disposition))
                }
                AuthorityResponseDispositionV2::KnownFailure(failure) => {
                    Ok(AuthorityOutcomeV2::KnownFailure(failure))
                }
                AuthorityResponseDispositionV2::ReplayDetected => Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ReplayDetected,
                )),
                AuthorityResponseDispositionV2::ServerQuarantined => Ok(
                    AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ServerQuarantined),
                ),
                _ => Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ResponseInvalid,
                )),
            },
        }
    }

    fn lease_operation(
        &self,
        command: AuthorityCommandV2,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        let request = self.request(command, AuthorityRequestPayloadV2::LeaseIntent(intent))?;
        match self.exchange(request)? {
            ClientExchangeV2::Unknown(reason) => Ok(AuthorityOutcomeV2::Unknown(reason)),
            ClientExchangeV2::Response(response) => match response.disposition {
                AuthorityResponseDispositionV2::Success(AuthoritySuccessV2::Receipt(receipt))
                    if receipt.intent() == intent
                        && receipt.intent().expected_config() == self.identity.config()
                        && receipt_command(&receipt) == Some(command) =>
                {
                    Ok(AuthorityOutcomeV2::Known(*receipt))
                }
                AuthorityResponseDispositionV2::KnownFailure(failure) => {
                    Ok(AuthorityOutcomeV2::KnownFailure(failure))
                }
                AuthorityResponseDispositionV2::ReplayDetected => Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ReplayDetected,
                )),
                AuthorityResponseDispositionV2::ServerQuarantined => Ok(
                    AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ServerQuarantined),
                ),
                _ => Ok(AuthorityOutcomeV2::Unknown(
                    AuthorityUnknownV2::ResponseInvalid,
                )),
            },
        }
    }

    fn request(
        &self,
        command: AuthorityCommandV2,
        payload: AuthorityRequestPayloadV2,
    ) -> Result<AuthorityRequestV2, AuthorityTransportErrorV2> {
        AuthorityRequestV2::new(self.identity, random_nonce()?, command, payload)
            .map_err(map_protocol_request)
    }

    fn exchange(
        &self,
        request: AuthorityRequestV2,
    ) -> Result<ClientExchangeV2, AuthorityTransportErrorV2> {
        let deadline = Instant::now()
            .checked_add(self.total_deadline)
            .ok_or(AuthorityTransportErrorV2::InvalidConfiguration)?;
        let request_body = request.body().map_err(map_protocol_request)?;
        let request_digest = hash_fields(AUTHORITY_REQUEST_DIGEST_DOMAIN, &[&request_body])
            .map_err(|_| AuthorityTransportErrorV2::EncodingFailed)?;
        let request_envelope = sign_envelope(&request_body, self.client_signing_key.as_bytes())
            .map_err(map_request_authentication)?;
        let connect_budget = remaining(deadline).map_err(|_| AuthorityTransportErrorV2::NotSent)?;
        let mut stream = TcpStream::connect_timeout(&self.address, connect_budget)
            .map_err(|_| AuthorityTransportErrorV2::NotSent)?;
        if let Err(error) = write_frame_until(&mut stream, &request_envelope, deadline) {
            return if error.wrote_any {
                Ok(ClientExchangeV2::Unknown(
                    AuthorityUnknownV2::RequestWriteIndeterminate,
                ))
            } else {
                Err(AuthorityTransportErrorV2::NotSent)
            };
        }
        let response_envelope = match read_frame_until(&mut stream, deadline) {
            Ok(envelope) => envelope,
            Err(FrameReadErrorV2::Invalid) => {
                return Ok(ClientExchangeV2::Unknown(
                    AuthorityUnknownV2::ResponseInvalid,
                ));
            }
            Err(FrameReadErrorV2::Unavailable | FrameReadErrorV2::Allocation) => {
                return Ok(ClientExchangeV2::Unknown(
                    AuthorityUnknownV2::ResponseUnavailable,
                ));
            }
        };
        if remaining(deadline).is_err() {
            return Ok(ClientExchangeV2::Unknown(
                AuthorityUnknownV2::ResponseUnavailable,
            ));
        }
        let response_body = match verify_envelope(&response_envelope, &self.server_verification_key)
        {
            Ok(body) => body,
            Err(_) => {
                return Ok(ClientExchangeV2::Unknown(
                    AuthorityUnknownV2::ResponseAuthenticationFailed,
                ));
            }
        };
        let response = match AuthorityResponseV2::decode(response_body) {
            Ok(response) => response,
            Err(_) => {
                return Ok(ClientExchangeV2::Unknown(
                    AuthorityUnknownV2::ResponseInvalid,
                ));
            }
        };
        if remaining(deadline).is_err() {
            return Ok(ClientExchangeV2::Unknown(
                AuthorityUnknownV2::ResponseUnavailable,
            ));
        }
        if response.server_id != self.identity.server_id()
            || response.client_id != self.identity.client_id()
            || response.authority_epoch != self.identity.authority_epoch()
            || response.nonce != request.nonce
            || response.command != request.command
            || response.request_digest != request_digest
        {
            return Ok(ClientExchangeV2::Unknown(
                AuthorityUnknownV2::ResponseInvalid,
            ));
        }
        Ok(ClientExchangeV2::Response(response))
    }
}

enum ClientExchangeV2 {
    Response(AuthorityResponseV2),
    Unknown(AuthorityUnknownV2),
}

/// Mandatory instance-lease authority boundary consumed by the product service.
///
/// The product Agent uses this port to serialize key-use behind exactly one
/// witness-clock-bounded instance lease. Implementations must preserve the
/// Authority Wire V2 outcome discipline: `Known` only for an authenticated
/// exact result, `KnownFailure` only for a closed no-mutation failure, and
/// `Unknown` whenever the request may have reached dispatch.
pub trait InstanceAuthorityPort: Send + Sync {
    /// Return the exact deployment-configuration revision every intent must name.
    fn wire_config(&self) -> DeploymentConfigRevisionV2;

    /// Read the exact current authority projection.
    fn snapshot(
        &self,
    ) -> Result<AuthorityOutcomeV2<AuthoritySnapshotV2>, AuthorityTransportErrorV2>;

    /// Apply one complete acquire-lease intent.
    fn acquire(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2>;

    /// Apply one complete renew-lease intent.
    fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2>;

    /// Apply one complete release-lease intent.
    fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2>;

    /// Query one exact operation after an uncertain lease result.
    fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityQueryResultV2>, AuthorityTransportErrorV2>;

    /// Let the authority prune one receipt the caller has already retained.
    fn acknowledge(
        &self,
        retained: &DurablyRetainedAuthorityReceiptV2,
    ) -> Result<AuthorityOutcomeV2<ReceiptAckDispositionV2>, AuthorityTransportErrorV2>;
}

impl InstanceAuthorityPort for AuthenticatedTcpAuthorityV2 {
    fn wire_config(&self) -> DeploymentConfigRevisionV2 {
        self.identity.config()
    }

    fn snapshot(
        &self,
    ) -> Result<AuthorityOutcomeV2<AuthoritySnapshotV2>, AuthorityTransportErrorV2> {
        Self::snapshot(self)
    }

    fn acquire(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        Self::acquire(self, intent)
    }

    fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        Self::renew(self, intent)
    }

    fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        Self::release(self, intent)
    }

    fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityQueryResultV2>, AuthorityTransportErrorV2> {
        Self::query(self, operation_id)
    }

    fn acknowledge(
        &self,
        retained: &DurablyRetainedAuthorityReceiptV2,
    ) -> Result<AuthorityOutcomeV2<ReceiptAckDispositionV2>, AuthorityTransportErrorV2> {
        Self::acknowledge(self, retained)
    }
}

/// Sequential reference server that exclusively owns one authority store.
pub struct ReferenceAuthorityServerV2 {
    store: AuthorityStoreV2,
    identity: AuthorityWireIdentityV2,
    client_verification_key: [u8; ML_DSA_65_VK_LEN],
    server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
    limits: AuthorityTransportLimitsV2,
    nonces: NonceCacheV2,
    quarantined: bool,
    #[cfg(all(test, unix))]
    fail_next_response: bool,
}

impl fmt::Debug for ReferenceAuthorityServerV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferenceAuthorityServerV2([redacted])")
    }
}

impl ReferenceAuthorityServerV2 {
    /// Provision a fresh Store V2 and pin one client principal and response key.
    pub fn provision(
        path: &Path,
        provision: AuthorityServerProvisionV2,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        limits: AuthorityTransportLimitsV2,
    ) -> Result<Self, AuthorityServerErrorV2> {
        validate_authentication_material(
            server_signing_key.as_bytes(),
            &client_verification_key,
            limits.total_deadline,
        )
        .map_err(map_server_configuration)?;
        let nonces = NonceCacheV2::new(limits)?;
        let store = AuthorityStoreV2::provision(
            path,
            provision.state_head,
            provision.config,
            provision.store_limits,
        )
        .map_err(map_store_setup)?;
        let identity = AuthorityWireIdentityV2::new(
            provision.client_id,
            provision.server_id,
            store.authority_epoch(),
            provision.state_head,
            provision.config,
        )
        .map_err(|_| AuthorityServerErrorV2::InvalidConfiguration)?;
        Self::from_store(
            store,
            identity,
            client_verification_key,
            server_signing_key,
            limits,
            nonces,
        )
    }

    /// Open an existing Store V2 only if its epoch exactly matches the pinned identity.
    pub fn open(
        path: &Path,
        identity: AuthorityWireIdentityV2,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        limits: AuthorityTransportLimitsV2,
    ) -> Result<Self, AuthorityServerErrorV2> {
        validate_authentication_material(
            server_signing_key.as_bytes(),
            &client_verification_key,
            limits.total_deadline,
        )
        .map_err(map_server_configuration)?;
        let nonces = NonceCacheV2::new(limits)?;
        let store = AuthorityStoreV2::open(path).map_err(map_store_setup)?;
        if store.authority_epoch() != identity.authority_epoch() {
            return Err(AuthorityServerErrorV2::InvalidConfiguration);
        }
        Self::from_store(
            store,
            identity,
            client_verification_key,
            server_signing_key,
            limits,
            nonces,
        )
    }

    fn from_store(
        store: AuthorityStoreV2,
        identity: AuthorityWireIdentityV2,
        client_verification_key: [u8; ML_DSA_65_VK_LEN],
        server_signing_key: ZeroizingBytes<ML_DSA_65_SK_LEN>,
        limits: AuthorityTransportLimitsV2,
        nonces: NonceCacheV2,
    ) -> Result<Self, AuthorityServerErrorV2> {
        let mut server = Self {
            store,
            identity,
            client_verification_key,
            server_signing_key,
            limits,
            nonces,
            quarantined: false,
            #[cfg(all(test, unix))]
            fail_next_response: false,
        };
        server.preflight()?;
        Ok(server)
    }

    /// Return the exact identity clients must pin, including the fresh store epoch.
    #[must_use]
    pub const fn identity(&self) -> AuthorityWireIdentityV2 {
        self.identity
    }

    /// Validate exact store state, then serve one authenticated request per connection.
    pub fn serve(
        &mut self,
        listener: TcpListener,
        shutdown: &AtomicBool,
    ) -> Result<(), AuthorityServerErrorV2> {
        self.preflight()?;
        listener
            .set_nonblocking(true)
            .map_err(|_| AuthorityServerErrorV2::ListenerUnavailable)?;
        while !shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if stream.set_nonblocking(false).is_err() {
                        continue;
                    }
                    if self.handle(&mut stream) == HandleResultV2::Quarantined {
                        return Err(AuthorityServerErrorV2::Quarantined);
                    }
                }
                Err(error) if accept_error_is_transient(&error) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(AuthorityServerErrorV2::ListenerUnavailable),
            }
        }
        Ok(())
    }

    fn preflight(&mut self) -> Result<(), AuthorityServerErrorV2> {
        if self.quarantined || self.store.authority_epoch() != self.identity.authority_epoch() {
            return Err(AuthorityServerErrorV2::Quarantined);
        }
        let snapshot = match self.store.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => return self.preflight_store_error(error),
        };
        if snapshot.config() != self.identity.config()
            || snapshot.state_head() != self.identity.state_head()
            || snapshot.capability_count() != 0
            || snapshot.retained_key_count() != 0
            || snapshot.active_key_count() != 0
        {
            return Err(AuthorityServerErrorV2::InvalidConfiguration);
        }
        let safe = match self
            .store
            .wire_v2_history_is_lease_only(self.identity.config())
        {
            Ok(safe) => safe,
            Err(error) => return self.preflight_store_error(error),
        };
        if !safe {
            return Err(AuthorityServerErrorV2::InvalidConfiguration);
        }
        Ok(())
    }

    fn preflight_store_error(
        &mut self,
        error: AuthorityStoreErrorV2,
    ) -> Result<(), AuthorityServerErrorV2> {
        match classify_store_error(error) {
            StoreDispositionV2::KnownFailure(_) => Err(AuthorityServerErrorV2::StoreUnavailable),
            StoreDispositionV2::Fatal => {
                self.quarantined = true;
                Err(AuthorityServerErrorV2::Quarantined)
            }
        }
    }

    fn handle(&mut self, stream: &mut TcpStream) -> HandleResultV2 {
        let Some(deadline) = Instant::now().checked_add(self.limits.total_deadline) else {
            return HandleResultV2::Continue;
        };
        let request_envelope = match read_frame_until(stream, deadline) {
            Ok(envelope) => envelope,
            Err(_) => return HandleResultV2::Continue,
        };
        let request_body = match verify_envelope(&request_envelope, &self.client_verification_key) {
            Ok(body) => body,
            Err(_) => return HandleResultV2::Continue,
        };
        let request = match AuthorityRequestV2::decode(request_body) {
            Ok(request) => request,
            Err(_) => return HandleResultV2::Continue,
        };
        if remaining(deadline).is_err() {
            return HandleResultV2::Continue;
        }
        if request.client_id != self.identity.client_id()
            || request.server_id != self.identity.server_id()
            || request.authority_epoch != self.identity.authority_epoch()
            || request.expected_state_head != self.identity.state_head()
            || request.expected_config != self.identity.config()
        {
            return HandleResultV2::Continue;
        }
        let request_digest = match hash_fields(AUTHORITY_REQUEST_DIGEST_DOMAIN, &[request_body]) {
            Ok(digest) => digest,
            Err(_) => return HandleResultV2::Continue,
        };
        if remaining(deadline).is_err() {
            return HandleResultV2::Continue;
        }
        let nonce_decision = self.nonces.observe(request.nonce, Instant::now());
        let disposition = match nonce_decision {
            NonceDecisionV2::Duplicate => AuthorityResponseDispositionV2::ReplayDetected,
            NonceDecisionV2::Capacity => {
                AuthorityResponseDispositionV2::KnownFailure(AuthorityKnownFailureV2::RateLimited)
            }
            NonceDecisionV2::Invariant => {
                self.quarantined = true;
                AuthorityResponseDispositionV2::ServerQuarantined
            }
            NonceDecisionV2::Inserted => match self.dispatch(request) {
                StoreDispatchV2::Success(success) => {
                    AuthorityResponseDispositionV2::Success(success)
                }
                StoreDispatchV2::KnownFailure(failure) => {
                    AuthorityResponseDispositionV2::KnownFailure(failure)
                }
                StoreDispatchV2::Fatal => {
                    self.quarantined = true;
                    AuthorityResponseDispositionV2::ServerQuarantined
                }
            },
        };
        let response = AuthorityResponseV2 {
            server_id: self.identity.server_id(),
            client_id: self.identity.client_id(),
            authority_epoch: self.identity.authority_epoch(),
            nonce: request.nonce,
            command: request.command,
            request_digest,
            disposition,
        };
        #[cfg(all(test, unix))]
        let fail_response = {
            let fail = self.fail_next_response;
            self.fail_next_response = false;
            fail
        };
        #[cfg(not(all(test, unix)))]
        let fail_response = false;
        if !fail_response {
            let _ = send_response(
                stream,
                deadline,
                &response,
                self.server_signing_key.as_bytes(),
            );
        }
        if self.quarantined {
            HandleResultV2::Quarantined
        } else {
            HandleResultV2::Continue
        }
    }

    fn dispatch(&mut self, request: AuthorityRequestV2) -> StoreDispatchV2 {
        let result = match request.payload {
            AuthorityRequestPayloadV2::Snapshot => self
                .store
                .snapshot()
                .map(|snapshot| AuthoritySuccessV2::Snapshot(Box::new(snapshot))),
            AuthorityRequestPayloadV2::LeaseIntent(intent) => self
                .store
                .apply(intent)
                .map(|receipt| AuthoritySuccessV2::Receipt(Box::new(receipt))),
            AuthorityRequestPayloadV2::Query(operation_id) => {
                self.store.query(operation_id).and_then(|result| {
                    if query_result_matches(&result, operation_id, self.identity.config()) {
                        Ok(AuthoritySuccessV2::Query(result))
                    } else {
                        Err(AuthorityStoreErrorV2::CorruptStore)
                    }
                })
            }
            AuthorityRequestPayloadV2::Ack(locator) => self
                .store
                .acknowledge_receipt(locator)
                .map(AuthoritySuccessV2::Ack),
        };
        match result {
            Ok(success) => StoreDispatchV2::Success(success),
            Err(error) => match classify_store_error(error) {
                StoreDispositionV2::KnownFailure(failure) => StoreDispatchV2::KnownFailure(failure),
                StoreDispositionV2::Fatal => StoreDispatchV2::Fatal,
            },
        }
    }

    #[cfg(all(test, unix))]
    fn fail_next_response_for_test(&mut self) {
        self.fail_next_response = true;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandleResultV2 {
    Continue,
    Quarantined,
}

enum StoreDispatchV2 {
    Success(AuthoritySuccessV2),
    KnownFailure(AuthorityKnownFailureV2),
    Fatal,
}

enum StoreDispositionV2 {
    KnownFailure(AuthorityKnownFailureV2),
    Fatal,
}

fn classify_store_error(error: AuthorityStoreErrorV2) -> StoreDispositionV2 {
    match error {
        AuthorityStoreErrorV2::AllocationFailed
        | AuthorityStoreErrorV2::Authority(AuthorityErrorV2::AllocationFailed) => {
            StoreDispositionV2::KnownFailure(AuthorityKnownFailureV2::AllocationFailed)
        }
        AuthorityStoreErrorV2::Authority(AuthorityErrorV2::ClockUnavailable) => {
            StoreDispositionV2::KnownFailure(AuthorityKnownFailureV2::ClockUnavailable)
        }
        AuthorityStoreErrorV2::Authority(AuthorityErrorV2::OperationConflict) => {
            StoreDispositionV2::KnownFailure(AuthorityKnownFailureV2::OperationConflict)
        }
        AuthorityStoreErrorV2::Authority(AuthorityErrorV2::AuthorityVersionMismatch) => {
            StoreDispositionV2::KnownFailure(AuthorityKnownFailureV2::AuthorityVersionMismatch)
        }
        AuthorityStoreErrorV2::Authority(AuthorityErrorV2::AuthorityVersionExhausted) => {
            StoreDispositionV2::KnownFailure(AuthorityKnownFailureV2::AuthorityVersionExhausted)
        }
        AuthorityStoreErrorV2::Authority(AuthorityErrorV2::ReceiptCapacityExceeded) => {
            StoreDispositionV2::KnownFailure(AuthorityKnownFailureV2::ReceiptCapacityExceeded)
        }
        AuthorityStoreErrorV2::ReceiptAcknowledgement(_) => StoreDispositionV2::KnownFailure(
            AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch,
        ),
        AuthorityStoreErrorV2::InsecureOrMissingStore
        | AuthorityStoreErrorV2::AlreadyOpen
        | AuthorityStoreErrorV2::UnsupportedSchema
        | AuthorityStoreErrorV2::CorruptStore
        | AuthorityStoreErrorV2::EntropyUnavailable
        | AuthorityStoreErrorV2::Authority(AuthorityErrorV2::InternalInvariant)
        | AuthorityStoreErrorV2::CommitUncertain
        | AuthorityStoreErrorV2::Poisoned => StoreDispositionV2::Fatal,
    }
}

fn query_result_matches(
    result: &AuthorityQueryResultV2,
    operation_id: OperationIdV2,
    expected_config: DeploymentConfigRevisionV2,
) -> bool {
    match result {
        AuthorityQueryResultV2::Found(receipt) => {
            receipt.intent().operation_id() == operation_id
                && receipt.intent().expected_config() == expected_config
                && receipt_command(receipt).is_some()
        }
        AuthorityQueryResultV2::AbsentAtVersion { authority_version } => *authority_version != 0,
    }
}

fn send_response(
    stream: &mut TcpStream,
    deadline: Instant,
    response: &AuthorityResponseV2,
    signing_key: &[u8],
) -> Result<(), ()> {
    let body = response.body().map_err(|_| ())?;
    let envelope = sign_envelope(&body, signing_key).map_err(|_| ())?;
    write_frame_until(stream, &envelope, deadline).map_err(|_| ())
}

fn validate_authentication_material(
    signing_key: &[u8],
    verification_key: &[u8],
    total_deadline: Duration,
) -> Result<(), AuthorityTransportErrorV2> {
    if !(HARD_MIN_TOTAL_DEADLINE..=HARD_MAX_TOTAL_DEADLINE).contains(&total_deadline)
        || Instant::now().checked_add(total_deadline).is_none()
        || signing_key.iter().all(|byte| *byte == 0)
        || verification_key.iter().all(|byte| *byte == 0)
    {
        return Err(AuthorityTransportErrorV2::InvalidConfiguration);
    }
    match signing_key_matches_verification_key(
        ROLE_SEPARATION_CHALLENGE,
        signing_key,
        verification_key,
    ) {
        Ok(false) => Ok(()),
        Ok(true) | Err(_) => Err(AuthorityTransportErrorV2::InvalidConfiguration),
    }
}

fn map_server_configuration(_: AuthorityTransportErrorV2) -> AuthorityServerErrorV2 {
    AuthorityServerErrorV2::InvalidConfiguration
}

fn map_store_setup(error: AuthorityStoreErrorV2) -> AuthorityServerErrorV2 {
    match error {
        AuthorityStoreErrorV2::CommitUncertain | AuthorityStoreErrorV2::Poisoned => {
            AuthorityServerErrorV2::Quarantined
        }
        AuthorityStoreErrorV2::InsecureOrMissingStore
        | AuthorityStoreErrorV2::AlreadyOpen
        | AuthorityStoreErrorV2::UnsupportedSchema
        | AuthorityStoreErrorV2::CorruptStore
        | AuthorityStoreErrorV2::AllocationFailed
        | AuthorityStoreErrorV2::EntropyUnavailable
        | AuthorityStoreErrorV2::Authority(_)
        | AuthorityStoreErrorV2::ReceiptAcknowledgement(_) => {
            AuthorityServerErrorV2::StoreUnavailable
        }
    }
}

fn map_protocol_request(error: AuthorityProtocolErrorV2) -> AuthorityTransportErrorV2 {
    match error {
        AuthorityProtocolErrorV2::Allocation => AuthorityTransportErrorV2::EncodingFailed,
        AuthorityProtocolErrorV2::Invalid => AuthorityTransportErrorV2::InvalidRequest,
    }
}

fn map_request_authentication(error: AuthenticationError) -> AuthorityTransportErrorV2 {
    match error {
        AuthenticationError::Entropy => AuthorityTransportErrorV2::EntropyUnavailable,
        AuthenticationError::Authentication | AuthenticationError::InvalidEnvelope => {
            AuthorityTransportErrorV2::EncodingFailed
        }
    }
}

fn random_nonce() -> Result<[u8; 32], AuthorityTransportErrorV2> {
    for _ in 0..4 {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| AuthorityTransportErrorV2::EntropyUnavailable)?;
        if nonce.iter().any(|byte| *byte != 0) {
            return Ok(nonce);
        }
    }
    Err(AuthorityTransportErrorV2::EntropyUnavailable)
}

struct NonceEntryV2 {
    nonce: [u8; 32],
    expires_at: Instant,
}

struct NonceCacheV2 {
    entries: VecDeque<NonceEntryV2>,
    values: HashSet<[u8; 32]>,
    ttl: Duration,
    maximum: usize,
}

impl NonceCacheV2 {
    fn new(limits: AuthorityTransportLimitsV2) -> Result<Self, AuthorityServerErrorV2> {
        let mut entries = VecDeque::new();
        entries
            .try_reserve(limits.max_nonces)
            .map_err(|_| AuthorityServerErrorV2::InvalidConfiguration)?;
        let mut values = HashSet::new();
        values
            .try_reserve(limits.max_nonces)
            .map_err(|_| AuthorityServerErrorV2::InvalidConfiguration)?;
        Ok(Self {
            entries,
            values,
            ttl: limits.nonce_ttl,
            maximum: limits.max_nonces,
        })
    }

    fn observe(&mut self, nonce: [u8; 32], now: Instant) -> NonceDecisionV2 {
        while matches!(self.entries.front(), Some(entry) if entry.expires_at <= now) {
            let Some(expired) = self.entries.pop_front() else {
                return NonceDecisionV2::Invariant;
            };
            if !self.values.remove(&expired.nonce) {
                return NonceDecisionV2::Invariant;
            }
        }
        if self.values.contains(&nonce) {
            return NonceDecisionV2::Duplicate;
        }
        if self.entries.len() >= self.maximum || self.values.len() >= self.maximum {
            return NonceDecisionV2::Capacity;
        }
        let Some(expires_at) = now.checked_add(self.ttl) else {
            return NonceDecisionV2::Invariant;
        };
        if !self.values.insert(nonce) {
            return NonceDecisionV2::Invariant;
        }
        self.entries.push_back(NonceEntryV2 { nonce, expires_at });
        NonceDecisionV2::Inserted
    }
}

enum NonceDecisionV2 {
    Inserted,
    Duplicate,
    Capacity,
    Invariant,
}

trait DeadlineStreamV2: Read + Write {
    fn set_read_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl DeadlineStreamV2 for TcpStream {
    fn set_read_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }

    fn set_write_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

struct FrameWriteErrorV2 {
    wrote_any: bool,
}

enum FrameReadErrorV2 {
    Unavailable,
    Invalid,
    Allocation,
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "absolute deadline expired"))
}

fn write_frame_until<S: DeadlineStreamV2>(
    stream: &mut S,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), FrameWriteErrorV2> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(FrameWriteErrorV2 { wrote_any: false });
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| FrameWriteErrorV2 { wrote_any: false })?
        .to_be_bytes();
    let mut wrote_any = false;
    for bytes in [length.as_slice(), payload] {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let timeout = remaining(deadline).map_err(|_| FrameWriteErrorV2 { wrote_any })?;
            stream
                .set_write_deadline_timeout(Some(timeout))
                .map_err(|_| FrameWriteErrorV2 { wrote_any })?;
            let Some(pending) = bytes.get(offset..) else {
                return Err(FrameWriteErrorV2 { wrote_any });
            };
            match stream.write(pending) {
                Ok(0) => return Err(FrameWriteErrorV2 { wrote_any }),
                Ok(written) => {
                    wrote_any = true;
                    offset = offset
                        .checked_add(written)
                        .ok_or(FrameWriteErrorV2 { wrote_any })?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(FrameWriteErrorV2 { wrote_any }),
            }
        }
    }
    let timeout = remaining(deadline).map_err(|_| FrameWriteErrorV2 { wrote_any })?;
    stream
        .set_write_deadline_timeout(Some(timeout))
        .and_then(|()| stream.flush())
        .map_err(|_| FrameWriteErrorV2 { wrote_any })
}

fn read_frame_until<S: DeadlineStreamV2>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Vec<u8>, FrameReadErrorV2> {
    let mut length = [0u8; 4];
    read_exact_until(stream, &mut length, deadline)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| FrameReadErrorV2::Invalid)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(FrameReadErrorV2::Invalid);
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| FrameReadErrorV2::Allocation)?;
    payload.resize(length, 0);
    read_exact_until(stream, &mut payload, deadline)?;
    Ok(payload)
}

fn read_exact_until<S: DeadlineStreamV2>(
    stream: &mut S,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), FrameReadErrorV2> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let timeout = remaining(deadline).map_err(|_| FrameReadErrorV2::Unavailable)?;
        stream
            .set_read_deadline_timeout(Some(timeout))
            .map_err(|_| FrameReadErrorV2::Unavailable)?;
        let Some(pending) = bytes.get_mut(offset..) else {
            return Err(FrameReadErrorV2::Invalid);
        };
        match stream.read(pending) {
            Ok(0) => return Err(FrameReadErrorV2::Unavailable),
            Ok(read) => {
                offset = offset.checked_add(read).ok_or(FrameReadErrorV2::Invalid)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(FrameReadErrorV2::Unavailable),
        }
    }
    remaining(deadline)
        .map(|_| ())
        .map_err(|_| FrameReadErrorV2::Unavailable)
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    use q_periapt_backends::MlDsa65;

    use super::*;
    use crate::authority::{
        AuthorityDispositionV2, AuthorityEpochV2, AuthorityMutationV2, AuthorityRejectionV2,
        AuthorityValueErrorV2, InstanceFenceV2, ProcessInstanceIdV2, StateAdvanceV2, StateFenceV2,
        StateHeadV2, StateRevisionV2, StateTransitionKindV2,
    };
    use crate::authority_protocol::DurablyRetainedAuthorityReceiptV2;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    const CLIENT_SEED: [u8; 32] = [0xA1; 32];
    const SERVER_SEED: [u8; 32] = [0xA2; 32];
    const FOREIGN_SEED: [u8; 32] = [0xA3; 32];

    struct PrivateDirectory {
        _temporary: tempfile::TempDir,
        path: PathBuf,
    }

    impl PrivateDirectory {
        fn new() -> TestResult<Self> {
            use std::os::unix::fs::PermissionsExt;

            let temporary = tempfile::Builder::new()
                .prefix("q-periapt-authority-wire-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()?;
            let path = temporary.path().canonicalize()?;
            Ok(Self {
                _temporary: temporary,
                path,
            })
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    fn client_id() -> Result<AuthorityClientIdV2, AuthorityValueErrorV2> {
        AuthorityClientIdV2::from_bytes([0x11; 32])
    }

    fn server_id() -> Result<AuthorityServerIdV2, AuthorityValueErrorV2> {
        AuthorityServerIdV2::from_bytes([0x12; 32])
    }

    fn head() -> Result<StateHeadV2, AuthorityValueErrorV2> {
        Ok(StateHeadV2::new(
            StateRevisionV2::new(1, [0x21; 32], 1, [0x22; 32])?,
            StateFenceV2::from_bytes([0x23; 32])?,
        ))
    }

    fn config() -> Result<DeploymentConfigRevisionV2, AuthorityValueErrorV2> {
        DeploymentConfigRevisionV2::new(1, [0x31; 32])
    }

    fn store_limits() -> Result<AuthorityLimitsV2, AuthorityValueErrorV2> {
        AuthorityLimitsV2::new(8, 4, 4, 60_000)
    }

    fn transport_limits() -> Result<AuthorityTransportLimitsV2, AuthorityTransportErrorV2> {
        AuthorityTransportLimitsV2::new(Duration::from_secs(2), Duration::from_secs(60), 64)
    }

    fn instance(byte: u8) -> Result<ProcessInstanceIdV2, AuthorityValueErrorV2> {
        ProcessInstanceIdV2::from_bytes([byte; 32])
    }

    fn acquire_intent(
        version: u64,
        expected_lease_generation: u64,
        instance_byte: u8,
        operation_byte: u8,
    ) -> Result<AuthorityIntentV2, AuthorityValueErrorV2> {
        AuthorityIntentV2::new(
            OperationIdV2::new(version, [operation_byte; 32])?,
            version,
            config()?,
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation,
                instance_id: instance(instance_byte)?,
            },
        )
    }

    fn renew_intent(
        version: u64,
        lease_generation: u64,
        instance_byte: u8,
        operation_byte: u8,
    ) -> Result<AuthorityIntentV2, AuthorityValueErrorV2> {
        AuthorityIntentV2::new(
            OperationIdV2::new(version, [operation_byte; 32])?,
            version,
            config()?,
            AuthorityMutationV2::RenewLease {
                fence: InstanceFenceV2::new(lease_generation, instance(instance_byte)?)?,
            },
        )
    }

    fn release_intent(
        version: u64,
        lease_generation: u64,
        instance_byte: u8,
        operation_byte: u8,
    ) -> Result<AuthorityIntentV2, AuthorityValueErrorV2> {
        AuthorityIntentV2::new(
            OperationIdV2::new(version, [operation_byte; 32])?,
            version,
            config()?,
            AuthorityMutationV2::ReleaseLease {
                fence: InstanceFenceV2::new(lease_generation, instance(instance_byte)?)?,
            },
        )
    }

    fn provisioned_server(path: &Path) -> TestResult<ReferenceAuthorityServerV2> {
        let (_, client_vk) = MlDsa65::generate(CLIENT_SEED);
        let (server_sk, _) = MlDsa65::generate(SERVER_SEED);
        let provision = AuthorityServerProvisionV2::new(
            client_id()?,
            server_id()?,
            head()?,
            config()?,
            store_limits()?,
        )?;
        Ok(ReferenceAuthorityServerV2::provision(
            path,
            provision,
            client_vk,
            ZeroizingBytes::from_bytes(server_sk),
            transport_limits()?,
        )?)
    }

    fn pinned_client(
        address: SocketAddr,
        identity: AuthorityWireIdentityV2,
    ) -> TestResult<AuthenticatedTcpAuthorityV2> {
        let (client_sk, _) = MlDsa65::generate(CLIENT_SEED);
        let (_, server_vk) = MlDsa65::generate(SERVER_SEED);
        Ok(AuthenticatedTcpAuthorityV2::new(
            address,
            identity,
            ZeroizingBytes::from_bytes(client_sk),
            server_vk,
            Duration::from_secs(2),
        )?)
    }

    type SpawnedServer = (
        SocketAddr,
        Arc<AtomicBool>,
        thread::JoinHandle<Result<(), AuthorityServerErrorV2>>,
    );

    fn spawn_server(mut server: ReferenceAuthorityServerV2) -> TestResult<SpawnedServer> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || server.serve(listener, &server_shutdown));
        Ok((address, shutdown, handle))
    }

    fn join<T>(handle: thread::JoinHandle<T>) -> TestResult<T> {
        handle
            .join()
            .map_err(|_| io::Error::other("test worker panicked").into())
    }

    fn known_receipt(
        outcome: AuthorityOutcomeV2<AuthorityReceiptV2>,
    ) -> TestResult<AuthorityReceiptV2> {
        match outcome {
            AuthorityOutcomeV2::Known(receipt) => Ok(receipt),
            other => Err(format!("expected a known lease receipt, got {other:?}").into()),
        }
    }

    #[test]
    fn lease_lifecycle_fencing_and_acknowledgement_round_trip_over_tcp() -> TestResult {
        let directory = PrivateDirectory::new()?;
        let path = directory.join("authority-wire.redb");
        let server = provisioned_server(&path)?;
        let identity = server.identity();
        let (address, shutdown, handle) = spawn_server(server)?;
        let client = pinned_client(address, identity)?;

        let snapshot = match client.snapshot()? {
            AuthorityOutcomeV2::Known(snapshot) => snapshot,
            other => return Err(format!("expected a known snapshot, got {other:?}").into()),
        };
        assert_eq!(snapshot.authority_version(), 1);
        assert_eq!(snapshot.state_head(), identity.state_head());
        assert_eq!(snapshot.config(), identity.config());

        let acquire_a = acquire_intent(1, 0, 0x41, 0x51)?;
        let acquire_receipt = known_receipt(client.acquire(acquire_a)?)?;
        assert_eq!(acquire_receipt.intent(), acquire_a);
        assert_eq!(
            acquire_receipt.disposition(),
            AuthorityDispositionV2::Applied
        );
        assert_eq!(acquire_receipt.resulting_authority_version(), 2);

        let retained = DurablyRetainedAuthorityReceiptV2::after_durable_commit(acquire_receipt)?;
        assert_eq!(
            client.acknowledge(&retained)?,
            AuthorityOutcomeV2::Known(ReceiptAckDispositionV2::Removed)
        );
        assert_eq!(
            client.acknowledge(&retained)?,
            AuthorityOutcomeV2::Known(ReceiptAckDispositionV2::AlreadyAbsent)
        );

        let renew_a = renew_intent(2, 1, 0x41, 0x52)?;
        let renew_receipt = known_receipt(client.renew(renew_a)?)?;
        assert_eq!(renew_receipt.disposition(), AuthorityDispositionV2::Applied);

        let release_a = release_intent(3, 1, 0x41, 0x53)?;
        let release_receipt = known_receipt(client.release(release_a)?)?;
        assert_eq!(
            release_receipt.disposition(),
            AuthorityDispositionV2::Applied
        );

        assert_eq!(
            client.query(renew_a.operation_id())?,
            AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(Box::new(renew_receipt)))
        );
        assert_eq!(
            client.query(acquire_a.operation_id())?,
            AuthorityOutcomeV2::Known(AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: 4
            })
        );

        let stale = acquire_intent(1, 1, 0x42, 0x54)?;
        assert_eq!(
            client.acquire(stale)?,
            AuthorityOutcomeV2::KnownFailure(AuthorityKnownFailureV2::AuthorityVersionMismatch)
        );

        let refreshed = match client.snapshot()? {
            AuthorityOutcomeV2::Known(snapshot) => snapshot,
            other => return Err(format!("expected a refreshed snapshot, got {other:?}").into()),
        };
        assert_eq!(refreshed.authority_version(), 4);

        let acquire_b = acquire_intent(4, 1, 0x42, 0x55)?;
        let acquire_b_receipt = known_receipt(client.acquire(acquire_b)?)?;
        assert_eq!(
            acquire_b_receipt.disposition(),
            AuthorityDispositionV2::Applied
        );

        let fenced_out = renew_intent(5, 1, 0x41, 0x56)?;
        let fenced_receipt = known_receipt(client.renew(fenced_out)?)?;
        assert_eq!(
            fenced_receipt.disposition(),
            AuthorityDispositionV2::Rejected(AuthorityRejectionV2::FenceMismatch)
        );

        shutdown.store(true, Ordering::Release);
        join(handle)??;

        let (_, client_vk) = MlDsa65::generate(CLIENT_SEED);
        let (server_sk, _) = MlDsa65::generate(SERVER_SEED);
        let reopened = ReferenceAuthorityServerV2::open(
            &path,
            identity,
            client_vk,
            ZeroizingBytes::from_bytes(server_sk),
            transport_limits()?,
        )?;
        let (address, shutdown, handle) = spawn_server(reopened)?;
        let client = pinned_client(address, identity)?;
        let renew_b = renew_intent(6, 2, 0x42, 0x57)?;
        let renew_b_receipt = known_receipt(client.renew(renew_b)?)?;
        assert_eq!(
            renew_b_receipt.disposition(),
            AuthorityDispositionV2::Applied
        );
        shutdown.store(true, Ordering::Release);
        join(handle)??;
        Ok(())
    }

    fn raw_exchange(
        address: SocketAddr,
        envelope: &[u8],
        server_verification_key: &[u8; ML_DSA_65_VK_LEN],
    ) -> TestResult<AuthorityResponseV2> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or("test deadline overflowed")?;
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        write_frame_until(&mut stream, envelope, deadline)
            .map_err(|_| "raw request write failed")?;
        let response_envelope =
            read_frame_until(&mut stream, deadline).map_err(|_| "raw response read failed")?;
        let body = verify_envelope(&response_envelope, server_verification_key)
            .map_err(|_| "raw response authentication failed")?;
        AuthorityResponseV2::decode(body).map_err(|_| "raw response decode failed".into())
    }

    #[test]
    fn replayed_request_envelope_is_detected_and_dispatched_only_once() -> TestResult {
        let directory = PrivateDirectory::new()?;
        let path = directory.join("authority-replay.redb");
        let server = provisioned_server(&path)?;
        let identity = server.identity();
        let (address, shutdown, handle) = spawn_server(server)?;

        let (client_sk, _) = MlDsa65::generate(CLIENT_SEED);
        let (_, server_vk) = MlDsa65::generate(SERVER_SEED);
        let intent = acquire_intent(1, 0, 0x43, 0x61)?;
        let request = AuthorityRequestV2::new(
            identity,
            [0x71; 32],
            AuthorityCommandV2::Acquire,
            AuthorityRequestPayloadV2::LeaseIntent(intent),
        )
        .map_err(|_| "raw request construction failed")?;
        let request_body = request.body().map_err(|_| "raw request encoding failed")?;
        let envelope =
            sign_envelope(&request_body, &client_sk).map_err(|_| "raw request signing failed")?;

        let first = raw_exchange(address, &envelope, &server_vk)?;
        match first.disposition {
            AuthorityResponseDispositionV2::Success(AuthoritySuccessV2::Receipt(receipt)) => {
                assert_eq!(receipt.intent(), intent);
                assert_eq!(receipt.disposition(), AuthorityDispositionV2::Applied);
            }
            other => return Err(format!("expected an applied receipt, got {other:?}").into()),
        }

        let replayed = raw_exchange(address, &envelope, &server_vk)?;
        assert_eq!(
            replayed.disposition,
            AuthorityResponseDispositionV2::ReplayDetected
        );

        let client = pinned_client(address, identity)?;
        let queried = match client.query(intent.operation_id())? {
            AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(receipt)) => *receipt,
            other => return Err(format!("expected the retained receipt, got {other:?}").into()),
        };
        assert_eq!(queried.resulting_authority_version(), 2);
        let retained = DurablyRetainedAuthorityReceiptV2::after_durable_commit(queried)?;
        assert_eq!(
            client.acknowledge(&retained)?,
            AuthorityOutcomeV2::Known(ReceiptAckDispositionV2::Removed)
        );

        shutdown.store(true, Ordering::Release);
        join(handle)??;
        Ok(())
    }

    #[test]
    fn mismatched_identity_or_unpinned_key_receives_no_authority_response() -> TestResult {
        let directory = PrivateDirectory::new()?;
        let path = directory.join("authority-binding.redb");
        let server = provisioned_server(&path)?;
        let identity = server.identity();
        let (address, shutdown, handle) = spawn_server(server)?;

        let wrong_config = AuthorityWireIdentityV2::new(
            identity.client_id(),
            identity.server_id(),
            identity.authority_epoch(),
            identity.state_head(),
            DeploymentConfigRevisionV2::new(2, [0x32; 32])?,
        )?;
        assert_eq!(
            pinned_client(address, wrong_config)?.snapshot()?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        );

        let wrong_head = AuthorityWireIdentityV2::new(
            identity.client_id(),
            identity.server_id(),
            identity.authority_epoch(),
            StateHeadV2::new(
                StateRevisionV2::new(2, [0x21; 32], 2, [0x24; 32])?,
                StateFenceV2::from_bytes([0x25; 32])?,
            ),
            identity.config(),
        )?;
        assert_eq!(
            pinned_client(address, wrong_head)?.snapshot()?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        );

        let wrong_epoch = AuthorityWireIdentityV2::new(
            identity.client_id(),
            identity.server_id(),
            AuthorityEpochV2::from_bytes([0xEE; 32])?,
            identity.state_head(),
            identity.config(),
        )?;
        assert_eq!(
            pinned_client(address, wrong_epoch)?.snapshot()?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        );

        let (foreign_sk, _) = MlDsa65::generate(FOREIGN_SEED);
        let (_, server_vk) = MlDsa65::generate(SERVER_SEED);
        let unpinned = AuthenticatedTcpAuthorityV2::new(
            address,
            identity,
            ZeroizingBytes::from_bytes(foreign_sk),
            server_vk,
            Duration::from_secs(2),
        )?;
        assert_eq!(
            unpinned.snapshot()?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        );

        let pinned = pinned_client(address, identity)?;
        assert!(matches!(pinned.snapshot()?, AuthorityOutcomeV2::Known(_)));

        shutdown.store(true, Ordering::Release);
        join(handle)??;
        Ok(())
    }

    #[test]
    fn lost_response_is_recovered_by_query_and_acknowledged_once() -> TestResult {
        let directory = PrivateDirectory::new()?;
        let path = directory.join("authority-lost-response.redb");
        let mut server = provisioned_server(&path)?;
        let identity = server.identity();
        server.fail_next_response_for_test();
        let (address, shutdown, handle) = spawn_server(server)?;
        let client = pinned_client(address, identity)?;

        let intent = acquire_intent(1, 0, 0x44, 0x62)?;
        assert_eq!(
            client.acquire(intent)?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        );

        let recovered = match client.query(intent.operation_id())? {
            AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(receipt)) => *receipt,
            other => return Err(format!("expected the committed receipt, got {other:?}").into()),
        };
        assert_eq!(recovered.intent(), intent);
        assert_eq!(recovered.disposition(), AuthorityDispositionV2::Applied);

        let retained = DurablyRetainedAuthorityReceiptV2::after_durable_commit(recovered)?;
        assert_eq!(
            client.acknowledge(&retained)?,
            AuthorityOutcomeV2::Known(ReceiptAckDispositionV2::Removed)
        );

        shutdown.store(true, Ordering::Release);
        join(handle)??;
        Ok(())
    }

    #[test]
    fn nonce_capacity_returns_rate_limited_before_dispatch() -> TestResult {
        let directory = PrivateDirectory::new()?;
        let path = directory.join("authority-rate-limit.redb");
        let (_, client_vk) = MlDsa65::generate(CLIENT_SEED);
        let (server_sk, _) = MlDsa65::generate(SERVER_SEED);
        let provision = AuthorityServerProvisionV2::new(
            client_id()?,
            server_id()?,
            head()?,
            config()?,
            store_limits()?,
        )?;
        let server = ReferenceAuthorityServerV2::provision(
            &path,
            provision,
            client_vk,
            ZeroizingBytes::from_bytes(server_sk),
            AuthorityTransportLimitsV2::new(Duration::from_secs(2), Duration::from_secs(60), 1)?,
        )?;
        let identity = server.identity();
        let (address, shutdown, handle) = spawn_server(server)?;
        let client = pinned_client(address, identity)?;

        assert!(matches!(client.snapshot()?, AuthorityOutcomeV2::Known(_)));
        assert_eq!(
            client.snapshot()?,
            AuthorityOutcomeV2::KnownFailure(AuthorityKnownFailureV2::RateLimited)
        );

        shutdown.store(true, Ordering::Release);
        join(handle)??;
        Ok(())
    }

    #[test]
    fn endpoint_configuration_and_key_role_separation_fail_closed() -> TestResult {
        assert_eq!(
            AuthorityTransportLimitsV2::new(Duration::ZERO, Duration::from_secs(1), 1).err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );
        assert_eq!(
            AuthorityTransportLimitsV2::new(Duration::from_secs(31), Duration::from_secs(1), 1)
                .err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );
        assert_eq!(
            AuthorityTransportLimitsV2::new(Duration::from_secs(1), Duration::ZERO, 1).err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );
        assert_eq!(
            AuthorityTransportLimitsV2::new(
                Duration::from_secs(1),
                Duration::from_secs(11 * 60),
                1
            )
            .err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );
        assert_eq!(
            AuthorityTransportLimitsV2::new(Duration::from_secs(1), Duration::from_secs(1), 0)
                .err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );
        assert_eq!(
            AuthorityTransportLimitsV2::new(Duration::from_secs(1), Duration::from_secs(1), 4097)
                .err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );

        let same_identity = AuthorityClientIdV2::from_bytes([0x11; 32])?;
        assert_eq!(
            AuthorityServerProvisionV2::new(
                same_identity,
                AuthorityServerIdV2::from_bytes([0x11; 32])?,
                head()?,
                config()?,
                store_limits()?,
            )
            .err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );

        let address: SocketAddr = "127.0.0.1:1".parse()?;
        let identity = AuthorityWireIdentityV2::new(
            client_id()?,
            server_id()?,
            AuthorityEpochV2::from_bytes([0x13; 32])?,
            head()?,
            config()?,
        )?;
        let (server_sk, server_vk) = MlDsa65::generate(SERVER_SEED);
        assert_eq!(
            AuthenticatedTcpAuthorityV2::new(
                address,
                identity,
                ZeroizingBytes::from_bytes(server_sk),
                server_vk,
                Duration::from_secs(1),
            )
            .err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );

        let (client_sk, _) = MlDsa65::generate(CLIENT_SEED);
        assert_eq!(
            AuthenticatedTcpAuthorityV2::new(
                address,
                identity,
                ZeroizingBytes::from_bytes(client_sk),
                [0u8; ML_DSA_65_VK_LEN],
                Duration::from_secs(1),
            )
            .err(),
            Some(AuthorityTransportErrorV2::InvalidConfiguration)
        );

        let directory = PrivateDirectory::new()?;
        let (role_crossed_sk, role_crossed_vk) = MlDsa65::generate(FOREIGN_SEED);
        assert_eq!(
            ReferenceAuthorityServerV2::provision(
                &directory.join("authority-role-crossed.redb"),
                AuthorityServerProvisionV2::new(
                    client_id()?,
                    server_id()?,
                    head()?,
                    config()?,
                    store_limits()?,
                )?,
                role_crossed_vk,
                ZeroizingBytes::from_bytes(role_crossed_sk),
                transport_limits()?,
            )
            .err(),
            Some(AuthorityServerErrorV2::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn server_open_requires_exact_epoch_and_lease_only_history() -> TestResult {
        let directory = PrivateDirectory::new()?;
        let (_, client_vk) = MlDsa65::generate(CLIENT_SEED);
        let (server_sk, _) = MlDsa65::generate(SERVER_SEED);

        let wire_path = directory.join("authority-epoch.redb");
        let server = provisioned_server(&wire_path)?;
        let identity = server.identity();
        drop(server);
        let wrong_epoch = AuthorityWireIdentityV2::new(
            identity.client_id(),
            identity.server_id(),
            AuthorityEpochV2::from_bytes([0xEF; 32])?,
            identity.state_head(),
            identity.config(),
        )?;
        assert_eq!(
            ReferenceAuthorityServerV2::open(
                &wire_path,
                wrong_epoch,
                client_vk,
                ZeroizingBytes::from_bytes(server_sk),
                transport_limits()?,
            )
            .err(),
            Some(AuthorityServerErrorV2::InvalidConfiguration)
        );

        let direct_path = directory.join("authority-non-lease.redb");
        let mut store =
            AuthorityStoreV2::provision(&direct_path, head()?, config()?, store_limits()?)?;
        let epoch = store.authority_epoch();
        let acquire = acquire_intent(1, 0, 0x45, 0x63)?;
        assert_eq!(
            store.apply(acquire)?.disposition(),
            AuthorityDispositionV2::Applied
        );
        let next_head = StateHeadV2::new(
            StateRevisionV2::new(2, [0x21; 32], 2, [0x26; 32])?,
            StateFenceV2::from_bytes([0x27; 32])?,
        );
        let advance = StateAdvanceV2::new(StateTransitionKindV2::Advance, head()?, next_head)?;
        let advance_intent = AuthorityIntentV2::new(
            OperationIdV2::new(2, [0x64; 32])?,
            2,
            config()?,
            AuthorityMutationV2::AdvanceState {
                fence: InstanceFenceV2::new(1, instance(0x45)?)?,
                advance,
            },
        )?;
        assert_eq!(
            store.apply(advance_intent)?.disposition(),
            AuthorityDispositionV2::Applied
        );
        drop(store);

        let advanced_identity =
            AuthorityWireIdentityV2::new(client_id()?, server_id()?, epoch, next_head, config()?)?;
        assert_eq!(
            ReferenceAuthorityServerV2::open(
                &direct_path,
                advanced_identity,
                client_vk,
                ZeroizingBytes::from_bytes(server_sk),
                transport_limits()?,
            )
            .err(),
            Some(AuthorityServerErrorV2::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn unresponsive_or_refused_endpoints_stay_within_the_deadline_contract() -> TestResult {
        let identity = AuthorityWireIdentityV2::new(
            client_id()?,
            server_id()?,
            AuthorityEpochV2::from_bytes([0x13; 32])?,
            head()?,
            config()?,
        )?;
        let (client_sk, _) = MlDsa65::generate(CLIENT_SEED);
        let (_, server_vk) = MlDsa65::generate(SERVER_SEED);

        let silent_listener = TcpListener::bind("127.0.0.1:0")?;
        let silent_address = silent_listener.local_addr()?;
        let silent_thread = thread::spawn(move || {
            if let Ok((stream, _)) = silent_listener.accept() {
                thread::sleep(Duration::from_millis(900));
                drop(stream);
            }
        });
        let silent_client = AuthenticatedTcpAuthorityV2::new(
            silent_address,
            identity,
            ZeroizingBytes::from_bytes(client_sk),
            server_vk,
            Duration::from_millis(250),
        )?;
        assert_eq!(
            silent_client.snapshot()?,
            AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
        );
        join(silent_thread)?;

        let refused_listener = TcpListener::bind("127.0.0.1:0")?;
        let refused_address = refused_listener.local_addr()?;
        drop(refused_listener);
        assert_eq!(
            silent_client_at(refused_address, identity)?
                .snapshot()
                .err(),
            Some(AuthorityTransportErrorV2::NotSent)
        );
        Ok(())
    }

    fn silent_client_at(
        address: SocketAddr,
        identity: AuthorityWireIdentityV2,
    ) -> TestResult<AuthenticatedTcpAuthorityV2> {
        let (client_sk, _) = MlDsa65::generate(CLIENT_SEED);
        let (_, server_vk) = MlDsa65::generate(SERVER_SEED);
        Ok(AuthenticatedTcpAuthorityV2::new(
            address,
            identity,
            ZeroizingBytes::from_bytes(client_sk),
            server_vk,
            Duration::from_millis(250),
        )?)
    }
}
