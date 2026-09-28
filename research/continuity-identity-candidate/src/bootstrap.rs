// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded, volatile three-flight candidate. These objects do not authorize
//! dispatch, consume prekeys, or establish durable session installation.
use crate::{
    bootstrap_suite_digest,
    codec::{nonzero, Decoder},
    crypto::{digest, envelope, open_envelope, Purpose},
    AuthenticatedPrekeySelection, DeviceSigningKey, Error, VerifiedDevice, VerifiedSessionPolicy,
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use q_periapt_core::ZeroizingBytes;
use q_periapt_sdk::{
    expert::{self, PqKeySource, TraditionalKeySource},
    Ciphertext, HybridKey, KeyPurpose, PublicKey, SharedSecret, CIPHERTEXT_LEN, PUBLIC_KEY_LEN,
};
use sha2::Sha256;
use std::sync::Arc;
use zeroize::Zeroize;

const INITIAL_TAG: &[u8; 8] = b"QPBSI001";
const REPLY_TAG: &[u8; 8] = b"QPBSR001";
const FINAL_TAG: &[u8; 8] = b"QPBSF001";
const INITIAL_PREFIX: usize = 8 + 32 + 32 + PUBLIC_KEY_LEN;
const INITIAL_CORE: usize = INITIAL_PREFIX + CIPHERTEXT_LEN;
const REPLY_PREFIX: usize = 8 + 32 + 32 + 32;
const REPLY_CORE: usize = REPLY_PREFIX + CIPHERTEXT_LEN;
const FINAL_PREFIX: usize = 8 + 32 + 32 + 32;

pub(crate) mod response_staged;
pub(crate) mod staged;

fn hash(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut domain = b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/".to_vec();
    domain.extend_from_slice(label);
    digest(&domain, bytes)
}

/// Independently retained directory expectation; not a consistency proof.
#[derive(Clone, Copy)]
pub struct DirectoryExpectation([u8; 32]);
impl DirectoryExpectation {
    /// Load trusted state, never a checkpoint selected by an incoming manifest.
    pub fn from_trusted_state(checkpoint: [u8; 32]) -> Result<Self, Error> {
        nonzero(&checkpoint)?;
        Ok(Self(checkpoint))
    }
}

/// Role-ordered authenticated inputs bound to the local verified SDK runtime.
/// Current directory/roster state and durable admission remain service duties.
pub struct BootstrapContext {
    policy: Arc<VerifiedSessionPolicy>,
    initiator: Arc<VerifiedDevice>,
    responder: Arc<VerifiedDevice>,
    selection: Arc<AuthenticatedPrekeySelection>,
    peer: PublicKey,
    digest: [u8; 32],
}
impl BootstrapContext {
    /// Bind both identities, exact policies, selection and independent directory expectation.
    pub fn new(
        policy: Arc<VerifiedSessionPolicy>,
        initiator: Arc<VerifiedDevice>,
        responder: Arc<VerifiedDevice>,
        selection: Arc<AuthenticatedPrekeySelection>,
        directory: DirectoryExpectation,
        trusted_time: u64,
    ) -> Result<Self, Error> {
        policy.check_mode(selection.quality(), trusted_time)?;
        policy.check_device(&initiator, trusted_time)?;
        policy.check_device(&responder, trusted_time)?;
        selection.check_time(trusted_time)?;
        if (initiator.account_id(), initiator.device_id())
            == (responder.account_id(), responder.device_id())
            || initiator.key.shares_component(&responder.key)
            || !selection.matches_device(&responder)
        {
            return Err(Error::Scope);
        }
        let manifest = selection.manifest_context();
        if manifest.policy_digest() != policy.runtime.trusted_state().digest()
            || manifest.suite_digest() != bootstrap_suite_digest()
            || manifest.directory_checkpoint() != directory.0
        {
            return Err(Error::Scope);
        }
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&bootstrap_suite_digest());
        encoded.extend_from_slice(&policy.family());
        encoded.extend_from_slice(&policy.checkpoint().version().to_be_bytes());
        encoded.extend_from_slice(&policy.checkpoint().digest());
        encoded.extend_from_slice(&policy.sdk_binding());
        for device in [&initiator, &responder] {
            encoded.extend_from_slice(&device.account_id());
            encoded.extend_from_slice(&device.device_id());
            encoded.extend_from_slice(&device.generation().to_be_bytes());
            encoded.extend_from_slice(&device.credential_digest());
            encoded.extend_from_slice(&device.authority_binding());
        }
        encoded.extend_from_slice(selection.as_bytes());
        encoded.extend_from_slice(&directory.0);
        let mut public = selection.post_quantum().public_key().to_vec();
        public.extend_from_slice(selection.classical().public_key());
        Ok(Self {
            digest: hash(b"context", &encoded),
            peer: PublicKey::from_bytes(&public)?,
            policy,
            initiator,
            responder,
            selection,
        })
    }

    /// Public commitment; it is not a session ID or an admission capability.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn check(&self, now: u64) -> Result<(), Error> {
        self.policy.check_mode(self.selection.quality(), now)?;
        self.selection.check_time(now)?;
        self.policy.check_device(&self.initiator, now)?;
        self.policy.check_device(&self.responder, now)
    }

    pub(crate) fn storage_owner(&self) -> [u8; 32] {
        storage_owner(&self.responder)
    }
    pub(crate) fn initiator_storage_owner(&self) -> [u8; 32] {
        storage_owner(&self.initiator)
    }

    pub(crate) fn one_time_fingerprints(&self) -> Vec<[u8; 32]> {
        use crate::PrekeyQuality;
        let mut keys = Vec::new();
        if matches!(
            self.selection.quality(),
            PrekeyQuality::OneTimeBoth | PrekeyQuality::OneTimeClassicalLastResortPq
        ) {
            keys.push(self.selection.classical().key_fingerprint());
        }
        if matches!(
            self.selection.quality(),
            PrekeyQuality::OneTimeBoth | PrekeyQuality::SignedClassicalOneTimePq
        ) {
            keys.push(self.selection.post_quantum().key_fingerprint());
        }
        keys.sort();
        keys
    }

    pub(crate) fn validate_initial_signature(&self, wire: &[u8]) -> Result<(), Error> {
        let (body, signature) = open_envelope(wire)?;
        if body.len() != INITIAL_CORE + 32
            || body.get(..8) != Some(INITIAL_TAG)
            || body.get(8..40) != Some(self.digest.as_slice())
        {
            return Err(Error::Encoding);
        }
        self.initiator
            .key
            .verify(Purpose::BootstrapInitiator, body, signature)
    }
    pub(crate) fn validate_reply_signature(
        &self,
        initial: &[u8],
        wire: &[u8],
    ) -> Result<(), Error> {
        let (body, signature) = open_envelope(wire)?;
        if body.len() != REPLY_CORE + 32
            || body.get(..8) != Some(REPLY_TAG)
            || body.get(8..40) != Some(self.digest.as_slice())
            || body.get(40..72) != Some(hash(b"initial-wire", initial).as_slice())
        {
            return Err(Error::Scope);
        }
        self.responder
            .key
            .verify(Purpose::BootstrapResponder, body, signature)
    }
}

pub(crate) fn storage_owner(device: &VerifiedDevice) -> [u8; 32] {
    let mut bytes = device.account_id().to_vec();
    bytes.extend_from_slice(&device.device_id());
    bytes.extend_from_slice(&device.generation().to_be_bytes());
    bytes.extend_from_slice(&device.credential_digest());
    hash(b"storage-owner", &bytes)
}

/// Global handshake role, independent of the local send/receive direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapRole {
    /// Sender of the initial and final flights.
    Initiator,
    /// Sender of the response with fresh hybrid KEM randomness.
    Responder,
}

/// Secret result awaiting a real atomic storage transaction. No traffic, raw-key
/// export, serialization or clone API is supplied by this candidate.
pub struct PendingSession {
    root: Option<ZeroizingBytes<32>>,
    id: [u8; 32],
    role: BootstrapRole,
}
impl PendingSession {
    /// Public identity committing to context and both complete signed flights.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    /// Global role for subsequent directional key scheduling.
    pub fn role(&self) -> BootstrapRole {
        self.role
    }
    /// Erase the owned root immediately. Public transcript identity remains.
    pub fn close(&mut self) {
        self.root.take();
    }
}

/// Initiator cryptographic result for a future session-and-final-outbox transaction.
/// It does not assert that the responder received the final flight.
pub struct InitiatorOutcome {
    final_wire: Vec<u8>,
    session: PendingSession,
}
impl InitiatorOutcome {
    /// Exact cached final flight; obtaining bytes is not permission to dispatch.
    pub fn final_message(&self) -> &[u8] {
        &self.final_wire
    }
    /// Result awaiting durable installation, with no application key access.
    pub fn pending_session(&self) -> &PendingSession {
        &self.session
    }
}

struct WaitingInitiator {
    reply_key: HybridKey,
    // Explicit protocol ownership; never a public SDK shared-secret constructor.
    first_secret: ZeroizingBytes<32>,
}
enum InitiatorState {
    Waiting(Box<WaitingInitiator>),
    Finished {
        reply: Vec<u8>,
        outcome: Box<InitiatorOutcome>,
    },
    Closed,
}

/// One bounded volatile operation. Exact accepted replies are idempotent;
/// different replies conflict. Restart/unknown commit handling is not supplied.
pub struct InitiatorOperation {
    context: Arc<BootstrapContext>,
    initial: Vec<u8>,
    state: InitiatorState,
}
impl InitiatorOperation {
    /// Generate a fresh reply key and first KEM contribution, then sign the full flight.
    pub fn start(
        context: Arc<BootstrapContext>,
        signer: &DeviceSigningKey,
        trusted_time: u64,
    ) -> Result<Self, Error> {
        context.check(trusted_time)?;
        if signer.public_key()? != context.initiator.key {
            return Err(Error::Scope);
        }
        let reply_key = context.policy.runtime.generate_key()?;
        let body = initial_prefix(&context, &reply_key, &nonce()?)?;
        let result = context
            .policy
            .runtime
            .encapsulate(&context.peer, &hash(b"kem-initial", &body))?;
        let (body, first_secret) = initial_body(body, result)?;
        let signature = signer.sign(Purpose::BootstrapInitiator, &body)?;
        Self::from_initial(context, reply_key, body, first_secret, &signature)
    }

    fn from_initial(
        context: Arc<BootstrapContext>,
        reply_key: HybridKey,
        body: Vec<u8>,
        first_secret: ZeroizingBytes<32>,
        signature: &[u8],
    ) -> Result<Self, Error> {
        let initial = envelope(&body, signature)?;
        Ok(Self {
            context,
            initial,
            state: InitiatorState::Waiting(Box::new(WaitingInitiator {
                reply_key,
                first_secret,
            })),
        })
    }

    /// Exact initial result for persistence; no dispatch or prekey-use capability.
    pub fn initial_message(&self, trusted_time: u64) -> Result<&[u8], Error> {
        self.context.check(trusted_time)?;
        if matches!(self.state, InitiatorState::Closed) {
            return Err(Error::Closed);
        }
        Ok(&self.initial)
    }

    /// Authenticate and confirm the responder, pinning only a successful reply.
    /// Invalid replies leave the original operation available for a valid reply.
    pub fn finish(&mut self, reply: &[u8], trusted_time: u64) -> Result<&InitiatorOutcome, Error> {
        self.context.check(trusted_time)?;
        match &self.state {
            InitiatorState::Closed => return Err(Error::Closed),
            InitiatorState::Finished {
                reply: accepted, ..
            } if accepted != reply => {
                return Err(Error::Conflict);
            }
            InitiatorState::Finished { .. } => {}
            InitiatorState::Waiting(waiting) => {
                let outcome = finish_initiator(&self.context, &self.initial, waiting, reply)?;
                self.state = InitiatorState::Finished {
                    reply: reply.to_vec(),
                    outcome: Box::new(outcome),
                };
            }
        }
        match &self.state {
            InitiatorState::Finished { outcome, .. } => Ok(outcome),
            _ => Err(Error::Closed),
        }
    }

    /// Erase all retained reply-key and session secrets. Repeated close is valid.
    pub fn close(&mut self) {
        self.state = InitiatorState::Closed;
    }

    pub(crate) fn checkpoint(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(11000));
        bytes.extend_from_slice(b"QPICHK01");
        bytes.extend_from_slice(&self.context.digest);
        bytes.extend_from_slice(&self.initial);
        match &self.state {
            InitiatorState::Waiting(waiting) => {
                bytes.push(1);
                bytes.extend_from_slice(waiting.first_secret.as_bytes());
                let key = expert::export_expanded(&waiting.reply_key)?;
                bytes.extend_from_slice(key.as_bytes());
            }
            InitiatorState::Finished { reply, outcome } => {
                bytes.push(2);
                bytes.extend_from_slice(reply);
                bytes.extend_from_slice(
                    outcome
                        .session
                        .root
                        .as_ref()
                        .ok_or(Error::Closed)?
                        .as_bytes(),
                );
                bytes.extend_from_slice(&outcome.final_wire);
            }
            InitiatorState::Closed => return Err(Error::Closed),
        }
        Ok(bytes)
    }

    // Only authenticated local storage can reach this private restore boundary.
    pub(crate) fn restore_checkpoint(
        context: Arc<BootstrapContext>,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        if decoder.array::<8>()? != *b"QPICHK01" || decoder.array::<32>()? != context.digest {
            return Err(Error::Scope);
        }
        let initial = decoder.take(5817)?.to_vec();
        context.validate_initial_signature(&initial)?;
        let [state] = decoder.array()?;
        let state = match state {
            1 => {
                let mut first_secret = ZeroizingBytes::zeroed();
                first_secret
                    .as_mut_bytes()
                    .copy_from_slice(decoder.take(32)?);
                let reply_key = expert::import_expanded(
                    &context.policy.runtime,
                    decoder.take(expert::EXPANDED_KEY_LEN)?,
                )?;
                if initial.get(4 + 72..4 + 72 + PUBLIC_KEY_LEN)
                    != Some(reply_key.public_key()?.to_bytes().as_slice())
                {
                    return Err(Error::Scope);
                }
                InitiatorState::Waiting(Box::new(WaitingInitiator {
                    reply_key,
                    first_secret,
                }))
            }
            2 => {
                let reply = decoder.take(4633)?.to_vec();
                context.validate_reply_signature(&initial, &reply)?;
                let mut root = ZeroizingBytes::zeroed();
                root.as_mut_bytes().copy_from_slice(decoder.take(32)?);
                let final_wire = decoder.take(136)?.to_vec();
                let prefix = final_prefix(&context.digest, &initial, &reply);
                if final_wire.get(..FINAL_PREFIX) != Some(prefix.as_slice()) {
                    return Err(Error::Scope);
                }
                let session = PendingSession {
                    root: Some(root),
                    id: hash(b"session-id", &prefix),
                    role: BootstrapRole::Initiator,
                };
                InitiatorState::Finished {
                    reply,
                    outcome: Box::new(InitiatorOutcome {
                        final_wire,
                        session,
                    }),
                }
            }
            _ => return Err(Error::Encoding),
        };
        decoder.finish()?;
        Ok(Self {
            context,
            initial,
            state,
        })
    }
}

struct PreparedResponder {
    initial: Vec<u8>,
    reply: Vec<u8>,
    session: PendingSession,
    confirmation: Option<ZeroizingBytes<32>>,
    accepted_final: Option<Vec<u8>>,
}
enum ResponderState {
    Idle,
    Prepared(Box<PreparedResponder>),
    Closed,
}

/// One volatile responder computation. A cached response never repeats entropy
/// generation or decapsulation. Global one-time consumption requires real storage.
pub struct ResponderOperation {
    context: Arc<BootstrapContext>,
    state: ResponderState,
}
impl ResponderOperation {
    /// Create an empty operation; no prekey reservation or authorization is implied.
    pub fn new(context: Arc<BootstrapContext>) -> Self {
        Self {
            context,
            state: ResponderState::Idle,
        }
    }

    /// Verify the signed initial flight and initial KEM confirmation, then produce
    /// a fresh responder contribution. Owners must match the authenticated selection
    /// and the policy's exact local runtime. After initial confirmation, provider
    /// failure closes this operation rather than permitting an unpinned retry.
    pub fn respond(
        &mut self,
        initial: &[u8],
        signer: &DeviceSigningKey,
        pq: PqKeySource<'_>,
        classical: TraditionalKeySource<'_>,
        trusted_time: u64,
    ) -> Result<&[u8], Error> {
        self.context.check(trusted_time)?;
        match &self.state {
            ResponderState::Closed => return Err(Error::Closed),
            ResponderState::Prepared(ready) if ready.initial != initial => {
                return Err(Error::Conflict)
            }
            ResponderState::Prepared(_) => {}
            ResponderState::Idle => {
                if signer.public_key()? != self.context.responder.key {
                    return Err(Error::Scope);
                }
                let (peer, first_secret) =
                    authenticate_initial(&self.context, initial, pq, classical)?;
                // No further failure may silently reset an admitted computation.
                self.state = ResponderState::Closed;
                let ready = prepare_response(&self.context, initial, signer, peer, first_secret)?;
                self.state = ResponderState::Prepared(Box::new(ready));
            }
        }
        match &self.state {
            ResponderState::Prepared(ready) => Ok(&ready.reply),
            _ => Err(Error::Closed),
        }
    }

    /// Confirm receipt of the fresh responder contribution. Successful final bytes
    /// are pinned exactly; no prekey is consumed and no root is installed here.
    pub fn finish(
        &mut self,
        final_wire: &[u8],
        trusted_time: u64,
    ) -> Result<&PendingSession, Error> {
        self.context.check(trusted_time)?;
        let ready = match &mut self.state {
            ResponderState::Prepared(ready) => ready,
            ResponderState::Closed => return Err(Error::Closed),
            ResponderState::Idle => return Err(Error::State),
        };
        if let Some(accepted) = &ready.accepted_final {
            if accepted != final_wire {
                return Err(Error::Conflict);
            }
        } else {
            let expected = final_prefix(&self.context.digest, &ready.initial, &ready.reply);
            let mut decoder = Decoder::new(final_wire);
            if decoder.take(FINAL_PREFIX)? != expected {
                return Err(Error::Scope);
            }
            let tag = decoder.array::<32>()?;
            decoder.finish()?;
            let key = ready.confirmation.as_ref().ok_or(Error::Closed)?;
            verify_mac(key.as_bytes(), &hash(b"final-core", &expected), &tag)?;
            ready.accepted_final = Some(final_wire.to_vec());
            ready.confirmation.take();
        }
        Ok(&ready.session)
    }

    /// Erase all pending confirmation and session secrets.
    pub fn close(&mut self) {
        self.state = ResponderState::Closed;
    }

    // Only the authenticated, encrypted local journal may restore these secret
    // bytes. No network decoder or public constructor exposes this capability.
    pub(crate) fn checkpoint(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        let ready = match &self.state {
            ResponderState::Prepared(ready) => ready,
            _ => return Err(Error::State),
        };
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(11000));
        bytes.extend_from_slice(b"QPRCHK01");
        bytes.extend_from_slice(&self.context.digest);
        bytes.extend_from_slice(&ready.initial);
        bytes.extend_from_slice(&ready.reply);
        bytes.extend_from_slice(ready.session.root.as_ref().ok_or(Error::Closed)?.as_bytes());
        match (&ready.confirmation, &ready.accepted_final) {
            (Some(key), None) => {
                bytes.push(1);
                bytes.extend_from_slice(key.as_bytes());
            }
            (None, Some(final_wire)) => {
                bytes.push(2);
                bytes.extend_from_slice(final_wire);
            }
            _ => return Err(Error::State),
        }
        Ok(bytes)
    }

    pub(crate) fn restore_checkpoint(
        context: Arc<BootstrapContext>,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes);
        if decoder.array::<8>()? != *b"QPRCHK01" || decoder.array::<32>()? != context.digest {
            return Err(Error::Scope);
        }
        let initial = decoder.take(5817)?.to_vec();
        context.validate_initial_signature(&initial)?;
        let reply = decoder.take(4633)?.to_vec();
        let (body, signature) = open_envelope(&reply)?;
        context
            .responder
            .key
            .verify(Purpose::BootstrapResponder, body, signature)?;
        let mut expected = prefix(REPLY_TAG, &context.digest);
        expected.extend_from_slice(&hash(b"initial-wire", &initial));
        if body.len() != REPLY_CORE + 32 || body.get(..72) != Some(expected.as_slice()) {
            return Err(Error::Scope);
        }
        let mut root = ZeroizingBytes::zeroed();
        root.as_mut_bytes().copy_from_slice(decoder.take(32)?);
        let [state] = decoder.array()?;
        let (confirmation, accepted_final) = match state {
            1 => {
                let mut key = ZeroizingBytes::zeroed();
                key.as_mut_bytes().copy_from_slice(decoder.take(32)?);
                (Some(key), None)
            }
            2 => {
                let final_wire = decoder.take(136)?.to_vec();
                if final_wire.get(..FINAL_PREFIX)
                    != Some(final_prefix(&context.digest, &initial, &reply).as_slice())
                {
                    return Err(Error::Scope);
                }
                (None, Some(final_wire))
            }
            _ => return Err(Error::Encoding),
        };
        decoder.finish()?;
        let id = hash(
            b"session-id",
            &final_prefix(&context.digest, &initial, &reply),
        );
        let ready = PreparedResponder {
            initial,
            reply,
            session: PendingSession {
                root: Some(root),
                id,
                role: BootstrapRole::Responder,
            },
            confirmation,
            accepted_final,
        };
        Ok(Self {
            context,
            state: ResponderState::Prepared(Box::new(ready)),
        })
    }

    pub(crate) fn stored_reply(&self) -> Result<&[u8], Error> {
        match &self.state {
            ResponderState::Prepared(ready) => Ok(&ready.reply),
            _ => Err(Error::State),
        }
    }
}

fn prefix(tag: &[u8; 8], context: &[u8; 32]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(context);
    bytes
}

fn initial_prefix(
    context: &BootstrapContext,
    key: &HybridKey,
    nonce: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let mut body = prefix(INITIAL_TAG, &context.digest);
    body.extend_from_slice(nonce);
    body.extend_from_slice(&key.public_key()?.to_bytes());
    Ok(body)
}

fn initial_body(
    mut body: Vec<u8>,
    result: q_periapt_sdk::Encapsulation,
) -> Result<(Vec<u8>, ZeroizingBytes<32>), Error> {
    body.extend_from_slice(&result.ciphertext.to_bytes());
    let core = hash(b"initial-core", &body);
    let key = initial_key(&result.secret, &core)?;
    body.extend_from_slice(&mac(key.as_bytes(), &core)?);
    Ok((body, result.secret.export_for_protocol()?))
}
fn nonce() -> Result<[u8; 32], Error> {
    let mut value = [0; 32];
    getrandom::fill(&mut value).map_err(|_| Error::Entropy)?;
    Ok(value)
}
fn initial_key(secret: &SharedSecret, core: &[u8; 32]) -> Result<ZeroizingBytes<32>, Error> {
    Ok(secret
        .derive_key(
            KeyPurpose::InitiatorConfirmation,
            b"ContinuityBootstrapCandidate/v1/initial",
            core,
        )?
        .export_for_protocol()?)
}
fn mac(key: &[u8; 32], body: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut state = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Provider)?;
    state.update(body);
    Ok(state.finalize().into_bytes().into())
}
fn verify_mac(key: &[u8; 32], body: &[u8; 32], tag: &[u8; 32]) -> Result<(), Error> {
    let mut state = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Provider)?;
    state.update(body);
    state.verify_slice(tag).map_err(|_| Error::Authentication)
}

fn authenticate_initial(
    context: &BootstrapContext,
    wire: &[u8],
    pq: PqKeySource<'_>,
    classical: TraditionalKeySource<'_>,
) -> Result<(PublicKey, SharedSecret), Error> {
    let (body, signature) = open_envelope(wire)?;
    context
        .initiator
        .key
        .verify(Purpose::BootstrapInitiator, body, signature)?;
    let mut decoder = Decoder::new(body);
    if decoder.array::<8>()? != *INITIAL_TAG || decoder.array::<32>()? != context.digest {
        return Err(Error::Scope);
    }
    decoder.array::<32>()?; // Signed nonce; zero is a valid random output.
    let reply_key = PublicKey::from_bytes(decoder.take(PUBLIC_KEY_LEN)?)?;
    let ct = Ciphertext::from_bytes(decoder.take(CIPHERTEXT_LEN)?)?;
    let tag = decoder.array::<32>()?;
    decoder.finish()?;
    let runtime = &context.policy.runtime;
    if expert::component_public_key(runtime, pq, classical)?.to_bytes() != context.peer.to_bytes() {
        return Err(Error::Scope);
    }
    let kem_context = hash(
        b"kem-initial",
        body.get(..INITIAL_PREFIX).ok_or(Error::Encoding)?,
    );
    let first_secret = expert::decapsulate_components(runtime, pq, classical, &ct, &kem_context)?;
    let core = hash(
        b"initial-core",
        body.get(..INITIAL_CORE).ok_or(Error::Encoding)?,
    );
    let key = initial_key(&first_secret, &core)?;
    verify_mac(key.as_bytes(), &core, &tag)?;
    Ok((reply_key, first_secret))
}

struct Schedule {
    seed: ZeroizingBytes<32>,
    responder: ZeroizingBytes<32>,
    initiator: ZeroizingBytes<32>,
}
fn derive(ikm: &[u8], salt: &[u8; 32], label: &[u8]) -> Result<ZeroizingBytes<32>, Error> {
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.zeroize();
    let mut out = ZeroizingBytes::zeroed();
    hkdf.expand_multi_info(
        &[b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-KDF-CANDIDATE/v1/", label],
        out.as_mut_bytes(),
    )
    .map_err(|_| Error::Provider)?;
    Ok(out)
}
fn schedule(
    first: &ZeroizingBytes<32>,
    second: &SharedSecret,
    core: &[u8; 32],
) -> Result<Schedule, Error> {
    let second = second.export_for_protocol()?;
    let mut ikm = ZeroizingBytes::<64>::zeroed();
    let (left, right) = ikm.as_mut_bytes().split_at_mut(32);
    left.copy_from_slice(first.as_bytes());
    right.copy_from_slice(second.as_bytes());
    Ok(Schedule {
        seed: derive(ikm.as_bytes(), core, b"handshake-seed")?,
        responder: derive(ikm.as_bytes(), core, b"confirmation-responder")?,
        initiator: derive(ikm.as_bytes(), core, b"confirmation-initiator")?,
    })
}
fn final_prefix(context: &[u8; 32], initial: &[u8], reply: &[u8]) -> Vec<u8> {
    let mut bytes = prefix(FINAL_TAG, context);
    bytes.extend_from_slice(&hash(b"initial-wire", initial));
    bytes.extend_from_slice(&hash(b"reply-wire", reply));
    bytes
}
fn pending(
    context: &[u8; 32],
    initial: &[u8],
    reply: &[u8],
    seed: &ZeroizingBytes<32>,
    role: BootstrapRole,
) -> Result<PendingSession, Error> {
    let identity = final_prefix(context, initial, reply);
    let id = hash(b"session-id", &identity);
    let mut label = b"session-root/".to_vec();
    label.extend_from_slice(context);
    Ok(PendingSession {
        root: Some(derive(seed.as_bytes(), &id, &label)?),
        id,
        role,
    })
}

fn prepare_response(
    context: &BootstrapContext,
    initial: &[u8],
    signer: &DeviceSigningKey,
    peer: PublicKey,
    first: SharedSecret,
) -> Result<PreparedResponder, Error> {
    let body = response_prefix(context, initial, &nonce()?);
    let result = context
        .policy
        .runtime
        .encapsulate(&peer, &hash(b"kem-reply", &body))?;
    let (body, keys) = response_body(body, &first.export_for_protocol()?, result)?;
    let signature = signer.sign(Purpose::BootstrapResponder, &body)?;
    prepared_response(context, initial, &body, &signature, keys)
}

fn response_prefix(context: &BootstrapContext, initial: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    let mut body = prefix(REPLY_TAG, &context.digest);
    body.extend_from_slice(&hash(b"initial-wire", initial));
    body.extend_from_slice(nonce);
    body
}

fn response_body(
    mut body: Vec<u8>,
    first: &ZeroizingBytes<32>,
    result: q_periapt_sdk::Encapsulation,
) -> Result<(Vec<u8>, Schedule), Error> {
    body.extend_from_slice(&result.ciphertext.to_bytes());
    let core = hash(b"reply-core", &body);
    let keys = schedule(first, &result.secret, &core)?;
    body.extend_from_slice(&mac(keys.responder.as_bytes(), &core)?);
    Ok((body, keys))
}

fn prepared_response(
    context: &BootstrapContext,
    initial: &[u8],
    body: &[u8],
    signature: &[u8],
    keys: Schedule,
) -> Result<PreparedResponder, Error> {
    let reply = envelope(body, signature)?;
    let session = pending(
        &context.digest,
        initial,
        &reply,
        &keys.seed,
        BootstrapRole::Responder,
    )?;
    Ok(PreparedResponder {
        initial: initial.to_vec(),
        reply,
        session,
        confirmation: Some(keys.initiator),
        accepted_final: None,
    })
}

fn finish_initiator(
    context: &BootstrapContext,
    initial: &[u8],
    waiting: &WaitingInitiator,
    reply: &[u8],
) -> Result<InitiatorOutcome, Error> {
    let (body, signature) = open_envelope(reply)?;
    context
        .responder
        .key
        .verify(Purpose::BootstrapResponder, body, signature)?;
    let mut decoder = Decoder::new(body);
    if decoder.array::<8>()? != *REPLY_TAG
        || decoder.array::<32>()? != context.digest
        || decoder.array::<32>()? != hash(b"initial-wire", initial)
    {
        return Err(Error::Scope);
    }
    decoder.array::<32>()?;
    let ct = Ciphertext::from_bytes(decoder.take(CIPHERTEXT_LEN)?)?;
    let tag = decoder.array::<32>()?;
    decoder.finish()?;
    let kem_context = hash(
        b"kem-reply",
        body.get(..REPLY_PREFIX).ok_or(Error::Encoding)?,
    );
    let second = waiting.reply_key.decapsulate(&ct, &kem_context)?;
    let core = hash(
        b"reply-core",
        body.get(..REPLY_CORE).ok_or(Error::Encoding)?,
    );
    let keys = schedule(&waiting.first_secret, &second, &core)?;
    verify_mac(keys.responder.as_bytes(), &core, &tag)?;
    let mut final_wire = final_prefix(&context.digest, initial, reply);
    let tag = mac(keys.initiator.as_bytes(), &hash(b"final-core", &final_wire))?;
    final_wire.extend_from_slice(&tag);
    let session = pending(
        &context.digest,
        initial,
        reply,
        &keys.seed,
        BootstrapRole::Initiator,
    )?;
    Ok(InitiatorOutcome {
        final_wire,
        session,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        tests::{interval, sdk_runtime_with_limits, session_policy_fixture},
        *,
    };

    pub(crate) struct Fixture {
        pub(crate) initiator: Arc<BootstrapContext>,
        pub(crate) responder: Arc<BootstrapContext>,
        pub(crate) signer_i: DeviceSigningKey,
        pub(crate) signer_r: DeviceSigningKey,
        pub(crate) reusable: HybridKey,
        pub(crate) once: HybridKey,
    }
    fn enrolled(seed: u8, family: [u8; 32]) -> (DeviceSigningKey, Arc<VerifiedDevice>) {
        let root = RootSigningKey::deterministic([seed; 32], [seed + 1; 32]).expect("root");
        let signer =
            DeviceSigningKey::deterministic([seed + 2; 32], [seed + 3; 32]).expect("device");
        let certificate = root
            .issue_device(
                DeviceDescription::new([seed; 16], 1, family, interval()).expect("description"),
                signer.public_key().expect("public"),
            )
            .expect("certificate");
        let roster = root
            .issue_roster(
                1,
                interval(),
                &[root.roster_entry(&certificate).expect("entry")],
            )
            .expect("roster");
        let pin = AccountPin::new(
            root.account_id().expect("account"),
            root.public_key().expect("root public"),
            roster.checkpoint(),
            family,
        )
        .expect("pin");
        (
            signer,
            Arc::new(
                pin.verify_device(&certificate, roster.as_bytes(), 150)
                    .expect("verified"),
            ),
        )
    }
    pub(crate) fn fixture(quality: PrekeyQuality) -> Fixture {
        fixture_from_public(quality, None)
    }
    pub(crate) fn fixture_from_public(
        quality: PrekeyQuality,
        public_keys: Option<(
            [u8; q_periapt_sdk::PUBLIC_KEY_LEN],
            [u8; q_periapt_sdk::PUBLIC_KEY_LEN],
        )>,
    ) -> Fixture {
        fixture_with_options(quality, public_keys, q_periapt_sdk::Limits::default())
    }
    #[cfg(unix)]
    pub(crate) fn fixture_with_initiator_limits(
        quality: PrekeyQuality,
        limits: q_periapt_sdk::Limits,
    ) -> Fixture {
        fixture_with_options(quality, None, limits)
    }
    fn fixture_with_options(
        quality: PrekeyQuality,
        public_keys: Option<(
            [u8; q_periapt_sdk::PUBLIC_KEY_LEN],
            [u8; q_periapt_sdk::PUBLIC_KEY_LEN],
        )>,
        limits: q_periapt_sdk::Limits,
    ) -> Fixture {
        let (_, issued, pin, runtime_r) = session_policy_fixture(&[quality]);
        let runtime_i = sdk_runtime_with_limits(limits);
        let policy_i = Arc::new(
            pin.verify(issued.as_bytes(), runtime_i, 150)
                .expect("initiator policy"),
        );
        let policy_r = Arc::new(
            pin.verify(issued.as_bytes(), Arc::clone(&runtime_r), 150)
                .expect("responder policy"),
        );
        let (signer_i, device_i) = enrolled(90, policy_r.family());
        let (signer_r, device_r) = enrolled(94, policy_r.family());
        let reusable = runtime_r.generate_key().expect("reusable");
        let once = runtime_r.generate_key().expect("one time");
        let (public, one) = match public_keys {
            Some(keys) => keys,
            None => (
                reusable.public_key().expect("public").to_bytes(),
                once.public_key().expect("public").to_bytes(),
            ),
        };
        let (pq, classic) = public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
        let (pq_once, classic_once) = one.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
        let leaves = [
            (LeafKind::SignedClassical, classic),
            (LeafKind::OneTimeClassical, classic_once),
            (LeafKind::LastResortPq, pq),
            (LeafKind::OneTimePq, pq_once),
        ]
        .map(|(kind, key)| PrekeyLeaf::new(kind, key, interval()).expect("leaf"));
        let manifest = signer_r
            .issue_manifest(
                &device_r,
                ManifestContext::new(
                    1,
                    runtime_r.trusted_state().digest(),
                    bootstrap_suite_digest(),
                    [99; 32],
                    interval(),
                )
                .expect("manifest context"),
                &leaves,
            )
            .expect("manifest");
        let verified = device_r
            .verify_manifest(manifest.as_bytes(), 150)
            .expect("verify manifest");
        let proofs: Vec<_> = (0..manifest.leaf_count())
            .map(|i| {
                let proof = manifest.proof(i).expect("proof");
                (
                    verified.verify_leaf(&proof, 150).expect("leaf").kind(),
                    proof,
                )
            })
            .collect();
        let proof = |kind| &proofs.iter().find(|(k, _)| *k == kind).expect("role").1;
        let classical = match quality {
            PrekeyQuality::OneTimeBoth | PrekeyQuality::OneTimeClassicalLastResortPq => {
                ClassicalChoice::OneTime(proof(LeafKind::OneTimeClassical))
            }
            _ => ClassicalChoice::SignedOnly,
        };
        let pq = match quality {
            PrekeyQuality::OneTimeBoth | PrekeyQuality::SignedClassicalOneTimePq => {
                PqChoice::OneTime(proof(LeafKind::OneTimePq))
            }
            _ => PqChoice::LastResort,
        };
        let selection = Arc::new(
            verified
                .select_prekeys(
                    proof(LeafKind::SignedClassical),
                    proof(LeafKind::LastResortPq),
                    classical,
                    pq,
                    150,
                )
                .expect("selection"),
        );
        let directory = DirectoryExpectation::from_trusted_state([99; 32]).expect("directory");
        let initiator = Arc::new(
            BootstrapContext::new(
                policy_i,
                Arc::clone(&device_i),
                Arc::clone(&device_r),
                Arc::clone(&selection),
                directory,
                150,
            )
            .expect("initiator context"),
        );
        let responder = Arc::new(
            BootstrapContext::new(policy_r, device_i, device_r, selection, directory, 150)
                .expect("responder context"),
        );
        assert_eq!(initiator.digest(), responder.digest());
        Fixture {
            initiator,
            responder,
            signer_i,
            signer_r,
            reusable,
            once,
        }
    }
    impl Fixture {
        #[cfg(unix)]
        pub(crate) fn initiator_device(&self) -> &VerifiedDevice {
            &self.initiator.initiator
        }
        #[cfg(unix)]
        pub(crate) fn close_initiator_policy(&self) {
            self.initiator.policy.close();
        }
        #[cfg(unix)]
        pub(crate) fn occupy_initiator_slot(&self) -> HybridKey {
            self.initiator
                .policy
                .runtime
                .generate_key()
                .expect("occupy slot")
        }
        #[cfg(unix)]
        pub(crate) fn local_device(&self) -> &VerifiedDevice {
            &self.responder.responder
        }
        #[cfg(unix)]
        pub(crate) fn close_responder_policy(&self) {
            self.responder.policy.close();
        }
        #[cfg(unix)]
        pub(crate) fn next_bundle_epoch(&self) -> (Arc<BootstrapContext>, Arc<BootstrapContext>) {
            let reusable = self.reusable.public_key().expect("public").to_bytes();
            let once = self.once.public_key().expect("public").to_bytes();
            let (pq, classic) = reusable.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
            let (pq_once, classic_once) = once.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
            let leaves = [
                (LeafKind::SignedClassical, classic),
                (LeafKind::OneTimeClassical, classic_once),
                (LeafKind::LastResortPq, pq),
                (LeafKind::OneTimePq, pq_once),
            ]
            .map(|(kind, bytes)| PrekeyLeaf::new(kind, bytes, interval()).expect("leaf"));
            let device = &self.responder.responder;
            let manifest = self
                .signer_r
                .issue_manifest(
                    device,
                    ManifestContext::new(
                        2,
                        self.responder.policy.runtime.trusted_state().digest(),
                        bootstrap_suite_digest(),
                        [99; 32],
                        interval(),
                    )
                    .expect("next epoch"),
                    &leaves,
                )
                .expect("manifest");
            let verified = device
                .verify_manifest(manifest.as_bytes(), 150)
                .expect("signed manifest");
            let mut proofs = std::collections::BTreeMap::new();
            for index in 0..manifest.leaf_count() {
                let proof = manifest.proof(index).expect("proof");
                proofs.insert(
                    verified.verify_leaf(&proof, 150).expect("member").kind() as u8,
                    proof,
                );
            }
            let selection = Arc::new(
                verified
                    .select_prekeys(
                        proofs.get(&1).expect("signed"),
                        proofs.get(&3).expect("last resort"),
                        ClassicalChoice::OneTime(proofs.get(&2).expect("classical once")),
                        PqChoice::OneTime(proofs.get(&4).expect("PQ once")),
                        150,
                    )
                    .expect("next selection"),
            );
            let make = |policy| {
                Arc::new(
                    BootstrapContext::new(
                        policy,
                        Arc::clone(&self.responder.initiator),
                        Arc::clone(device),
                        Arc::clone(&selection),
                        DirectoryExpectation::from_trusted_state([99; 32]).expect("directory"),
                        150,
                    )
                    .expect("context"),
                )
            };
            (
                make(Arc::clone(&self.initiator.policy)),
                make(Arc::clone(&self.responder.policy)),
            )
        }
        pub(crate) fn sources(&self) -> (PqKeySource<'_>, TraditionalKeySource<'_>) {
            let quality = self.responder.selection.quality();
            let pq = match quality {
                PrekeyQuality::OneTimeBoth | PrekeyQuality::SignedClassicalOneTimePq => &self.once,
                _ => &self.reusable,
            };
            let classical = match quality {
                PrekeyQuality::OneTimeBoth | PrekeyQuality::OneTimeClassicalLastResortPq => {
                    &self.once
                }
                _ => &self.reusable,
            };
            (
                PqKeySource::from_key(pq),
                TraditionalKeySource::from_key(classical),
            )
        }
    }
    fn fail<T>(result: Result<T, Error>, error: Error) {
        assert_eq!(result.err(), Some(error));
    }

    #[test]
    fn both_real_peers_agree_for_every_permitted_mode_and_pin_all_flights() {
        for quality in [
            PrekeyQuality::OneTimeBoth,
            PrekeyQuality::ReusableBoth,
            PrekeyQuality::SignedClassicalOneTimePq,
            PrekeyQuality::OneTimeClassicalLastResortPq,
        ] {
            let f = fixture(quality);
            let mut initiator =
                InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
                    .expect("start");
            let initial = initiator.initial_message(150).expect("initial").to_vec();
            assert_eq!(initial.len(), 5817);
            let mut responder = ResponderOperation::new(Arc::clone(&f.responder));
            let (pq, classical) = f.sources();
            let reply = responder
                .respond(&initial, &f.signer_r, pq, classical, 150)
                .expect("response")
                .to_vec();
            assert_eq!(reply.len(), 4633);
            assert_eq!(
                responder
                    .respond(&initial, &f.signer_r, pq, classical, 150)
                    .expect("replay"),
                reply
            );
            let outcome = initiator
                .finish(&reply, 150)
                .expect("initiator confirmation");
            assert_eq!(outcome.final_message().len(), 136);
            let final_wire = outcome.final_message().to_vec();
            let session = responder
                .finish(&final_wire, 150)
                .expect("responder confirmation");
            assert_eq!(session.id(), outcome.session.id());
            assert_eq!(session.role(), BootstrapRole::Responder);
            assert_eq!(outcome.session.role(), BootstrapRole::Initiator);
            assert_eq!(
                session.root.as_ref().expect("root").as_bytes(),
                outcome.session.root.as_ref().expect("root").as_bytes()
            );
            assert_eq!(
                initiator
                    .finish(&reply, 150)
                    .expect("exact repeat")
                    .final_message(),
                final_wire
            );
            responder
                .finish(&final_wire, 150)
                .expect("exact final repeat");
            for (wire, phase) in [(&initial, 0), (&reply, 1), (&final_wire, 2)] {
                let mut changed = wire.to_vec();
                *changed.last_mut().expect("byte") ^= 1;
                match phase {
                    0 => fail(
                        responder.respond(&changed, &f.signer_r, pq, classical, 150),
                        Error::Conflict,
                    ),
                    1 => fail(initiator.finish(&changed, 150), Error::Conflict),
                    _ => fail(responder.finish(&changed, 150), Error::Conflict),
                }
            }
            initiator.close();
            responder.close();
            fail(initiator.initial_message(150), Error::Closed);
            fail(responder.finish(&final_wire, 150), Error::Closed);
        }
    }

    #[test]
    fn valid_signatures_cannot_replace_kem_confirmation_or_transcript_binding() {
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let (pq, classical) = f.sources();
        let mut i =
            InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("start");
        let initial = i.initial_message(150).expect("initial").to_vec();
        let mut r = ResponderOperation::new(Arc::clone(&f.responder));
        fail(r.finish(&[], 150), Error::State);
        let (body, _) = open_envelope(&initial).expect("envelope");
        for offset in [INITIAL_PREFIX, INITIAL_CORE] {
            let mut changed = body.to_vec();
            *changed.get_mut(offset).expect("field") ^= 1;
            let wire = envelope(
                &changed,
                &f.signer_i
                    .sign(Purpose::BootstrapInitiator, &changed)
                    .expect("sign"),
            )
            .expect("wire");
            fail(
                r.respond(&wire, &f.signer_r, pq, classical, 150),
                Error::Authentication,
            );
        }
        let reply = r
            .respond(&initial, &f.signer_r, pq, classical, 150)
            .expect("valid initial after failures")
            .to_vec();
        let (body, signature) = open_envelope(&reply).expect("reply");
        for offset in [0, q_periapt_backends::ML_DSA_65_SIG_LEN + 63] {
            let mut altered = signature.to_vec();
            *altered.get_mut(offset).expect("signature byte") ^= 1;
            fail(
                i.finish(&envelope(body, &altered).expect("wire"), 150),
                Error::Authentication,
            );
        }
        for (offset, error) in [
            (8, Error::Scope),
            (40, Error::Scope),
            (72, Error::Authentication),
            (REPLY_PREFIX, Error::Authentication),
            (REPLY_CORE, Error::Authentication),
        ] {
            let mut changed = body.to_vec();
            *changed.get_mut(offset).expect("field") ^= 1;
            let wire = envelope(
                &changed,
                &f.signer_r
                    .sign(Purpose::BootstrapResponder, &changed)
                    .expect("sign"),
            )
            .expect("wire");
            fail(i.finish(&wire, 150), error);
        }
        let mut extended = body.to_vec();
        extended.push(0);
        let wire = envelope(
            &extended,
            &f.signer_r
                .sign(Purpose::BootstrapResponder, &extended)
                .expect("sign"),
        )
        .expect("wire");
        fail(i.finish(&wire, 150), Error::Encoding);
        let outcome = i.finish(&reply, 150).expect("valid reply after failures");
        let mut altered = outcome.final_message().to_vec();
        *altered.last_mut().expect("tag") ^= 1;
        fail(r.finish(&altered, 150), Error::Authentication);
        r.finish(outcome.final_message(), 150)
            .expect("valid final after failure");
    }

    #[test]
    fn repeated_initial_requires_fresh_responder_contribution_and_conflicts_at_initiator() {
        let f = fixture(PrekeyQuality::ReusableBoth);
        let (pq, classical) = f.sources();
        let mut i =
            InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("start");
        let initial = i.initial_message(150).expect("initial").to_vec();
        let mut first = ResponderOperation::new(Arc::clone(&f.responder));
        let mut second = ResponderOperation::new(Arc::clone(&f.responder));
        let a = first
            .respond(&initial, &f.signer_r, pq, classical, 150)
            .expect("first")
            .to_vec();
        let b = second
            .respond(&initial, &f.signer_r, pq, classical, 150)
            .expect("second")
            .to_vec();
        assert_ne!(a, b);
        let first = match &first.state {
            ResponderState::Prepared(p) => p,
            _ => unreachable!(),
        };
        let second = match &second.state {
            ResponderState::Prepared(p) => p,
            _ => unreachable!(),
        };
        assert_ne!(first.session.id(), second.session.id());
        assert_ne!(
            first.session.root.as_ref().expect("root").as_bytes(),
            second.session.root.as_ref().expect("root").as_bytes()
        );
        i.finish(&a, 150).expect("accept first");
        fail(i.finish(&b, 150), Error::Conflict);
    }

    #[test]
    fn admission_requires_exact_roles_runtime_selection_directory_and_live_policy() {
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let c = &f.initiator;
        fail(
            BootstrapContext::new(
                Arc::clone(&c.policy),
                Arc::clone(&c.initiator),
                Arc::clone(&c.responder),
                Arc::clone(&c.selection),
                DirectoryExpectation::from_trusted_state([98; 32]).expect("directory"),
                150,
            ),
            Error::Scope,
        );
        fail(
            BootstrapContext::new(
                Arc::clone(&c.policy),
                Arc::clone(&c.responder),
                Arc::clone(&c.initiator),
                Arc::clone(&c.selection),
                DirectoryExpectation::from_trusted_state([99; 32]).expect("directory"),
                150,
            ),
            Error::Scope,
        );
        fail(
            InitiatorOperation::start(Arc::clone(c), &f.signer_r, 150),
            Error::Scope,
        );
        let i = InitiatorOperation::start(Arc::clone(c), &f.signer_i, 150).expect("start");
        let initial = i.initial_message(150).expect("initial");
        let mut r = ResponderOperation::new(Arc::clone(&f.responder));
        let (pq, classical) = f.sources();
        fail(
            r.respond(
                initial,
                &f.signer_r,
                PqKeySource::from_key(&f.reusable),
                classical,
                150,
            ),
            Error::Scope,
        );
        let other = c.policy.runtime.generate_key().expect("other runtime");
        fail(
            r.respond(
                initial,
                &f.signer_r,
                PqKeySource::from_key(&other),
                TraditionalKeySource::from_key(&other),
                150,
            ),
            Error::Runtime(q_periapt_sdk::Error::PolicyDenied),
        );
        fail(
            r.respond(initial, &f.signer_r, pq, classical, 200),
            Error::Validity,
        );
        f.responder.policy.close();
        fail(
            r.respond(initial, &f.signer_r, pq, classical, 150),
            Error::Closed,
        );
        c.policy.runtime.close();
        fail(
            i.initial_message(150),
            Error::Runtime(q_periapt_sdk::Error::Closed),
        );
    }

    #[test]
    fn confirmed_initial_with_invalid_reply_key_burns_the_volatile_operation() {
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let i =
            InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150).expect("start");
        let original = i.initial_message(150).expect("initial");
        let (body, _) = open_envelope(original).expect("body");
        let mut changed = body.get(..INITIAL_PREFIX).expect("prefix").to_vec();
        // A real authenticated initiator can supply an invalid reply ML-KEM
        // encoding. Recompute its first contribution and MAC under that prefix.
        changed
            .get_mut(72..74)
            .expect("reply key coefficients")
            .fill(0xff);
        let result = f
            .initiator
            .policy
            .runtime
            .encapsulate(&f.initiator.peer, &hash(b"kem-initial", &changed))
            .expect("initial KEM");
        changed.extend_from_slice(&result.ciphertext.to_bytes());
        let core = hash(b"initial-core", &changed);
        changed.extend_from_slice(
            &mac(
                initial_key(&result.secret, &core).expect("key").as_bytes(),
                &core,
            )
            .expect("MAC"),
        );
        let wire = envelope(
            &changed,
            &f.signer_i
                .sign(Purpose::BootstrapInitiator, &changed)
                .expect("sign"),
        )
        .expect("wire");
        let mut r = ResponderOperation::new(Arc::clone(&f.responder));
        let (pq, classical) = f.sources();
        fail(
            r.respond(&wire, &f.signer_r, pq, classical, 150),
            Error::Runtime(q_periapt_sdk::Error::InvalidKeyShare),
        );
        assert!(matches!(r.state, ResponderState::Closed));
        fail(
            r.respond(original, &f.signer_r, pq, classical, 150),
            Error::Closed,
        );
    }

    #[test]
    fn key_schedule_matches_independent_python_hmac_sha256_and_sha3_vectors() {
        fn hex(bytes: &[u8]) -> String {
            use std::fmt::Write;
            let mut text = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                write!(&mut text, "{byte:02x}").expect("format into String");
            }
            text
        }
        // Public synthetic inputs, independently calculated using Python's
        // hashlib/hmac (extract and the first expand block), not live secrets.
        let mut ikm = [1u8; 64];
        ikm.get_mut(32..).expect("second").fill(2);
        let seed = derive(&ikm, &[3; 32], b"handshake-seed").expect("seed");
        assert_eq!(
            hex(seed.as_bytes()),
            "e2c777bf03f765fe3b3ac4a6391e577e4dde8f0882a68830eed7b9dc26cd54f7"
        );
        let responder = derive(&ikm, &[3; 32], b"confirmation-responder").expect("R key");
        assert_eq!(
            hex(responder.as_bytes()),
            "cafff40b1d46ccfdd6ca696cbebc5567a1f008c17ccb5d7ca1589f104e4c406c"
        );
        assert_eq!(
            hex(derive(&ikm, &[3; 32], b"confirmation-initiator")
                .expect("I key")
                .as_bytes()),
            "b23f2dc706de4bee05b6e0989f816de58bfe754e17df20af02744000265b1685"
        );
        assert_eq!(
            hex(&mac(responder.as_bytes(), &[3; 32]).expect("MAC")),
            "93d5e7c82e65e20984d4172073ba80b05781da6ef8e3dd1cdc5b475d88791472"
        );
        let mut session = pending(
            &[4; 32],
            b"initial-test",
            b"reply-test",
            &seed,
            BootstrapRole::Initiator,
        )
        .expect("session");
        assert_eq!(
            hex(&session.id()),
            "8d4558a28f45f0546808519c0eae01f2f699114436c5bcef4d0cba8ac0e8c81d"
        );
        assert_eq!(
            hex(session.root.as_ref().expect("root").as_bytes()),
            "59f448cc11216e01b6b5ee2f2f9f9dd4609eaf4d2ca0c0b226054ee0b1dfa96e"
        );
        session.close();
        assert!(session.root.is_none());
    }
}
