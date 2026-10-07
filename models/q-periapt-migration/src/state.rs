//! Signed migration-state certificates and an exact in-memory commit model.

use core::fmt;

use q_periapt_policy::{AuthenticatedResolvedSuite, HybridSuite, TrustedPolicyState};
use q_periapt_sig::{Signer, Verifier};
use sha3::{Digest, Sha3_256};

use crate::codec::{encode_lp8_fields, CodecError, Lp8Reader};
use crate::{MigrationProtocolId, SecurityFloor};

/// Domain for canonical migration-state bodies.
pub const MIGRATION_STATE_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-STATE/v1";
/// Domain for signatures over migration-state certificates.
pub const MIGRATION_STATE_CERTIFICATE_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-STATE-CERTIFICATE/v1";
/// Domain for explicitly authorized lineage resets.
pub const MIGRATION_RESET_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-RESET/v1";
/// Migration-state schema version.
pub const MIGRATION_STATE_SCHEMA_VERSION: u16 = 1;
/// Maximum detached signature accepted by this research contract.
pub const MAX_MIGRATION_SIGNATURE_BYTES: usize = 64 * 1024;
/// Maximum reset body accepted before recovery-signature verification.
pub const MAX_MIGRATION_RESET_BODY_BYTES: usize = 4 * 1024;

macro_rules! public_bytes {
    ($name:ident, $len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Construct the public identifier from its exact bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

public_bytes!(MigrationChainId, 32, "A migration-lineage identifier.");
public_bytes!(
    MigrationAuthorityKeyId,
    32,
    "A pinned migration-authority key identifier."
);
public_bytes!(
    MigrationStateDigest,
    32,
    "SHA3-256 over one canonical migration-state body."
);
public_bytes!(
    MigrationResetNonce,
    32,
    "A unique nonce for one explicit lineage reset."
);

/// Whether an accepted suite must retain or forbid a traditional component.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ComponentMode {
    /// A PQ and a traditional component are both required.
    HybridRequired = 1,
    /// Traditional components are forbidden; frozen ABI 2 cannot execute this mode.
    PostQuantumOnly = 2,
}

impl ComponentMode {
    fn from_u8(value: u8) -> Result<Self, MigrationStateError> {
        match value {
            1 => Ok(Self::HybridRequired),
            2 => Ok(Self::PostQuantumOnly),
            _ => Err(MigrationStateError::UnknownComponentMode),
        }
    }

    /// Return the stable one-byte code.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Closed set of suites authorized by one migration state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationSuiteSet(u8);

impl MigrationSuiteSet {
    const MLKEM768_X25519: u8 = 1 << 0;
    const MLKEM1024_X25519: u8 = 1 << 1;
    const KNOWN: u8 = Self::MLKEM768_X25519 | Self::MLKEM1024_X25519;

    /// Construct a non-empty suite set from closed policy-suite values.
    pub fn from_suites(suites: &[HybridSuite]) -> Result<Self, MigrationStateError> {
        let mut bits = 0u8;
        for suite in suites {
            bits |= match suite {
                HybridSuite::MlKem768X25519 => Self::MLKEM768_X25519,
                HybridSuite::MlKem1024X25519 => Self::MLKEM1024_X25519,
            };
        }
        Self::from_bits(bits)
    }

    fn from_bits(bits: u8) -> Result<Self, MigrationStateError> {
        if bits == 0 || bits & !Self::KNOWN != 0 {
            return Err(MigrationStateError::InvalidSuiteSet);
        }
        Ok(Self(bits))
    }

    /// Report whether the set authorizes `suite`.
    #[must_use]
    pub const fn contains(self, suite: HybridSuite) -> bool {
        let bit = match suite {
            HybridSuite::MlKem768X25519 => Self::MLKEM768_X25519,
            HybridSuite::MlKem1024X25519 => Self::MLKEM1024_X25519,
        };
        self.0 & bit != 0
    }

    /// Return the stable bit representation.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// State-owned minimum security posture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationSecurityPosture {
    minimum_pq_level: SecurityFloor,
    component_mode: ComponentMode,
}

impl MigrationSecurityPosture {
    /// Construct a closed migration posture.
    #[must_use]
    pub const fn new(minimum_pq_level: SecurityFloor, component_mode: ComponentMode) -> Self {
        Self {
            minimum_pq_level,
            component_mode,
        }
    }

    /// Return the minimum PQ security category.
    #[must_use]
    pub const fn minimum_pq_level(self) -> SecurityFloor {
        self.minimum_pq_level
    }

    /// Return the component requirement.
    #[must_use]
    pub const fn component_mode(self) -> ComponentMode {
        self.component_mode
    }
}

/// One canonical, authority-signable migration state.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationStateV1 {
    global_generation: u64,
    chain_id: MigrationChainId,
    protocol_id: MigrationProtocolId,
    epoch: u64,
    previous_state_digest: MigrationStateDigest,
    authority_key_id: MigrationAuthorityKeyId,
    execution_policy_state: TrustedPolicyState,
    posture: MigrationSecurityPosture,
    allowed_suites: MigrationSuiteSet,
}

/// Explicit fields for one migration-state draft before validation and authentication.
///
/// Keeping the complete draft in one typed record makes call sites name every
/// security-relevant field while [`MigrationStateV1::new`] remains the sole
/// invariant-checking constructor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationStateDraftV1 {
    /// Never-reset global generation.
    pub global_generation: u64,
    /// Migration lineage identifier.
    pub chain_id: MigrationChainId,
    /// Protocol namespace governed by the state.
    pub protocol_id: MigrationProtocolId,
    /// Lineage-local epoch.
    pub epoch: u64,
    /// Exact predecessor-state commitment.
    pub previous_state_digest: MigrationStateDigest,
    /// Migration authority identifier.
    pub authority_key_id: MigrationAuthorityKeyId,
    /// Exact authenticated execution-policy state.
    pub execution_policy_state: TrustedPolicyState,
    /// Minimum security and component requirements.
    pub posture: MigrationSecurityPosture,
    /// Closed state-authorized suite set.
    pub allowed_suites: MigrationSuiteSet,
}

impl fmt::Debug for MigrationStateDraftV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationStateDraftV1([redacted])")
    }
}

impl fmt::Debug for MigrationStateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationStateV1([redacted])")
    }
}

impl MigrationStateV1 {
    /// Construct a state draft that still requires certificate verification and commit.
    pub fn new(draft: MigrationStateDraftV1) -> Result<Self, MigrationStateError> {
        let MigrationStateDraftV1 {
            global_generation,
            chain_id,
            protocol_id,
            epoch,
            previous_state_digest,
            authority_key_id,
            execution_policy_state,
            posture,
            allowed_suites,
        } = draft;
        if global_generation == 0 || global_generation == u64::MAX {
            return Err(MigrationStateError::InvalidGlobalGeneration);
        }
        if epoch == 0 || epoch == u64::MAX {
            return Err(MigrationStateError::InvalidEpoch);
        }
        if all_zero(chain_id.as_bytes()) || all_zero(protocol_id.as_bytes()) {
            return Err(MigrationStateError::ZeroIdentifier);
        }
        if all_zero(authority_key_id.as_bytes()) {
            return Err(MigrationStateError::ZeroIdentifier);
        }
        Ok(Self {
            global_generation,
            chain_id,
            protocol_id,
            epoch,
            previous_state_digest,
            authority_key_id,
            execution_policy_state,
            posture,
            allowed_suites,
        })
    }

    /// Return the global generation, which never resets across lineages.
    #[must_use]
    pub const fn global_generation(self) -> u64 {
        self.global_generation
    }

    /// Return the lineage identifier.
    #[must_use]
    pub const fn chain_id(self) -> MigrationChainId {
        self.chain_id
    }

    /// Return the protocol namespace governed by this state.
    #[must_use]
    pub const fn protocol_id(self) -> MigrationProtocolId {
        self.protocol_id
    }

    /// Return the lineage-local epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Return the exact predecessor-state commitment.
    #[must_use]
    pub const fn previous_state_digest(self) -> MigrationStateDigest {
        self.previous_state_digest
    }

    /// Return the migration authority identifier.
    #[must_use]
    pub const fn authority_key_id(self) -> MigrationAuthorityKeyId {
        self.authority_key_id
    }

    /// Return the exact signed execution-policy state.
    #[must_use]
    pub const fn execution_policy_state(self) -> TrustedPolicyState {
        self.execution_policy_state
    }

    /// Return the migration security posture.
    #[must_use]
    pub const fn posture(self) -> MigrationSecurityPosture {
        self.posture
    }

    /// Return the state-authorized suite set.
    #[must_use]
    pub const fn allowed_suites(self) -> MigrationSuiteSet {
        self.allowed_suites
    }

    /// Encode the exact canonical LP8 state body.
    pub fn encode(&self) -> Result<Vec<u8>, MigrationStateError> {
        let schema = MIGRATION_STATE_SCHEMA_VERSION.to_be_bytes();
        let generation = self.global_generation.to_be_bytes();
        let epoch = self.epoch.to_be_bytes();
        let execution = self.execution_policy_state.encode();
        let floor = [self.posture.minimum_pq_level.to_u8()];
        let mode = [self.posture.component_mode.to_u8()];
        let suites = [self.allowed_suites.bits()];
        encode_lp8_fields(&[
            MIGRATION_STATE_DOMAIN,
            &schema,
            &generation,
            self.chain_id.as_bytes(),
            self.protocol_id.as_bytes(),
            &epoch,
            self.previous_state_digest.as_bytes(),
            self.authority_key_id.as_bytes(),
            &execution,
            &floor,
            &mode,
            &suites,
        ])
        .map_err(MigrationStateError::from_codec)
    }

    /// Strictly decode one canonical state body, rejecting trailing bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, MigrationStateError> {
        let mut reader = Lp8Reader::new(encoded);
        require_field(&mut reader, MIGRATION_STATE_DOMAIN)?;
        let schema = read_u16(reader.field().map_err(MigrationStateError::from_codec)?)?;
        if schema != MIGRATION_STATE_SCHEMA_VERSION {
            return Err(MigrationStateError::UnsupportedSchema);
        }
        let global_generation = read_u64(reader.field().map_err(MigrationStateError::from_codec)?)?;
        let chain_id = MigrationChainId(read_array(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?);
        let protocol_id = MigrationProtocolId::from_bytes(read_array(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?);
        let epoch = read_u64(reader.field().map_err(MigrationStateError::from_codec)?)?;
        let previous_state_digest = MigrationStateDigest(read_array(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?);
        let authority_key_id = MigrationAuthorityKeyId(read_array(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?);
        let execution_policy_state =
            TrustedPolicyState::decode(reader.field().map_err(MigrationStateError::from_codec)?)
                .map_err(|_| MigrationStateError::InvalidExecutionPolicyState)?;
        let floor = read_byte(reader.field().map_err(MigrationStateError::from_codec)?)?;
        let minimum_pq_level = SecurityFloor::from_nist_level(floor)
            .map_err(|_| MigrationStateError::InvalidSecurityFloor)?;
        let component_mode = ComponentMode::from_u8(read_byte(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?)?;
        let allowed_suites = MigrationSuiteSet::from_bits(read_byte(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?)?;
        reader.finish().map_err(MigrationStateError::from_codec)?;
        Self::new(MigrationStateDraftV1 {
            global_generation,
            chain_id,
            protocol_id,
            epoch,
            previous_state_digest,
            authority_key_id,
            execution_policy_state,
            posture: MigrationSecurityPosture::new(minimum_pq_level, component_mode),
            allowed_suites,
        })
    }

    /// Compute SHA3-256 over the canonical state body.
    pub fn digest(&self) -> Result<MigrationStateDigest, MigrationStateError> {
        Ok(MigrationStateDigest(
            Sha3_256::digest(self.encode()?).into(),
        ))
    }
}

/// Certificate purpose; signatures cannot be replayed between genesis and advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StateCertificateKind {
    /// Explicit first installation.
    Genesis = 1,
    /// Normal same-lineage advance.
    Advance = 2,
}

impl StateCertificateKind {
    fn from_u8(value: u8) -> Result<Self, MigrationStateError> {
        match value {
            1 => Ok(Self::Genesis),
            2 => Ok(Self::Advance),
            _ => Err(MigrationStateError::UnknownCertificateKind),
        }
    }
}

/// Detached authority signature over one exact canonical state body.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedMigrationStateV1 {
    kind: StateCertificateKind,
    state: MigrationStateV1,
    signature: Vec<u8>,
}

impl fmt::Debug for SignedMigrationStateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedMigrationStateV1([redacted])")
    }
}

impl SignedMigrationStateV1 {
    /// Sign one genesis or normal-advance state with a supplied backend.
    ///
    /// `signature_output` must be exactly the selected backend's signature
    /// length. Success requires the backend to write the complete slice.
    pub fn sign<S: Signer>(
        kind: StateCertificateKind,
        state: MigrationStateV1,
        signer: &S,
        signing_key: &[u8],
        randomness: &[u8],
        signature_output: &mut [u8],
    ) -> Result<Self, MigrationStateError> {
        if signature_output.is_empty() || signature_output.len() > MAX_MIGRATION_SIGNATURE_BYTES {
            return Err(MigrationStateError::InvalidSignatureLength);
        }
        let message = state_signature_message(kind, &state)?;
        let written = signer
            .sign(signing_key, &message, randomness, signature_output)
            .map_err(|_| MigrationStateError::SignatureFailure)?;
        if written != signature_output.len() {
            return Err(MigrationStateError::InvalidSignatureLength);
        }
        let signature = signature_output
            .get(..written)
            .ok_or(MigrationStateError::InvalidSignatureLength)?
            .to_vec();
        Ok(Self {
            kind,
            state,
            signature,
        })
    }

    /// Encode certificate kind, exact state body, and detached signature.
    pub fn encode(&self) -> Result<Vec<u8>, MigrationStateError> {
        let kind = [self.kind as u8];
        let state = self.state.encode()?;
        encode_lp8_fields(&[&kind, &state, &self.signature])
            .map_err(MigrationStateError::from_codec)
    }

    /// Strictly decode one untrusted signed-state envelope.
    pub fn decode(encoded: &[u8]) -> Result<Self, MigrationStateError> {
        let mut reader = Lp8Reader::new(encoded);
        let kind = StateCertificateKind::from_u8(read_byte(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?)?;
        let state =
            MigrationStateV1::decode(reader.field().map_err(MigrationStateError::from_codec)?)?;
        let signature = reader.field().map_err(MigrationStateError::from_codec)?;
        if signature.is_empty() || signature.len() > MAX_MIGRATION_SIGNATURE_BYTES {
            return Err(MigrationStateError::InvalidSignatureLength);
        }
        reader.finish().map_err(MigrationStateError::from_codec)?;
        Ok(Self {
            kind,
            state,
            signature: signature.to_vec(),
        })
    }

    /// Return the signed state draft.
    #[must_use]
    pub const fn state(&self) -> MigrationStateV1 {
        self.state
    }
}

/// Canonical reset statement signed by a separately pinned recovery authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationResetV1 {
    old_revision: StateRevisionV1,
    next_state: MigrationStateV1,
    reset_nonce: MigrationResetNonce,
    recovery_key_id: MigrationAuthorityKeyId,
}

impl fmt::Debug for MigrationResetV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationResetV1([redacted])")
    }
}

impl MigrationResetV1 {
    /// Construct an explicit reset binding the exact old revision to a new lineage.
    #[must_use]
    pub const fn new(
        old_revision: StateRevisionV1,
        next_state: MigrationStateV1,
        reset_nonce: MigrationResetNonce,
        recovery_key_id: MigrationAuthorityKeyId,
    ) -> Self {
        Self {
            old_revision,
            next_state,
            reset_nonce,
            recovery_key_id,
        }
    }

    /// Encode the exact reset statement signed by the recovery authority.
    pub fn encode(&self) -> Result<Vec<u8>, MigrationStateError> {
        let schema = MIGRATION_STATE_SCHEMA_VERSION.to_be_bytes();
        let old_generation = self.old_revision.global_generation.to_be_bytes();
        let old_epoch = self.old_revision.epoch.to_be_bytes();
        let next = self.next_state.encode()?;
        let encoded = encode_lp8_fields(&[
            MIGRATION_RESET_DOMAIN,
            &schema,
            &old_generation,
            self.old_revision.chain_id.as_bytes(),
            &old_epoch,
            self.old_revision.digest.as_bytes(),
            &next,
            self.reset_nonce.as_bytes(),
            self.recovery_key_id.as_bytes(),
        ])
        .map_err(MigrationStateError::from_codec)?;
        if encoded.len() > MAX_MIGRATION_RESET_BODY_BYTES {
            return Err(MigrationStateError::ResetTooLarge);
        }
        Ok(encoded)
    }

    /// Strictly decode one untrusted reset body and reject trailing bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, MigrationStateError> {
        if encoded.len() > MAX_MIGRATION_RESET_BODY_BYTES {
            return Err(MigrationStateError::ResetTooLarge);
        }
        let mut reader = Lp8Reader::new(encoded);
        require_field(&mut reader, MIGRATION_RESET_DOMAIN)?;
        if read_u16(reader.field().map_err(MigrationStateError::from_codec)?)?
            != MIGRATION_STATE_SCHEMA_VERSION
        {
            return Err(MigrationStateError::UnsupportedSchema);
        }
        let old_generation = read_u64(reader.field().map_err(MigrationStateError::from_codec)?)?;
        let old_chain = MigrationChainId(read_array(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?);
        let old_epoch = read_u64(reader.field().map_err(MigrationStateError::from_codec)?)?;
        let old_digest = MigrationStateDigest(read_array(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?);
        let next_state =
            MigrationStateV1::decode(reader.field().map_err(MigrationStateError::from_codec)?)?;
        let reset_nonce = MigrationResetNonce(read_array(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?);
        let recovery_key_id = MigrationAuthorityKeyId(read_array(
            reader.field().map_err(MigrationStateError::from_codec)?,
        )?);
        reader.finish().map_err(MigrationStateError::from_codec)?;
        if old_generation == 0
            || old_generation == u64::MAX
            || old_epoch == 0
            || old_epoch == u64::MAX
            || all_zero(old_chain.as_bytes())
            || all_zero(old_digest.as_bytes())
            || all_zero(reset_nonce.as_bytes())
            || all_zero(recovery_key_id.as_bytes())
        {
            return Err(MigrationStateError::InvalidReset);
        }
        Ok(Self {
            old_revision: StateRevisionV1 {
                global_generation: old_generation,
                chain_id: old_chain,
                epoch: old_epoch,
                digest: old_digest,
            },
            next_state,
            reset_nonce,
            recovery_key_id,
        })
    }
}

/// Recovery-authority signature over one exact reset statement.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedMigrationResetV1 {
    reset: MigrationResetV1,
    signature: Vec<u8>,
}

impl fmt::Debug for SignedMigrationResetV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedMigrationResetV1([redacted])")
    }
}

impl SignedMigrationResetV1 {
    /// Sign an explicit reset with the recovery authority.
    ///
    /// `signature_output` must be exactly the selected backend's signature
    /// length. Success requires the backend to write the complete slice.
    pub fn sign<S: Signer>(
        reset: MigrationResetV1,
        signer: &S,
        signing_key: &[u8],
        randomness: &[u8],
        signature_output: &mut [u8],
    ) -> Result<Self, MigrationStateError> {
        if signature_output.is_empty() || signature_output.len() > MAX_MIGRATION_SIGNATURE_BYTES {
            return Err(MigrationStateError::InvalidSignatureLength);
        }
        let message = reset.encode()?;
        let written = signer
            .sign(signing_key, &message, randomness, signature_output)
            .map_err(|_| MigrationStateError::SignatureFailure)?;
        if written != signature_output.len() {
            return Err(MigrationStateError::InvalidSignatureLength);
        }
        let signature = signature_output
            .get(..written)
            .ok_or(MigrationStateError::InvalidSignatureLength)?
            .to_vec();
        Ok(Self { reset, signature })
    }

    /// Encode reset body and detached recovery signature as a strict LP8 envelope.
    pub fn encode(&self) -> Result<Vec<u8>, MigrationStateError> {
        let body = self.reset.encode()?;
        encode_lp8_fields(&[&body, &self.signature]).map_err(MigrationStateError::from_codec)
    }

    /// Strictly decode an untrusted signed-reset envelope.
    pub fn decode(encoded: &[u8]) -> Result<Self, MigrationStateError> {
        let maximum = MAX_MIGRATION_RESET_BODY_BYTES
            .checked_add(MAX_MIGRATION_SIGNATURE_BYTES)
            .and_then(|value| value.checked_add(16))
            .ok_or(MigrationStateError::ResetTooLarge)?;
        if encoded.len() > maximum {
            return Err(MigrationStateError::ResetTooLarge);
        }
        let mut reader = Lp8Reader::new(encoded);
        let reset =
            MigrationResetV1::decode(reader.field().map_err(MigrationStateError::from_codec)?)?;
        let signature = reader.field().map_err(MigrationStateError::from_codec)?;
        if signature.is_empty() || signature.len() > MAX_MIGRATION_SIGNATURE_BYTES {
            return Err(MigrationStateError::InvalidSignatureLength);
        }
        reader.finish().map_err(MigrationStateError::from_codec)?;
        Ok(Self {
            reset,
            signature: signature.to_vec(),
        })
    }
}

/// Exact committed migration-state identity used for CAS and session rechecks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateRevisionV1 {
    global_generation: u64,
    chain_id: MigrationChainId,
    epoch: u64,
    digest: MigrationStateDigest,
}

impl StateRevisionV1 {
    fn from_state(state: MigrationStateV1) -> Result<Self, MigrationStateError> {
        Ok(Self {
            global_generation: state.global_generation,
            chain_id: state.chain_id,
            epoch: state.epoch,
            digest: state.digest()?,
        })
    }

    /// Return the non-resetting generation.
    #[must_use]
    pub const fn global_generation(self) -> u64 {
        self.global_generation
    }

    /// Return the current lineage.
    #[must_use]
    pub const fn chain_id(self) -> MigrationChainId {
        self.chain_id
    }

    /// Return the lineage-local epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Return the exact canonical state digest.
    #[must_use]
    pub const fn digest(self) -> MigrationStateDigest {
        self.digest
    }
}

/// A state that passed its authority/reset checks and an exact commit recheck.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommittedMigrationStateV1 {
    state: MigrationStateV1,
    revision: StateRevisionV1,
}

impl fmt::Debug for CommittedMigrationStateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommittedMigrationStateV1([redacted])")
    }
}

impl CommittedMigrationStateV1 {
    /// Return the authenticated state.
    #[must_use]
    pub const fn state(self) -> MigrationStateV1 {
        self.state
    }

    /// Return its exact committed revision.
    #[must_use]
    pub const fn revision(self) -> StateRevisionV1 {
        self.revision
    }
}

/// Explicit uninitialized state; it cannot authorize a context or session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UninitializedMigrationStateV1;

/// Verified genesis awaiting an explicit commit.
pub struct PendingGenesisCommitV1 {
    state: MigrationStateV1,
}

/// Verified state-change kind carried by an unforgeable pending-commit token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingMigrationCommitKind {
    /// Normal same-lineage advance.
    Advance,
    /// Explicit recovery-authority reset to a new lineage.
    Reset,
}

/// Verified transition/reset awaiting exact-current-state commit.
pub struct PendingMigrationCommitV1 {
    kind: PendingMigrationCommitKind,
    expected: StateRevisionV1,
    next: MigrationStateV1,
}

impl UninitializedMigrationStateV1 {
    /// Verify an explicit signed genesis. There is no unsigned or implicit genesis path.
    pub fn verify_genesis<V: Verifier>(
        self,
        certificate: &SignedMigrationStateV1,
        verifier: &V,
        verification_key: &[u8],
        expected_authority: MigrationAuthorityKeyId,
    ) -> Result<PendingGenesisCommitV1, MigrationStateError> {
        if certificate.kind != StateCertificateKind::Genesis {
            return Err(MigrationStateError::WrongCertificateKind);
        }
        verify_state_signature(certificate, verifier, verification_key, expected_authority)?;
        let state = certificate.state;
        if state.global_generation != 1
            || state.epoch != 1
            || !all_zero(state.previous_state_digest.as_bytes())
        {
            return Err(MigrationStateError::InvalidGenesis);
        }
        Ok(PendingGenesisCommitV1 { state })
    }
}

impl PendingGenesisCommitV1 {
    /// Return the authority-verified genesis state for durable reservation.
    #[must_use]
    pub const fn state(&self) -> MigrationStateV1 {
        self.state
    }

    /// Return the exact revision a durable genesis commit will install.
    pub fn revision(&self) -> Result<StateRevisionV1, MigrationStateError> {
        StateRevisionV1::from_state(self.state)
    }

    /// Commit the verified genesis into an initialized state owner.
    pub fn commit(self) -> Result<MigrationStateMachineV1, MigrationStateError> {
        let revision = StateRevisionV1::from_state(self.state)?;
        Ok(MigrationStateMachineV1 {
            current: CommittedMigrationStateV1 {
                state: self.state,
                revision,
            },
        })
    }
}

impl PendingMigrationCommitV1 {
    /// Return whether this token represents a normal advance or authorized reset.
    #[must_use]
    pub const fn kind(&self) -> PendingMigrationCommitKind {
        self.kind
    }

    /// Return the exact predecessor revision required by durable CAS.
    #[must_use]
    pub const fn expected_revision(&self) -> StateRevisionV1 {
        self.expected
    }

    /// Return the authority-verified next state for durable reservation.
    #[must_use]
    pub const fn next_state(&self) -> MigrationStateV1 {
        self.next
    }

    /// Return the exact successor revision a durable commit will install.
    pub fn next_revision(&self) -> Result<StateRevisionV1, MigrationStateError> {
        StateRevisionV1::from_state(self.next)
    }
}

/// Exact state owner used by the model and by key-confirmation revision checks.
#[derive(Eq, PartialEq)]
pub struct MigrationStateMachineV1 {
    current: CommittedMigrationStateV1,
}

impl fmt::Debug for MigrationStateMachineV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationStateMachineV1([redacted])")
    }
}

impl MigrationStateMachineV1 {
    /// Return the current committed state.
    #[must_use]
    pub const fn current(&self) -> CommittedMigrationStateV1 {
        self.current
    }

    /// Return the exact current revision for an acceptance-time recheck.
    #[must_use]
    pub const fn current_revision(&self) -> StateRevisionV1 {
        self.current.revision
    }

    /// Verify a normal same-lineage, non-weakening state advance.
    pub fn prepare_advance<V: Verifier>(
        &self,
        certificate: &SignedMigrationStateV1,
        verifier: &V,
        verification_key: &[u8],
    ) -> Result<PendingMigrationCommitV1, MigrationStateError> {
        if certificate.kind != StateCertificateKind::Advance {
            return Err(MigrationStateError::WrongCertificateKind);
        }
        let current = self.current.state;
        verify_state_signature(
            certificate,
            verifier,
            verification_key,
            current.authority_key_id,
        )?;
        let next = certificate.state;
        validate_common_advance(current, next)?;
        if next.chain_id != current.chain_id
            || next.protocol_id != current.protocol_id
            || next.authority_key_id != current.authority_key_id
        {
            return Err(MigrationStateError::LineageMismatch);
        }
        let expected_epoch = current
            .epoch
            .checked_add(1)
            .ok_or(MigrationStateError::CounterOverflow)?;
        if next.epoch != expected_epoch {
            return Err(MigrationStateError::EpochNotNext);
        }
        Ok(PendingMigrationCommitV1 {
            kind: PendingMigrationCommitKind::Advance,
            expected: self.current.revision,
            next,
        })
    }

    /// Verify a separately signed reset to a new lineage without resetting the global counter.
    pub fn prepare_reset<V: Verifier>(
        &self,
        certificate: &SignedMigrationResetV1,
        verifier: &V,
        verification_key: &[u8],
        expected_recovery_key: MigrationAuthorityKeyId,
    ) -> Result<PendingMigrationCommitV1, MigrationStateError> {
        let reset = certificate.reset;
        if reset.recovery_key_id != expected_recovery_key {
            return Err(MigrationStateError::AuthorityMismatch);
        }
        if verifier.algorithm().nist_level() < reset.next_state.posture.minimum_pq_level.to_u8() {
            return Err(MigrationStateError::WeakSigner);
        }
        verifier
            .verify(verification_key, &reset.encode()?, &certificate.signature)
            .map_err(|_| MigrationStateError::SignatureFailure)?;
        if reset.old_revision != self.current.revision {
            return Err(MigrationStateError::RevisionMismatch);
        }
        let current = self.current.state;
        let next = reset.next_state;
        validate_common_advance(current, next)?;
        if next.chain_id == current.chain_id
            || next.protocol_id != current.protocol_id
            || next.epoch != 1
            || next.previous_state_digest != self.current.revision.digest
            || all_zero(reset.reset_nonce.as_bytes())
        {
            return Err(MigrationStateError::InvalidReset);
        }
        Ok(PendingMigrationCommitV1 {
            kind: PendingMigrationCommitKind::Reset,
            expected: self.current.revision,
            next,
        })
    }

    /// Atomically install a prepared state only if the exact predecessor is still current.
    pub fn commit(
        &mut self,
        pending: PendingMigrationCommitV1,
    ) -> Result<CommittedMigrationStateV1, MigrationStateError> {
        if pending.expected != self.current.revision {
            return Err(MigrationStateError::RevisionMismatch);
        }
        let revision = StateRevisionV1::from_state(pending.next)?;
        self.current = CommittedMigrationStateV1 {
            state: pending.next,
            revision,
        };
        Ok(self.current)
    }
}

/// State parsing, authentication, transition, or commit failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MigrationStateError {
    /// LP8 or integer length was malformed.
    InvalidEncoding,
    /// The schema is unsupported.
    UnsupportedSchema,
    /// A required identifier was all zero.
    ZeroIdentifier,
    /// The global generation is reserved or invalid.
    InvalidGlobalGeneration,
    /// The lineage-local epoch is reserved or invalid.
    InvalidEpoch,
    /// The execution policy state was malformed.
    InvalidExecutionPolicyState,
    /// The security floor code was not closed.
    InvalidSecurityFloor,
    /// The component-mode code was unknown.
    UnknownComponentMode,
    /// The suite bit set was empty or contained unknown bits.
    InvalidSuiteSet,
    /// The certificate kind was unknown.
    UnknownCertificateKind,
    /// The wrong certificate kind was used for this transition.
    WrongCertificateKind,
    /// A detached signature was empty or too large.
    InvalidSignatureLength,
    /// A reset body or envelope exceeded its fixed resource bound.
    ResetTooLarge,
    /// Signing or verification failed.
    SignatureFailure,
    /// The signing algorithm was below the state floor.
    WeakSigner,
    /// The pinned authority identifier did not match.
    AuthorityMismatch,
    /// The signed genesis did not use generation/epoch one and the zero predecessor.
    InvalidGenesis,
    /// The exact committed predecessor no longer matched.
    RevisionMismatch,
    /// A normal advance changed its lineage or authority.
    LineageMismatch,
    /// The global generation was not exactly the next value.
    GlobalGenerationNotNext,
    /// The lineage epoch was not exactly the next value.
    EpochNotNext,
    /// The next state did not name the exact predecessor digest.
    PreviousDigestMismatch,
    /// A state transition lowered the PQ floor.
    FloorDowngrade,
    /// A state transition re-enabled a forbidden traditional component.
    ComponentModeDowngrade,
    /// An explicitly authorized reset was malformed or replayable.
    InvalidReset,
    /// A counter overflowed.
    CounterOverflow,
    /// The selected execution policy was not the committed one.
    ExecutionDecisionMismatch,
    /// The selected suite was not state-authorized.
    SuiteNotAuthorized,
    /// The selected suite was below the committed floor.
    SuiteBelowFloor,
}

impl MigrationStateError {
    fn from_codec(_error: CodecError) -> Self {
        Self::InvalidEncoding
    }
}

impl fmt::Display for MigrationStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "migration state rejected: {self:?}")
    }
}

impl std::error::Error for MigrationStateError {}

pub(crate) fn validate_committed_execution(
    committed: CommittedMigrationStateV1,
    execution: AuthenticatedResolvedSuite,
) -> Result<(), MigrationStateError> {
    let state = committed.state;
    if execution.trusted_state() != state.execution_policy_state {
        return Err(MigrationStateError::ExecutionDecisionMismatch);
    }
    let suite = execution.resolved().suite();
    if !state.allowed_suites.contains(suite) {
        return Err(MigrationStateError::SuiteNotAuthorized);
    }
    if suite.nist_level() < state.posture.minimum_pq_level.to_u8() {
        return Err(MigrationStateError::SuiteBelowFloor);
    }
    Ok(())
}

fn verify_state_signature<V: Verifier>(
    certificate: &SignedMigrationStateV1,
    verifier: &V,
    verification_key: &[u8],
    expected_authority: MigrationAuthorityKeyId,
) -> Result<(), MigrationStateError> {
    if certificate.state.authority_key_id != expected_authority {
        return Err(MigrationStateError::AuthorityMismatch);
    }
    if verifier.algorithm().nist_level() < certificate.state.posture.minimum_pq_level.to_u8() {
        return Err(MigrationStateError::WeakSigner);
    }
    verifier
        .verify(
            verification_key,
            &state_signature_message(certificate.kind, &certificate.state)?,
            &certificate.signature,
        )
        .map_err(|_| MigrationStateError::SignatureFailure)
}

fn state_signature_message(
    kind: StateCertificateKind,
    state: &MigrationStateV1,
) -> Result<Vec<u8>, MigrationStateError> {
    let kind = [kind as u8];
    let body = state.encode()?;
    encode_lp8_fields(&[MIGRATION_STATE_CERTIFICATE_DOMAIN, &kind, &body])
        .map_err(MigrationStateError::from_codec)
}

fn validate_common_advance(
    current: MigrationStateV1,
    next: MigrationStateV1,
) -> Result<(), MigrationStateError> {
    let expected_generation = current
        .global_generation
        .checked_add(1)
        .ok_or(MigrationStateError::CounterOverflow)?;
    if next.global_generation != expected_generation {
        return Err(MigrationStateError::GlobalGenerationNotNext);
    }
    if next.previous_state_digest != current.digest()? {
        return Err(MigrationStateError::PreviousDigestMismatch);
    }
    if next.posture.minimum_pq_level < current.posture.minimum_pq_level {
        return Err(MigrationStateError::FloorDowngrade);
    }
    if current.posture.component_mode == ComponentMode::PostQuantumOnly
        && next.posture.component_mode != ComponentMode::PostQuantumOnly
    {
        return Err(MigrationStateError::ComponentModeDowngrade);
    }
    Ok(())
}

fn require_field(reader: &mut Lp8Reader<'_>, expected: &[u8]) -> Result<(), MigrationStateError> {
    let actual = reader.field().map_err(MigrationStateError::from_codec)?;
    if actual == expected {
        Ok(())
    } else {
        Err(MigrationStateError::InvalidEncoding)
    }
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], MigrationStateError> {
    bytes
        .try_into()
        .map_err(|_| MigrationStateError::InvalidEncoding)
}

fn read_u16(bytes: &[u8]) -> Result<u16, MigrationStateError> {
    Ok(u16::from_be_bytes(read_array(bytes)?))
}

fn read_u64(bytes: &[u8]) -> Result<u64, MigrationStateError> {
    Ok(u64::from_be_bytes(read_array(bytes)?))
}

fn read_byte(bytes: &[u8]) -> Result<u8, MigrationStateError> {
    bytes
        .first()
        .copied()
        .filter(|_| bytes.len() == 1)
        .ok_or(MigrationStateError::InvalidEncoding)
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
