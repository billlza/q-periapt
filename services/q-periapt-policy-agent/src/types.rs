//! Exact state revisions and unpredictable capability identifiers.

use core::fmt;

use crate::codec::{CodecError, Decoder, Encoder};

const REVISION_ENCODED_LEN: usize = 48;
const HEAD_ENCODED_LEN: usize = 80;

/// Invalid state, transition, or random identifier input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateValueError {
    /// Cryptographic randomness was unavailable.
    EntropyUnavailable,
    /// A generation or epoch used a reserved value or did not advance exactly.
    InvalidCounter,
    /// An integrity commitment used the reserved all-zero value.
    InvalidDigest,
    /// An identifier or fence used the reserved all-zero value.
    InvalidIdentifier,
    /// An ordinary transition did not advance epoch, or a reset did not restart it.
    InvalidTransition,
}

impl fmt::Display for StateValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EntropyUnavailable => "cryptographic randomness unavailable",
            Self::InvalidCounter => "state counter is reserved or not the exact successor",
            Self::InvalidDigest => "state digest must be non-zero",
            Self::InvalidIdentifier => "identifier must be unpredictable and non-zero",
            Self::InvalidTransition => "state transition violates its closed transition kind",
        })
    }
}

impl std::error::Error for StateValueError {}

fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

fn random_nonzero() -> Result<[u8; 32], StateValueError> {
    for _ in 0..4 {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| StateValueError::EntropyUnavailable)?;
        if nonzero(&bytes) {
            return Ok(bytes);
        }
    }
    Err(StateValueError::EntropyUnavailable)
}

macro_rules! random_identifier {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) fn generate() -> Result<Self, StateValueError> {
                Ok(Self(random_nonzero()?))
            }

            pub(crate) fn decode(bytes: [u8; 32]) -> Result<Self, StateValueError> {
                nonzero(&bytes)
                    .then_some(Self(bytes))
                    .ok_or(StateValueError::InvalidIdentifier)
            }

            /// Borrow the exact opaque identifier bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
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

random_identifier!(
    OperationId,
    "An unpredictable identifier for one exact witness CAS operation."
);
random_identifier!(
    SessionId,
    "An unpredictable durable session reservation identifier."
);
random_identifier!(
    FenceToken,
    "An unpredictable single-writer fence changed by every state transition."
);

/// Exact migration state identity held by the agent and external witness.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StateRevision {
    global_generation: u64,
    epoch: u64,
    digest: [u8; 32],
}

impl fmt::Debug for StateRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateRevision")
            .field("global_generation", &self.global_generation)
            .field("epoch", &self.epoch)
            .field("digest", &"[redacted]")
            .finish()
    }
}

impl StateRevision {
    /// Construct an exact non-genesis-sentinel revision.
    pub fn new(
        global_generation: u64,
        epoch: u64,
        digest: [u8; 32],
    ) -> Result<Self, StateValueError> {
        if global_generation == 0
            || global_generation == u64::MAX
            || epoch == 0
            || epoch == u64::MAX
        {
            return Err(StateValueError::InvalidCounter);
        }
        if !nonzero(&digest) {
            return Err(StateValueError::InvalidDigest);
        }
        Ok(Self {
            global_generation,
            epoch,
            digest,
        })
    }

    /// Return the never-reset global generation.
    #[must_use]
    pub const fn global_generation(self) -> u64 {
        self.global_generation
    }

    /// Return the chain-local migration epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Borrow the exact canonical state digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder) -> Result<(), CodecError> {
        encoder.u64(self.global_generation)?;
        encoder.u64(self.epoch)?;
        encoder.fixed(&self.digest)
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Self::new(decoder.u64()?, decoder.u64()?, decoder.array()?)
            .map_err(|_| CodecError::InvalidValue)
    }

    pub(crate) fn to_bytes(self) -> [u8; REVISION_ENCODED_LEN] {
        let mut bytes = [0u8; REVISION_ENCODED_LEN];
        bytes[..8].copy_from_slice(&self.global_generation.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[16..].copy_from_slice(&self.digest);
        bytes
    }
}

/// Repository/witness head: exact state revision plus its unpredictable writer fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateHead {
    revision: StateRevision,
    fence: FenceToken,
}

impl StateHead {
    /// Pair an exact revision with a nonzero fence.
    #[must_use]
    pub const fn new(revision: StateRevision, fence: FenceToken) -> Self {
        Self { revision, fence }
    }

    /// Return the exact state revision.
    #[must_use]
    pub const fn revision(self) -> StateRevision {
        self.revision
    }

    /// Return the writer fence.
    #[must_use]
    pub const fn fence(self) -> FenceToken {
        self.fence
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder) -> Result<(), CodecError> {
        self.revision.encode(encoder)?;
        encoder.fixed(self.fence.as_bytes())
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let revision = StateRevision::decode(decoder)?;
        let fence = FenceToken::decode(decoder.array()?).map_err(|_| CodecError::InvalidValue)?;
        Ok(Self { revision, fence })
    }

    pub(crate) fn to_bytes(self) -> [u8; HEAD_ENCODED_LEN] {
        let mut bytes = [0u8; HEAD_ENCODED_LEN];
        bytes[..REVISION_ENCODED_LEN].copy_from_slice(&self.revision.to_bytes());
        bytes[REVISION_ENCODED_LEN..].copy_from_slice(self.fence.as_bytes());
        bytes
    }
}

/// Closed state-transition category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransitionKind {
    /// Advance the current chain by exactly one epoch.
    Advance = 1,
    /// Explicitly authorized chain reset; global generation still advances by one.
    AuthorizedReset = 2,
}

impl TransitionKind {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Advance),
            2 => Some(Self::AuthorizedReset),
            _ => None,
        }
    }
}

/// Exact predecessor/successor pair authorized for a transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateAdvance {
    kind: TransitionKind,
    expected: StateRevision,
    next: StateRevision,
}

impl StateAdvance {
    /// Validate the generation and epoch rules for a closed transition kind.
    pub fn new(
        kind: TransitionKind,
        expected: StateRevision,
        next: StateRevision,
    ) -> Result<Self, StateValueError> {
        if expected.global_generation.checked_add(1) != Some(next.global_generation)
            || expected.digest == next.digest
        {
            return Err(StateValueError::InvalidTransition);
        }
        let epoch_valid = match kind {
            TransitionKind::Advance => expected.epoch.checked_add(1) == Some(next.epoch),
            TransitionKind::AuthorizedReset => next.epoch == 1,
        };
        if !epoch_valid {
            return Err(StateValueError::InvalidTransition);
        }
        Ok(Self {
            kind,
            expected,
            next,
        })
    }

    /// Return the closed transition kind.
    #[must_use]
    pub const fn kind(self) -> TransitionKind {
        self.kind
    }

    /// Return the required predecessor revision.
    #[must_use]
    pub const fn expected(self) -> StateRevision {
        self.expected
    }

    /// Return the authorized successor revision.
    #[must_use]
    pub const fn next(self) -> StateRevision {
        self.next
    }

    pub(crate) fn encode(&self, encoder: &mut Encoder) -> Result<(), CodecError> {
        encoder.byte(self.kind as u8)?;
        self.expected.encode(encoder)?;
        self.next.encode(encoder)
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        let kind = TransitionKind::from_u8(decoder.byte()?).ok_or(CodecError::InvalidValue)?;
        let expected = StateRevision::decode(decoder)?;
        let next = StateRevision::decode(decoder)?;
        Self::new(kind, expected, next).map_err(|_| CodecError::InvalidValue)
    }
}
