//! Fixed-width public commitments shared by canonical Continuity projections.

macro_rules! fixed_commitment_type {
    ($name:ident, $len:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Construct the value from its exact fixed-width representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact fixed-width representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }
    };
}

macro_rules! integer_commitment_type {
    ($name:ident, $raw:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name($raw);

        impl $name {
            /// Construct the typed integer.
            #[must_use]
            pub const fn new(value: $raw) -> Self {
                Self(value)
            }

            /// Return the underlying integer.
            #[must_use]
            pub const fn get(self) -> $raw {
                self.0
            }
        }
    };
}

fixed_commitment_type!(AccountId, 32, "A canonical account identifier commitment.");
fixed_commitment_type!(
    ProtocolId,
    16,
    "A protocol namespace, distinct from every reference protocol."
);
fixed_commitment_type!(SessionId, 32, "A pairwise per-device session identifier.");
fixed_commitment_type!(
    DeviceId,
    16,
    "A device identifier within an account roster."
);
fixed_commitment_type!(
    SuiteDigest,
    32,
    "A commitment to the closed protocol suite."
);
fixed_commitment_type!(
    IdentityCredentialDigest,
    32,
    "A commitment to one authenticated device identity credential."
);
fixed_commitment_type!(RosterDigest, 32, "A commitment to one exact device roster.");
fixed_commitment_type!(
    DirectoryCheckpointDigest,
    32,
    "A commitment to one verified directory checkpoint and its authority."
);
fixed_commitment_type!(
    TranscriptDigest,
    32,
    "A commitment to the exact non-circular public key-schedule transcript."
);
fixed_commitment_type!(
    PolicyDigest,
    32,
    "A commitment to one closed resolved session policy."
);
fixed_commitment_type!(
    ContextDigest,
    32,
    "A fixed-width commitment to the typed context stage."
);

integer_commitment_type!(WireVersion, u16, "A protocol wire version.");
integer_commitment_type!(DeviceEpoch, u64, "A monotonic device generation.");
integer_commitment_type!(
    RosterVersion,
    u64,
    "A monotonic authenticated roster version."
);
integer_commitment_type!(RatchetEpoch, u64, "A monotonic ratchet epoch.");
