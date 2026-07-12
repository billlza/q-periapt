//! Canonical, lossless commitment to one two-leg bootstrap prekey selection.
//!
//! This codec fixes exact candidate bytes. It does not verify a manifest
//! signature, directory consistency, key membership, freshness, unique leasing,
//! one-time consumption, or rollback resistance.

use crate::codec::{CodecError, LpReader, LpWriter};
use crate::commitments::{
    AccountId, DeviceEpoch, DeviceId, DirectoryCheckpointDigest, IdentityCredentialDigest,
    SuiteDigest,
};

/// Domain for the canonical prekey-selection record.
pub const PREKEY_SELECTION_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-PREKEY-SELECTION/v1";
/// Domain for the prekey-selection digest preimage.
pub const PREKEY_SELECTION_DIGEST_DOMAIN: &[u8] =
    b"Q-PERIAPT-CONTINUITY-PREKEY-SELECTION-DIGEST/v1";
/// Candidate prekey-selection schema version.
pub const PREKEY_SELECTION_SCHEMA_VERSION: u16 = 1;
/// Exact encoded length of the sixteen-field canonical record.
pub const PREKEY_SELECTION_ENCODED_LEN: usize = 492;
/// Exact encoded length of `LP8(digest-domain) || LP8(record)`.
pub const PREKEY_SELECTION_DIGEST_PREIMAGE_LEN: usize = 555;

macro_rules! fixed_prekey_bytes_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Construct the value from its exact fixed-width representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact fixed-width representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

fixed_prekey_bytes_type!(
    SignedPrekeyManifestDigest,
    "A commitment to one authenticated, role-complete signed-prekey manifest."
);
fixed_prekey_bytes_type!(
    PrekeyId,
    "A manifest-resolved commitment identifying one exact prekey entry."
);

/// A digest derived only from a complete canonical [`PrekeySelectionV1`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PrekeySelectionDigest([u8; 32]);

impl PrekeySelectionDigest {
    /// Borrow the exact fixed-width representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Monotonic generation of the responder's signed prekey bundle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrekeyBundleEpoch(u64);

impl PrekeyBundleEpoch {
    /// Construct the typed bundle epoch. Validation occurs in the record.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the underlying integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Classical-leg selection semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClassicalPrekeyMode {
    /// A distinct one-time classical prekey is selected in addition to the SPK.
    OneTime = 1,
    /// No classical OPK is selected; the signed prekey is the selected entry.
    SignedOnly = 2,
}

/// Post-quantum-leg selection semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PostQuantumPrekeyMode {
    /// A distinct one-time post-quantum prekey is selected.
    OneTime = 1,
    /// The explicitly policy-authorized signed last-resort PQ prekey is selected.
    LastResort = 2,
}

/// Lossless Lifecycle B21 projection of both prekey legs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PrekeyQuality {
    /// Both classical and post-quantum legs use distinct one-time prekeys.
    BothOneTime = 1,
    /// Classical uses only its SPK and PQ uses its signed last-resort entry.
    ClassicalSignedOnlyPqLastResort = 2,
    /// Classical uses only its SPK while PQ uses a distinct one-time prekey.
    ClassicalSignedOnlyPqOneTime = 3,
    /// Classical uses a distinct OPK while PQ uses its signed last-resort key.
    ClassicalOneTimePqLastResort = 4,
}

/// The leg named by a semantic validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrekeyLeg {
    /// The classical DH prekey leg.
    Classical,
    /// The post-quantum KEM prekey leg.
    PostQuantum,
}

/// One field in the canonical sixteen-field prekey-selection record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrekeySelectionField {
    /// Record domain separator.
    Domain,
    /// Record schema version.
    SchemaVersion,
    /// Closed suite commitment.
    SuiteDigest,
    /// Responder account commitment.
    ResponderAccountId,
    /// Responder device identifier.
    ResponderDeviceId,
    /// Responder device generation.
    ResponderDeviceEpoch,
    /// Responder identity-credential commitment.
    ResponderIdentityCredentialDigest,
    /// Signed bundle generation.
    BundleEpoch,
    /// Verified directory-checkpoint commitment.
    DirectoryCheckpointDigest,
    /// Signed prekey-manifest commitment.
    SignedManifestDigest,
    /// Classical-leg selection mode.
    ClassicalMode,
    /// Classical signed-prekey identifier.
    ClassicalSignedPrekeyId,
    /// Classical selected-prekey identifier.
    ClassicalSelectedPrekeyId,
    /// Post-quantum-leg selection mode.
    PostQuantumMode,
    /// Signed post-quantum last-resort prekey identifier.
    PostQuantumLastResortPrekeyId,
    /// Post-quantum selected-prekey identifier.
    PostQuantumSelectedPrekeyId,
}

/// Semantic failure in a decoded or constructed selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrekeySelectionError {
    /// A required commitment or identifier is the all-zero unset sentinel.
    ZeroField(PrekeySelectionField),
    /// A device or bundle epoch is zero or the reserved terminal sentinel.
    InvalidMonotonicValue(PrekeySelectionField),
    /// The selected ID does not have the unique canonical relation to its mode.
    InvalidModeKeyRelation(PrekeyLeg),
}

/// Strict canonical-record codec failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrekeySelectionCodecError {
    /// The caller-provided output buffer is not the one canonical length.
    InvalidOutputLength,
    /// The named field has an incomplete LP8 prefix or value.
    TruncatedField(PrekeySelectionField),
    /// The named LP8 length cannot be represented or safely indexed.
    LengthOutOfRange(PrekeySelectionField),
    /// The named fixed-width field has a non-canonical length.
    InvalidFieldLength {
        /// Field whose encoded length is invalid.
        field: PrekeySelectionField,
        /// Only accepted canonical length.
        expected: usize,
        /// Length supplied by the input.
        actual: usize,
    },
    /// Bytes remain after all sixteen canonical fields.
    TrailingBytes,
    /// The record domain separator does not match version one.
    InvalidDomain,
    /// The schema version is well formed but unsupported.
    UnsupportedSchemaVersion(u16),
    /// The classical-leg mode byte is outside the closed enumeration.
    UnknownClassicalMode(u8),
    /// The post-quantum-leg mode byte is outside the closed enumeration.
    UnknownPostQuantumMode(u8),
    /// The decoded fields violate a semantic record invariant.
    InvalidSelection(PrekeySelectionError),
}

/// Failure while deriving a fixed-width digest through a trusted adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrekeySelectionDigestError<E> {
    /// Canonical record validation or encoding failed.
    Encoding(PrekeySelectionCodecError),
    /// The explicit digest adapter failed.
    Backend(E),
    /// The adapter returned the all-zero unset sentinel.
    ZeroDigest,
}

/// Exact responder identity scope to which the selection belongs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrekeyResponder {
    account_id: AccountId,
    device_id: DeviceId,
    device_epoch: DeviceEpoch,
    identity_credential_digest: IdentityCredentialDigest,
}

impl PrekeyResponder {
    /// Construct the responder scope. Validation occurs in the complete record.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        device_id: DeviceId,
        device_epoch: DeviceEpoch,
        identity_credential_digest: IdentityCredentialDigest,
    ) -> Self {
        Self {
            account_id,
            device_id,
            device_epoch,
            identity_credential_digest,
        }
    }

    #[must_use]
    /// Return the responder account commitment.
    pub const fn account_id(self) -> AccountId {
        self.account_id
    }

    #[must_use]
    /// Return the responder device identifier.
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    #[must_use]
    /// Return the responder device generation.
    pub const fn device_epoch(self) -> DeviceEpoch {
        self.device_epoch
    }

    #[must_use]
    /// Return the responder identity-credential commitment.
    pub const fn identity_credential_digest(self) -> IdentityCredentialDigest {
        self.identity_credential_digest
    }
}

/// Canonical classical prekey leg.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassicalPrekeySelection {
    mode: ClassicalPrekeyMode,
    signed_prekey_id: PrekeyId,
    selected_prekey_id: PrekeyId,
}

impl ClassicalPrekeySelection {
    /// Select a distinct one-time classical prekey alongside the signed prekey.
    pub fn one_time(
        signed_prekey_id: PrekeyId,
        selected_prekey_id: PrekeyId,
    ) -> Result<Self, PrekeySelectionError> {
        let selection = Self {
            mode: ClassicalPrekeyMode::OneTime,
            signed_prekey_id,
            selected_prekey_id,
        };
        selection.validate()?;
        Ok(selection)
    }

    /// Select only the classical signed prekey.
    pub fn signed_only(signed_prekey_id: PrekeyId) -> Result<Self, PrekeySelectionError> {
        let selection = Self {
            mode: ClassicalPrekeyMode::SignedOnly,
            signed_prekey_id,
            selected_prekey_id: signed_prekey_id,
        };
        selection.validate()?;
        Ok(selection)
    }

    fn validate(self) -> Result<(), PrekeySelectionError> {
        require_nonzero(
            self.signed_prekey_id.as_bytes(),
            PrekeySelectionField::ClassicalSignedPrekeyId,
        )?;
        require_nonzero(
            self.selected_prekey_id.as_bytes(),
            PrekeySelectionField::ClassicalSelectedPrekeyId,
        )?;
        let relation_is_canonical = match self.mode {
            ClassicalPrekeyMode::OneTime => self.selected_prekey_id != self.signed_prekey_id,
            ClassicalPrekeyMode::SignedOnly => self.selected_prekey_id == self.signed_prekey_id,
        };
        if relation_is_canonical {
            Ok(())
        } else {
            Err(PrekeySelectionError::InvalidModeKeyRelation(
                PrekeyLeg::Classical,
            ))
        }
    }
}

/// Canonical post-quantum prekey leg.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostQuantumPrekeySelection {
    mode: PostQuantumPrekeyMode,
    last_resort_prekey_id: PrekeyId,
    selected_prekey_id: PrekeyId,
}

impl PostQuantumPrekeySelection {
    /// Select a distinct one-time post-quantum prekey.
    pub fn one_time(
        last_resort_prekey_id: PrekeyId,
        selected_prekey_id: PrekeyId,
    ) -> Result<Self, PrekeySelectionError> {
        let selection = Self {
            mode: PostQuantumPrekeyMode::OneTime,
            last_resort_prekey_id,
            selected_prekey_id,
        };
        selection.validate()?;
        Ok(selection)
    }

    /// Select the explicitly authorized signed last-resort PQ prekey.
    pub fn last_resort(last_resort_prekey_id: PrekeyId) -> Result<Self, PrekeySelectionError> {
        let selection = Self {
            mode: PostQuantumPrekeyMode::LastResort,
            last_resort_prekey_id,
            selected_prekey_id: last_resort_prekey_id,
        };
        selection.validate()?;
        Ok(selection)
    }

    fn validate(self) -> Result<(), PrekeySelectionError> {
        require_nonzero(
            self.last_resort_prekey_id.as_bytes(),
            PrekeySelectionField::PostQuantumLastResortPrekeyId,
        )?;
        require_nonzero(
            self.selected_prekey_id.as_bytes(),
            PrekeySelectionField::PostQuantumSelectedPrekeyId,
        )?;
        let relation_is_canonical = match self.mode {
            PostQuantumPrekeyMode::OneTime => self.selected_prekey_id != self.last_resort_prekey_id,
            PostQuantumPrekeyMode::LastResort => {
                self.selected_prekey_id == self.last_resort_prekey_id
            }
        };
        if relation_is_canonical {
            Ok(())
        } else {
            Err(PrekeySelectionError::InvalidModeKeyRelation(
                PrekeyLeg::PostQuantum,
            ))
        }
    }
}

/// Complete responder-, directory-, manifest-, and suite-bound selection record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrekeySelectionV1 {
    suite_digest: SuiteDigest,
    responder: PrekeyResponder,
    bundle_epoch: PrekeyBundleEpoch,
    directory_checkpoint_digest: DirectoryCheckpointDigest,
    signed_manifest_digest: SignedPrekeyManifestDigest,
    classical: ClassicalPrekeySelection,
    post_quantum: PostQuantumPrekeySelection,
}

impl PrekeySelectionV1 {
    /// Construct and validate one complete canonical selection.
    pub fn new(
        suite_digest: SuiteDigest,
        responder: PrekeyResponder,
        bundle_epoch: PrekeyBundleEpoch,
        directory_checkpoint_digest: DirectoryCheckpointDigest,
        signed_manifest_digest: SignedPrekeyManifestDigest,
        classical: ClassicalPrekeySelection,
        post_quantum: PostQuantumPrekeySelection,
    ) -> Result<Self, PrekeySelectionError> {
        let selection = Self {
            suite_digest,
            responder,
            bundle_epoch,
            directory_checkpoint_digest,
            signed_manifest_digest,
            classical,
            post_quantum,
        };
        selection.validate()?;
        Ok(selection)
    }

    /// Validate every semantic invariant represented by this record.
    pub fn validate(self) -> Result<(), PrekeySelectionError> {
        require_nonzero(
            self.suite_digest.as_bytes(),
            PrekeySelectionField::SuiteDigest,
        )?;
        require_nonzero(
            self.responder.account_id.as_bytes(),
            PrekeySelectionField::ResponderAccountId,
        )?;
        require_nonzero(
            self.responder.device_id.as_bytes(),
            PrekeySelectionField::ResponderDeviceId,
        )?;
        validate_monotonic(
            self.responder.device_epoch.get(),
            PrekeySelectionField::ResponderDeviceEpoch,
        )?;
        require_nonzero(
            self.responder.identity_credential_digest.as_bytes(),
            PrekeySelectionField::ResponderIdentityCredentialDigest,
        )?;
        validate_monotonic(self.bundle_epoch.get(), PrekeySelectionField::BundleEpoch)?;
        require_nonzero(
            self.directory_checkpoint_digest.as_bytes(),
            PrekeySelectionField::DirectoryCheckpointDigest,
        )?;
        require_nonzero(
            self.signed_manifest_digest.as_bytes(),
            PrekeySelectionField::SignedManifestDigest,
        )?;
        self.classical.validate()?;
        self.post_quantum.validate()
    }

    /// Return the exact canonical-record length.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        PREKEY_SELECTION_ENCODED_LEN
    }

    /// Return the exact digest-preimage length.
    #[must_use]
    pub const fn digest_preimage_len(self) -> usize {
        PREKEY_SELECTION_DIGEST_PREIMAGE_LEN
    }

    /// Return the lossless B21 projection of both prekey legs.
    #[must_use]
    pub const fn quality(self) -> PrekeyQuality {
        match (self.classical.mode, self.post_quantum.mode) {
            (ClassicalPrekeyMode::OneTime, PostQuantumPrekeyMode::OneTime) => {
                PrekeyQuality::BothOneTime
            }
            (ClassicalPrekeyMode::SignedOnly, PostQuantumPrekeyMode::LastResort) => {
                PrekeyQuality::ClassicalSignedOnlyPqLastResort
            }
            (ClassicalPrekeyMode::SignedOnly, PostQuantumPrekeyMode::OneTime) => {
                PrekeyQuality::ClassicalSignedOnlyPqOneTime
            }
            (ClassicalPrekeyMode::OneTime, PostQuantumPrekeyMode::LastResort) => {
                PrekeyQuality::ClassicalOneTimePqLastResort
            }
        }
    }

    #[must_use]
    /// Return the closed suite commitment.
    pub const fn suite_digest(self) -> SuiteDigest {
        self.suite_digest
    }

    #[must_use]
    /// Return the exact responder identity scope.
    pub const fn responder(self) -> PrekeyResponder {
        self.responder
    }

    #[must_use]
    /// Return the signed bundle generation.
    pub const fn bundle_epoch(self) -> PrekeyBundleEpoch {
        self.bundle_epoch
    }

    #[must_use]
    /// Return the verified directory-checkpoint commitment.
    pub const fn directory_checkpoint_digest(self) -> DirectoryCheckpointDigest {
        self.directory_checkpoint_digest
    }

    #[must_use]
    /// Return the signed prekey-manifest commitment.
    pub const fn signed_manifest_digest(self) -> SignedPrekeyManifestDigest {
        self.signed_manifest_digest
    }

    /// Encode the exact sixteen-field record atomically.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, PrekeySelectionCodecError> {
        self.validate()
            .map_err(PrekeySelectionCodecError::InvalidSelection)?;
        if out.len() != PREKEY_SELECTION_ENCODED_LEN {
            return Err(PrekeySelectionCodecError::InvalidOutputLength);
        }
        let mut writer = LpWriter::new(out);
        write_field(&mut writer, PREKEY_SELECTION_DOMAIN)?;
        write_field(&mut writer, &PREKEY_SELECTION_SCHEMA_VERSION.to_be_bytes())?;
        write_field(&mut writer, self.suite_digest.as_bytes())?;
        write_field(&mut writer, self.responder.account_id.as_bytes())?;
        write_field(&mut writer, self.responder.device_id.as_bytes())?;
        write_field(
            &mut writer,
            &self.responder.device_epoch.get().to_be_bytes(),
        )?;
        write_field(
            &mut writer,
            self.responder.identity_credential_digest.as_bytes(),
        )?;
        write_field(&mut writer, &self.bundle_epoch.get().to_be_bytes())?;
        write_field(&mut writer, self.directory_checkpoint_digest.as_bytes())?;
        write_field(&mut writer, self.signed_manifest_digest.as_bytes())?;
        write_field(&mut writer, &[self.classical.mode as u8])?;
        write_field(&mut writer, self.classical.signed_prekey_id.as_bytes())?;
        write_field(&mut writer, self.classical.selected_prekey_id.as_bytes())?;
        write_field(&mut writer, &[self.post_quantum.mode as u8])?;
        write_field(
            &mut writer,
            self.post_quantum.last_resort_prekey_id.as_bytes(),
        )?;
        write_field(&mut writer, self.post_quantum.selected_prekey_id.as_bytes())?;
        if !writer.is_empty() {
            return Err(PrekeySelectionCodecError::InvalidOutputLength);
        }
        Ok(out.len())
    }

    /// Decode and validate one exact record; non-canonical encodings fail closed.
    pub fn decode(encoded: &[u8]) -> Result<Self, PrekeySelectionCodecError> {
        let mut reader = LpReader::new(encoded);
        let domain = read_exact(&mut reader, PrekeySelectionField::Domain, 40)?;
        if domain != PREKEY_SELECTION_DOMAIN {
            return Err(PrekeySelectionCodecError::InvalidDomain);
        }
        let schema = parse_u16(read_exact(
            &mut reader,
            PrekeySelectionField::SchemaVersion,
            2,
        )?);
        if schema != PREKEY_SELECTION_SCHEMA_VERSION {
            return Err(PrekeySelectionCodecError::UnsupportedSchemaVersion(schema));
        }
        let suite_digest = SuiteDigest::from_bytes(parse_32(read_exact(
            &mut reader,
            PrekeySelectionField::SuiteDigest,
            32,
        )?));
        let responder_account_id = AccountId::from_bytes(parse_32(read_exact(
            &mut reader,
            PrekeySelectionField::ResponderAccountId,
            32,
        )?));
        let responder_device_id = DeviceId::from_bytes(parse_16(read_exact(
            &mut reader,
            PrekeySelectionField::ResponderDeviceId,
            16,
        )?));
        let responder_device_epoch = DeviceEpoch::new(parse_u64(read_exact(
            &mut reader,
            PrekeySelectionField::ResponderDeviceEpoch,
            8,
        )?));
        let responder_identity_credential_digest =
            IdentityCredentialDigest::from_bytes(parse_32(read_exact(
                &mut reader,
                PrekeySelectionField::ResponderIdentityCredentialDigest,
                32,
            )?));
        let bundle_epoch = PrekeyBundleEpoch::new(parse_u64(read_exact(
            &mut reader,
            PrekeySelectionField::BundleEpoch,
            8,
        )?));
        let directory_checkpoint_digest =
            DirectoryCheckpointDigest::from_bytes(parse_32(read_exact(
                &mut reader,
                PrekeySelectionField::DirectoryCheckpointDigest,
                32,
            )?));
        let signed_manifest_digest = SignedPrekeyManifestDigest::from_bytes(parse_32(read_exact(
            &mut reader,
            PrekeySelectionField::SignedManifestDigest,
            32,
        )?));
        let classical_mode = match parse_u8(
            read_exact(&mut reader, PrekeySelectionField::ClassicalMode, 1)?,
            PrekeySelectionField::ClassicalMode,
        )? {
            1 => ClassicalPrekeyMode::OneTime,
            2 => ClassicalPrekeyMode::SignedOnly,
            value => return Err(PrekeySelectionCodecError::UnknownClassicalMode(value)),
        };
        let classical_signed_prekey_id = PrekeyId::from_bytes(parse_32(read_exact(
            &mut reader,
            PrekeySelectionField::ClassicalSignedPrekeyId,
            32,
        )?));
        let classical_selected_prekey_id = PrekeyId::from_bytes(parse_32(read_exact(
            &mut reader,
            PrekeySelectionField::ClassicalSelectedPrekeyId,
            32,
        )?));
        let post_quantum_mode = match parse_u8(
            read_exact(&mut reader, PrekeySelectionField::PostQuantumMode, 1)?,
            PrekeySelectionField::PostQuantumMode,
        )? {
            1 => PostQuantumPrekeyMode::OneTime,
            2 => PostQuantumPrekeyMode::LastResort,
            value => return Err(PrekeySelectionCodecError::UnknownPostQuantumMode(value)),
        };
        let post_quantum_last_resort_prekey_id = PrekeyId::from_bytes(parse_32(read_exact(
            &mut reader,
            PrekeySelectionField::PostQuantumLastResortPrekeyId,
            32,
        )?));
        let post_quantum_selected_prekey_id = PrekeyId::from_bytes(parse_32(read_exact(
            &mut reader,
            PrekeySelectionField::PostQuantumSelectedPrekeyId,
            32,
        )?));
        if !reader.is_empty() {
            return Err(PrekeySelectionCodecError::TrailingBytes);
        }
        let selection = Self {
            suite_digest,
            responder: PrekeyResponder::new(
                responder_account_id,
                responder_device_id,
                responder_device_epoch,
                responder_identity_credential_digest,
            ),
            bundle_epoch,
            directory_checkpoint_digest,
            signed_manifest_digest,
            classical: ClassicalPrekeySelection {
                mode: classical_mode,
                signed_prekey_id: classical_signed_prekey_id,
                selected_prekey_id: classical_selected_prekey_id,
            },
            post_quantum: PostQuantumPrekeySelection {
                mode: post_quantum_mode,
                last_resort_prekey_id: post_quantum_last_resort_prekey_id,
                selected_prekey_id: post_quantum_selected_prekey_id,
            },
        };
        selection
            .validate()
            .map_err(PrekeySelectionCodecError::InvalidSelection)?;
        Ok(selection)
    }

    /// Encode the complete domain-separated digest preimage atomically.
    pub fn encode_digest_preimage(
        self,
        out: &mut [u8],
    ) -> Result<usize, PrekeySelectionCodecError> {
        self.validate()
            .map_err(PrekeySelectionCodecError::InvalidSelection)?;
        if out.len() != PREKEY_SELECTION_DIGEST_PREIMAGE_LEN {
            return Err(PrekeySelectionCodecError::InvalidOutputLength);
        }
        let mut record = [0u8; PREKEY_SELECTION_ENCODED_LEN];
        self.encode(&mut record)?;
        let mut writer = LpWriter::new(out);
        write_field(&mut writer, PREKEY_SELECTION_DIGEST_DOMAIN)?;
        write_field(&mut writer, &record)?;
        if !writer.is_empty() {
            return Err(PrekeySelectionCodecError::InvalidOutputLength);
        }
        Ok(out.len())
    }

    /// Derive an indivisible canonical selection through an explicit digest adapter.
    pub fn derive_with<E, F>(
        self,
        derive: F,
    ) -> Result<CanonicalPrekeySelection, PrekeySelectionDigestError<E>>
    where
        F: FnOnce(&[u8]) -> Result<[u8; 32], E>,
    {
        let mut preimage = [0u8; PREKEY_SELECTION_DIGEST_PREIMAGE_LEN];
        self.encode_digest_preimage(&mut preimage)
            .map_err(PrekeySelectionDigestError::Encoding)?;
        let digest = derive(&preimage).map_err(PrekeySelectionDigestError::Backend)?;
        if all_zero(&digest) {
            return Err(PrekeySelectionDigestError::ZeroDigest);
        }
        Ok(CanonicalPrekeySelection {
            record: self,
            digest: PrekeySelectionDigest(digest),
        })
    }
}

/// A complete validated record and the digest derived from its exact bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalPrekeySelection {
    record: PrekeySelectionV1,
    digest: PrekeySelectionDigest,
}

impl CanonicalPrekeySelection {
    #[must_use]
    /// Return the complete canonical record.
    pub const fn record(self) -> PrekeySelectionV1 {
        self.record
    }

    #[must_use]
    /// Return the adapter-derived digest of the complete record.
    pub const fn digest(self) -> PrekeySelectionDigest {
        self.digest
    }

    #[must_use]
    /// Return the lossless two-leg quality projection.
    pub const fn quality(self) -> PrekeyQuality {
        self.record.quality()
    }

    #[must_use]
    /// Return the manifest commitment embedded in the record.
    pub const fn signed_manifest_digest(self) -> SignedPrekeyManifestDigest {
        self.record.signed_manifest_digest
    }
}

/// Reduced Lifecycle projection derived from one canonical selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrekeyContext {
    quality: PrekeyQuality,
    signed_manifest_digest: SignedPrekeyManifestDigest,
    selection_digest: PrekeySelectionDigest,
}

impl PrekeyContext {
    pub(crate) const fn from_canonical(selection: CanonicalPrekeySelection) -> Self {
        Self {
            quality: selection.quality(),
            signed_manifest_digest: selection.signed_manifest_digest(),
            selection_digest: selection.digest(),
        }
    }

    pub(crate) const fn quality(self) -> PrekeyQuality {
        self.quality
    }

    pub(crate) const fn signed_manifest_digest(self) -> SignedPrekeyManifestDigest {
        self.signed_manifest_digest
    }

    pub(crate) const fn selection_digest(self) -> PrekeySelectionDigest {
        self.selection_digest
    }
}

fn write_field(writer: &mut LpWriter<'_>, value: &[u8]) -> Result<(), PrekeySelectionCodecError> {
    writer
        .field(value)
        .map_err(|_| PrekeySelectionCodecError::InvalidOutputLength)
}

fn read_exact<'a>(
    reader: &mut LpReader<'a>,
    field: PrekeySelectionField,
    expected: usize,
) -> Result<&'a [u8], PrekeySelectionCodecError> {
    let value = reader.field().map_err(|error| match error {
        CodecError::LengthOverflow => PrekeySelectionCodecError::LengthOutOfRange(field),
        CodecError::TruncatedLength | CodecError::TruncatedValue => {
            PrekeySelectionCodecError::TruncatedField(field)
        }
        CodecError::OutputTooShort => PrekeySelectionCodecError::TruncatedField(field),
    })?;
    if value.len() != expected {
        return Err(PrekeySelectionCodecError::InvalidFieldLength {
            field,
            expected,
            actual: value.len(),
        });
    }
    Ok(value)
}

fn parse_16(value: &[u8]) -> [u8; 16] {
    let mut parsed = [0u8; 16];
    parsed.copy_from_slice(value);
    parsed
}

fn parse_32(value: &[u8]) -> [u8; 32] {
    let mut parsed = [0u8; 32];
    parsed.copy_from_slice(value);
    parsed
}

fn parse_u16(value: &[u8]) -> u16 {
    let mut parsed = [0u8; 2];
    parsed.copy_from_slice(value);
    u16::from_be_bytes(parsed)
}

fn parse_u8(value: &[u8], field: PrekeySelectionField) -> Result<u8, PrekeySelectionCodecError> {
    value
        .first()
        .copied()
        .ok_or(PrekeySelectionCodecError::InvalidFieldLength {
            field,
            expected: 1,
            actual: value.len(),
        })
}

fn parse_u64(value: &[u8]) -> u64 {
    let mut parsed = [0u8; 8];
    parsed.copy_from_slice(value);
    u64::from_be_bytes(parsed)
}

fn validate_monotonic(value: u64, field: PrekeySelectionField) -> Result<(), PrekeySelectionError> {
    if value == 0 || value == u64::MAX {
        Err(PrekeySelectionError::InvalidMonotonicValue(field))
    } else {
        Ok(())
    }
}

fn require_nonzero(value: &[u8], field: PrekeySelectionField) -> Result<(), PrekeySelectionError> {
    if all_zero(value) {
        Err(PrekeySelectionError::ZeroField(field))
    } else {
        Ok(())
    }
}

fn all_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
