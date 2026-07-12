//! Strict controls for the canonical two-leg prekey-selection record.

use q_periapt_continuity_model::{
    AccountId, ClassicalPrekeySelection, DeviceEpoch, DeviceId, DirectoryCheckpointDigest,
    IdentityCredentialDigest, PostQuantumPrekeySelection, PrekeyBundleEpoch, PrekeyId, PrekeyLeg,
    PrekeyQuality, PrekeyResponder, PrekeySelectionCodecError, PrekeySelectionDigestError,
    PrekeySelectionError, PrekeySelectionField, PrekeySelectionV1, SignedPrekeyManifestDigest,
    SuiteDigest, PREKEY_SELECTION_DIGEST_DOMAIN, PREKEY_SELECTION_DIGEST_PREIMAGE_LEN,
    PREKEY_SELECTION_DOMAIN, PREKEY_SELECTION_ENCODED_LEN, PREKEY_SELECTION_SCHEMA_VERSION,
};

fn bytes<const N: usize>(tag: u8) -> [u8; N] {
    [tag; N]
}

fn legs(quality: PrekeyQuality) -> (ClassicalPrekeySelection, PostQuantumPrekeySelection) {
    let classical = match quality {
        PrekeyQuality::BothOneTime | PrekeyQuality::ClassicalOneTimePqLastResort => {
            ClassicalPrekeySelection::one_time(
                PrekeyId::from_bytes(bytes(11)),
                PrekeyId::from_bytes(bytes(12)),
            )
            .expect("valid classical OPK")
        }
        PrekeyQuality::ClassicalSignedOnlyPqLastResort
        | PrekeyQuality::ClassicalSignedOnlyPqOneTime => {
            ClassicalPrekeySelection::signed_only(PrekeyId::from_bytes(bytes(11)))
                .expect("valid classical SPK")
        }
    };
    let post_quantum = match quality {
        PrekeyQuality::BothOneTime | PrekeyQuality::ClassicalSignedOnlyPqOneTime => {
            PostQuantumPrekeySelection::one_time(
                PrekeyId::from_bytes(bytes(13)),
                PrekeyId::from_bytes(bytes(14)),
            )
            .expect("valid PQ OPK")
        }
        PrekeyQuality::ClassicalSignedOnlyPqLastResort
        | PrekeyQuality::ClassicalOneTimePqLastResort => {
            PostQuantumPrekeySelection::last_resort(PrekeyId::from_bytes(bytes(13)))
                .expect("valid PQ last-resort key")
        }
    };
    (classical, post_quantum)
}

fn selection(quality: PrekeyQuality) -> PrekeySelectionV1 {
    let (classical, post_quantum) = legs(quality);
    PrekeySelectionV1::new(
        SuiteDigest::from_bytes(bytes(1)),
        PrekeyResponder::new(
            AccountId::from_bytes(bytes(2)),
            DeviceId::from_bytes(bytes(3)),
            DeviceEpoch::new(4),
            IdentityCredentialDigest::from_bytes(bytes(5)),
        ),
        PrekeyBundleEpoch::new(6),
        DirectoryCheckpointDigest::from_bytes(bytes(7)),
        SignedPrekeyManifestDigest::from_bytes(bytes(8)),
        classical,
        post_quantum,
    )
    .expect("valid selection")
}

fn encode(value: PrekeySelectionV1) -> Vec<u8> {
    let mut encoded = vec![0u8; PREKEY_SELECTION_ENCODED_LEN];
    assert_eq!(value.encode(&mut encoded), Ok(encoded.len()));
    encoded
}

fn digest_preimage(value: PrekeySelectionV1) -> Vec<u8> {
    let mut encoded = vec![0u8; PREKEY_SELECTION_DIGEST_PREIMAGE_LEN];
    assert_eq!(
        value.encode_digest_preimage(&mut encoded),
        Ok(encoded.len())
    );
    encoded
}

fn lp_fields_with_offsets(encoded: &[u8]) -> Vec<(usize, &[u8])> {
    let mut fields = Vec::new();
    let mut offset = 0usize;
    while offset < encoded.len() {
        let prefix_end = offset.checked_add(8).expect("test prefix offset");
        let prefix: [u8; 8] = encoded
            .get(offset..prefix_end)
            .expect("complete test prefix")
            .try_into()
            .expect("complete test prefix");
        let length = usize::try_from(u64::from_be_bytes(prefix)).expect("test length");
        let value_start = prefix_end;
        let value_end = value_start.checked_add(length).expect("test field end");
        fields.push((
            offset,
            encoded
                .get(value_start..value_end)
                .expect("complete test field"),
        ));
        offset = value_end;
    }
    fields
}

fn field_at<'a>(fields: &[(usize, &'a [u8])], index: usize) -> (usize, &'a [u8]) {
    fields.get(index).copied().expect("named test field")
}

fn field_byte(fields: &[(usize, &[u8])], field_index: usize) -> u8 {
    field_at(fields, field_index)
        .1
        .first()
        .copied()
        .expect("one-byte test field")
}

fn replace_field(encoded: &mut [u8], field_index: usize, value: &[u8]) {
    let fields = lp_fields_with_offsets(encoded);
    let (prefix_offset, prior) = field_at(&fields, field_index);
    assert_eq!(prior.len(), value.len());
    let value_offset = prefix_offset.checked_add(8).expect("test value offset");
    let value_end = value_offset
        .checked_add(value.len())
        .expect("test value end");
    encoded
        .get_mut(value_offset..value_end)
        .expect("complete mutable test field")
        .copy_from_slice(value);
}

#[test]
fn record_has_exact_sixteen_fields_domains_lengths_and_big_endian_epochs() {
    let value = selection(PrekeyQuality::BothOneTime);
    assert_eq!(value.encoded_len(), 492);
    assert_eq!(value.digest_preimage_len(), 555);
    assert_eq!(PREKEY_SELECTION_DOMAIN.len(), 40);
    assert_eq!(PREKEY_SELECTION_DIGEST_DOMAIN.len(), 47);

    let encoded = encode(value);
    let fields = lp_fields_with_offsets(&encoded);
    assert_eq!(fields.len(), 16);
    let expected_lengths = [40, 2, 32, 32, 16, 8, 32, 8, 32, 32, 1, 32, 32, 1, 32, 32];
    assert_eq!(
        fields
            .iter()
            .map(|(_, field)| field.len())
            .collect::<Vec<_>>(),
        expected_lengths
    );
    assert_eq!(field_at(&fields, 0).1, PREKEY_SELECTION_DOMAIN);
    assert_eq!(
        field_at(&fields, 1).1,
        PREKEY_SELECTION_SCHEMA_VERSION.to_be_bytes().as_slice()
    );
    assert_eq!(field_at(&fields, 5).1, 4u64.to_be_bytes().as_slice());
    assert_eq!(field_at(&fields, 7).1, 6u64.to_be_bytes().as_slice());

    let preimage = digest_preimage(value);
    let outer = lp_fields_with_offsets(&preimage);
    assert_eq!(outer.len(), 2);
    assert_eq!(field_at(&outer, 0).1, PREKEY_SELECTION_DIGEST_DOMAIN);
    assert_eq!(field_at(&outer, 1).1, encoded);
}

#[test]
fn all_four_prekey_quadrants_have_stable_distinct_quality_codes() {
    for (quality, expected) in [
        (PrekeyQuality::BothOneTime, 1u8),
        (PrekeyQuality::ClassicalSignedOnlyPqLastResort, 2),
        (PrekeyQuality::ClassicalSignedOnlyPqOneTime, 3),
        (PrekeyQuality::ClassicalOneTimePqLastResort, 4),
    ] {
        let value = selection(quality);
        assert_eq!(value.quality() as u8, expected);
        let encoded = encode(value);
        let fields = lp_fields_with_offsets(&encoded);
        assert_eq!(
            field_byte(&fields, 10),
            if matches!(expected, 1 | 4) { 1 } else { 2 }
        );
        assert_eq!(
            field_byte(&fields, 13),
            if matches!(expected, 1 | 3) { 1 } else { 2 }
        );
    }
}

#[test]
fn leg_mode_identifier_and_monotonic_rules_fail_closed() {
    let zero = PrekeyId::from_bytes([0u8; 32]);
    let signed = PrekeyId::from_bytes(bytes(11));
    assert_eq!(
        ClassicalPrekeySelection::one_time(signed, signed),
        Err(PrekeySelectionError::InvalidModeKeyRelation(
            PrekeyLeg::Classical
        ))
    );
    assert_eq!(
        PostQuantumPrekeySelection::one_time(signed, signed),
        Err(PrekeySelectionError::InvalidModeKeyRelation(
            PrekeyLeg::PostQuantum
        ))
    );
    assert_eq!(
        ClassicalPrekeySelection::signed_only(zero),
        Err(PrekeySelectionError::ZeroField(
            PrekeySelectionField::ClassicalSignedPrekeyId
        ))
    );
    assert_eq!(
        PostQuantumPrekeySelection::last_resort(zero),
        Err(PrekeySelectionError::ZeroField(
            PrekeySelectionField::PostQuantumLastResortPrekeyId
        ))
    );

    let (classical, post_quantum) = legs(PrekeyQuality::BothOneTime);
    for (device_epoch, bundle_epoch, expected_field) in [
        (0, 6, PrekeySelectionField::ResponderDeviceEpoch),
        (u64::MAX, 6, PrekeySelectionField::ResponderDeviceEpoch),
        (4, 0, PrekeySelectionField::BundleEpoch),
        (4, u64::MAX, PrekeySelectionField::BundleEpoch),
    ] {
        assert_eq!(
            PrekeySelectionV1::new(
                SuiteDigest::from_bytes(bytes(1)),
                PrekeyResponder::new(
                    AccountId::from_bytes(bytes(2)),
                    DeviceId::from_bytes(bytes(3)),
                    DeviceEpoch::new(device_epoch),
                    IdentityCredentialDigest::from_bytes(bytes(5)),
                ),
                PrekeyBundleEpoch::new(bundle_epoch),
                DirectoryCheckpointDigest::from_bytes(bytes(7)),
                SignedPrekeyManifestDigest::from_bytes(bytes(8)),
                classical,
                post_quantum,
            ),
            Err(PrekeySelectionError::InvalidMonotonicValue(expected_field))
        );
    }
    for epoch in [1, u64::MAX - 1] {
        assert!(PrekeySelectionV1::new(
            SuiteDigest::from_bytes(bytes(1)),
            PrekeyResponder::new(
                AccountId::from_bytes(bytes(2)),
                DeviceId::from_bytes(bytes(3)),
                DeviceEpoch::new(epoch),
                IdentityCredentialDigest::from_bytes(bytes(5)),
            ),
            PrekeyBundleEpoch::new(epoch),
            DirectoryCheckpointDigest::from_bytes(bytes(7)),
            SignedPrekeyManifestDigest::from_bytes(bytes(8)),
            classical,
            post_quantum,
        )
        .is_ok());
    }
}

#[test]
fn encode_decode_roundtrip_is_byte_exact_for_all_quadrants() {
    for quality in [
        PrekeyQuality::BothOneTime,
        PrekeyQuality::ClassicalSignedOnlyPqLastResort,
        PrekeyQuality::ClassicalSignedOnlyPqOneTime,
        PrekeyQuality::ClassicalOneTimePqLastResort,
    ] {
        let original = selection(quality);
        let encoded = encode(original);
        let decoded = PrekeySelectionV1::decode(&encoded).expect("canonical record");
        assert_eq!(decoded, original);
        assert_eq!(encode(decoded), encoded);
    }
}

#[test]
fn strict_decoder_rejects_truncation_trailing_and_noncanonical_lp8() {
    let canonical = encode(selection(PrekeyQuality::BothOneTime));
    for length in 0..canonical.len() {
        assert!(PrekeySelectionV1::decode(
            canonical.get(..length).expect("test truncation prefix")
        )
        .is_err());
    }
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        PrekeySelectionV1::decode(&trailing),
        Err(PrekeySelectionCodecError::TrailingBytes)
    );

    let field_offsets = lp_fields_with_offsets(&canonical)
        .iter()
        .map(|(offset, _)| *offset)
        .collect::<Vec<_>>();
    for (index, offset) in field_offsets.iter().copied().enumerate() {
        let mut huge = canonical.clone();
        let prefix_end = offset.checked_add(8).expect("test prefix end");
        huge.get_mut(offset..prefix_end)
            .expect("mutable test prefix")
            .copy_from_slice(&u64::MAX.to_be_bytes());
        let expected_field = [
            PrekeySelectionField::Domain,
            PrekeySelectionField::SchemaVersion,
            PrekeySelectionField::SuiteDigest,
            PrekeySelectionField::ResponderAccountId,
            PrekeySelectionField::ResponderDeviceId,
            PrekeySelectionField::ResponderDeviceEpoch,
            PrekeySelectionField::ResponderIdentityCredentialDigest,
            PrekeySelectionField::BundleEpoch,
            PrekeySelectionField::DirectoryCheckpointDigest,
            PrekeySelectionField::SignedManifestDigest,
            PrekeySelectionField::ClassicalMode,
            PrekeySelectionField::ClassicalSignedPrekeyId,
            PrekeySelectionField::ClassicalSelectedPrekeyId,
            PrekeySelectionField::PostQuantumMode,
            PrekeySelectionField::PostQuantumLastResortPrekeyId,
            PrekeySelectionField::PostQuantumSelectedPrekeyId,
        ]
        .get(index)
        .copied()
        .expect("named field index");
        assert_eq!(
            PrekeySelectionV1::decode(&huge),
            Err(PrekeySelectionCodecError::LengthOutOfRange(expected_field))
        );

        let canonical_fields = lp_fields_with_offsets(&canonical);
        let canonical_length = field_at(&canonical_fields, index).1.len();
        for adjusted_length in [canonical_length - 1, canonical_length + 1] {
            let mut noncanonical = canonical.clone();
            let adjusted_length = u64::try_from(adjusted_length).expect("test length fits u64");
            noncanonical
                .get_mut(offset..prefix_end)
                .expect("mutable noncanonical test prefix")
                .copy_from_slice(&adjusted_length.to_be_bytes());
            assert!(PrekeySelectionV1::decode(&noncanonical).is_err());
        }
    }

    let mut compensated = canonical.clone();
    let suite_offset = *field_offsets.get(2).expect("suite prefix offset");
    let account_offset = *field_offsets.get(3).expect("account prefix offset");
    compensated
        .get_mut(suite_offset..suite_offset + 8)
        .expect("mutable suite prefix")
        .copy_from_slice(&33u64.to_be_bytes());
    compensated
        .get_mut(account_offset..account_offset + 8)
        .expect("mutable account prefix")
        .copy_from_slice(&31u64.to_be_bytes());
    assert!(PrekeySelectionV1::decode(&compensated).is_err());
}

#[test]
fn strict_decoder_rejects_wrong_domain_schema_modes_zero_fields_and_relations() {
    let canonical = encode(selection(PrekeyQuality::BothOneTime));

    let mut wrong_domain = canonical.clone();
    replace_field(&mut wrong_domain, 0, &[b'X'; 40]);
    assert_eq!(
        PrekeySelectionV1::decode(&wrong_domain),
        Err(PrekeySelectionCodecError::InvalidDomain)
    );

    for version in [0u16, 2] {
        let mut wrong_schema = canonical.clone();
        replace_field(&mut wrong_schema, 1, &version.to_be_bytes());
        assert_eq!(
            PrekeySelectionV1::decode(&wrong_schema),
            Err(PrekeySelectionCodecError::UnsupportedSchemaVersion(version))
        );
    }
    for mode in [0u8, 3, 255] {
        let mut wrong_classical = canonical.clone();
        replace_field(&mut wrong_classical, 10, &[mode]);
        assert_eq!(
            PrekeySelectionV1::decode(&wrong_classical),
            Err(PrekeySelectionCodecError::UnknownClassicalMode(mode))
        );
        let mut wrong_pq = canonical.clone();
        replace_field(&mut wrong_pq, 13, &[mode]);
        assert_eq!(
            PrekeySelectionV1::decode(&wrong_pq),
            Err(PrekeySelectionCodecError::UnknownPostQuantumMode(mode))
        );
    }

    for (field_index, expected_field, length) in [
        (2, PrekeySelectionField::SuiteDigest, 32),
        (3, PrekeySelectionField::ResponderAccountId, 32),
        (4, PrekeySelectionField::ResponderDeviceId, 16),
        (
            6,
            PrekeySelectionField::ResponderIdentityCredentialDigest,
            32,
        ),
        (8, PrekeySelectionField::DirectoryCheckpointDigest, 32),
        (9, PrekeySelectionField::SignedManifestDigest, 32),
        (11, PrekeySelectionField::ClassicalSignedPrekeyId, 32),
        (12, PrekeySelectionField::ClassicalSelectedPrekeyId, 32),
        (14, PrekeySelectionField::PostQuantumLastResortPrekeyId, 32),
        (15, PrekeySelectionField::PostQuantumSelectedPrekeyId, 32),
    ] {
        let mut zero = canonical.clone();
        replace_field(&mut zero, field_index, &vec![0u8; length]);
        assert_eq!(
            PrekeySelectionV1::decode(&zero),
            Err(PrekeySelectionCodecError::InvalidSelection(
                PrekeySelectionError::ZeroField(expected_field)
            ))
        );
    }

    for (field_index, expected_field) in [
        (5, PrekeySelectionField::ResponderDeviceEpoch),
        (7, PrekeySelectionField::BundleEpoch),
    ] {
        for invalid in [0u64, u64::MAX] {
            let mut invalid_epoch = canonical.clone();
            replace_field(&mut invalid_epoch, field_index, &invalid.to_be_bytes());
            assert_eq!(
                PrekeySelectionV1::decode(&invalid_epoch),
                Err(PrekeySelectionCodecError::InvalidSelection(
                    PrekeySelectionError::InvalidMonotonicValue(expected_field)
                ))
            );
        }
    }

    let fields = lp_fields_with_offsets(&canonical);
    let classical_signed = field_at(&fields, 11).1.to_vec();
    let mut invalid_classical_relation = canonical.clone();
    replace_field(&mut invalid_classical_relation, 12, &classical_signed);
    assert_eq!(
        PrekeySelectionV1::decode(&invalid_classical_relation),
        Err(PrekeySelectionCodecError::InvalidSelection(
            PrekeySelectionError::InvalidModeKeyRelation(PrekeyLeg::Classical)
        ))
    );
    let pq_last_resort = field_at(&fields, 14).1.to_vec();
    let mut invalid_pq_relation = canonical;
    replace_field(&mut invalid_pq_relation, 15, &pq_last_resort);
    assert_eq!(
        PrekeySelectionV1::decode(&invalid_pq_relation),
        Err(PrekeySelectionCodecError::InvalidSelection(
            PrekeySelectionError::InvalidModeKeyRelation(PrekeyLeg::PostQuantum)
        ))
    );
}

#[test]
fn wrong_output_lengths_are_atomic_and_digest_adapter_is_explicit() {
    let value = selection(PrekeyQuality::BothOneTime);
    for length in [
        PREKEY_SELECTION_ENCODED_LEN - 1,
        PREKEY_SELECTION_ENCODED_LEN + 1,
    ] {
        let mut out = vec![0xA5; length];
        assert_eq!(
            value.encode(&mut out),
            Err(PrekeySelectionCodecError::InvalidOutputLength)
        );
        assert!(out.iter().all(|byte| *byte == 0xA5));
    }
    for length in [
        PREKEY_SELECTION_DIGEST_PREIMAGE_LEN - 1,
        PREKEY_SELECTION_DIGEST_PREIMAGE_LEN + 1,
    ] {
        let mut out = vec![0xA5; length];
        assert_eq!(
            value.encode_digest_preimage(&mut out),
            Err(PrekeySelectionCodecError::InvalidOutputLength)
        );
        assert!(out.iter().all(|byte| *byte == 0xA5));
    }

    let mut calls = 0u8;
    let canonical = value
        .derive_with(|preimage| {
            calls += 1;
            assert_eq!(preimage, digest_preimage(value));
            Ok::<_, ()>(bytes(21))
        })
        .expect("trusted test adapter");
    assert_eq!(calls, 1);
    assert_eq!(canonical.record(), value);
    assert_eq!(canonical.digest().as_bytes(), &bytes(21));
    assert_eq!(canonical.quality(), PrekeyQuality::BothOneTime);

    assert_eq!(
        value.derive_with(|_| Err::<[u8; 32], _>(7u8)),
        Err(PrekeySelectionDigestError::Backend(7))
    );
    assert_eq!(
        value.derive_with(|_| Ok::<_, ()>([0u8; 32])),
        Err(PrekeySelectionDigestError::ZeroDigest)
    );
}

#[test]
fn canonical_selection_is_send_sync_copy_and_deterministic() {
    fn assert_traits<T: Copy + Send + Sync>() {}
    assert_traits::<q_periapt_continuity_model::CanonicalPrekeySelection>();

    let value = selection(PrekeyQuality::ClassicalSignedOnlyPqOneTime);
    assert_eq!(encode(value), encode(value));
    assert_eq!(digest_preimage(value), digest_preimage(value));
}
