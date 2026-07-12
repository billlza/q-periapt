//! Emit deterministic PrekeySelectionV1 bytes for the independent Python oracle.

use q_periapt_continuity_model::{
    AccountId, ClassicalPrekeySelection, DeviceEpoch, DeviceId, DirectoryCheckpointDigest,
    IdentityCredentialDigest, PostQuantumPrekeySelection, PrekeyBundleEpoch, PrekeyId,
    PrekeyQuality, PrekeyResponder, PrekeySelectionV1, SignedPrekeyManifestDigest, SuiteDigest,
    PREKEY_SELECTION_DIGEST_PREIMAGE_LEN, PREKEY_SELECTION_ENCODED_LEN,
};

fn bytes<const N: usize>(tag: u8) -> [u8; N] {
    [tag; N]
}

fn selection(quality: PrekeyQuality) -> PrekeySelectionV1 {
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
    .expect("valid prekey selection")
}

fn print_hex(label: &str, value: &[u8]) {
    print!("{label}=");
    for byte in value {
        print!("{byte:02x}");
    }
    println!();
}

fn emit(name: &str, quality: PrekeyQuality) -> bool {
    let selection = selection(quality);
    let mut record = [0u8; PREKEY_SELECTION_ENCODED_LEN];
    let mut digest_preimage = [0u8; PREKEY_SELECTION_DIGEST_PREIMAGE_LEN];
    if selection.encode(&mut record).is_err()
        || selection
            .encode_digest_preimage(&mut digest_preimage)
            .is_err()
    {
        return false;
    }
    print_hex(&format!("{name}.record"), &record);
    print_hex(&format!("{name}.digest_preimage"), &digest_preimage);
    true
}

fn main() {
    let all_emitted = [
        ("both-one-time", PrekeyQuality::BothOneTime),
        (
            "classical-signed-only-pq-last-resort",
            PrekeyQuality::ClassicalSignedOnlyPqLastResort,
        ),
        (
            "classical-signed-only-pq-one-time",
            PrekeyQuality::ClassicalSignedOnlyPqOneTime,
        ),
        (
            "classical-one-time-pq-last-resort",
            PrekeyQuality::ClassicalOneTimePqLastResort,
        ),
    ]
    .into_iter()
    .all(|(name, quality)| emit(name, quality));
    if !all_emitted {
        std::process::exit(1);
    }
}
