// SPDX-License-Identifier: Apache-2.0 OR MIT

use sha3::{Digest, Sha3_256};

use super::*;

const TEST_INVARIANT_STATUS: i32 = i32::MIN;

fn invariant<T>(value: Option<T>) -> Result<T, Error> {
    value.ok_or(Error::UnexpectedStatus(TEST_INVARIANT_STATUS))
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

macro_rules! parameter_set_test {
    (
        $test_name:ident,
        $type_name:ident,
        public_key_len = $public_key_len:literal,
        decapsulation_key_len = $decapsulation_key_len:literal,
        ciphertext_len = $ciphertext_len:literal,
        embedded_public_key_offset = $embedded_public_key_offset:literal
    ) => {
        #[test]
        fn $test_name() -> Result<(), Error> {
            assert_eq!($type_name::PUBLIC_KEY_LEN, $public_key_len);
            assert_eq!($type_name::DECAPSULATION_KEY_LEN, $decapsulation_key_len);
            assert_eq!($type_name::CIPHERTEXT_LEN, $ciphertext_len);

            let key_generation_seed = [0x42_u8; KEY_GENERATION_SEED_LEN];
            let mut public_key = [0xa5_u8; $public_key_len];
            let mut decapsulation_key = [0xa5_u8; $decapsulation_key_len];
            $type_name::keypair_derand(
                &key_generation_seed,
                &mut public_key,
                &mut decapsulation_key,
            )?;
            assert!(!all_zero(&public_key));
            assert!(!all_zero(&decapsulation_key));

            let mut repeated_public_key = [0_u8; $public_key_len];
            let mut repeated_decapsulation_key = [0_u8; $decapsulation_key_len];
            $type_name::keypair_derand(
                &key_generation_seed,
                &mut repeated_public_key,
                &mut repeated_decapsulation_key,
            )?;
            assert_eq!(repeated_public_key, public_key);
            assert_eq!(repeated_decapsulation_key, decapsulation_key);

            let encapsulation_seed = [0x24_u8; ENCAPSULATION_SEED_LEN];
            let mut ciphertext = [0xa5_u8; $ciphertext_len];
            let mut sender_secret = [0xa5_u8; SHARED_SECRET_LEN];
            $type_name::encapsulate_derand(
                &public_key,
                &encapsulation_seed,
                &mut ciphertext,
                &mut sender_secret,
            )?;
            assert!(!all_zero(&ciphertext));
            assert!(!all_zero(&sender_secret));

            let mut repeated_ciphertext = [0_u8; $ciphertext_len];
            let mut repeated_sender_secret = [0_u8; SHARED_SECRET_LEN];
            $type_name::encapsulate_derand(
                &public_key,
                &encapsulation_seed,
                &mut repeated_ciphertext,
                &mut repeated_sender_secret,
            )?;
            assert_eq!(repeated_ciphertext, ciphertext);
            assert_eq!(repeated_sender_secret, sender_secret);

            let mut recipient_secret = [0xa5_u8; SHARED_SECRET_LEN];
            $type_name::decapsulate(&decapsulation_key, &ciphertext, &mut recipient_secret)?;
            assert_eq!(recipient_secret, sender_secret);

            let mut invalid_public_key = public_key;
            invariant(invalid_public_key.get_mut(..3))?.fill(0xff);
            let mut failed_ciphertext = [0xa5_u8; $ciphertext_len];
            let mut failed_sender_secret = [0xa5_u8; SHARED_SECRET_LEN];
            assert_eq!(
                $type_name::encapsulate_derand(
                    &invalid_public_key,
                    &encapsulation_seed,
                    &mut failed_ciphertext,
                    &mut failed_sender_secret,
                ),
                Err(Error::InvalidPublicKey)
            );
            assert!(all_zero(&failed_ciphertext));
            assert!(all_zero(&failed_sender_secret));

            let mut invalid_hash_key = decapsulation_key;
            let hash_start = $decapsulation_key_len - 64;
            let invalid_hash_byte = invariant(invalid_hash_key.get_mut(hash_start))?;
            *invalid_hash_byte ^= 1;
            let mut failed_recipient_secret = [0xa5_u8; SHARED_SECRET_LEN];
            assert_eq!(
                $type_name::decapsulate(
                    &invalid_hash_key,
                    &ciphertext,
                    &mut failed_recipient_secret,
                ),
                Err(Error::InvalidDecapsulationKey)
            );
            assert!(all_zero(&failed_recipient_secret));

            // Recompute H(EK) after corrupting the embedded public key. This
            // makes the hash check pass and proves the separate modulus check
            // remains part of the strict expanded-key import path.
            let mut noncanonical_embedded_key = decapsulation_key;
            let embedded_public_key_end = $embedded_public_key_offset + $public_key_len;
            let recomputed_hash = {
                let embedded_public_key = invariant(
                    noncanonical_embedded_key
                        .get_mut($embedded_public_key_offset..embedded_public_key_end),
                )?;
                invariant(embedded_public_key.get_mut(..3))?.fill(0xff);
                Sha3_256::digest(embedded_public_key)
            };
            let stored_hash_end = hash_start + SHARED_SECRET_LEN;
            invariant(noncanonical_embedded_key.get_mut(hash_start..stored_hash_end))?
                .copy_from_slice(&recomputed_hash);
            failed_recipient_secret.fill(0xa5);
            assert_eq!(
                $type_name::decapsulate(
                    &noncanonical_embedded_key,
                    &ciphertext,
                    &mut failed_recipient_secret,
                ),
                Err(Error::InvalidDecapsulationKey)
            );
            assert!(all_zero(&failed_recipient_secret));

            // Shared references can overlap in safe Rust. The boundary must
            // reject that before entering a C function whose contract requires
            // all inputs to be disjoint.
            let overlapping_seed = invariant(public_key.first_chunk::<ENCAPSULATION_SEED_LEN>())?;
            failed_ciphertext.fill(0xa5);
            failed_sender_secret.fill(0xa5);
            assert_eq!(
                $type_name::encapsulate_derand(
                    &public_key,
                    overlapping_seed,
                    &mut failed_ciphertext,
                    &mut failed_sender_secret,
                ),
                Err(Error::Aliasing)
            );
            assert!(all_zero(&failed_ciphertext));
            assert!(all_zero(&failed_sender_secret));

            let overlapping_ciphertext =
                invariant(decapsulation_key.first_chunk::<$ciphertext_len>())?;
            failed_recipient_secret.fill(0xa5);
            assert_eq!(
                $type_name::decapsulate(
                    &decapsulation_key,
                    overlapping_ciphertext,
                    &mut failed_recipient_secret,
                ),
                Err(Error::Aliasing)
            );
            assert!(all_zero(&failed_recipient_secret));

            let mut invalid_ciphertext = ciphertext;
            let first_ciphertext_byte = invariant(invalid_ciphertext.first_mut())?;
            *first_ciphertext_byte ^= 1;
            let mut rejection_secret = [0xa5_u8; SHARED_SECRET_LEN];
            $type_name::decapsulate(
                &decapsulation_key,
                &invalid_ciphertext,
                &mut rejection_secret,
            )?;
            assert_ne!(rejection_secret, sender_secret);
            let mut repeated_rejection_secret = [0_u8; SHARED_SECRET_LEN];
            $type_name::decapsulate(
                &decapsulation_key,
                &invalid_ciphertext,
                &mut repeated_rejection_secret,
            )?;
            assert_eq!(repeated_rejection_secret, rejection_secret);

            Ok(())
        }
    };
}

parameter_set_test!(
    mlkem512_contract,
    MlKem512,
    public_key_len = 800,
    decapsulation_key_len = 1632,
    ciphertext_len = 768,
    embedded_public_key_offset = 768
);

parameter_set_test!(
    mlkem768_contract,
    MlKem768,
    public_key_len = 1184,
    decapsulation_key_len = 2400,
    ciphertext_len = 1088,
    embedded_public_key_offset = 1152
);

parameter_set_test!(
    mlkem1024_contract,
    MlKem1024,
    public_key_len = 1568,
    decapsulation_key_len = 3168,
    ciphertext_len = 1568,
    embedded_public_key_offset = 1536
);

#[test]
fn raw_status_codes_are_mapped_without_fallback() {
    use raw::{CallResult, Operation};

    assert_eq!(map_call(CallResult::Aliasing), Err(Error::Aliasing));
    assert_eq!(
        map_call(CallResult::Status(Operation::Keypair, MLK_ERR_FAIL)),
        Err(Error::KeyGenerationFailed)
    );
    assert_eq!(
        map_call(CallResult::Status(Operation::Encapsulate, MLK_ERR_FAIL)),
        Err(Error::InvalidPublicKey)
    );
    assert_eq!(
        map_call(CallResult::Status(
            Operation::CheckEmbeddedPublicKey,
            MLK_ERR_FAIL
        )),
        Err(Error::InvalidDecapsulationKey)
    );
    assert_eq!(
        map_call(CallResult::Status(Operation::Decapsulate, MLK_ERR_FAIL)),
        Err(Error::InvalidDecapsulationKey)
    );
    assert_eq!(
        map_call(CallResult::Status(
            Operation::Encapsulate,
            MLK_ERR_OUT_OF_MEMORY
        )),
        Err(Error::OutOfMemory)
    );
    assert_eq!(
        map_call(CallResult::Status(Operation::Decapsulate, -3)),
        Err(Error::UnexpectedStatus(-3))
    );
    assert_eq!(
        map_call(CallResult::Status(Operation::Keypair, 7)),
        Err(Error::UnexpectedStatus(7))
    );
}
