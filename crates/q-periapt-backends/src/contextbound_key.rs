// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::*;

// FIPS-expanded ML-KEM-768: dk_PKE || ek || H(ek) || z. Keep the public
// field's position tied to the fixed native format, not a second cached copy.
const EMBEDDED_PUBLIC_KEY_OFFSET: usize = 1152;
const _: () = assert!(EMBEDDED_PUBLIC_KEY_OFFSET + ML_KEM_768_PK_LEN + 2 * 32 == ML_KEM_768_SK_LEN);

fn embedded_public_key(key: &[u8; ML_KEM_768_SK_LEN]) -> &[u8; ML_KEM_768_PK_LEN] {
    key.split_at(EMBEDDED_PUBLIC_KEY_OFFSET)
        .1
        .first_chunk()
        .expect("fixed expanded key includes its complete public field")
}

/// Generated or explicitly imported ContextBound ML-KEM-768 key, with stable,
/// zeroizing secret storage.
///
/// This owner is neither `Clone` nor serializable. Its paired public key comes
/// from key generation or a checked expanded import. Every decapsulation performs the native
/// expanded-key canonical-encoding and H(EK) checks. This does not make expanded
/// ML-KEM keys eligible for CompatXWing.
pub struct PreparedMlKem768Key {
    decapsulation_key: Box<ZeroizingBytes<ML_KEM_768_SK_LEN>>,
}

impl PreparedMlKem768Key {
    /// Public key paired with this owner, borrowed from its stable expanded-key
    /// storage. The public view cannot outlive the key owner.
    pub fn encapsulation_key(&self) -> &[u8; ML_KEM_768_PK_LEN] {
        embedded_public_key(self.decapsulation_key.as_bytes())
    }

    /// Explicit expert-only private-key copy. The caller owns and must erase
    /// the output; this is not a seed-derived X-Wing representation.
    pub fn export_expanded_for_expert(&self, output: &mut [u8; ML_KEM_768_SK_LEN]) {
        output.copy_from_slice(self.decapsulation_key.as_bytes());
    }
}

/// Failures of an explicit expanded-key import, distinct from ciphertext rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandedKeyImportError {
    /// Invalid embedded public-key encoding/hash, or failed pairwise consistency.
    InvalidKey,
    /// The native provider reported an allocation failure.
    ResourceLimit,
    /// An unexpected provider status or internal boundary failure occurred.
    Backend,
}

impl core::fmt::Display for ExpandedKeyImportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "invalid expanded key encoding or consistency",
            Self::ResourceLimit => "native key import allocation failed",
            Self::Backend => "native key import provider failure",
        })
    }
}
impl std::error::Error for ExpandedKeyImportError {}

fn import_error(error: NativeMlKemError) -> ExpandedKeyImportError {
    match error {
        NativeMlKemError::InvalidPublicKey | NativeMlKemError::InvalidDecapsulationKey => {
            ExpandedKeyImportError::InvalidKey
        }
        NativeMlKemError::OutOfMemory => ExpandedKeyImportError::ResourceLimit,
        NativeMlKemError::Aliasing
        | NativeMlKemError::KeyGenerationFailed
        | NativeMlKemError::UnexpectedStatus(_) => ExpandedKeyImportError::Backend,
    }
}

impl MlKem768 {
    /// Generate a ContextBound owner from borrowed deterministic keygen input.
    /// Product callers must obtain this input from their platform CSPRNG.
    pub fn prepare(seed: &[u8; ML_KEM_768_KEYGEN_SEED_LEN]) -> Result<PreparedMlKem768Key, Error> {
        let (decapsulation_key, encapsulation_key) = Self::generate_zeroizing(seed)?;
        // A provider inconsistency must fail instead of silently changing which
        // public key the owner publishes. Both compared values are public.
        if embedded_public_key(decapsulation_key.as_bytes()) != &encapsulation_key {
            return Err(Error::Backend);
        }
        Ok(PreparedMlKem768Key { decapsulation_key })
    }

    /// Import an expanded key with the FIPS 203 public-key/hash checks and a
    /// pairwise consistency test. `check_coins` must be fresh platform randomness
    /// for product use. No seed is supplied, so seed consistency cannot be checked.
    /// Passing these checks does not prove correct generation or sufficient entropy.
    /// Normal decapsulation continues to perform its native integrity checks.
    pub fn import_expanded_for_expert(
        decapsulation_key: Box<ZeroizingBytes<ML_KEM_768_SK_LEN>>,
        check_coins: &[u8; 32],
    ) -> Result<PreparedMlKem768Key, ExpandedKeyImportError> {
        let public = embedded_public_key(decapsulation_key.as_bytes());
        let mut ciphertext = ZeroizingBytes::<ML_KEM_768_CT_LEN>::zeroed();
        let mut expected = ZeroizingBytes::<32>::zeroed();
        let mut recovered = ZeroizingBytes::<32>::zeroed();
        NativeMlKem768::encapsulate_derand(
            public,
            check_coins,
            ciphertext.as_mut_bytes(),
            expected.as_mut_bytes(),
        )
        .map_err(import_error)?;
        NativeMlKem768::decapsulate(
            decapsulation_key.as_bytes(),
            ciphertext.as_bytes(),
            recovered.as_mut_bytes(),
        )
        .map_err(import_error)?;
        if q_periapt_core::ct_eq(expected.as_bytes(), recovered.as_bytes()) != 0xff {
            return Err(ExpandedKeyImportError::InvalidKey);
        }
        Ok(PreparedMlKem768Key { decapsulation_key })
    }
}

impl PreparedKem for MlKem768 {
    type PreparedKey = PreparedMlKem768Key;

    fn prepared_encapsulation_key<'a>(&self, key: &'a Self::PreparedKey) -> &'a [u8] {
        key.encapsulation_key()
    }

    fn decapsulate_prepared(
        &self,
        key: &Self::PreparedKey,
        ct: &[u8],
        ss: &mut [u8],
    ) -> Result<(), Error> {
        if ss.len() != SHARED_SECRET_LEN {
            return Err(Error::InvalidLength);
        }
        let ciphertext =
            <&[u8; ML_KEM_768_CT_LEN]>::try_from(ct).map_err(|_| Error::InvalidLength)?;
        let mut secret = ZeroizingBytes::<SHARED_SECRET_LEN>::zeroed();
        NativeMlKem768::decapsulate(
            key.decapsulation_key.as_bytes(),
            ciphertext,
            secret.as_mut_bytes(),
        )
        .map_err(map_mlkem_error)?;
        write_exact(ss, secret.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_and_imported_public_views_borrow_the_paired_expanded_field() {
        let seed = [7; 64];
        let (expanded, expected_public) = MlKem768::generate_zeroizing(&seed).expect("keygen");
        let generated = MlKem768::prepare(&seed).expect("prepared generation");
        let imported = MlKem768::import_expanded_for_expert(expanded, &[9; 32])
            .expect("checked expanded import");
        for key in [&generated, &imported] {
            assert_eq!(key.encapsulation_key(), &expected_public);
            assert_eq!(
                key.encapsulation_key().as_ptr(),
                key.decapsulation_key
                    .as_bytes()
                    .as_ptr()
                    .wrapping_add(EMBEDDED_PUBLIC_KEY_OFFSET),
                "public access must borrow the paired field instead of another owner allocation"
            );
        }
    }

    #[test]
    fn prepared_owner_keeps_both_native_import_checks_and_failure_atomicity() {
        for offset in [ML_KEM_768_SK_LEN - 64, 1152] {
            let mut key = MlKem768::prepare(&[7; 64]).expect("generated key");
            let changed = key
                .decapsulation_key
                .as_mut_bytes()
                .get_mut(offset..offset + 2)
                .expect("key range");
            // Corrupt H(EK), or force the embedded public key to a noncanonical coefficient.
            changed.fill(0xff);
            let mut output = [0xa5; 32];
            assert_eq!(
                MlKem768.decapsulate_prepared(&key, &[0; ML_KEM_768_CT_LEN], &mut output),
                Err(Error::Backend)
            );
            assert_eq!(output, [0xa5; 32]);
        }
    }
}
