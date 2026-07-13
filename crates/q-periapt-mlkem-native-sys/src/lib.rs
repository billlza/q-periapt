// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! Safe, allocation-free Rust boundary for the portable `mlkem-native` C
//! implementation.
//!
//! All public operations use exact-size arrays and caller-owned output
//! buffers. Outputs are zero before entering C and are zeroed again whenever
//! an operation fails. The only raw FFI and `unsafe` code is confined to the
//! private `raw` module.

use core::fmt;

#[allow(unsafe_code)]
mod raw;

/// Length in bytes of deterministic ML-KEM key-generation input (`d || z`).
pub const KEY_GENERATION_SEED_LEN: usize = 64;

/// Length in bytes of deterministic ML-KEM encapsulation randomness.
pub const ENCAPSULATION_SEED_LEN: usize = 32;

/// Length in bytes of an ML-KEM shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

const MLK_ERR_FAIL: i32 = -1;
const MLK_ERR_OUT_OF_MEMORY: i32 = -2;

/// Failure reported by the safe ML-KEM boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Two shared C inputs overlap, violating the upstream no-alias contract.
    Aliasing,
    /// The public key is not a canonical FIPS 203 encoding.
    InvalidPublicKey,
    /// The expanded decapsulation key fails its embedded-key or hash check.
    InvalidDecapsulationKey,
    /// Deterministic key generation reported its generic failure status.
    KeyGenerationFailed,
    /// The configured C implementation reported an allocation failure.
    OutOfMemory,
    /// The C bridge returned a status not documented for the called API.
    UnexpectedStatus(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aliasing => formatter.write_str("ML-KEM inputs overlap"),
            Self::InvalidPublicKey => formatter.write_str("invalid ML-KEM public key"),
            Self::InvalidDecapsulationKey => {
                formatter.write_str("invalid ML-KEM decapsulation key")
            }
            Self::KeyGenerationFailed => formatter.write_str("ML-KEM key generation failed"),
            Self::OutOfMemory => formatter.write_str("ML-KEM backend ran out of memory"),
            Self::UnexpectedStatus(status) => {
                write!(
                    formatter,
                    "ML-KEM backend returned unexpected status {status}"
                )
            }
        }
    }
}

fn map_call(result: raw::CallResult) -> Result<(), Error> {
    use raw::{CallResult, Operation};

    let (operation, status) = match result {
        CallResult::Aliasing => return Err(Error::Aliasing),
        CallResult::Status(operation, status) => (operation, status),
    };
    match status {
        0 => Ok(()),
        MLK_ERR_OUT_OF_MEMORY => Err(Error::OutOfMemory),
        MLK_ERR_FAIL => match operation {
            Operation::Keypair => Err(Error::KeyGenerationFailed),
            Operation::Encapsulate => Err(Error::InvalidPublicKey),
            Operation::CheckEmbeddedPublicKey | Operation::Decapsulate => {
                Err(Error::InvalidDecapsulationKey)
            }
        },
        unexpected => Err(Error::UnexpectedStatus(unexpected)),
    }
}

macro_rules! define_parameter_set {
    (
        $(#[$type_meta:meta])*
        $type_name:ident,
        public_key_len = $public_key_len:literal,
        decapsulation_key_len = $decapsulation_key_len:literal,
        ciphertext_len = $ciphertext_len:literal,
        keypair = $keypair:path,
        encapsulate = $encapsulate:path,
        decapsulate = $decapsulate:path
    ) => {
        $(#[$type_meta])*
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $type_name;

        impl $type_name {
            /// Public-key length in bytes.
            pub const PUBLIC_KEY_LEN: usize = $public_key_len;

            /// Expanded decapsulation-key length in bytes.
            pub const DECAPSULATION_KEY_LEN: usize = $decapsulation_key_len;

            /// Ciphertext length in bytes.
            pub const CIPHERTEXT_LEN: usize = $ciphertext_len;

            /// Deterministically generates an ML-KEM key pair from `d || z`.
            ///
            /// Both outputs are zeroed before the C call and after every
            /// failure. They contain a complete key pair only on success.
            pub fn keypair_derand(
                seed: &[u8; KEY_GENERATION_SEED_LEN],
                public_key_out: &mut [u8; $public_key_len],
                decapsulation_key_out: &mut [u8; $decapsulation_key_len],
            ) -> Result<(), Error> {
                public_key_out.fill(0);
                decapsulation_key_out.fill(0);
                let result = map_call($keypair(seed, public_key_out, decapsulation_key_out));
                if result.is_err() {
                    public_key_out.fill(0);
                    decapsulation_key_out.fill(0);
                }
                result
            }

            /// Deterministically encapsulates to a canonical public key.
            ///
            /// `public_key` and `seed` must not overlap. Both outputs are zero
            /// before the C call and after every failure.
            pub fn encapsulate_derand(
                public_key: &[u8; $public_key_len],
                seed: &[u8; ENCAPSULATION_SEED_LEN],
                ciphertext_out: &mut [u8; $ciphertext_len],
                shared_secret_out: &mut [u8; SHARED_SECRET_LEN],
            ) -> Result<(), Error> {
                ciphertext_out.fill(0);
                shared_secret_out.fill(0);
                let result = map_call($encapsulate(
                    public_key,
                    seed,
                    ciphertext_out,
                    shared_secret_out,
                ));
                if result.is_err() {
                    ciphertext_out.fill(0);
                    shared_secret_out.fill(0);
                }
                result
            }

            /// Decapsulates a ciphertext with a strict expanded key.
            ///
            /// This rejects a non-canonical embedded public key before the C
            /// decapsulation call; upstream `dec` then verifies `H(EK)` before
            /// computing the shared secret. An invalid ciphertext is not an
            /// error: FIPS 203 implicit rejection returns its deterministic
            /// rejection secret. The two shared inputs must not overlap.
            pub fn decapsulate(
                decapsulation_key: &[u8; $decapsulation_key_len],
                ciphertext: &[u8; $ciphertext_len],
                shared_secret_out: &mut [u8; SHARED_SECRET_LEN],
            ) -> Result<(), Error> {
                shared_secret_out.fill(0);
                let result = map_call($decapsulate(
                    decapsulation_key,
                    ciphertext,
                    shared_secret_out,
                ));
                if result.is_err() {
                    shared_secret_out.fill(0);
                }
                result
            }
        }
    };
}

define_parameter_set!(
    /// ML-KEM-512 portable backend.
    MlKem512,
    public_key_len = 800,
    decapsulation_key_len = 1632,
    ciphertext_len = 768,
    keypair = raw::mlkem512_keypair_derand,
    encapsulate = raw::mlkem512_encapsulate_derand,
    decapsulate = raw::mlkem512_decapsulate
);

define_parameter_set!(
    /// ML-KEM-768 portable backend.
    MlKem768,
    public_key_len = 1184,
    decapsulation_key_len = 2400,
    ciphertext_len = 1088,
    keypair = raw::mlkem768_keypair_derand,
    encapsulate = raw::mlkem768_encapsulate_derand,
    decapsulate = raw::mlkem768_decapsulate
);

define_parameter_set!(
    /// ML-KEM-1024 portable backend.
    MlKem1024,
    public_key_len = 1568,
    decapsulation_key_len = 3168,
    ciphertext_len = 1568,
    keypair = raw::mlkem1024_keypair_derand,
    encapsulate = raw::mlkem1024_encapsulate_derand,
    decapsulate = raw::mlkem1024_decapsulate
);

#[cfg(test)]
mod tests;
