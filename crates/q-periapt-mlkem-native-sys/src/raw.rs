// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::ffi::c_int;

use crate::{ENCAPSULATION_SEED_LEN, KEY_GENERATION_SEED_LEN, SHARED_SECRET_LEN};

#[cfg(any(qpn_mlkem_x86_dispatch, test))]
#[path = "x86_cpu.rs"]
mod x86_cpu;

#[cfg(qpn_mlkem_x86_dispatch)]
pub(super) fn avx2_available() -> bool {
    x86_cpu::available()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Operation {
    Keypair,
    Encapsulate,
    CheckEmbeddedPublicKey,
    Decapsulate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CallResult {
    Aliasing,
    Status(Operation, c_int),
}

fn ranges_overlap(first: &[u8], second: &[u8]) -> bool {
    let first_start = first.as_ptr() as usize;
    let second_start = second.as_ptr() as usize;
    let Some(first_end) = first_start.checked_add(first.len()) else {
        return true;
    };
    let Some(second_end) = second_start.checked_add(second.len()) else {
        return true;
    };
    first_start < second_end && second_start < first_end
}

macro_rules! define_raw_parameter_set {
    (
        keypair = ($keypair_ffi:ident, $keypair:ident, $keypair_symbol:literal),
        encapsulate = ($encapsulate_ffi:ident, $encapsulate:ident, $encapsulate_symbol:literal),
        decapsulate = ($decapsulate_ffi:ident, $decapsulate:ident, $decapsulate_symbol:literal),
        check_public_key = ($check_public_key_ffi:ident, $check_public_key_symbol:literal),
        avx2 = ($avx2_module:ident, $avx2_keypair_symbol:literal, $avx2_encapsulate_symbol:literal,
                $avx2_decapsulate_symbol:literal, $avx2_check_public_key_symbol:literal),
        public_key_len = $public_key_len:literal,
        decapsulation_key_len = $decapsulation_key_len:literal,
        ciphertext_len = $ciphertext_len:literal,
        embedded_public_key_offset = $embedded_public_key_offset:literal
    ) => {
        const _: () = assert!(
            $embedded_public_key_offset + $public_key_len <= $decapsulation_key_len,
            "embedded public key must fit in the decapsulation key"
        );

        unsafe extern "C" {
            #[link_name = $keypair_symbol]
            fn $keypair_ffi(
                public_key: *mut u8,
                decapsulation_key: *mut u8,
                seed: *const u8,
            ) -> c_int;
            #[link_name = $encapsulate_symbol]
            fn $encapsulate_ffi(
                ciphertext: *mut u8,
                shared_secret: *mut u8,
                public_key: *const u8,
                seed: *const u8,
            ) -> c_int;
            #[link_name = $decapsulate_symbol]
            fn $decapsulate_ffi(
                shared_secret: *mut u8,
                ciphertext: *const u8,
                decapsulation_key: *const u8,
            ) -> c_int;
            #[link_name = $check_public_key_symbol]
            fn $check_public_key_ffi(public_key: *const u8) -> c_int;
        }

        #[cfg(qpn_mlkem_x86_dispatch)]
        mod $avx2_module {
            use core::ffi::c_int;
            unsafe extern "C" {
                #[link_name = $avx2_keypair_symbol]
                pub(super) fn keypair(
                    public_key: *mut u8,
                    secret_key: *mut u8,
                    seed: *const u8,
                ) -> c_int;
                #[link_name = $avx2_encapsulate_symbol]
                pub(super) fn encapsulate(
                    ciphertext: *mut u8,
                    secret: *mut u8,
                    public_key: *const u8,
                    seed: *const u8,
                ) -> c_int;
                #[link_name = $avx2_decapsulate_symbol]
                pub(super) fn decapsulate(
                    secret: *mut u8,
                    ciphertext: *const u8,
                    secret_key: *const u8,
                ) -> c_int;
                #[link_name = $avx2_check_public_key_symbol]
                pub(super) fn check_public_key(public_key: *const u8) -> c_int;
            }

            #[cfg(test)]
            #[test]
            fn matches_portable_bytes_and_failures() -> Result<(), &'static str> {
                // This is a native qualification test, not a skipped success
                // on hardware that cannot exercise the candidate assembly.
                assert!(
                    super::avx2_available(),
                    "AVX2 differential qualification requires CPU and OS support"
                );
                for value in 0_u8..32 {
                    // Public deterministic test material, never application keys.
                    let seed = [value; 64];
                    let coins = [value.wrapping_add(99); 32];
                    let mut pk_portable = [0; $public_key_len];
                    let mut sk_portable = [0; $decapsulation_key_len];
                    let mut pk_native = [0; $public_key_len];
                    let mut sk_native = [0; $decapsulation_key_len];
                    // SAFETY: all buffers are distinct exact-size arrays and the
                    // candidate's CPU/OS precondition was checked above.
                    unsafe {
                        assert_eq!(
                            super::$keypair_ffi(
                                pk_portable.as_mut_ptr(),
                                sk_portable.as_mut_ptr(),
                                seed.as_ptr()
                            ),
                            0
                        );
                        assert_eq!(
                            keypair(
                                pk_native.as_mut_ptr(),
                                sk_native.as_mut_ptr(),
                                seed.as_ptr()
                            ),
                            0
                        );
                    }
                    assert_eq!(pk_portable, pk_native);
                    assert_eq!(sk_portable, sk_native);
                    let mut ct_portable = [0; $ciphertext_len];
                    let mut ct_native = [0; $ciphertext_len];
                    let mut ss_portable = [0; 32];
                    let mut ss_native = [0; 32];
                    // SAFETY: exact, initialized, disjoint inputs/outputs.
                    unsafe {
                        assert_eq!(
                            super::$encapsulate_ffi(
                                ct_portable.as_mut_ptr(),
                                ss_portable.as_mut_ptr(),
                                pk_portable.as_ptr(),
                                coins.as_ptr()
                            ),
                            0
                        );
                        assert_eq!(
                            encapsulate(
                                ct_native.as_mut_ptr(),
                                ss_native.as_mut_ptr(),
                                pk_native.as_ptr(),
                                coins.as_ptr()
                            ),
                            0
                        );
                    }
                    assert_eq!(ct_portable, ct_native);
                    assert_eq!(ss_portable, ss_native);
                    let mut recovered_portable = [0; 32];
                    let mut recovered_native = [0; 32];
                    // SAFETY: exact, initialized, disjoint inputs/outputs.
                    unsafe {
                        assert_eq!(
                            super::$decapsulate_ffi(
                                recovered_portable.as_mut_ptr(),
                                ct_portable.as_ptr(),
                                sk_portable.as_ptr()
                            ),
                            0
                        );
                        assert_eq!(
                            decapsulate(
                                recovered_native.as_mut_ptr(),
                                ct_native.as_ptr(),
                                sk_native.as_ptr()
                            ),
                            0
                        );
                    }
                    assert_eq!(recovered_portable, ss_portable);
                    assert_eq!(recovered_native, ss_portable);

                    *ct_native.first_mut().ok_or("ciphertext extent")? ^= 1;
                    // SAFETY: correct-length invalid ciphertexts are allowed and
                    // must produce the identical implicit-rejection secret.
                    unsafe {
                        assert_eq!(
                            super::$decapsulate_ffi(
                                recovered_portable.as_mut_ptr(),
                                ct_native.as_ptr(),
                                sk_portable.as_ptr()
                            ),
                            0
                        );
                        assert_eq!(
                            decapsulate(
                                recovered_native.as_mut_ptr(),
                                ct_native.as_ptr(),
                                sk_native.as_ptr()
                            ),
                            0
                        );
                    }
                    assert_eq!(recovered_portable, recovered_native);
                    assert_ne!(recovered_native, ss_native);

                    // Independently reject a noncanonical first 12-bit coefficient.
                    let mut bad_pk = pk_native;
                    for (index, byte) in bad_pk.iter_mut().take(2).enumerate() {
                        if index == 0 {
                            *byte = 0xff;
                        } else {
                            *byte |= 0x0f;
                        }
                    }
                    // SAFETY: fixed public-key extent, arbitrary encodings permitted.
                    unsafe {
                        assert_eq!(super::$check_public_key_ffi(bad_pk.as_ptr()), -1);
                        assert_eq!(check_public_key(bad_pk.as_ptr()), -1);
                    }
                    *sk_native
                        .get_mut($embedded_public_key_offset + $public_key_len)
                        .ok_or("embedded hash extent")? ^= 1;
                    // SAFETY: full expanded-key extent with deliberately invalid H(EK).
                    unsafe {
                        assert_eq!(
                            super::$decapsulate_ffi(
                                recovered_portable.as_mut_ptr(),
                                ct_portable.as_ptr(),
                                sk_native.as_ptr()
                            ),
                            -1
                        );
                        assert_eq!(
                            decapsulate(
                                recovered_native.as_mut_ptr(),
                                ct_portable.as_ptr(),
                                sk_native.as_ptr()
                            ),
                            -1
                        );
                    }
                }
                Ok(())
            }
        }

        pub(super) fn $keypair(
            seed: &[u8; KEY_GENERATION_SEED_LEN],
            public_key_out: &mut [u8; $public_key_len],
            decapsulation_key_out: &mut [u8; $decapsulation_key_len],
        ) -> CallResult {
            let function: unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> c_int = $keypair_ffi;
            #[cfg(qpn_mlkem_x86_dispatch)]
            let function = if avx2_available() {
                $avx2_module::keypair
            } else {
                function
            };
            // SAFETY: Exact array types establish all C buffer lengths. Rust's
            // shared/exclusive borrow rules establish that the seed and both
            // output buffers do not overlap and remain live for the call.
            let status = unsafe {
                function(
                    public_key_out.as_mut_ptr(),
                    decapsulation_key_out.as_mut_ptr(),
                    seed.as_ptr(),
                )
            };
            CallResult::Status(Operation::Keypair, status)
        }

        pub(super) fn $encapsulate(
            public_key: &[u8; $public_key_len],
            seed: &[u8; ENCAPSULATION_SEED_LEN],
            ciphertext_out: &mut [u8; $ciphertext_len],
            shared_secret_out: &mut [u8; SHARED_SECRET_LEN],
        ) -> CallResult {
            if ranges_overlap(public_key, seed) {
                return CallResult::Aliasing;
            }
            let function: unsafe extern "C" fn(*mut u8, *mut u8, *const u8, *const u8) -> c_int =
                $encapsulate_ffi;
            #[cfg(qpn_mlkem_x86_dispatch)]
            let function = if avx2_available() {
                $avx2_module::encapsulate
            } else {
                function
            };
            // SAFETY: Exact array types establish all buffer lengths and the
            // checked range test establishes that the two shared inputs do not
            // overlap. Rust's exclusive borrows establish every other no-alias
            // relation required by the upstream C contract.
            let status = unsafe {
                function(
                    ciphertext_out.as_mut_ptr(),
                    shared_secret_out.as_mut_ptr(),
                    public_key.as_ptr(),
                    seed.as_ptr(),
                )
            };
            CallResult::Status(Operation::Encapsulate, status)
        }

        pub(super) fn $decapsulate(
            decapsulation_key: &[u8; $decapsulation_key_len],
            ciphertext: &[u8; $ciphertext_len],
            shared_secret_out: &mut [u8; SHARED_SECRET_LEN],
        ) -> CallResult {
            if ranges_overlap(decapsulation_key, ciphertext) {
                return CallResult::Aliasing;
            }
            let check_public_key: unsafe extern "C" fn(*const u8) -> c_int = $check_public_key_ffi;
            let decapsulate: unsafe extern "C" fn(*mut u8, *const u8, *const u8) -> c_int =
                $decapsulate_ffi;
            #[cfg(qpn_mlkem_x86_dispatch)]
            let (check_public_key, decapsulate) = if avx2_available() {
                (
                    $avx2_module::check_public_key as unsafe extern "C" fn(*const u8) -> c_int,
                    $avx2_module::decapsulate
                        as unsafe extern "C" fn(*mut u8, *const u8, *const u8) -> c_int,
                )
            } else {
                (check_public_key, decapsulate)
            };

            // Give the public-key check a standalone object, matching the
            // upstream CBMC `memory_no_alias`/fresh-object precondition rather
            // than passing a subrange of the expanded key. This copies only
            // public material.
            let mut embedded_public_key = [0_u8; $public_key_len];
            for (destination, source) in embedded_public_key
                .iter_mut()
                .zip(decapsulation_key.iter().skip($embedded_public_key_offset))
            {
                *destination = *source;
            }
            // SAFETY: `embedded_public_key` is a distinct initialized array of
            // exactly the size required by the C check function.
            let public_key_status = unsafe { check_public_key(embedded_public_key.as_ptr()) };
            if public_key_status != 0 {
                return CallResult::Status(Operation::CheckEmbeddedPublicKey, public_key_status);
            }

            // SAFETY: Exact array types establish all buffer lengths. The
            // checked range test establishes that the two shared inputs do not
            // overlap; the exclusive output borrow establishes all remaining
            // no-alias relations. Upstream `dec` performs the mandatory H(EK)
            // check before decapsulation.
            let status = unsafe {
                decapsulate(
                    shared_secret_out.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    decapsulation_key.as_ptr(),
                )
            };
            CallResult::Status(Operation::Decapsulate, status)
        }
    };
}

define_raw_parameter_set!(
    keypair = (
        ffi_mlkem512_keypair_derand,
        mlkem512_keypair_derand,
        "qpn_mlkem_bridge_v1_2_0_512_keypair_derand"
    ),
    encapsulate = (
        ffi_mlkem512_encapsulate_derand,
        mlkem512_encapsulate_derand,
        "qpn_mlkem_bridge_v1_2_0_512_encapsulate_derand"
    ),
    decapsulate = (
        ffi_mlkem512_decapsulate,
        mlkem512_decapsulate,
        "qpn_mlkem_bridge_v1_2_0_512_decapsulate"
    ),
    check_public_key = (
        ffi_mlkem512_check_public_key,
        "qpn_mlkem_bridge_v1_2_0_512_check_public_key"
    ),
    avx2 = (
        avx2_512,
        "qpn_mlkem_bridge_v1_2_0_avx2_512_keypair_derand",
        "qpn_mlkem_bridge_v1_2_0_avx2_512_encapsulate_derand",
        "qpn_mlkem_bridge_v1_2_0_avx2_512_decapsulate",
        "qpn_mlkem_bridge_v1_2_0_avx2_512_check_public_key"
    ),
    public_key_len = 800,
    decapsulation_key_len = 1632,
    ciphertext_len = 768,
    embedded_public_key_offset = 768
);

define_raw_parameter_set!(
    keypair = (
        ffi_mlkem768_keypair_derand,
        mlkem768_keypair_derand,
        "qpn_mlkem_bridge_v1_2_0_768_keypair_derand"
    ),
    encapsulate = (
        ffi_mlkem768_encapsulate_derand,
        mlkem768_encapsulate_derand,
        "qpn_mlkem_bridge_v1_2_0_768_encapsulate_derand"
    ),
    decapsulate = (
        ffi_mlkem768_decapsulate,
        mlkem768_decapsulate,
        "qpn_mlkem_bridge_v1_2_0_768_decapsulate"
    ),
    check_public_key = (
        ffi_mlkem768_check_public_key,
        "qpn_mlkem_bridge_v1_2_0_768_check_public_key"
    ),
    avx2 = (
        avx2_768,
        "qpn_mlkem_bridge_v1_2_0_avx2_768_keypair_derand",
        "qpn_mlkem_bridge_v1_2_0_avx2_768_encapsulate_derand",
        "qpn_mlkem_bridge_v1_2_0_avx2_768_decapsulate",
        "qpn_mlkem_bridge_v1_2_0_avx2_768_check_public_key"
    ),
    public_key_len = 1184,
    decapsulation_key_len = 2400,
    ciphertext_len = 1088,
    embedded_public_key_offset = 1152
);

define_raw_parameter_set!(
    keypair = (
        ffi_mlkem1024_keypair_derand,
        mlkem1024_keypair_derand,
        "qpn_mlkem_bridge_v1_2_0_1024_keypair_derand"
    ),
    encapsulate = (
        ffi_mlkem1024_encapsulate_derand,
        mlkem1024_encapsulate_derand,
        "qpn_mlkem_bridge_v1_2_0_1024_encapsulate_derand"
    ),
    decapsulate = (
        ffi_mlkem1024_decapsulate,
        mlkem1024_decapsulate,
        "qpn_mlkem_bridge_v1_2_0_1024_decapsulate"
    ),
    check_public_key = (
        ffi_mlkem1024_check_public_key,
        "qpn_mlkem_bridge_v1_2_0_1024_check_public_key"
    ),
    avx2 = (
        avx2_1024,
        "qpn_mlkem_bridge_v1_2_0_avx2_1024_keypair_derand",
        "qpn_mlkem_bridge_v1_2_0_avx2_1024_encapsulate_derand",
        "qpn_mlkem_bridge_v1_2_0_avx2_1024_decapsulate",
        "qpn_mlkem_bridge_v1_2_0_avx2_1024_check_public_key"
    ),
    public_key_len = 1568,
    decapsulation_key_len = 3168,
    ciphertext_len = 1568,
    embedded_public_key_offset = 1536
);
