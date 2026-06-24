//! Multi-backend differential tests.
//!
//! Cross-validates the suite's primitives and the full hybrid against **independent
//! implementations** on random inputs — an assurance method orthogonal to fixed KATs
//! and the EasyCrypt proof. FIPS 203 / RFC 7748 fix every byte encoding, so any
//! divergence is a conformance or integration bug that 3 fixed X-Wing vectors miss:
//!
//! - **ML-KEM-512 / 768 / 1024** — our libcrux backends vs RustCrypto `ml-kem`
//!   (byte-identical keygen/encaps/decaps across the full FIPS 203 family).
//! - **X25519** — our `x25519-dalek` backend vs the independent `orion` impl, plus
//!   the authoritative RFC 7748 §6.1 ground-truth Diffie–Hellman vector.
//! - **Hybrid CompatXWing** — our [`HybridKem`] reconstructed from RustCrypto ML-KEM
//!   + orion X25519 + a RustCrypto SHA3 X-Wing combiner, for encaps **and** decaps.
//! - **ML-DSA-44 / 65 / 87** — our libcrux signature backends vs RustCrypto `ml-dsa`
//!   (byte-identical keygen + deterministic signatures, plus cross-verification + tamper
//!   rejection, across the full FIPS 204 family).
//!
//! Fully deterministic: per-iteration inputs are `SHAKE-256(counter)`, no RNG.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, deprecated)]

use crate::{
    MlDsa44, MlDsa65, MlDsa87, MlKem1024, MlKem512, MlKem768, Sha3_256Xof,
    ML_DSA_44_KEYGEN_SEED_LEN, ML_DSA_44_SIGN_RAND_LEN, ML_DSA_44_SIG_LEN,
    ML_DSA_65_KEYGEN_SEED_LEN, ML_DSA_65_SIGN_RAND_LEN, ML_DSA_65_SIG_LEN,
    ML_DSA_87_KEYGEN_SEED_LEN, ML_DSA_87_SIGN_RAND_LEN, ML_DSA_87_SIG_LEN, ML_KEM_1024_CT_LEN,
    ML_KEM_1024_KEYGEN_SEED_LEN, ML_KEM_512_CT_LEN, ML_KEM_512_KEYGEN_SEED_LEN, ML_KEM_768_CT_LEN,
    ML_KEM_768_KEYGEN_SEED_LEN, SHARED_SECRET_LEN, X25519, X25519_LEN,
};
use ml_dsa::{
    EncodedSignature, ExpandedSigningKey, MlDsa44 as RcMlDsa44, MlDsa65 as RcMlDsa65,
    MlDsa87 as RcMlDsa87, Seed, Signature,
};
use ml_kem::kem::Decapsulate;
use ml_kem::{
    EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024 as RcMlKem1024,
    MlKem512 as RcMlKem512, MlKem768 as RcMlKem768, B32,
};
use orion::hazardous::ecc::x25519 as ox;
use q_periapt_core::{Kem, Profile, XWING_LABEL};
use q_periapt_kem::HybridKem;
use q_periapt_sig::{Signer, Verifier};
use sha3::{Digest, Sha3_256};

fn b32(s: &[u8]) -> B32 {
    B32::try_from(s).unwrap()
}

/// X25519 base-point scalar multiplication via the independent orion impl (keygen).
fn orion_pub(scalar: &[u8]) -> [u8; X25519_LEN] {
    let sk = ox::PrivateKey::from_slice(scalar).unwrap();
    ox::PublicKey::try_from(&sk).unwrap().to_bytes()
}

/// X25519 Diffie–Hellman via the independent orion impl.
fn orion_dh(scalar: &[u8], peer_pub: &[u8]) -> [u8; X25519_LEN] {
    let sk = ox::PrivateKey::from_slice(scalar).unwrap();
    let pk = ox::PublicKey::from_slice(peer_pub).unwrap();
    let ss = ox::key_agreement(&sk, &pk).unwrap();
    let mut out = [0u8; X25519_LEN];
    out.copy_from_slice(ss.unprotected_as_bytes());
    out
}

fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut o = [0u8; 32];
    for (i, byte) in o.iter_mut().enumerate() {
        let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        *byte = (hi << 4) | lo;
    }
    o
}

#[test]
fn ml_kem_768_byte_identical_to_independent_rustcrypto() {
    // FIPS 203 keygen seed is d‖z, each 32 bytes.
    const HALF: usize = ML_KEM_768_KEYGEN_SEED_LEN / 2;
    for ctr in 0u32..64 {
        // Deterministic per-iteration inputs: SHAKE-256(counter) -> 96 bytes
        // = a 64-byte keygen seed (d‖z) + a 32-byte encapsulation message m.
        let expand = libcrux_sha3::shake256::<96>(&ctr.to_le_bytes());
        let mut seed = [0u8; ML_KEM_768_KEYGEN_SEED_LEN];
        seed.copy_from_slice(&expand[..ML_KEM_768_KEYGEN_SEED_LEN]);
        let m = &expand[ML_KEM_768_KEYGEN_SEED_LEN..];

        // --- keygen: byte-identical decapsulation + encapsulation keys ---
        let (sk, pk) = MlKem768::generate(seed);
        let (dk_rc, ek_rc) =
            RcMlKem768::generate_deterministic(&b32(&seed[..HALF]), &b32(&seed[HALF..]));
        assert_eq!(
            &ek_rc.as_bytes()[..],
            &pk[..],
            "encapsulation key diverged @ {ctr}"
        );
        assert_eq!(
            &dk_rc.as_bytes()[..],
            &sk[..],
            "decapsulation key diverged @ {ctr}"
        );

        // --- encapsulation: byte-identical ciphertext + shared secret ---
        let mut ct = [0u8; ML_KEM_768_CT_LEN];
        let mut ss = [0u8; SHARED_SECRET_LEN];
        MlKem768.encapsulate(&pk, m, &mut ct, &mut ss).unwrap();
        let (ct_rc, ss_rc) = ek_rc.encapsulate_deterministic(&b32(m)).unwrap();
        assert_eq!(&ct_rc[..], &ct[..], "ciphertext diverged @ {ctr}");
        assert_eq!(&ss_rc[..], &ss[..], "encaps shared secret diverged @ {ctr}");

        // --- decapsulation: the independent impl recovers the same secret ---
        let mut ss_dec = [0u8; SHARED_SECRET_LEN];
        MlKem768.decapsulate(&sk, &ct, &mut ss_dec).unwrap();
        let ss_rc_dec = dk_rc.decapsulate(&ct_rc).unwrap();
        assert_eq!(&ss_dec[..], &ss[..], "our decaps != our encaps @ {ctr}");
        assert_eq!(
            &ss_rc_dec[..],
            &ss_dec[..],
            "rustcrypto decaps diverged @ {ctr}"
        );
    }
}

/// ML-KEM-1024 (the enhanced-mode KEM): our libcrux backend vs the independent
/// RustCrypto `ml-kem`, byte-identical keygen + encaps + decaps over random `(d‖z, m)`.
#[test]
fn ml_kem_1024_byte_identical_to_independent_rustcrypto() {
    const HALF: usize = ML_KEM_1024_KEYGEN_SEED_LEN / 2;
    for ctr in 0u32..64 {
        let expand = libcrux_sha3::shake256::<96>(&(ctr ^ 0x0401).to_le_bytes());
        let mut seed = [0u8; ML_KEM_1024_KEYGEN_SEED_LEN];
        seed.copy_from_slice(&expand[..ML_KEM_1024_KEYGEN_SEED_LEN]);
        let m = &expand[ML_KEM_1024_KEYGEN_SEED_LEN..];

        let (sk, pk) = MlKem1024::generate(seed);
        let (dk_rc, ek_rc) =
            RcMlKem1024::generate_deterministic(&b32(&seed[..HALF]), &b32(&seed[HALF..]));
        assert_eq!(&ek_rc.as_bytes()[..], &pk[..], "1024 ek diverged @ {ctr}");
        assert_eq!(&dk_rc.as_bytes()[..], &sk[..], "1024 dk diverged @ {ctr}");

        let mut ct = [0u8; ML_KEM_1024_CT_LEN];
        let mut ss = [0u8; SHARED_SECRET_LEN];
        MlKem1024.encapsulate(&pk, m, &mut ct, &mut ss).unwrap();
        let (ct_rc, ss_rc) = ek_rc.encapsulate_deterministic(&b32(m)).unwrap();
        assert_eq!(&ct_rc[..], &ct[..], "1024 ct diverged @ {ctr}");
        assert_eq!(&ss_rc[..], &ss[..], "1024 encaps ss diverged @ {ctr}");

        let mut ss_dec = [0u8; SHARED_SECRET_LEN];
        MlKem1024.decapsulate(&sk, &ct, &mut ss_dec).unwrap();
        let ss_rc_dec = dk_rc.decapsulate(&ct_rc).unwrap();
        assert_eq!(&ss_dec[..], &ss[..], "1024 our decaps != encaps @ {ctr}");
        assert_eq!(
            &ss_rc_dec[..],
            &ss_dec[..],
            "1024 rustcrypto decaps diverged @ {ctr}"
        );
    }
}

/// X25519: our x25519-dalek backend vs the independent orion implementation,
/// byte-identical public keys + shared secrets over random scalars.
#[test]
fn x25519_byte_identical_to_independent_orion() {
    for ctr in 0u32..64 {
        let exp = libcrux_sha3::shake256::<64>(&(ctr ^ 0xA5A5).to_le_bytes());
        let a = &exp[..X25519_LEN]; // recipient scalar
        let eph = &exp[X25519_LEN..]; // ephemeral scalar

        // keygen (base-point mult) agrees
        let (_sk, pk) = X25519::generate(a.try_into().unwrap());
        assert_eq!(pk, orion_pub(a), "x25519 public key diverged @ {ctr}");

        // encapsulation: ct = ephemeral public key, ss = DH(eph, pk)
        let mut ct = [0u8; X25519_LEN];
        let mut ss = [0u8; SHARED_SECRET_LEN];
        X25519.encapsulate(&pk, eph, &mut ct, &mut ss).unwrap();
        assert_eq!(ct, orion_pub(eph), "x25519 ciphertext diverged @ {ctr}");
        assert_eq!(
            ss,
            orion_dh(eph, &pk),
            "x25519 encaps secret diverged @ {ctr}"
        );

        // decapsulation recovers the same secret, independently confirmed
        let mut ss_dec = [0u8; SHARED_SECRET_LEN];
        X25519.decapsulate(a, &ct, &mut ss_dec).unwrap();
        assert_eq!(ss_dec, ss, "x25519 decaps != encaps @ {ctr}");
        assert_eq!(ss_dec, orion_dh(a, &ct), "x25519 decaps diverged @ {ctr}");
    }
}

/// X25519 against the authoritative RFC 7748 §6.1 Diffie–Hellman test vector
/// (ground truth from the specification, no second implementation involved).
#[test]
fn x25519_rfc7748_diffie_hellman_kat() {
    let a_priv = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let a_pub = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let b_priv = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let b_pub = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let k = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    // keygen reproduces the published public keys
    assert_eq!(
        X25519::generate(a_priv).1,
        a_pub,
        "RFC 7748 Alice public key"
    );
    assert_eq!(X25519::generate(b_priv).1, b_pub, "RFC 7748 Bob public key");

    // Diffie–Hellman from both sides yields the published shared secret K
    let mut ss = [0u8; SHARED_SECRET_LEN];
    X25519.decapsulate(&a_priv, &b_pub, &mut ss).unwrap();
    assert_eq!(ss, k, "RFC 7748 K (Alice·B)");
    let mut ss2 = [0u8; SHARED_SECRET_LEN];
    X25519.decapsulate(&b_priv, &a_pub, &mut ss2).unwrap();
    assert_eq!(ss2, k, "RFC 7748 K (Bob·A)");
}

/// Full hybrid CompatXWing chain: our `HybridKem` output reconstructed from THREE
/// independent components — RustCrypto ML-KEM, orion X25519, and a RustCrypto SHA3
/// X-Wing combiner — must match byte-for-byte. Cross-validates the orchestration
/// and the combiner end-to-end (encaps and decaps) on random inputs.
#[test]
fn hybrid_compat_xwing_byte_identical_to_independent_reconstruction() {
    let pq = MlKem768;
    let trad = X25519;
    let hk =
        HybridKem::<MlKem768, X25519, Sha3_256Xof>::new(&pq, &trad, Profile::CompatXWing, b"", 0)
            .unwrap();

    for ctr in 0u32..32 {
        let exp = libcrux_sha3::shake256::<160>(&(ctr ^ 0x5A5A).to_le_bytes());
        let mut pq_seed = [0u8; ML_KEM_768_KEYGEN_SEED_LEN];
        pq_seed.copy_from_slice(&exp[..ML_KEM_768_KEYGEN_SEED_LEN]); // d‖z
        let (sk_pq, pk_pq) = MlKem768::generate(pq_seed);
        let x_seed = &exp[64..96];
        let (sk_trad, pk_trad) = X25519::generate(x_seed.try_into().unwrap());
        let m = &exp[96..128]; // ML-KEM encaps message
        let eph = &exp[128..160]; // X25519 ephemeral scalar

        // --- our hybrid encapsulation ---
        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        let (mut ssp, mut sst) = ([0u8; 32], [0u8; 32]);
        let secret = hk
            .encapsulate(
                &pk_pq,
                &pk_trad,
                b"",
                m,
                eph,
                &mut ct_pq,
                &mut ssp,
                &mut ct_trad,
                &mut sst,
            )
            .unwrap();

        // --- independent reconstruction of the SAME shared secret ---
        let (dk_rc, ek_rc) =
            RcMlKem768::generate_deterministic(&b32(&pq_seed[..32]), &b32(&pq_seed[32..]));
        let (ct_pq_rc, ss_pq_rc) = ek_rc.encapsulate_deterministic(&b32(m)).unwrap();
        let ct_trad_ref = orion_pub(eph);
        let ss_trad_ref = orion_dh(eph, &pk_trad);
        let secret_ref = xwing_combine(&ss_pq_rc, &ss_trad_ref, &ct_trad_ref, &pk_trad);

        assert_eq!(&ct_pq[..], &ct_pq_rc[..], "hybrid ct_pq diverged @ {ctr}");
        assert_eq!(ct_trad, ct_trad_ref, "hybrid ct_trad diverged @ {ctr}");
        assert_eq!(
            secret.as_bytes(),
            &secret_ref,
            "hybrid encaps secret diverged @ {ctr}"
        );

        // --- decapsulation: ours, and an independent reconstruction, both agree ---
        let (mut ssp2, mut sst2) = ([0u8; 32], [0u8; 32]);
        let secret_dec = hk
            .decapsulate(
                &sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, b"", &mut ssp2, &mut sst2,
            )
            .unwrap();
        let ss_pq_dec: [u8; 32] = (&dk_rc.decapsulate(&ct_pq_rc).unwrap()[..])
            .try_into()
            .unwrap();
        let ss_trad_dec = orion_dh(&sk_trad, &ct_trad);
        let secret_dec_ref = xwing_combine(&ss_pq_dec, &ss_trad_dec, &ct_trad, &pk_trad);
        assert_eq!(
            secret_dec.as_bytes(),
            &secret_dec_ref,
            "hybrid decaps secret diverged @ {ctr}"
        );
        assert_eq!(
            secret_dec.as_bytes(),
            secret.as_bytes(),
            "hybrid decaps != encaps @ {ctr}"
        );
    }
}

/// Enhanced suite (ML-KEM-1024 + X25519), full `CompatXWing` hybrid chain: our
/// `HybridKem<MlKem1024, X25519>` output reconstructed from THREE independent
/// components — RustCrypto ML-KEM-1024, orion X25519, and a RustCrypto SHA3 X-Wing
/// combiner — must match byte-for-byte. The X-Wing combiner consumes only the 32-byte
/// `ss_pq` and the X25519 components (never `ct_pq`/`pk_pq`), so it is parameter-set
/// independent; this is the strongest single end-to-end check of the enhanced suite.
#[test]
fn hybrid_enhanced_compat_xwing_byte_identical_to_independent_reconstruction() {
    let pq = MlKem1024;
    let trad = X25519;
    let hk =
        HybridKem::<MlKem1024, X25519, Sha3_256Xof>::new(&pq, &trad, Profile::CompatXWing, b"", 0)
            .unwrap();

    for ctr in 0u32..32 {
        let exp = libcrux_sha3::shake256::<160>(&(ctr ^ 0xA51C).to_le_bytes());
        let mut pq_seed = [0u8; ML_KEM_1024_KEYGEN_SEED_LEN];
        pq_seed.copy_from_slice(&exp[..ML_KEM_1024_KEYGEN_SEED_LEN]); // d‖z
        let (sk_pq, pk_pq) = MlKem1024::generate(pq_seed);
        let x_seed = &exp[64..96];
        let (sk_trad, pk_trad) = X25519::generate(x_seed.try_into().unwrap());
        let m = &exp[96..128]; // ML-KEM encaps message
        let eph = &exp[128..160]; // X25519 ephemeral scalar

        // --- our enhanced hybrid encapsulation ---
        let mut ct_pq = [0u8; ML_KEM_1024_CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        let (mut ssp, mut sst) = ([0u8; 32], [0u8; 32]);
        let secret = hk
            .encapsulate(
                &pk_pq,
                &pk_trad,
                b"",
                m,
                eph,
                &mut ct_pq,
                &mut ssp,
                &mut ct_trad,
                &mut sst,
            )
            .unwrap();

        // --- independent reconstruction of the SAME shared secret ---
        let (dk_rc, ek_rc) =
            RcMlKem1024::generate_deterministic(&b32(&pq_seed[..32]), &b32(&pq_seed[32..]));
        let (ct_pq_rc, ss_pq_rc) = ek_rc.encapsulate_deterministic(&b32(m)).unwrap();
        let ct_trad_ref = orion_pub(eph);
        let ss_trad_ref = orion_dh(eph, &pk_trad);
        let secret_ref = xwing_combine(&ss_pq_rc, &ss_trad_ref, &ct_trad_ref, &pk_trad);

        assert_eq!(&ct_pq[..], &ct_pq_rc[..], "enhanced ct_pq diverged @ {ctr}");
        assert_eq!(ct_trad, ct_trad_ref, "enhanced ct_trad diverged @ {ctr}");
        assert_eq!(
            secret.as_bytes(),
            &secret_ref,
            "enhanced encaps secret diverged @ {ctr}"
        );

        // --- decapsulation: ours, and an independent reconstruction, both agree ---
        let (mut ssp2, mut sst2) = ([0u8; 32], [0u8; 32]);
        let secret_dec = hk
            .decapsulate(
                &sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, b"", &mut ssp2, &mut sst2,
            )
            .unwrap();
        let ss_pq_dec: [u8; 32] = (&dk_rc.decapsulate(&ct_pq_rc).unwrap()[..])
            .try_into()
            .unwrap();
        let ss_trad_dec = orion_dh(&sk_trad, &ct_trad);
        let secret_dec_ref = xwing_combine(&ss_pq_dec, &ss_trad_dec, &ct_trad, &pk_trad);
        assert_eq!(
            secret_dec.as_bytes(),
            &secret_dec_ref,
            "enhanced decaps secret diverged @ {ctr}"
        );
        assert_eq!(
            secret_dec.as_bytes(),
            secret.as_bytes(),
            "enhanced decaps != encaps @ {ctr}"
        );
    }
}

/// Independent X-Wing combiner: SHA3-256(ss_pq‖ss_trad‖ct_trad‖pk_trad‖LABEL) via
/// RustCrypto `sha3` (not our libcrux path), matching `CompatXWing`'s field order.
fn xwing_combine(ss_pq: &[u8], ss_trad: &[u8], ct_trad: &[u8], pk_trad: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ss_pq);
    h.update(ss_trad);
    h.update(ct_trad);
    h.update(pk_trad);
    h.update(XWING_LABEL);
    h.finalize().into()
}

/// Signature layer: our libcrux ML-DSA-65 backend vs the independent RustCrypto
/// `ml-dsa`. FIPS 204 deterministic keygen (from ξ) and deterministic signing
/// (rnd = 0, external `ML-DSA.Sign` with empty context — what our backend does) are
/// fully specified, so conformant implementations agree byte-for-byte. Cross-
/// verification additionally proves signature interoperability, and a tampered
/// signature must be rejected.
#[test]
fn ml_dsa_65_byte_identical_to_independent_rustcrypto() {
    for ctr in 0u32..16 {
        let exp = libcrux_sha3::shake256::<64>(&(ctr ^ 0x33CC).to_le_bytes());
        let seed: [u8; ML_DSA_65_KEYGEN_SEED_LEN] =
            exp[..ML_DSA_65_KEYGEN_SEED_LEN].try_into().unwrap();
        let msg = &exp[ML_DSA_65_KEYGEN_SEED_LEN..];

        // --- keygen: byte-identical signing + verifying keys ---
        let (sk, vk) = MlDsa65::generate(seed);
        let esk_rc =
            ExpandedSigningKey::<RcMlDsa65>::from_seed(&Seed::try_from(&seed[..]).unwrap());
        let sk_rc = esk_rc.to_expanded();
        let vk_rc = esk_rc.verifying_key().encode();
        assert_eq!(&sk_rc[..], &sk[..], "ml-dsa signing key diverged @ {ctr}");
        assert_eq!(&vk_rc[..], &vk[..], "ml-dsa verifying key diverged @ {ctr}");

        // --- deterministic signing: byte-identical signatures ---
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        MlDsa65
            .sign(&sk, msg, &[0u8; ML_DSA_65_SIGN_RAND_LEN], &mut sig)
            .unwrap();
        let sig_rc = esk_rc.sign_deterministic(msg, b"").unwrap().encode();
        assert_eq!(&sig_rc[..], &sig[..], "ml-dsa signature diverged @ {ctr}");

        // --- cross-verification (interoperability), both directions ---
        let our_sig = Signature::<RcMlDsa65>::decode(
            &EncodedSignature::<RcMlDsa65>::try_from(&sig[..]).unwrap(),
        )
        .unwrap();
        assert!(
            esk_rc
                .verifying_key()
                .verify_with_context(msg, b"", &our_sig),
            "rustcrypto rejected our signature @ {ctr}"
        );
        MlDsa65
            .verify(&vk, msg, &sig_rc)
            .expect("our verifier rejected the rustcrypto signature");

        // --- tampering is rejected ---
        let mut bad = sig;
        bad[100] ^= 1;
        assert!(
            MlDsa65.verify(&vk, msg, &bad).is_err(),
            "tampered sig accepted @ {ctr}"
        );
    }
}

/// ML-DSA-87 (the enhanced-mode signature, NIST level 5): our libcrux backend vs the
/// independent RustCrypto `ml-dsa`. Byte-identical deterministic keygen (from ξ) and
/// deterministic signing (rnd = 0, external, empty context), plus cross-verification
/// both directions and tamper rejection.
#[test]
fn ml_dsa_87_byte_identical_to_independent_rustcrypto() {
    for ctr in 0u32..16 {
        let exp = libcrux_sha3::shake256::<64>(&(ctr ^ 0x57AC).to_le_bytes());
        let seed: [u8; ML_DSA_87_KEYGEN_SEED_LEN] =
            exp[..ML_DSA_87_KEYGEN_SEED_LEN].try_into().unwrap();
        let msg = &exp[ML_DSA_87_KEYGEN_SEED_LEN..];

        // --- keygen: byte-identical signing + verifying keys ---
        let (sk, vk) = MlDsa87::generate(seed);
        let esk_rc =
            ExpandedSigningKey::<RcMlDsa87>::from_seed(&Seed::try_from(&seed[..]).unwrap());
        let sk_rc = esk_rc.to_expanded();
        let vk_rc = esk_rc.verifying_key().encode();
        assert_eq!(
            &sk_rc[..],
            &sk[..],
            "ml-dsa-87 signing key diverged @ {ctr}"
        );
        assert_eq!(
            &vk_rc[..],
            &vk[..],
            "ml-dsa-87 verifying key diverged @ {ctr}"
        );

        // --- deterministic signing: byte-identical signatures ---
        let mut sig = [0u8; ML_DSA_87_SIG_LEN];
        MlDsa87
            .sign(&sk, msg, &[0u8; ML_DSA_87_SIGN_RAND_LEN], &mut sig)
            .unwrap();
        let sig_rc = esk_rc.sign_deterministic(msg, b"").unwrap().encode();
        assert_eq!(
            &sig_rc[..],
            &sig[..],
            "ml-dsa-87 signature diverged @ {ctr}"
        );

        // --- cross-verification (interoperability), both directions ---
        let our_sig = Signature::<RcMlDsa87>::decode(
            &EncodedSignature::<RcMlDsa87>::try_from(&sig[..]).unwrap(),
        )
        .unwrap();
        assert!(
            esk_rc
                .verifying_key()
                .verify_with_context(msg, b"", &our_sig),
            "rustcrypto rejected our ml-dsa-87 signature @ {ctr}"
        );
        MlDsa87
            .verify(&vk, msg, &sig_rc)
            .expect("our verifier rejected the rustcrypto ml-dsa-87 signature");

        // --- tampering is rejected ---
        let mut bad = sig;
        bad[100] ^= 1;
        assert!(
            MlDsa87.verify(&vk, msg, &bad).is_err(),
            "tampered ml-dsa-87 sig accepted @ {ctr}"
        );
    }
}

/// ML-KEM-512 (NIST L1, the smallest set): our libcrux backend vs the independent
/// RustCrypto `ml-kem`, byte-identical keygen + encaps + decaps over random `(d‖z, m)`.
#[test]
fn ml_kem_512_byte_identical_to_independent_rustcrypto() {
    const HALF: usize = ML_KEM_512_KEYGEN_SEED_LEN / 2;
    for ctr in 0u32..64 {
        let expand = libcrux_sha3::shake256::<96>(&(ctr ^ 0x0201).to_le_bytes());
        let mut seed = [0u8; ML_KEM_512_KEYGEN_SEED_LEN];
        seed.copy_from_slice(&expand[..ML_KEM_512_KEYGEN_SEED_LEN]);
        let m = &expand[ML_KEM_512_KEYGEN_SEED_LEN..];

        let (sk, pk) = MlKem512::generate(seed);
        let (dk_rc, ek_rc) =
            RcMlKem512::generate_deterministic(&b32(&seed[..HALF]), &b32(&seed[HALF..]));
        assert_eq!(&ek_rc.as_bytes()[..], &pk[..], "512 ek diverged @ {ctr}");
        assert_eq!(&dk_rc.as_bytes()[..], &sk[..], "512 dk diverged @ {ctr}");

        let mut ct = [0u8; ML_KEM_512_CT_LEN];
        let mut ss = [0u8; SHARED_SECRET_LEN];
        MlKem512.encapsulate(&pk, m, &mut ct, &mut ss).unwrap();
        let (ct_rc, ss_rc) = ek_rc.encapsulate_deterministic(&b32(m)).unwrap();
        assert_eq!(&ct_rc[..], &ct[..], "512 ct diverged @ {ctr}");
        assert_eq!(&ss_rc[..], &ss[..], "512 encaps ss diverged @ {ctr}");

        let mut ss_dec = [0u8; SHARED_SECRET_LEN];
        MlKem512.decapsulate(&sk, &ct, &mut ss_dec).unwrap();
        let ss_rc_dec = dk_rc.decapsulate(&ct_rc).unwrap();
        assert_eq!(&ss_dec[..], &ss[..], "512 our decaps != encaps @ {ctr}");
        assert_eq!(
            &ss_rc_dec[..],
            &ss_dec[..],
            "512 rustcrypto decaps diverged @ {ctr}"
        );
    }
}

/// ML-DSA-44 (NIST L2, the smallest ML-DSA): our libcrux backend vs the independent
/// RustCrypto `ml-dsa`. Byte-identical deterministic keygen + signing, cross-
/// verification both directions, and tamper rejection.
#[test]
fn ml_dsa_44_byte_identical_to_independent_rustcrypto() {
    for ctr in 0u32..16 {
        let exp = libcrux_sha3::shake256::<64>(&(ctr ^ 0x44AC).to_le_bytes());
        let seed: [u8; ML_DSA_44_KEYGEN_SEED_LEN] =
            exp[..ML_DSA_44_KEYGEN_SEED_LEN].try_into().unwrap();
        let msg = &exp[ML_DSA_44_KEYGEN_SEED_LEN..];

        let (sk, vk) = MlDsa44::generate(seed);
        let esk_rc =
            ExpandedSigningKey::<RcMlDsa44>::from_seed(&Seed::try_from(&seed[..]).unwrap());
        let sk_rc = esk_rc.to_expanded();
        let vk_rc = esk_rc.verifying_key().encode();
        assert_eq!(
            &sk_rc[..],
            &sk[..],
            "ml-dsa-44 signing key diverged @ {ctr}"
        );
        assert_eq!(
            &vk_rc[..],
            &vk[..],
            "ml-dsa-44 verifying key diverged @ {ctr}"
        );

        let mut sig = [0u8; ML_DSA_44_SIG_LEN];
        MlDsa44
            .sign(&sk, msg, &[0u8; ML_DSA_44_SIGN_RAND_LEN], &mut sig)
            .unwrap();
        let sig_rc = esk_rc.sign_deterministic(msg, b"").unwrap().encode();
        assert_eq!(
            &sig_rc[..],
            &sig[..],
            "ml-dsa-44 signature diverged @ {ctr}"
        );

        let our_sig = Signature::<RcMlDsa44>::decode(
            &EncodedSignature::<RcMlDsa44>::try_from(&sig[..]).unwrap(),
        )
        .unwrap();
        assert!(
            esk_rc
                .verifying_key()
                .verify_with_context(msg, b"", &our_sig),
            "rustcrypto rejected our ml-dsa-44 signature @ {ctr}"
        );
        MlDsa44
            .verify(&vk, msg, &sig_rc)
            .expect("our verifier rejected the rustcrypto ml-dsa-44 signature");

        let mut bad = sig;
        bad[100] ^= 1;
        assert!(
            MlDsa44.verify(&vk, msg, &bad).is_err(),
            "tampered ml-dsa-44 sig accepted @ {ctr}"
        );
    }
}
