#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-tls-demo
//!
//! A minimal **server-authenticated PQ/T hybrid KEM handshake over TCP**, plus an
//! end-to-end **P99 latency harness**. It exercises the real suite (ML-KEM + X25519 +
//! SHA3 for the KEM, ML-DSA for server auth, via
//! `q-periapt-kem`/`q-periapt-sig`/`q-periapt-backends`) over real sockets, to make the project's
//! actual differentiator measurable: *handshake P99 is dominated by bytes/packets
//! on the wire (now including the multi-KB ML-DSA signature), not by CPU time.*
//!
//! ## Suites
//! The handshake is generic over a [`HandshakeSuite`]. Two are provided:
//! - [`DefaultSuite`] — ML-KEM-768 + X25519, ML-DSA-65 auth (NIST level 3); the
//!   default used by [`client_handshake`] / [`server_handshake`].
//! - [`EnhancedSuite`] — ML-KEM-1024 + X25519, ML-DSA-87 auth (NIST level 5); driven
//!   by [`client_handshake_enhanced`] / [`server_handshake_enhanced`]. Its messages
//!   are markedly larger (1568-byte KEM ct, 4627-byte signature), which is exactly the
//!   bytes-on-wire cost the P99 thesis is about.
//!
//! ## What this is (and isn't)
//! - It is an **HPKE-base-shaped, server-authenticated** handshake: the server has a
//!   static hybrid KEM key and an ML-DSA identity key (its verifying key is *pinned*
//!   by the client out-of-band). The client encapsulates; both derive a session secret
//!   bound to the transcript via [`Profile::ContextBound`]; the server signs the
//!   transcript and sends a key-confirmation.
//! - It is **not** the TLS 1.3 wire format. Real TLS 1.3 hybrid key exchange uses the
//!   `X25519MLKEM768` named group (`0x11EC`) with the TLS key-schedule combiner. See
//!   `README.md` for the mapping and the production path (a rustls `CryptoProvider`
//!   over `q-periapt-ffi`).

use core::fmt;
use std::io::{self, Read, Write};

use q_periapt_backends::{
    MlDsa65, MlDsa87, MlKem1024, MlKem768, Sha3_256Xof, ML_DSA_65_SIG_LEN, ML_DSA_87_SIG_LEN,
    ML_KEM_1024_CT_LEN, ML_KEM_1024_PK_LEN, ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN, X25519,
    X25519_LEN,
};
use q_periapt_core::{ct_eq, Kem, Profile, Secret, Xof256};
use q_periapt_kem::HybridKem;
use q_periapt_sig::{Signer, Verifier};

/// Canonical suite identifier for the default suite, bound into the combiner.
pub const SUITE_ID: &[u8] = DefaultSuite::SUITE_ID;
/// Canonical suite identifier for the enhanced (L5) suite.
pub const SUITE_ID_ENHANCED: &[u8] = EnhancedSuite::SUITE_ID;
/// Algorithm-policy version bound into the combiner (shared by both suites — the
/// suite_id, not the policy version, distinguishes them).
pub const POLICY_VERSION: u32 = 1;
const NONCE_LEN: usize = 32;
const SERVER_FINISHED_LABEL: &[u8] = b"q-periapt/v1/server-finished";
const MAX_MSG: usize = 1 << 20;
const PQ_KEYGEN_SEED_LEN: usize = 64;
const SEED32_LEN: usize = 32;

/// A concrete handshake suite: a post-quantum KEM partner (always paired with X25519)
/// and a server-authentication signature algorithm, plus the wire sizes the framing
/// needs. One generic handshake implementation serves every suite.
pub trait HandshakeSuite {
    /// The post-quantum KEM backend (paired with X25519 to form the hybrid KEM).
    type Pq: Kem + Default;
    /// The server-authentication signature backend.
    type Sig: Signer + Verifier + Default;
    /// Suite identifier bound into the combiner agility block.
    const SUITE_ID: &'static [u8];
    /// PQ encapsulation-key (public key) length, bytes.
    const PQ_PK_LEN: usize;
    /// PQ ciphertext length, bytes.
    const PQ_CT_LEN: usize;
    /// Signature length, bytes.
    const SIG_LEN: usize;
    /// Derive the PQ KEM key pair `(sk, pk)` from a 64-byte seed.
    fn pq_keypair(seed: &[u8; PQ_KEYGEN_SEED_LEN]) -> (Vec<u8>, Vec<u8>);
    /// Derive the signature key pair `(sk, vk)` from a 32-byte seed.
    fn sig_keypair(seed: &[u8; SEED32_LEN]) -> (Vec<u8>, Vec<u8>);
}

/// The default suite: ML-KEM-768 + X25519, ML-DSA-65 auth (NIST level 3).
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultSuite;

impl HandshakeSuite for DefaultSuite {
    type Pq = MlKem768;
    type Sig = MlDsa65;
    const SUITE_ID: &'static [u8] = b"ML-KEM-768+X25519";
    const PQ_PK_LEN: usize = ML_KEM_768_PK_LEN;
    const PQ_CT_LEN: usize = ML_KEM_768_CT_LEN;
    const SIG_LEN: usize = ML_DSA_65_SIG_LEN;
    fn pq_keypair(seed: &[u8; PQ_KEYGEN_SEED_LEN]) -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = MlKem768::generate(*seed);
        (sk.to_vec(), pk.to_vec())
    }
    fn sig_keypair(seed: &[u8; SEED32_LEN]) -> (Vec<u8>, Vec<u8>) {
        let (sk, vk) = MlDsa65::generate(*seed);
        (sk.to_vec(), vk.to_vec())
    }
}

/// The enhanced suite: ML-KEM-1024 + X25519, ML-DSA-87 auth (NIST level 5).
#[derive(Clone, Copy, Debug, Default)]
pub struct EnhancedSuite;

impl HandshakeSuite for EnhancedSuite {
    type Pq = MlKem1024;
    type Sig = MlDsa87;
    const SUITE_ID: &'static [u8] = b"ML-KEM-1024+X25519";
    const PQ_PK_LEN: usize = ML_KEM_1024_PK_LEN;
    const PQ_CT_LEN: usize = ML_KEM_1024_CT_LEN;
    const SIG_LEN: usize = ML_DSA_87_SIG_LEN;
    fn pq_keypair(seed: &[u8; PQ_KEYGEN_SEED_LEN]) -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = MlKem1024::generate(*seed);
        (sk.to_vec(), pk.to_vec())
    }
    fn sig_keypair(seed: &[u8; SEED32_LEN]) -> (Vec<u8>, Vec<u8>) {
        let (sk, vk) = MlDsa87::generate(*seed);
        (sk.to_vec(), vk.to_vec())
    }
}

/// Errors surfaced by the handshake.
#[derive(Debug)]
pub enum DemoError {
    /// Underlying socket I/O error.
    Io(io::Error),
    /// Malformed / unexpected protocol message.
    Protocol,
    /// A core crypto operation failed (e.g. policy/length).
    Crypto,
    /// The server's signature did not verify against the pinned key.
    AuthFailed,
    /// The server key-confirmation did not verify.
    ConfirmFailed,
}

impl fmt::Display for DemoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DemoError::Io(e) => write!(f, "io: {e}"),
            DemoError::Protocol => f.write_str("protocol error"),
            DemoError::Crypto => f.write_str("crypto error"),
            DemoError::AuthFailed => f.write_str("server authentication failed"),
            DemoError::ConfirmFailed => f.write_str("server confirmation failed"),
        }
    }
}
impl std::error::Error for DemoError {}
impl From<io::Error> for DemoError {
    fn from(e: io::Error) -> Self {
        DemoError::Io(e)
    }
}
impl From<q_periapt_core::Error> for DemoError {
    fn from(_: q_periapt_core::Error) -> Self {
        DemoError::Crypto
    }
}

/// Byte/packet accounting for one handshake (the metric that actually drives P99).
#[derive(Clone, Copy, Debug, Default)]
pub struct HandshakeStats {
    /// Bytes written to the peer (including 4-byte length prefixes).
    pub bytes_sent: usize,
    /// Bytes read from the peer.
    pub bytes_recv: usize,
    /// Application-level messages exchanged in each direction (≈ flights).
    pub messages: usize,
}

/// A server's static key material: a hybrid KEM key and an ML-DSA identity key, stored
/// as bytes so one struct serves every [`HandshakeSuite`]. Build it with the
/// constructor matching the handshake you will run ([`ServerKeys::from_seeds`] for the
/// default suite, [`ServerKeys::from_seeds_enhanced`] for the enhanced L5 suite).
pub struct ServerKeys {
    dk_pq: Vec<u8>,
    ek_pq: Vec<u8>,
    sk_x: Vec<u8>,
    pk_x: Vec<u8>,
    sign_sk: Vec<u8>,
    verify_vk: Vec<u8>,
}

impl Drop for ServerKeys {
    fn drop(&mut self) {
        // Zeroize the long-term PRIVATE keys on drop (decapsulation key, X25519 scalar,
        // signing key); the public ek_pq/pk_x/verify_vk need no wiping. Each Vec is built
        // once at the right size, so wiping the live allocation suffices.
        q_periapt_core::secure_wipe(&mut self.dk_pq);
        q_periapt_core::secure_wipe(&mut self.sk_x);
        q_periapt_core::secure_wipe(&mut self.sign_sk);
    }
}

impl ServerKeys {
    fn from_seeds_for<Su: HandshakeSuite>(
        seed_pq: [u8; PQ_KEYGEN_SEED_LEN],
        seed_x: [u8; SEED32_LEN],
        seed_sig: [u8; SEED32_LEN],
    ) -> Self {
        let (dk_pq, ek_pq) = Su::pq_keypair(&seed_pq);
        let (sk_x, pk_x) = X25519::generate(seed_x);
        let (sign_sk, verify_vk) = Su::sig_keypair(&seed_sig);
        Self {
            dk_pq,
            ek_pq,
            sk_x: sk_x.to_vec(),
            pk_x: pk_x.to_vec(),
            sign_sk,
            verify_vk,
        }
    }

    /// Generate **default-suite** keys from fixed seeds (deterministic — tests/benches).
    #[must_use]
    pub fn from_seeds(
        seed_pq: [u8; PQ_KEYGEN_SEED_LEN],
        seed_x: [u8; SEED32_LEN],
        seed_sig: [u8; SEED32_LEN],
    ) -> Self {
        Self::from_seeds_for::<DefaultSuite>(seed_pq, seed_x, seed_sig)
    }

    /// Generate **enhanced-suite** (ML-KEM-1024 + ML-DSA-87) keys from fixed seeds.
    #[must_use]
    pub fn from_seeds_enhanced(
        seed_pq: [u8; PQ_KEYGEN_SEED_LEN],
        seed_x: [u8; SEED32_LEN],
        seed_sig: [u8; SEED32_LEN],
    ) -> Self {
        Self::from_seeds_for::<EnhancedSuite>(seed_pq, seed_x, seed_sig)
    }

    fn generate_for<Su: HandshakeSuite>() -> Result<Self, DemoError> {
        let mut seed_pq = [0u8; PQ_KEYGEN_SEED_LEN];
        let mut seed_x = [0u8; SEED32_LEN];
        let mut seed_sig = [0u8; SEED32_LEN];
        getrandom::fill(&mut seed_pq).map_err(|_| DemoError::Crypto)?;
        getrandom::fill(&mut seed_x).map_err(|_| DemoError::Crypto)?;
        getrandom::fill(&mut seed_sig).map_err(|_| DemoError::Crypto)?;
        Ok(Self::from_seeds_for::<Su>(seed_pq, seed_x, seed_sig))
    }

    /// Generate **default-suite** keys from the OS CSPRNG.
    pub fn generate() -> Result<Self, DemoError> {
        Self::generate_for::<DefaultSuite>()
    }

    /// Generate **enhanced-suite** keys from the OS CSPRNG.
    pub fn generate_enhanced() -> Result<Self, DemoError> {
        Self::generate_for::<EnhancedSuite>()
    }

    /// The server's ML-DSA verifying key — the client pins this as the server identity
    /// (distributed out-of-band, not sent on the wire each handshake).
    #[must_use]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.verify_vk.clone()
    }
}

fn write_msg<W: Write>(w: &mut W, m: &[u8]) -> Result<usize, DemoError> {
    let len = u32::try_from(m.len()).map_err(|_| DemoError::Protocol)?;
    // One framed write per message (length prefix + payload) — one syscall, and
    // one "flight" for latency modeling in the P99 harness.
    let mut framed = Vec::with_capacity(4 + m.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(m);
    w.write_all(&framed)?;
    Ok(framed.len())
}

fn read_msg<R: Read>(r: &mut R) -> Result<Vec<u8>, DemoError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_MSG {
        return Err(DemoError::Protocol);
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}
impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DemoError> {
        let s = self
            .buf
            .get(self.off..self.off + n)
            .ok_or(DemoError::Protocol)?;
        self.off += n;
        Ok(s)
    }
    fn byte(&mut self) -> Result<u8, DemoError> {
        self.take(1)?.first().copied().ok_or(DemoError::Protocol)
    }
    /// Assert the whole buffer was consumed — reject any trailing bytes, so each
    /// message has a single canonical framing.
    fn finish(self) -> Result<(), DemoError> {
        if self.off == self.buf.len() {
            Ok(())
        } else {
            Err(DemoError::Protocol)
        }
    }
}

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut x = Sha3_256Xof::new();
    for p in parts {
        x.absorb(p);
    }
    x.squeeze32()
}

fn profile_byte(p: Profile) -> u8 {
    p.to_u8()
}
fn profile_from(b: u8) -> Result<Profile, DemoError> {
    Profile::from_u8(b).ok_or(DemoError::Protocol)
}

fn server_finished(secret: &Secret, context: &[u8]) -> [u8; 32] {
    sha3(&[secret.as_bytes(), SERVER_FINISHED_LABEL, context])
}

/// Generic **client** side, parameterized by the [`HandshakeSuite`].
fn client_core<Su: HandshakeSuite, S: Read + Write>(
    stream: &mut S,
    profile: Profile,
    server_vk: &[u8],
) -> Result<(Secret, HandshakeStats), DemoError> {
    let mut stats = HandshakeStats::default();

    // 1. ClientHello = client_nonce(32) || profile(1)
    let mut client_nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut client_nonce).map_err(|_| DemoError::Crypto)?;
    let mut ch = Vec::with_capacity(NONCE_LEN + 1);
    ch.extend_from_slice(&client_nonce);
    ch.push(profile_byte(profile));
    stats.bytes_sent += write_msg(stream, &ch)?;
    stats.messages += 1;

    // 2. ServerHello = ek_pq(PQ_PK_LEN) || pk_x(32) || server_nonce(32)
    let sh = read_msg(stream)?;
    stats.bytes_recv += 4 + sh.len();
    let mut cur = Cursor::new(&sh);
    let ek_pq = cur.take(Su::PQ_PK_LEN)?;
    let pk_x = cur.take(X25519_LEN)?;
    let _server_nonce = cur.take(NONCE_LEN)?;
    cur.finish()?;

    // 3. Transcript context for the combiner (binds nonces, profile, server keys).
    let context = sha3(&[&ch, &sh]);

    // 4. Encapsulate to the server's static hybrid key.
    let pq = Su::Pq::default();
    let trad = X25519;
    let kem =
        HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, Su::SUITE_ID, POLICY_VERSION)?;
    let mut coins = [0u8; 64];
    getrandom::fill(&mut coins).map_err(|_| DemoError::Crypto)?;
    let (rand_pq, rand_trad) = coins.split_at(32);
    let mut ct_pq = vec![0u8; Su::PQ_CT_LEN];
    let mut ct_trad = [0u8; X25519_LEN];
    let secret = kem.encapsulate(
        ek_pq,
        pk_x,
        &context,
        rand_pq,
        rand_trad,
        &mut ct_pq,
        &mut ct_trad,
    )?;

    // 5. ClientKem = ct_pq(PQ_CT_LEN) || ct_trad(32)
    let mut kem_msg = Vec::with_capacity(Su::PQ_CT_LEN + X25519_LEN);
    kem_msg.extend_from_slice(&ct_pq);
    kem_msg.extend_from_slice(&ct_trad);
    stats.bytes_sent += write_msg(stream, &kem_msg)?;
    stats.messages += 1;

    // 6. ServerFinished = signature(SIG_LEN) || key_confirmation(32)
    let sf = read_msg(stream)?;
    stats.bytes_recv += 4 + sf.len();
    let mut cur = Cursor::new(&sf);
    let signature = cur.take(Su::SIG_LEN)?;
    let confirm = cur.take(32)?;
    cur.finish()?;

    // Server authentication: signature over the full transcript, pinned vk.
    let auth_transcript = sha3(&[&ch, &sh, &kem_msg]);
    Su::Sig::default()
        .verify(server_vk, &auth_transcript, signature)
        .map_err(|_| DemoError::AuthFailed)?;

    // Key confirmation (constant-time).
    let expected = server_finished(&secret, &context);
    if ct_eq(confirm, &expected) != 0xFF {
        return Err(DemoError::ConfirmFailed);
    }

    Ok((secret, stats))
}

/// Generic **server** side, parameterized by the [`HandshakeSuite`].
fn server_core<Su: HandshakeSuite, S: Read + Write>(
    stream: &mut S,
    keys: &ServerKeys,
) -> Result<(Secret, HandshakeStats), DemoError> {
    let mut stats = HandshakeStats::default();

    // 1. ClientHello
    let ch = read_msg(stream)?;
    stats.bytes_recv += 4 + ch.len();
    let mut cur = Cursor::new(&ch);
    let _client_nonce = cur.take(NONCE_LEN)?;
    let profile = profile_from(cur.byte()?)?;
    cur.finish()?;

    // 2. ServerHello
    let mut server_nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut server_nonce).map_err(|_| DemoError::Crypto)?;
    let mut sh = Vec::with_capacity(Su::PQ_PK_LEN + X25519_LEN + NONCE_LEN);
    sh.extend_from_slice(&keys.ek_pq);
    sh.extend_from_slice(&keys.pk_x);
    sh.extend_from_slice(&server_nonce);
    stats.bytes_sent += write_msg(stream, &sh)?;
    stats.messages += 1;

    let context = sha3(&[&ch, &sh]);

    // 3. ClientKem
    let kem_msg = read_msg(stream)?;
    stats.bytes_recv += 4 + kem_msg.len();
    let mut cur = Cursor::new(&kem_msg);
    let ct_pq = cur.take(Su::PQ_CT_LEN)?;
    let ct_trad = cur.take(X25519_LEN)?;
    cur.finish()?;

    // 4. Decapsulate.
    let pq = Su::Pq::default();
    let trad = X25519;
    let kem =
        HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, Su::SUITE_ID, POLICY_VERSION)?;
    let secret = kem.decapsulate(
        &keys.dk_pq,
        ct_pq,
        &keys.ek_pq,
        &keys.sk_x,
        ct_trad,
        &keys.pk_x,
        &context,
    )?;

    // 5. ServerFinished = sign(transcript) || key_confirmation
    let auth_transcript = sha3(&[&ch, &sh, &kem_msg]);
    let mut sig_rand = [0u8; 32];
    getrandom::fill(&mut sig_rand).map_err(|_| DemoError::Crypto)?;
    let mut sig = vec![0u8; Su::SIG_LEN];
    Su::Sig::default()
        .sign(&keys.sign_sk, &auth_transcript, &sig_rand, &mut sig)
        .map_err(|_| DemoError::Crypto)?;
    let confirm = server_finished(&secret, &context);

    let mut sf = Vec::with_capacity(Su::SIG_LEN + 32);
    sf.extend_from_slice(&sig);
    sf.extend_from_slice(&confirm);
    stats.bytes_sent += write_msg(stream, &sf)?;
    stats.messages += 1;

    Ok((secret, stats))
}

/// Run the **default-suite** client handshake (ML-KEM-768 + X25519, ML-DSA-65 auth),
/// verifying the server's signature against the pinned `server_vk`.
pub fn client_handshake<S: Read + Write>(
    stream: &mut S,
    profile: Profile,
    server_vk: &[u8],
) -> Result<(Secret, HandshakeStats), DemoError> {
    client_core::<DefaultSuite, S>(stream, profile, server_vk)
}

/// Run the **enhanced-suite** (NIST L5) client handshake: ML-KEM-1024 + X25519 with
/// ML-DSA-87 server auth. `server_vk` is the server's pinned ML-DSA-87 verifying key.
pub fn client_handshake_enhanced<S: Read + Write>(
    stream: &mut S,
    profile: Profile,
    server_vk: &[u8],
) -> Result<(Secret, HandshakeStats), DemoError> {
    client_core::<EnhancedSuite, S>(stream, profile, server_vk)
}

/// Run the **default-suite** server handshake using its static keys (built with
/// [`ServerKeys::from_seeds`] / [`ServerKeys::generate`]).
pub fn server_handshake<S: Read + Write>(
    stream: &mut S,
    keys: &ServerKeys,
) -> Result<(Secret, HandshakeStats), DemoError> {
    server_core::<DefaultSuite, S>(stream, keys)
}

/// Run the **enhanced-suite** (NIST L5) server handshake using its static keys (built
/// with [`ServerKeys::from_seeds_enhanced`] / [`ServerKeys::generate_enhanced`]).
pub fn server_handshake_enhanced<S: Read + Write>(
    stream: &mut S,
    keys: &ServerKeys,
) -> Result<(Secret, HandshakeStats), DemoError> {
    server_core::<EnhancedSuite, S>(stream, keys)
}
