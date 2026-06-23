#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-tls-demo
//!
//! A minimal **server-authenticated PQ/T hybrid KEM handshake over TCP**, plus an
//! end-to-end **P99 latency harness**. It exercises the real suite (ML-KEM-768 +
//! X25519 + SHA3 for the KEM, ML-DSA-65 for server auth, via
//! `q-periapt-kem`/`q-periapt-sig`/`q-periapt-backends`) over real sockets, to make the project's
//! actual differentiator measurable: *handshake P99 is dominated by bytes/packets
//! on the wire (now including the ~3.3 KB ML-DSA signature), not by CPU time.*
//!
//! ## What this is (and isn't)
//! - It is an **HPKE-base-shaped, server-authenticated** handshake: the server
//!   has a static hybrid KEM key and an ML-DSA-65 identity key (its verifying key
//!   is *pinned* by the client out-of-band). The client encapsulates; both derive
//!   a session secret bound to the transcript via [`Profile::ContextBound`]; the
//!   server signs the transcript and sends a key-confirmation.
//! - It is **not** the TLS 1.3 wire format. Real TLS 1.3 hybrid key exchange uses
//!   the `X25519MLKEM768` named group (`0x11EC`) with the TLS key-schedule
//!   combiner. See `README.md` for the mapping and the production path (a rustls
//!   `CryptoProvider` over `q-periapt-ffi`).

use core::fmt;
use std::io::{self, Read, Write};

use q_periapt_backends::{
    MlDsa65, MlKem768, Sha3_256Xof, ML_DSA_65_SIG_LEN, ML_DSA_65_SK_LEN, ML_DSA_65_VK_LEN,
    ML_KEM_768_CT_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN, X25519, X25519_LEN,
};
use q_periapt_core::{ct_eq, Profile, Secret, Xof256};
use q_periapt_kem::HybridKem;
use q_periapt_sig::{Signer, Verifier};

/// Canonical suite identifier bound into the combiner.
pub const SUITE_ID: &[u8] = b"ML-KEM-768+X25519";
/// Algorithm-policy version bound into the combiner.
pub const POLICY_VERSION: u32 = 1;
const NONCE_LEN: usize = 32;
const SERVER_FINISHED_LABEL: &[u8] = b"q-periapt/v1/server-finished";
const MAX_MSG: usize = 1 << 20;

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

/// A server's static key material: a hybrid KEM key and an ML-DSA-65 identity key.
pub struct ServerKeys {
    dk_pq: [u8; ML_KEM_768_SK_LEN],
    ek_pq: [u8; ML_KEM_768_PK_LEN],
    sk_x: [u8; X25519_LEN],
    pk_x: [u8; X25519_LEN],
    sign_sk: [u8; ML_DSA_65_SK_LEN],
    verify_vk: [u8; ML_DSA_65_VK_LEN],
}

impl ServerKeys {
    /// Generate from fixed seeds (deterministic — for tests/benches).
    #[must_use]
    pub fn from_seeds(seed_pq: [u8; 64], seed_x: [u8; 32], seed_sig: [u8; 32]) -> Self {
        let (dk_pq, ek_pq) = MlKem768::generate(seed_pq);
        let (sk_x, pk_x) = X25519::generate(seed_x);
        let (sign_sk, verify_vk) = MlDsa65::generate(seed_sig);
        Self {
            dk_pq,
            ek_pq,
            sk_x,
            pk_x,
            sign_sk,
            verify_vk,
        }
    }

    /// Generate from the OS CSPRNG.
    pub fn generate() -> Result<Self, DemoError> {
        let mut seed_pq = [0u8; 64];
        let mut seed_x = [0u8; 32];
        let mut seed_sig = [0u8; 32];
        getrandom::fill(&mut seed_pq).map_err(|_| DemoError::Crypto)?;
        getrandom::fill(&mut seed_x).map_err(|_| DemoError::Crypto)?;
        getrandom::fill(&mut seed_sig).map_err(|_| DemoError::Crypto)?;
        Ok(Self::from_seeds(seed_pq, seed_x, seed_sig))
    }

    /// The server's ML-DSA-65 verifying key — the client pins this as the server
    /// identity (distributed out-of-band, not sent on the wire each handshake).
    #[must_use]
    pub fn verifying_key(&self) -> [u8; ML_DSA_65_VK_LEN] {
        self.verify_vk
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
}

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut x = Sha3_256Xof::new();
    for p in parts {
        x.absorb(p);
    }
    x.squeeze32()
}

fn profile_byte(p: Profile) -> u8 {
    match p {
        Profile::CompatXWing => 1,
        Profile::ContextBound => 2,
    }
}
fn profile_from(b: u8) -> Result<Profile, DemoError> {
    match b {
        1 => Ok(Profile::CompatXWing),
        2 => Ok(Profile::ContextBound),
        _ => Err(DemoError::Protocol),
    }
}

fn server_finished(secret: &Secret, context: &[u8]) -> [u8; 32] {
    sha3(&[secret.as_bytes(), SERVER_FINISHED_LABEL, context])
}

/// Run the **client** side of the handshake over `stream`, verifying the server's
/// signature against the pinned `server_vk` (its ML-DSA-65 verifying key).
pub fn client_handshake<S: Read + Write>(
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

    // 2. ServerHello = ek_pq(1184) || pk_x(32) || server_nonce(32)
    let sh = read_msg(stream)?;
    stats.bytes_recv += 4 + sh.len();
    let mut cur = Cursor::new(&sh);
    let ek_pq = cur.take(ML_KEM_768_PK_LEN)?;
    let pk_x = cur.take(X25519_LEN)?;
    let _server_nonce = cur.take(NONCE_LEN)?;

    // 3. Transcript context for the combiner (binds nonces, profile, server keys).
    let context = sha3(&[&ch, &sh]);

    // 4. Encapsulate to the server's static hybrid key.
    let (pq, trad) = (MlKem768, X25519);
    let kem = HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, SUITE_ID, POLICY_VERSION)?;
    let mut coins = [0u8; 64];
    getrandom::fill(&mut coins).map_err(|_| DemoError::Crypto)?;
    let (rand_pq, rand_trad) = coins.split_at(32);
    let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
    let mut ss_pq = [0u8; 32];
    let mut ct_trad = [0u8; X25519_LEN];
    let mut ss_trad = [0u8; 32];
    let secret = kem.encapsulate(
        ek_pq,
        pk_x,
        &context,
        rand_pq,
        rand_trad,
        &mut ct_pq,
        &mut ss_pq,
        &mut ct_trad,
        &mut ss_trad,
    )?;

    // 5. ClientKem = ct_pq(1088) || ct_trad(32)
    let mut kem_msg = Vec::with_capacity(ML_KEM_768_CT_LEN + X25519_LEN);
    kem_msg.extend_from_slice(&ct_pq);
    kem_msg.extend_from_slice(&ct_trad);
    stats.bytes_sent += write_msg(stream, &kem_msg)?;
    stats.messages += 1;

    // 6. ServerFinished = ml_dsa_signature(3309) || key_confirmation(32)
    let sf = read_msg(stream)?;
    stats.bytes_recv += 4 + sf.len();
    let mut cur = Cursor::new(&sf);
    let signature = cur.take(ML_DSA_65_SIG_LEN)?;
    let confirm = cur.take(32)?;

    // Server authentication: signature over the full transcript, pinned vk.
    let auth_transcript = sha3(&[&ch, &sh, &kem_msg]);
    MlDsa65
        .verify(server_vk, &auth_transcript, signature)
        .map_err(|_| DemoError::AuthFailed)?;

    // Key confirmation (constant-time).
    let expected = server_finished(&secret, &context);
    if ct_eq(confirm, &expected) != 0xFF {
        return Err(DemoError::ConfirmFailed);
    }

    Ok((secret, stats))
}

/// Run the **server** side of the handshake over `stream` using its static keys.
pub fn server_handshake<S: Read + Write>(
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

    // 2. ServerHello
    let mut server_nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut server_nonce).map_err(|_| DemoError::Crypto)?;
    let mut sh = Vec::with_capacity(ML_KEM_768_PK_LEN + X25519_LEN + NONCE_LEN);
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
    let ct_pq = cur.take(ML_KEM_768_CT_LEN)?;
    let ct_trad = cur.take(X25519_LEN)?;

    // 4. Decapsulate.
    let (pq, trad) = (MlKem768, X25519);
    let kem = HybridKem::<_, _, Sha3_256Xof>::new(&pq, &trad, profile, SUITE_ID, POLICY_VERSION)?;
    let mut ss_pq = [0u8; 32];
    let mut ss_trad = [0u8; 32];
    let secret = kem.decapsulate(
        &keys.dk_pq,
        ct_pq,
        &keys.ek_pq,
        &keys.sk_x,
        ct_trad,
        &keys.pk_x,
        &context,
        &mut ss_pq,
        &mut ss_trad,
    )?;

    // 5. ServerFinished = sign(transcript) || key_confirmation
    let auth_transcript = sha3(&[&ch, &sh, &kem_msg]);
    let mut sig_rand = [0u8; 32];
    getrandom::fill(&mut sig_rand).map_err(|_| DemoError::Crypto)?;
    let mut sig = [0u8; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(&keys.sign_sk, &auth_transcript, &sig_rand, &mut sig)
        .map_err(|_| DemoError::Crypto)?;
    let confirm = server_finished(&secret, &context);

    let mut sf = Vec::with_capacity(ML_DSA_65_SIG_LEN + 32);
    sf.extend_from_slice(&sig);
    sf.extend_from_slice(&confirm);
    stats.bytes_sent += write_msg(stream, &sf)?;
    stats.messages += 1;

    Ok((secret, stats))
}
