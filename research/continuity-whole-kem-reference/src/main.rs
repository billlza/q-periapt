// SPDX-License-Identifier: AGPL-3.0-only
//! Experimental component control, not a product protocol or a security proof.
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use prost::Message;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::Path,
    time::Instant,
};
use subtle::ConstantTimeEq;

const MESSAGES: usize = 2048;
const SEED: u64 = 0x5143505153524546;
const MAX_SKIPPED: usize = 2000;
const VERSION: u8 = 0xd1;
const IDLE: u32 = 0;
const OFFER: u32 = 1;
const ACCEPTED: u32 = 2;
const CIPHER: u32 = 3;
const ACK: u32 = 4;
const CUTS: [usize; 6] = [0, 1, 7, 63, 255, 1023];
type Result<T> = std::result::Result<T, Fault>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Invalid,
    Authentication,
    KeyUnavailable,
    Resource,
}
impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for Fault {}
fn require(value: bool, error: Fault) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(error)
    }
}
fn take<T>(value: Option<T>) -> Result<T> {
    value.ok_or(Fault::Invalid)
}
fn hash(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}
fn kdf(salt: &[u8], input: &[u8], info: &[u8], n: usize) -> Result<Vec<u8>> {
    let mut out = vec![0; n];
    Hkdf::<Sha256>::new(Some(salt), input)
        .expand(info, &mut out)
        .map_err(|_| Fault::Invalid)?;
    Ok(out)
}
fn proposer(epoch: u64) -> Result<u32> {
    require(epoch > 0, Fault::Invalid)?;
    u32::try_from((epoch - 1) % 2).map_err(|_| Fault::Invalid)
}
fn tag_data(profile: u32, sender: u32, kind: u8, epoch: u64, body: &[u8]) -> Vec<u8> {
    [
        b"QPWKR1:control".as_slice(),
        &profile.to_be_bytes(),
        &sender.to_be_bytes(),
        &[kind],
        &epoch.to_be_bytes(),
        body,
    ]
    .concat()
}
fn tag(root: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    require(root.len() == 32, Fault::Invalid)?;
    Ok(libcrux_hmac::hmac(
        libcrux_hmac::Algorithm::Sha256,
        root,
        data,
        Some(32),
    ))
}
fn check_tag(root: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let expected = tag(root, data)?;
    require(
        signature.ct_eq(expected.as_slice()).unwrap_u8() == 1,
        Fault::Authentication,
    )
}
fn material(
    root: &[u8],
    secret: &[u8],
    profile: u32,
    epoch: u64,
    key_id: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let info = [
        b"QPWKR1:root".as_slice(),
        &profile.to_be_bytes(),
        &epoch.to_be_bytes(),
        key_id,
        &hash(ciphertext),
    ]
    .concat();
    kdf(root, secret, &info, 96)
}
fn confirmation(key_id: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    hash(&[b"QPWKR1:confirmation".as_slice(), key_id, &hash(ciphertext)].concat())
}

#[derive(Clone, PartialEq, Message)]
struct Skipped {
    #[prost(uint32, tag = "1")]
    index: u32,
    #[prost(bytes = "vec", tag = "2")]
    key: Vec<u8>,
}
#[derive(Clone, PartialEq, Message)]
struct Epoch {
    #[prost(uint64, tag = "1")]
    number: u64,
    #[prost(bytes = "vec", tag = "2")]
    send_key: Vec<u8>,
    #[prost(uint32, tag = "3")]
    send_count: u32,
    #[prost(bytes = "vec", tag = "4")]
    receive_key: Vec<u8>,
    #[prost(uint32, tag = "5")]
    receive_count: u32,
    #[prost(uint32, tag = "6")]
    previous_send_count: u32,
    #[prost(uint32, tag = "7")]
    previous_receive_count: u32,
    #[prost(bool, tag = "8")]
    receive_seen: bool,
    #[prost(message, repeated, tag = "9")]
    skipped: Vec<Skipped>,
}
#[derive(Clone, PartialEq, Message)]
struct State {
    #[prost(uint32, tag = "1")]
    owner: u32,
    #[prost(uint32, tag = "2")]
    profile: u32,
    #[prost(uint64, tag = "3")]
    epoch: u64,
    #[prost(uint64, tag = "4")]
    confirmed_epoch: u64,
    #[prost(uint64, tag = "5")]
    send_epoch: u64,
    #[prost(uint64, tag = "6")]
    receive_epoch: u64,
    #[prost(bytes = "vec", tag = "7")]
    root: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    previous_root: Vec<u8>,
    #[prost(uint32, tag = "9")]
    phase: u32,
    #[prost(uint32, tag = "10")]
    countdown: u32,
    #[prost(bytes = "vec", tag = "11")]
    public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    private_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    key_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "14")]
    ciphertext: Vec<u8>,
    #[prost(bytes = "vec", tag = "15")]
    confirmation_id: Vec<u8>,
    #[prost(message, repeated, tag = "16")]
    chains: Vec<Epoch>,
}

fn next_key(seed: &mut Vec<u8>, counter: &mut u32) -> Result<Vec<u8>> {
    require(seed.len() == 32, Fault::KeyUnavailable)?;
    *counter = counter.checked_add(1).ok_or(Fault::Resource)?;
    let out = kdf(
        &[0; 32],
        seed,
        &[b"QPWKR1:message".as_slice(), &counter.to_be_bytes()].concat(),
        64,
    )?;
    let (next, key) = out.split_at(32);
    *seed = next.to_vec();
    Ok(key.to_vec())
}
impl State {
    fn initial(owner: u32, profile: u32) -> Result<Vec<u8>> {
        require(owner < 2 && matches!(profile, 1 | 32 | 64), Fault::Invalid)?;
        let out = kdf(
            &[0; 32],
            &[41; 32],
            &[b"QPWKR1:initial".as_slice(), &profile.to_be_bytes()].concat(),
            96,
        )?;
        let mut s = Self {
            owner,
            profile,
            ..Self::default()
        };
        s.install_material(0, &out)?;
        s.chain_mut(0)?.receive_seen = true;
        Ok(s.encode_to_vec())
    }
    fn read(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= 2 * 1024 * 1024, Fault::Resource)?;
        let s = Self::decode(bytes).map_err(|_| Fault::Invalid)?;
        require(s.encode_to_vec() == bytes, Fault::Invalid)?;
        require(
            s.owner < 2
                && matches!(s.profile, 1 | 32 | 64)
                && s.phase <= ACK
                && s.countdown < s.profile,
            Fault::Invalid,
        )?;
        require(
            s.root.len() == 32 && (s.previous_root.is_empty() || s.previous_root.len() == 32),
            Fault::Invalid,
        )?;
        require(
            s.send_epoch <= s.epoch && s.receive_epoch <= s.epoch && s.confirmed_epoch <= s.epoch,
            Fault::Invalid,
        )?;
        require(
            s.chains.len() <= MAX_SKIPPED + 3 && s.skipped_count() <= MAX_SKIPPED,
            Fault::Resource,
        )?;
        let mut epochs = BTreeSet::new();
        for chain in &s.chains {
            require(
                epochs.insert(chain.number) && chain.number <= s.epoch,
                Fault::Invalid,
            )?;
            require(
                (chain.send_key.is_empty() || chain.send_key.len() == 32)
                    && (chain.receive_key.is_empty() || chain.receive_key.len() == 32),
                Fault::Invalid,
            )?;
            let mut indices = BTreeSet::new();
            for key in &chain.skipped {
                require(
                    key.index > 0
                        && key.index <= chain.receive_count
                        && key.key.len() == 32
                        && indices.insert(key.index),
                    Fault::Invalid,
                )?;
            }
        }
        require(
            epochs.contains(&s.send_epoch)
                && epochs.contains(&s.receive_epoch)
                && epochs.contains(&s.epoch),
            Fault::Invalid,
        )?;
        require(
            match s.phase {
                OFFER => {
                    s.public_key.len() == 1184
                        && s.private_key.len() == 2400
                        && s.key_id.len() == 32
                }
                ACCEPTED => {
                    s.public_key.len() == 1184 && s.private_key.is_empty() && s.key_id.len() == 32
                }
                CIPHER => {
                    s.ciphertext.len() == 1088
                        && s.key_id.len() == 32
                        && s.confirmation_id.len() == 32
                        && s.private_key.is_empty()
                }
                ACK => {
                    s.confirmation_id.len() == 32
                        && s.key_id.len() == 32
                        && s.private_key.is_empty()
                }
                IDLE => s.private_key.is_empty(),
                _ => false,
            },
            Fault::Invalid,
        )?;
        Ok(s)
    }
    fn chain_mut(&mut self, epoch: u64) -> Result<&mut Epoch> {
        self.chains
            .iter_mut()
            .find(|c| c.number == epoch)
            .ok_or(Fault::KeyUnavailable)
    }
    fn skipped_count(&self) -> usize {
        self.chains.iter().map(|c| c.skipped.len()).sum()
    }
    fn install_material(&mut self, epoch: u64, bytes: &[u8]) -> Result<()> {
        require(bytes.len() == 96, Fault::Invalid)?;
        let (root, pair) = bytes.split_at(32);
        let (a, b) = pair.split_at(32);
        self.previous_root = std::mem::replace(&mut self.root, root.to_vec());
        self.epoch = epoch;
        self.chains.push(Epoch {
            number: epoch,
            send_key: if self.owner == 0 {
                a.to_vec()
            } else {
                b.to_vec()
            },
            receive_key: if self.owner == 0 {
                b.to_vec()
            } else {
                a.to_vec()
            },
            ..Epoch::default()
        });
        Ok(())
    }
    fn promote_send(&mut self) -> Result<()> {
        require(
            self.send_epoch.checked_add(1) == Some(self.epoch),
            Fault::Invalid,
        )?;
        let old = self.chain_mut(self.send_epoch)?;
        let previous = old.send_count;
        old.send_key.clear();
        self.send_epoch = self.epoch;
        self.chain_mut(self.send_epoch)?.previous_send_count = previous;
        Ok(())
    }
    fn prune(&mut self) {
        let floor = self.send_epoch.min(self.receive_epoch);
        self.chains
            .retain(|c| c.number >= floor || !c.receive_key.is_empty() || !c.skipped.is_empty());
    }
    fn receive_message_key(&mut self, p: &Packet) -> Result<Vec<u8>> {
        require(p.message_epoch <= self.epoch, Fault::Authentication)?;
        if p.message_epoch > self.receive_epoch {
            require(
                self.receive_epoch.checked_add(1) == Some(p.message_epoch),
                Fault::Authentication,
            )?;
            let total = self.skipped_count();
            let old = self.chain_mut(self.receive_epoch)?;
            require(p.previous >= old.receive_count, Fault::Authentication)?;
            let gap =
                usize::try_from(p.previous - old.receive_count).map_err(|_| Fault::Resource)?;
            require(gap <= 25_000 && total + gap <= MAX_SKIPPED, Fault::Resource)?;
            while old.receive_count < p.previous {
                let key = next_key(&mut old.receive_key, &mut old.receive_count)?;
                old.skipped.push(Skipped {
                    index: old.receive_count,
                    key,
                });
            }
            old.receive_key.clear();
            self.receive_epoch = p.message_epoch;
        }
        let total = self.skipped_count();
        let chain = self.chain_mut(p.message_epoch)?;
        if !chain.receive_seen {
            chain.previous_receive_count = p.previous;
            chain.receive_seen = true;
        }
        require(
            chain.previous_receive_count == p.previous,
            Fault::Authentication,
        )?;
        if p.index <= chain.receive_count {
            let at = chain
                .skipped
                .iter()
                .position(|k| k.index == p.index)
                .ok_or(Fault::KeyUnavailable)?;
            return Ok(chain.skipped.remove(at).key);
        }
        let gap =
            usize::try_from(p.index - chain.receive_count - 1).map_err(|_| Fault::Resource)?;
        require(gap < 25_000 && total + gap <= MAX_SKIPPED, Fault::Resource)?;
        while chain.receive_count + 1 < p.index {
            let key = next_key(&mut chain.receive_key, &mut chain.receive_count)?;
            chain.skipped.push(Skipped {
                index: chain.receive_count,
                key,
            });
        }
        next_key(&mut chain.receive_key, &mut chain.receive_count)
    }
    fn metadata(&self, bytes: usize) -> Value {
        json!({"known_epoch":self.epoch,"confirmed_epoch":self.confirmed_epoch,"send_epoch":self.send_epoch,
            "receive_epoch":self.receive_epoch,"phase":self.phase,"skipped_keys":self.skipped_count(),"bytes":bytes})
    }
}

struct Packet {
    profile: u32,
    message_epoch: u64,
    index: u32,
    previous: u32,
    kind: u8,
    epoch: u64,
    body: Vec<u8>,
}
fn put_var(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn get_var(bytes: &mut &[u8], maximum: u64) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = take(bytes.split_first())?;
        *bytes = rest;
        require(shift < 63 || byte <= 1, Fault::Invalid)?;
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            require(
                (shift == 0 || byte != 0) && value <= maximum,
                Fault::Invalid,
            )?;
            return Ok(value);
        }
    }
    Err(Fault::Invalid)
}
impl Packet {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = vec![
            VERSION,
            u8::try_from(self.profile).map_err(|_| Fault::Invalid)?,
        ];
        for value in [
            self.message_epoch,
            u64::from(self.index),
            u64::from(self.previous),
        ] {
            put_var(value, &mut out);
        }
        out.push(self.kind);
        if self.kind != 0 {
            put_var(self.epoch, &mut out);
            out.extend_from_slice(&self.body);
        }
        Ok(out)
    }
    fn read(wire: &[u8]) -> Result<Self> {
        require((6..=1250).contains(&wire.len()), Fault::Invalid)?;
        let (&version, rest) = take(wire.split_first())?;
        require(version == VERSION, Fault::Invalid)?;
        let (&profile, mut rest) = take(rest.split_first())?;
        require(matches!(profile, 1 | 32 | 64), Fault::Invalid)?;
        let message_epoch = get_var(&mut rest, u64::MAX)?;
        let index =
            u32::try_from(get_var(&mut rest, u64::from(u32::MAX))?).map_err(|_| Fault::Invalid)?;
        let previous =
            u32::try_from(get_var(&mut rest, u64::from(u32::MAX))?).map_err(|_| Fault::Invalid)?;
        require(index > 0, Fault::Invalid)?;
        let (&kind, tail) = take(rest.split_first())?;
        rest = tail;
        let epoch = if kind == 0 {
            0
        } else {
            get_var(&mut rest, u64::MAX)?
        };
        let expected = match kind {
            0 => 0,
            1 => 1216,
            2 => 1152,
            3 => 64,
            _ => return Err(Fault::Invalid),
        };
        require(
            match kind {
                0 => true,
                1 | 2 => message_epoch.checked_add(1) == Some(epoch),
                3 => message_epoch == epoch,
                _ => false,
            },
            Fault::Invalid,
        )?;
        require(
            rest.len() == expected && (kind == 0 || epoch > 0),
            Fault::Invalid,
        )?;
        Ok(Self {
            profile: u32::from(profile),
            message_epoch,
            index,
            previous,
            kind,
            epoch,
            body: rest.to_vec(),
        })
    }
}

fn send(state: &[u8], rng: &mut StdRng) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut s = State::read(state)?;
    if s.phase == ACCEPTED {
        let public = MlKem768PublicKey::from(
            <[u8; 1184]>::try_from(s.public_key.as_slice()).map_err(|_| Fault::Invalid)?,
        );
        require(
            mlkem768::validate_public_key(&public),
            Fault::Authentication,
        )?;
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        let (ciphertext, secret) = mlkem768::encapsulate(&public, seed);
        let epoch = s.epoch.checked_add(1).ok_or(Fault::Resource)?;
        let generated = material(
            &s.root,
            &secret,
            s.profile,
            epoch,
            &s.key_id,
            ciphertext.as_slice(),
        )?;
        s.ciphertext = ciphertext.as_slice().to_vec();
        s.confirmation_id = confirmation(&s.key_id, &s.ciphertext);
        s.install_material(epoch, &generated)?;
        s.public_key.clear();
        s.phase = CIPHER;
        s.countdown = 0;
    }
    if s.phase == IDLE
        && proposer(s.epoch.checked_add(1).ok_or(Fault::Resource)?)? == s.owner
        && s.countdown == 0
    {
        let mut seed = [0; 64];
        rng.fill_bytes(&mut seed);
        let pair = mlkem768::generate_key_pair(seed);
        s.public_key = pair.pk().to_vec();
        s.private_key = pair.sk().to_vec();
        s.key_id = hash(&s.public_key);
        s.phase = OFFER;
    }
    let mut packet = Packet {
        profile: s.profile,
        message_epoch: s.send_epoch,
        index: 0,
        previous: 0,
        kind: 0,
        epoch: 0,
        body: Vec::new(),
    };
    if matches!(s.phase, OFFER | CIPHER | ACK) && s.countdown == 0 {
        let (kind, epoch, body) = match s.phase {
            OFFER => (
                1,
                s.epoch.checked_add(1).ok_or(Fault::Resource)?,
                s.public_key.clone(),
            ),
            CIPHER => (
                2,
                s.epoch,
                [s.key_id.as_slice(), s.ciphertext.as_slice()].concat(),
            ),
            ACK => (3, s.epoch, s.confirmation_id.clone()),
            _ => return Err(Fault::Invalid),
        };
        let signature = tag(&s.root, &tag_data(s.profile, s.owner, kind, epoch, &body))?;
        packet.kind = kind;
        packet.epoch = epoch;
        packet.body = [body, signature].concat();
        s.countdown = s.profile - 1;
    } else if s.countdown > 0 {
        s.countdown -= 1;
    }
    let chain = s.chain_mut(s.send_epoch)?;
    let key = next_key(&mut chain.send_key, &mut chain.send_count)?;
    packet.index = chain.send_count;
    packet.previous = chain.previous_send_count;
    s.prune();
    Ok((s.encode_to_vec(), packet.encode()?, key))
}

fn control(s: &mut State, p: &Packet) -> Result<()> {
    if p.kind == 0 {
        return Ok(());
    }
    let split = p.body.len().checked_sub(32).ok_or(Fault::Invalid)?;
    let (body, signature) = p.body.split_at(split);
    let peer = 1 - s.owner;
    require(
        proposer(p.epoch)? == if p.kind == 2 { s.owner } else { peer },
        Fault::Authentication,
    )?;
    if p.epoch < s.epoch {
        return Ok(());
    }
    let authenticated = tag_data(s.profile, peer, p.kind, p.epoch, body);
    match p.kind {
        1 if p.epoch == s.epoch.checked_add(1).ok_or(Fault::Resource)? => {
            check_tag(&s.root, &authenticated, signature)?;
            let id = hash(body);
            if s.phase == ACCEPTED {
                return require(
                    id == s.key_id && body == s.public_key,
                    Fault::Authentication,
                );
            }
            require(matches!(s.phase, IDLE | ACK), Fault::Authentication)?;
            let public =
                MlKem768PublicKey::from(<[u8; 1184]>::try_from(body).map_err(|_| Fault::Invalid)?);
            require(
                mlkem768::validate_public_key(&public),
                Fault::Authentication,
            )?;
            s.public_key = body.to_vec();
            s.key_id = id;
            s.ciphertext.clear();
            s.phase = ACCEPTED;
            s.countdown = 0;
        }
        1 if p.epoch == s.epoch && s.phase == CIPHER => {
            check_tag(&s.previous_root, &authenticated, signature)?;
            require(hash(body) == s.key_id, Fault::Authentication)?;
        }
        1 if p.epoch <= s.confirmed_epoch => {}
        2 if p.epoch == s.epoch.checked_add(1).ok_or(Fault::Resource)? && s.phase == OFFER => {
            let (id, ct) = body.split_at(32);
            require(id == s.key_id, Fault::Authentication)?;
            let private = MlKem768PrivateKey::from(
                <[u8; 2400]>::try_from(s.private_key.as_slice()).map_err(|_| Fault::Invalid)?,
            );
            let ciphertext =
                MlKem768Ciphertext::from(<[u8; 1088]>::try_from(ct).map_err(|_| Fault::Invalid)?);
            require(
                mlkem768::validate_private_key(&private, &ciphertext),
                Fault::Authentication,
            )?;
            let secret = mlkem768::decapsulate(&private, &ciphertext);
            let generated = material(&s.root, &secret, s.profile, p.epoch, id, ct)?;
            check_tag(take(generated.get(..32))?, &authenticated, signature)?;
            s.confirmation_id = confirmation(id, ct);
            s.install_material(p.epoch, &generated)?;
            s.promote_send()?;
            s.private_key.clear();
            s.public_key.clear();
            s.ciphertext.clear();
            s.confirmed_epoch = s.epoch;
            s.phase = ACK;
            s.countdown = 0;
        }
        2 if p.epoch == s.epoch && s.confirmed_epoch == s.epoch => {
            let (id, ct) = body.split_at(32);
            check_tag(&s.root, &authenticated, signature)?;
            require(
                confirmation(id, ct) == s.confirmation_id,
                Fault::Authentication,
            )?;
            if s.phase == ACK {
                s.countdown = 0;
            }
        }
        3 if p.epoch == s.epoch => {
            check_tag(&s.root, &authenticated, signature)?;
            require(body == s.confirmation_id, Fault::Authentication)?;
            if s.phase == CIPHER {
                s.promote_send()?;
                s.confirmed_epoch = s.epoch;
                s.phase = IDLE;
                s.countdown = s.profile - 1;
                s.ciphertext.clear();
            } else {
                require(s.confirmed_epoch == s.epoch, Fault::Authentication)?;
            }
        }
        _ => return Err(Fault::Authentication),
    }
    Ok(())
}
fn receive(state: &[u8], wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut s = State::read(state)?;
    let packet = Packet::read(wire)?;
    require(s.profile == packet.profile, Fault::Authentication)?;
    control(&mut s, &packet)?;
    let key = s.receive_message_key(&packet)?;
    s.prune();
    Ok((s.encode_to_vec(), key))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn record(file: &mut File, value: Value) -> std::result::Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *file, &value)?;
    file.write_all(b"\n")?;
    Ok(())
}
struct Flight {
    sequence: usize,
    sender: usize,
    wire: Vec<u8>,
    key: Vec<u8>,
}
struct PublicFlight {
    sequence: usize,
    sender: usize,
    wire: Vec<u8>,
}
struct Snapshot {
    cut: usize,
    owner: usize,
    state: State,
}
fn predict(state: &mut State, packet: &Packet, sender: usize) -> Result<Option<Vec<u8>>> {
    let Some(chain) = state
        .chains
        .iter_mut()
        .find(|c| c.number == packet.message_epoch)
    else {
        return Ok(None);
    };
    let (seed, counter) = if sender == usize::try_from(state.owner).map_err(|_| Fault::Invalid)? {
        (&mut chain.send_key, &mut chain.send_count)
    } else {
        (&mut chain.receive_key, &mut chain.receive_count)
    };
    if packet.index <= *counter {
        return Ok(chain
            .skipped
            .iter()
            .find(|k| k.index == packet.index)
            .map(|k| k.key.clone()));
    }
    if seed.is_empty() {
        return Ok(None);
    }
    require(packet.index - *counter <= 25_000, Fault::Resource)?;
    let mut key = None;
    while *counter < packet.index {
        key = Some(next_key(seed, counter)?);
    }
    Ok(key)
}
impl Snapshot {
    fn recover_pending(&mut self, public: &[PublicFlight]) -> Result<Option<Value>> {
        if self.state.phase != OFFER {
            return Ok(None);
        }
        let epoch = self.state.epoch.checked_add(1).ok_or(Fault::Resource)?;
        for flight in public {
            let packet = Packet::read(&flight.wire)?;
            if packet.kind != 2 || packet.epoch != epoch || flight.sender == self.owner {
                continue;
            }
            let (id, tail) = packet.body.split_at(32);
            let (ct, signature) = tail.split_at(1088);
            require(id == self.state.key_id, Fault::Authentication)?;
            let sk = MlKem768PrivateKey::from(
                <[u8; 2400]>::try_from(self.state.private_key.as_slice())
                    .map_err(|_| Fault::Invalid)?,
            );
            let ct =
                MlKem768Ciphertext::from(<[u8; 1088]>::try_from(ct).map_err(|_| Fault::Invalid)?);
            let secret = mlkem768::decapsulate(&sk, &ct);
            let generated = material(
                &self.state.root,
                &secret,
                self.state.profile,
                epoch,
                id,
                ct.as_slice(),
            )?;
            let body = take(packet.body.get(..1120))?;
            check_tag(
                take(generated.get(..32))?,
                &tag_data(self.state.profile, 1 - self.state.owner, 2, epoch, body),
                signature,
            )?;
            self.state.install_material(epoch, &generated)?;
            return Ok(Some(
                json!({"epoch":epoch,"public_ciphertext_complete_at":flight.sequence}),
            ));
        }
        Ok(None)
    }
    fn report(mut self, public: &[PublicFlight], expected: &[Vec<u8>]) -> Result<Value> {
        let current = self.state.epoch;
        let phase = self.state.phase;
        let pending = if phase == OFFER {
            Some(current.checked_add(1).ok_or(Fault::Resource)?)
        } else {
            None
        };
        let recovered = self.recover_pending(public)?;
        let mut predicted = Vec::new();
        let mut unknown = Vec::new();
        let mut negative = None;
        for flight in public.iter().filter(|f| f.sequence >= self.cut) {
            let packet = Packet::read(&flight.wire)?;
            let mut wrong = if negative.is_none() {
                Some(self.state.clone())
            } else {
                None
            };
            if let Some(state) = &mut wrong {
                for chain in &mut state.chains {
                    for seed in [&mut chain.send_key, &mut chain.receive_key] {
                        if let Some(byte) = seed.first_mut() {
                            *byte ^= 1;
                        }
                    }
                }
            }
            match predict(&mut self.state, &packet, flight.sender)? {
                Some(key) => {
                    let actual = take(expected.get(flight.sequence))?;
                    require(&key == actual, Fault::Authentication)?;
                    if let Some(mut state) = wrong {
                        let incorrect = take(predict(&mut state, &packet, flight.sender)?)?;
                        require(&incorrect != actual, Fault::Invalid)?;
                        negative = Some(flight.sequence);
                    }
                    predicted.push(flight.sequence);
                }
                None => unknown.push(flight.sequence),
            }
        }
        require(!predicted.is_empty() && negative.is_some(), Fault::Invalid)?;
        Ok(
            json!({"cut_before_send":self.cut,"owner":self.owner,"snapshot_epoch":current,"snapshot_phase":phase,
            "stolen_pending_dk_epoch":pending,"recovered_pending_epoch":recovered,"predicted_sequences":predicted,
            "not_derived_sequences":unknown,"wrong_key_control_mismatch_at":negative}),
        )
    }
}
struct Run {
    states: [Vec<u8>; 2],
    trace: File,
    keys: BTreeSet<Vec<u8>>,
    sent: usize,
    received: usize,
    dropped: usize,
    duplicates: usize,
    wire_bytes: usize,
    peak_wire: usize,
    peak_state: usize,
    send_ns: Vec<u128>,
    receive_ns: Vec<u128>,
    snapshots: Vec<Snapshot>,
    public: Vec<PublicFlight>,
    expected: Vec<Vec<u8>>,
}
impl Run {
    fn send(
        &mut self,
        sequence: usize,
        sender: usize,
        rng: &mut StdRng,
    ) -> std::result::Result<Flight, Box<dyn Error>> {
        let state = take(self.states.get_mut(sender))?;
        let start = Instant::now();
        let (next, wire, key) = send(state, rng)?;
        self.send_ns.push(start.elapsed().as_nanos());
        *state = next;
        require(
            key.len() == 32 && self.keys.insert(key.clone()),
            Fault::Invalid,
        )?;
        self.public.push(PublicFlight {
            sequence,
            sender,
            wire: wire.clone(),
        });
        self.expected.push(key.clone());
        self.sent += 1;
        self.wire_bytes += wire.len();
        self.peak_wire = self.peak_wire.max(wire.len());
        self.peak_state = self.peak_state.max(state.len());
        record(
            &mut self.trace,
            json!({"event":"send","sequence":sequence,"sender":sender,"wire":hex(&wire),"state":State::read(state)?.metadata(state.len())}),
        )?;
        Ok(Flight {
            sequence,
            sender,
            wire,
            key,
        })
    }
    fn receive(
        &mut self,
        flight: Flight,
        duplicate: bool,
    ) -> std::result::Result<(), Box<dyn Error>> {
        let receiver = 1 - flight.sender;
        let state = take(self.states.get_mut(receiver))?;
        let start = Instant::now();
        let (next, key) = receive(state, &flight.wire)?;
        self.receive_ns.push(start.elapsed().as_nanos());
        require(key == flight.key, Fault::Authentication)?;
        *state = next;
        self.received += 1;
        self.peak_state = self.peak_state.max(state.len());
        record(
            &mut self.trace,
            json!({"event":"receive","sequence":flight.sequence,"receiver":receiver,"key_matches":true,"state":State::read(state)?.metadata(state.len())}),
        )?;
        if duplicate {
            require(
                matches!(receive(state, &flight.wire), Err(Fault::KeyUnavailable)),
                Fault::Invalid,
            )?;
            self.duplicates += 1;
            record(
                &mut self.trace,
                json!({"event":"duplicate","sequence":flight.sequence,"receiver":receiver,"outcome":"KeyUnavailable"}),
            )?;
        }
        Ok(())
    }
}
fn scenario(output: &Path, name: &str, profile: u32) -> std::result::Result<Value, Box<dyn Error>> {
    let path = output.join(format!("{name}.jsonl"));
    let mut run = Run {
        states: [State::initial(0, profile)?, State::initial(1, profile)?],
        trace: File::create_new(&path)?,
        keys: BTreeSet::new(),
        sent: 0,
        received: 0,
        dropped: 0,
        duplicates: 0,
        wire_bytes: 0,
        peak_wire: 0,
        peak_state: 0,
        send_ns: Vec::new(),
        receive_ns: Vec::new(),
        snapshots: Vec::new(),
        public: Vec::new(),
        expected: Vec::new(),
    };
    record(
        &mut run.trace,
        json!({"event":"configuration","schema":1,"construction":"experimental_whole_kem_v1","profile":profile,"scenario":name,"messages":MESSAGES,"seed":SEED,"public_test_entropy":true,"max_skipped":MAX_SKIPPED}),
    )?;
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut queue = Vec::new();
    for sequence in 0..MESSAGES {
        if CUTS.contains(&sequence) {
            for (owner, state) in run.states.iter().enumerate() {
                run.snapshots.push(Snapshot {
                    cut: sequence,
                    owner,
                    state: State::read(state)?,
                });
            }
        }
        let sender = match name {
            "one_way" => 0,
            "asymmetric" => usize::from(sequence % 10 == 9),
            "offline_then_exchange" if sequence < 256 => 0,
            _ => sequence % 2,
        };
        let flight = run.send(sequence, sender, &mut rng)?;
        if name == "lossy" && sequence % 10 == 4 {
            run.dropped += 1;
            record(&mut run.trace, json!({"event":"drop","sequence":sequence}))?;
        } else if name == "reordered" {
            queue.push(flight);
            if sequence % 7 == 6 {
                while let Some(flight) = queue.pop() {
                    run.receive(flight, false)?;
                }
            }
        } else if name == "offline_then_exchange" && sequence < 256 {
            queue.push(flight);
        } else {
            if name == "offline_then_exchange" && sequence == 256 {
                for flight in queue.drain(..) {
                    run.receive(flight, false)?;
                }
            }
            run.receive(flight, name == "duplicates" && sequence % 13 == 0)?;
        }
    }
    for flight in queue {
        run.receive(flight, false)?;
    }
    let a = take(run.states.first())?;
    let b = take(run.states.get(1))?;
    let a = State::read(a)?.metadata(a.len());
    let b = State::read(b)?.metadata(b.len());
    require(
        run.sent == MESSAGES && run.received + run.dropped == MESSAGES,
        Fault::Invalid,
    )?;
    if name == "one_way" {
        require(
            a.get("known_epoch").and_then(Value::as_u64) == Some(0)
                && b.get("known_epoch").and_then(Value::as_u64) == Some(0),
            Fault::Invalid,
        )?;
    }
    let summary = json!({"event":"summary","scenario":name,"sent":run.sent,"delivered":run.received,"dropped":run.dropped,"duplicates_rejected":run.duplicates,"unique_message_keys":run.keys.len(),"wire_bytes":run.wire_bytes,"peak_wire_bytes":run.peak_wire,"peak_serialized_state_bytes":run.peak_state,"final_a":a,"final_b":b});
    record(&mut run.trace, summary.clone())?;
    run.trace.sync_all()?;
    let cases = run
        .snapshots
        .into_iter()
        .map(|s| s.report(&run.public, &run.expected))
        .collect::<Result<Vec<_>>>()?;
    require(cases.len() == 12, Fault::Invalid)?;
    let mut compromise = File::create_new(output.join(format!("{name}.compromise.json")))?;
    serde_json::to_writer(
        &mut compromise,
        &json!({"schema":1,"construction":"experimental_whole_kem_v1","profile":profile,
        "scenario":name,"public_test_entropy":true,"interpretation":"passive retrospective derivation; not_derived is not a recovery claim","cases":cases}),
    )?;
    compromise.write_all(b"\n")?;
    compromise.sync_all()?;
    Ok(
        json!({"summary":summary,"trace_sha256":hex(&Sha256::digest(fs::read(path)?)),"send_ns":run.send_ns,"receive_ns":run.receive_ns}),
    )
}
fn main() -> std::result::Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let output = args
        .next()
        .ok_or_else(|| io::Error::other("new output directory required"))?;
    require(args.next().is_none(), Fault::Invalid)?;
    let output = Path::new(&output);
    fs::create_dir(output)?;
    for profile in [1, 32, 64] {
        let directory = output.join(format!("period-{profile}"));
        fs::create_dir(&directory)?;
        let mut runs = Vec::new();
        for name in [
            "ping_pong",
            "lossy",
            "reordered",
            "duplicates",
            "asymmetric",
            "offline_then_exchange",
            "one_way",
        ] {
            runs.push(scenario(&directory, name, profile)?);
        }
        let mut report = File::create_new(directory.join("report.json"))?;
        serde_json::to_writer_pretty(
            &mut report,
            &json!({"schema":1,"construction":"experimental_whole_kem_v1","profile":profile,"production_claim_eligible":false,"runs":runs}),
        )?;
        report.write_all(b"\n")?;
        report.sync_all()?;
    }
    println!(
        "WHOLE_KEM_REFERENCE_PASS profiles=3 scenarios=21 sends={}",
        MESSAGES * 21
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};

    // The attacker receives exactly B's initial serialized session state once.
    // It never receives a later honest state, private KEM input or RNG state.
    // Both impersonated roles are reconstructed from that one disclosure, then
    // evolve using ordinary protocol calls, public packets and attacker entropy.
    struct ActiveFork {
        toward_a: Vec<u8>,
        toward_b: Vec<u8>,
        rng: StdRng,
    }
    impl ActiveFork {
        fn from_initial_b_disclosure(stolen: &[u8]) -> Result<Self> {
            let mut opposite = State::read(stolen)?;
            require(
                opposite.owner == 1
                    && opposite.epoch == 0
                    && opposite.confirmed_epoch == 0
                    && opposite.phase == IDLE
                    && opposite.private_key.is_empty()
                    && opposite.chains.len() == 1,
                Fault::Invalid,
            )?;
            opposite.owner = 0;
            for chain in &mut opposite.chains {
                require(
                    chain.number == 0 && chain.send_count == 0 && chain.receive_count == 0,
                    Fault::Invalid,
                )?;
                std::mem::swap(&mut chain.send_key, &mut chain.receive_key);
                std::mem::swap(
                    &mut chain.previous_send_count,
                    &mut chain.previous_receive_count,
                );
            }
            let toward_b = opposite.encode_to_vec();
            State::read(&toward_b)?;
            Ok(Self {
                toward_a: stolen.to_vec(),
                toward_b,
                rng: StdRng::seed_from_u64(SEED ^ 0x41545441434b),
            })
        }
        fn replace(&mut self, sender: u32, wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            let (source, destination) = match sender {
                0 => (&mut self.toward_a, &mut self.toward_b),
                1 => (&mut self.toward_b, &mut self.toward_a),
                _ => return Err(Fault::Invalid),
            };
            let (received, intercepted_key) = receive(source, wire)?;
            *source = received;
            let (sent, replacement, replacement_key) = send(destination, &mut self.rng)?;
            *destination = sent;
            Ok((replacement, intercepted_key, replacement_key))
        }
    }

    #[test]
    fn confirmed_fresh_epochs_do_not_end_continuous_active_session_impersonation(
    ) -> std::result::Result<(), Box<dyn Error>> {
        let mut cases = Vec::new();
        for profile in [1, 32, 64] {
            let mut a = State::initial(0, profile)?;
            let mut b = State::initial(1, profile)?;
            let mut attacker = ActiveFork::from_initial_b_disclosure(&b)?;
            let mut a_rng = StdRng::seed_from_u64(SEED ^ 0x484f4e45535441);
            let mut b_rng = StdRng::seed_from_u64(SEED ^ 0x484f4e45535442);
            let mut rows = Vec::new();
            let mut divergent_keys = 0;
            let mut divergent_packets = 0;
            for sequence in 0..512 {
                let sender = sequence % 2;
                let (origin, destination, entropy) = if sender == 0 {
                    (&mut a, &mut b, &mut a_rng)
                } else {
                    (&mut b, &mut a, &mut b_rng)
                };
                let (sent, wire, sender_key) = send(origin, entropy)?;
                *origin = sent;
                if sequence == 0 {
                    let mut wrong = State::read(&attacker.toward_a)?;
                    *take(wrong.root.first_mut())? ^= 1;
                    assert!(
                        matches!(
                            receive(&wrong.encode_to_vec(), &wire),
                            Err(Fault::Authentication)
                        ),
                        "a fork without the disclosed authenticator must fail"
                    );
                }
                let (replacement, intercepted_key, replacement_key) =
                    attacker.replace(sender, &wire)?;
                let (accepted, receiver_key) = receive(destination, &replacement)?;
                *destination = accepted;
                assert_eq!(sender_key, intercepted_key);
                assert_eq!(receiver_key, replacement_key);
                divergent_keys += usize::from(sender_key != receiver_key);
                divergent_packets += usize::from(wire != replacement);
                let original = Packet::read(&wire)?;
                let substituted = Packet::read(&replacement)?;
                rows.push(json!({
                    "sequence":sequence,"sender":sender,
                    "original_wire":hex(&wire),"replacement_wire":hex(&replacement),
                    "original_message_epoch":original.message_epoch,
                    "replacement_message_epoch":substituted.message_epoch,
                    "sender_key_sha256":hex(&hash(&sender_key)),
                    "attacker_received_key_sha256":hex(&hash(&intercepted_key)),
                    "attacker_sent_key_sha256":hex(&hash(&replacement_key)),
                    "receiver_key_sha256":hex(&hash(&receiver_key)),
                    "honest_a_confirmed_epoch":State::read(&a)?.confirmed_epoch,
                    "honest_b_confirmed_epoch":State::read(&b)?.confirmed_epoch,
                }));
            }
            let a = State::read(&a)?;
            let b = State::read(&b)?;
            assert!(a.confirmed_epoch >= 3 && b.confirmed_epoch >= 3);
            assert!(divergent_packets > 0 && divergent_keys > 0);
            assert_ne!(
                a.root, b.root,
                "the honest endpoints confirm different attacker-held roots"
            );
            cases.push(
                json!({"profile":profile,"events":rows,"intercepted_keys":512,
                "divergent_message_keys":divergent_keys,"replaced_packets":divergent_packets,
                "confirmed_a":a.confirmed_epoch,"confirmed_b":b.confirmed_epoch,
                "wrong_authenticator_rejected":true}),
            );
        }
        let report = json!({"schema":1,"construction":"experimental_whole_kem_v1",
            "experiment":"continuous_active_fork_after_initial_b_session_disclosure",
            "public_test_entropy":true,"production_claim_eligible":false,
            "attacker_inputs":"one initial B session snapshot, public packets, own entropy",
            "interpretation":"confirmed fresh epochs do not establish recovery while session-authenticator impersonation continues; component key exposure, not full application execution",
            "cases":cases});
        if let Some(path) = std::env::var_os("QPERIAPT_WHOLE_KEM_ACTIVE_REPORT") {
            let mut file = File::create_new(path)?;
            serde_json::to_writer_pretty(&mut file, &report)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        println!("WHOLE_KEM_ACTIVE_FORK_PASS profiles=3 intercepted_keys=1536 wrong_authenticator_controls=3");
        Ok(())
    }

    #[test]
    fn control_mac_matches_independent_hmac_sha256() -> Result<()> {
        for length in [0, 9, 1024] {
            let input = vec![91; length];
            let key = [37; 32];
            let mut independent =
                Hmac::<Sha256>::new_from_slice(&key).map_err(|_| Fault::Invalid)?;
            independent.update(&input);
            assert_eq!(
                tag(&key, &input)?,
                independent.finalize().into_bytes().to_vec()
            );
        }
        Ok(())
    }
    #[test]
    fn three_flights_confirm_both_roles_and_reject_duplicate_keys() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let a = State::initial(0, 1)?;
        let b = State::initial(1, 1)?;
        let (a, offer, key) = send(&a, &mut rng)?;
        let (b, received) = receive(&b, &offer)?;
        assert_eq!(key, received);
        let (b, cipher, key) = send(&b, &mut rng)?;
        assert_eq!(State::read(&b)?.confirmed_epoch, 0);
        let (a, received) = receive(&a, &cipher)?;
        assert_eq!(key, received);
        assert_eq!(State::read(&a)?.confirmed_epoch, 1);
        let (a, ack, key) = send(&a, &mut rng)?;
        let (b, received) = receive(&b, &ack)?;
        assert_eq!(key, received);
        assert_eq!(State::read(&b)?.confirmed_epoch, 1);
        assert_eq!(State::read(&a)?.private_key.len(), 0);
        assert!(matches!(receive(&b, &ack), Err(Fault::KeyUnavailable)));
        Ok(())
    }
    #[test]
    fn corrupted_control_never_returns_candidate_state() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let a = State::initial(0, 1)?;
        let b = State::initial(1, 1)?;
        let (a, offer, _) = send(&a, &mut rng)?;
        let (b, _) = receive(&b, &offer)?;
        let (_, cipher, _) = send(&b, &mut rng)?;
        for original in [&offer, &cipher] {
            let mut bad = original.clone();
            *take(bad.last_mut())? ^= 1;
            let target = if original == &offer {
                State::initial(1, 1)?
            } else {
                a.clone()
            };
            let before = target.clone();
            assert!(matches!(receive(&target, &bad), Err(Fault::Authentication)));
            assert_eq!(target, before);
        }
        assert!(receive(&State::initial(1, 32)?, &offer).is_err());
        Ok(())
    }

    #[test]
    fn lost_confirmation_replays_one_ciphertext_without_replacing_entropy() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let (a, offer, _) = send(&State::initial(0, 1)?, &mut rng)?;
        let (b, _) = receive(&State::initial(1, 1)?, &offer)?;
        let (b, cipher, _) = send(&b, &mut rng)?;
        let (a, _) = receive(&a, &cipher)?;
        let (a, lost_ack, lost_key) = send(&a, &mut rng)?;
        let mut unchanged_rng = rng.clone();
        let (b, repeated_cipher, _) = send(&b, &mut rng)?;
        assert_eq!(rng.next_u64(), unchanged_rng.next_u64());
        assert_eq!(
            Packet::read(&cipher)?.body,
            Packet::read(&repeated_cipher)?.body
        );
        assert_eq!(State::read(&b)?.confirmed_epoch, 0);
        let (a, _) = receive(&a, &repeated_cipher)?;
        let (_, ack, key) = send(&a, &mut rng)?;
        let (b, received) = receive(&b, &ack)?;
        assert_eq!(key, received);
        let (b, offer2, _) = send(&b, &mut rng)?;
        assert_eq!(Packet::read(&offer2)?.epoch, 2);
        let before = State::read(&b)?;
        let (b, received) = receive(&b, &lost_ack)?;
        assert_eq!(received, lost_key);
        let after = State::read(&b)?;
        assert_eq!(before.private_key, after.private_key);
        assert_eq!(before.epoch, after.epoch);
        assert_eq!(after.phase, OFFER);
        assert!(matches!(receive(&b, &lost_ack), Err(Fault::KeyUnavailable)));
        Ok(())
    }

    #[test]
    fn conflicting_authenticated_offer_cannot_replace_selected_key() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let a = State::initial(0, 1)?;
        let b = State::initial(1, 1)?;
        let (_, offer, _) = send(&a, &mut rng)?;
        let (selected, _) = receive(&b, &offer)?;
        let (_, conflict, _) = send(&a, &mut rng)?;
        assert_ne!(Packet::read(&offer)?.body, Packet::read(&conflict)?.body);
        assert!(matches!(
            receive(&selected, &conflict),
            Err(Fault::Authentication)
        ));
        assert!(matches!(receive(&a, &offer), Err(Fault::Authentication)));
        Ok(())
    }

    #[test]
    fn altered_kem_ciphertext_rejects_implicit_output_at_confirmation() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let (a, offer, _) = send(&State::initial(0, 1)?, &mut rng)?;
        let (b, _) = receive(&State::initial(1, 1)?, &offer)?;
        let (_, cipher, _) = send(&b, &mut rng)?;
        let mut packet = Packet::read(&cipher)?;
        *take(packet.body.get_mut(40))? ^= 1;
        assert!(matches!(
            receive(&a, &packet.encode()?),
            Err(Fault::Authentication)
        ));
        let (restored, _) = receive(&a, &cipher)?;
        assert_eq!(State::read(&restored)?.confirmed_epoch, 1);
        Ok(())
    }

    #[test]
    fn excessive_key_jump_does_not_publish_prepared_offer_state() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let b = State::initial(1, 1)?;
        let (_, offer, _) = send(&State::initial(0, 1)?, &mut rng)?;
        let mut packet = Packet::read(&offer)?;
        packet.index = 25_002;
        assert!(matches!(
            receive(&b, &packet.encode()?),
            Err(Fault::Resource)
        ));
        assert_eq!(State::read(&b)?.phase, IDLE);
        let (accepted, _) = receive(&b, &offer)?;
        assert_eq!(State::read(&accepted)?.phase, ACCEPTED);
        Ok(())
    }

    #[test]
    fn parser_rejects_unknown_profiles_aliases_and_extra_bytes() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let (_, wire, _) = send(&State::initial(0, 1)?, &mut rng)?;
        let mut profile = wire.clone();
        *take(profile.get_mut(1))? = 0;
        let mut trailing = wire.clone();
        trailing.push(0);
        let mut alias = wire.clone();
        alias.splice(2..3, [0x80, 0]);
        for bad in [Vec::new(), profile, trailing, alias] {
            assert!(Packet::read(&bad).is_err());
        }
        let mut state = State::initial(0, 1)?;
        state.extend_from_slice(&[0xa0, 0x06, 1]);
        assert!(State::read(&state).is_err());
        Ok(())
    }

    #[test]
    fn control_key_epochs_have_no_alternate_header_interpretation() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(SEED);
        let (a, offer, _) = send(&State::initial(0, 1)?, &mut rng)?;
        let (b, _) = receive(&State::initial(1, 1)?, &offer)?;
        let (_, cipher, _) = send(&b, &mut rng)?;
        let (a, _) = receive(&a, &cipher)?;
        let (_, ack, _) = send(&a, &mut rng)?;
        for wire in [&offer, &cipher, &ack] {
            let mut packet = Packet::read(wire)?;
            packet.message_epoch = if packet.kind == 3 { 0 } else { packet.epoch };
            assert!(Packet::read(&packet.encode()?).is_err());
        }
        Ok(())
    }
}
