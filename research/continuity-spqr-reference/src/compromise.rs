// SPDX-License-Identifier: AGPL-3.0-only
//! Passive, retrospective snapshot attacker. Never receives future private state or RNG.
//! Failure to derive a key here is not a proof that no attacker can derive it.
use crate::{require, Result};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem768::incremental;
use prost::Message;
use serde_json::{json, Value};
use sha2::Sha256;
use spqr::{
    encoding::{polynomial::PolyDecoder, Chunk, Decoder},
    proto::pq_ratchet as pb,
    SerializedState,
};
use std::{collections::BTreeMap, io};

pub const CUTS: [usize; 6] = [0, 1, 7, 63, 255, 1023];

fn need<T>(value: Option<T>, detail: &str) -> Result<T> {
    value.ok_or_else(|| io::Error::other(detail).into())
}

fn kdf(salt: &[u8], input: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
    let mut output = vec![0; length];
    Hkdf::<Sha256>::new(Some(salt), input)
        .expand(info, &mut output)
        .map_err(|_| io::Error::other("snapshot oracle KDF length"))?;
    Ok(output)
}

fn varint(bytes: &mut &[u8], maximum: u64) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = need(bytes.split_first(), "truncated public varint")?;
        *bytes = rest;
        require(shift < 63 || byte <= 1, "public varint overflow")?;
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            require(shift == 0 || byte != 0, "aliased public varint")?;
            require(value <= maximum, "public integer range")?;
            return Ok(value);
        }
    }
    Err(io::Error::other("unterminated public varint").into())
}

struct PublicPacket {
    sequence: usize,
    sender: usize,
    epoch: u64,
    index: u32,
    kind: u8,
    chunk: Option<Chunk>,
}

impl PublicPacket {
    fn decode(sequence: usize, sender: usize, wire: &[u8]) -> Result<Self> {
        require(
            sender < 2 && (4..=52).contains(&wire.len()),
            "public packet shape",
        )?;
        let (&version, mut rest) = need(wire.split_first(), "missing version")?;
        require(version == 1, "public version")?;
        let epoch = varint(&mut rest, u64::MAX)?;
        let index = u32::try_from(varint(&mut rest, u64::from(u32::MAX))?)?;
        require(epoch > 0 && index > 0, "zero public epoch/index")?;
        let (&kind, tail) = need(rest.split_first(), "missing message kind")?;
        rest = tail;
        require(kind <= 6, "public message kind")?;
        let chunk = if kind == 0 || kind == 4 {
            require(rest.is_empty(), "unexpected control payload")?;
            None
        } else {
            let index = u16::try_from(varint(&mut rest, u64::from(u16::MAX))?)?;
            Some(Chunk {
                index,
                data: rest.try_into()?,
            })
        };
        Ok(Self {
            sequence,
            sender,
            epoch,
            index,
            kind,
            chunk,
        })
    }
}

#[derive(Clone)]
struct Direction {
    counter: u32,
    next: Vec<u8>,
    retained: BTreeMap<u32, Vec<u8>>,
}

impl Direction {
    fn from_snapshot(value: pb::chain::epoch::EpochDirection) -> Result<Self> {
        require(
            value.next.is_empty() || value.next.len() == 32,
            "snapshot chain key size",
        )?;
        require(
            value.prev.len().is_multiple_of(36),
            "snapshot skipped key size",
        )?;
        let mut retained = BTreeMap::new();
        for record in value.prev.as_chunks::<36>().0 {
            let (index, key) = record.split_at(4);
            let index = u32::from_be_bytes(index.try_into()?);
            require(
                retained.insert(index, key.to_vec()).is_none(),
                "duplicate retained key",
            )?;
        }
        Ok(Self {
            counter: value.ctr,
            next: value.next,
            retained,
        })
    }

    fn fresh(next: &[u8]) -> Self {
        Self {
            counter: 0,
            next: next.to_vec(),
            retained: BTreeMap::new(),
        }
    }

    fn predict(&mut self, index: u32) -> Result<Option<Vec<u8>>> {
        if index <= self.counter {
            return Ok(self.retained.get(&index).cloned());
        }
        if self.next.is_empty() {
            return Ok(None);
        }
        require(
            index - self.counter <= 25_000,
            "snapshot prediction work bound",
        )?;
        while self.counter < index {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| io::Error::other("chain overflow"))?;
            let info = [
                self.counter.to_be_bytes().as_slice(),
                b"Signal PQ Ratchet V1 Chain Next",
            ]
            .concat();
            let output = kdf(&[0; 32], &self.next, &info, 64)?;
            let (next, key) = output.split_at(32);
            self.next = next.to_vec();
            self.retained.insert(self.counter, key.to_vec());
        }
        Ok(self.retained.get(&index).cloned())
    }
}

struct Snapshot {
    cut: usize,
    owner: usize,
    current_epoch: u64,
    next_root: Vec<u8>,
    directions: BTreeMap<(usize, u64), Direction>,
    pending_dk: Option<(u64, Vec<u8>)>,
    state_kind: &'static str,
}

impl Snapshot {
    fn capture(cut: usize, owner: usize, state: &SerializedState) -> Result<Self> {
        let decoded = pb::PqRatchetState::decode(state.as_slice())?;
        let mut directions = BTreeMap::new();
        let (current_epoch, next_root) = if let Some(chain) = decoded.chain {
            require(
                usize::try_from(chain.direction)? == owner,
                "snapshot direction",
            )?;
            require(chain.next_root.len() == 32, "snapshot root size")?;
            let first = (chain.current_epoch + 1)
                .checked_sub(u64::try_from(chain.links.len())?)
                .ok_or_else(|| io::Error::other("snapshot epoch history"))?;
            for (offset, link) in chain.links.into_iter().enumerate() {
                let epoch = first + u64::try_from(offset)?;
                directions.insert(
                    (owner, epoch),
                    Direction::from_snapshot(need(link.send, "snapshot send chain")?)?,
                );
                directions.insert(
                    (1 - owner, epoch),
                    Direction::from_snapshot(need(link.recv, "snapshot receive chain")?)?,
                );
            }
            (chain.current_epoch, chain.next_root)
        } else {
            let negotiation = need(decoded.version_negotiation, "snapshot initial secret")?;
            require(
                usize::try_from(negotiation.direction)? == owner && negotiation.min_version == 1,
                "snapshot initial profile",
            )?;
            let output = kdf(
                &[0; 32],
                &negotiation.auth_key,
                b"Signal PQ Ratchet V1 Chain  Start",
                96,
            )?;
            let (root, pair) = output.split_at(32);
            let (a, b) = pair.split_at(32);
            directions.insert((0, 0), Direction::fresh(a));
            directions.insert((1, 0), Direction::fresh(b));
            (0, root.to_vec())
        };
        let pb::pq_ratchet_state::Inner::V1(inner) = need(decoded.inner, "snapshot v1")?;
        use pb::v1_state::InnerState as S;
        let (state_kind, pending_dk) = match need(inner.inner_state, "snapshot braid state")? {
            S::KeysUnsampled(_) => ("KeysUnsampled", None),
            S::KeysSampled(s) => {
                let s = need(s.uc, "sampled key state")?;
                ("KeysSampled", Some((s.epoch, s.dk)))
            }
            S::HeaderSent(s) => {
                let s = need(s.uc, "header state")?;
                ("HeaderSent", Some((s.epoch, s.dk)))
            }
            S::Ct1Received(s) => {
                let s = need(s.uc, "ct1 state")?;
                ("Ct1Received", Some((s.epoch, s.dk)))
            }
            S::EkSentCt1Received(s) => {
                let s = need(s.uc, "ct2 decoder state")?;
                ("EkSentCt1Received", Some((s.epoch, s.dk)))
            }
            S::NoHeaderReceived(_) => ("NoHeaderReceived", None),
            S::HeaderReceived(_) => ("HeaderReceived", None),
            S::Ct1Sampled(_) => ("Ct1Sampled", None),
            S::EkReceivedCt1Sampled(_) => ("EkReceivedCt1Sampled", None),
            S::Ct1Acknowledged(_) => ("Ct1Acknowledged", None),
            S::Ct2Sampled(_) => ("Ct2Sampled", None),
        };
        if let Some((epoch, dk)) = &pending_dk {
            require(
                *epoch == current_epoch + 1 && dk.len() == 2400,
                "snapshot pending KEM epoch/key",
            )?;
        }
        Ok(Self {
            cut,
            owner,
            current_epoch,
            next_root,
            directions,
            pending_dk,
            state_kind,
        })
    }

    fn recover_pending(&mut self, packets: &[PublicPacket]) -> Result<Option<Value>> {
        let Some((epoch, dk)) = &self.pending_dk else {
            return Ok(None);
        };
        let mut ct1_decoder = PolyDecoder::new(960)?;
        let mut ct2_decoder = PolyDecoder::new(160)?;
        for packet in packets {
            if packet.epoch != *epoch || packet.sender == self.owner {
                continue;
            }
            if let Some(chunk) = &packet.chunk {
                match packet.kind {
                    5 => ct1_decoder.add_chunk(chunk),
                    6 => ct2_decoder.add_chunk(chunk),
                    _ => continue,
                }
            }
            if let (Some(ct1), Some(ct2_mac)) =
                (ct1_decoder.decoded_message(), ct2_decoder.decoded_message())
            {
                let ct1 = incremental::Ciphertext1 {
                    value: ct1.as_slice().try_into()?,
                };
                let (ct2, _) = ct2_mac.split_at(128);
                let ct2 = incremental::Ciphertext2 {
                    value: ct2.try_into()?,
                };
                let secret =
                    incremental::decapsulate_compressed_key(dk.as_slice().try_into()?, &ct1, &ct2);
                let info = [
                    b"Signal_PQCKA_V1_MLKEM768:SCKA Key".as_slice(),
                    &epoch.to_be_bytes(),
                ]
                .concat();
                let epoch_key = kdf(&[0; 32], &secret, &info, 32)?;
                let output = kdf(
                    &self.next_root,
                    &epoch_key,
                    b"Signal PQ Ratchet V1 Chain Add Epoch",
                    96,
                )?;
                let (_, pair) = output.split_at(32);
                let (a, b) = pair.split_at(32);
                self.directions.insert((0, *epoch), Direction::fresh(a));
                self.directions.insert((1, *epoch), Direction::fresh(b));
                return Ok(Some(
                    json!({"epoch":epoch,"public_ciphertext_complete_at":packet.sequence}),
                ));
            }
        }
        Ok(None)
    }

    fn predict(&mut self, packet: &PublicPacket) -> Result<Option<Vec<u8>>> {
        match self.directions.get_mut(&(packet.sender, packet.epoch - 1)) {
            Some(direction) => direction.predict(packet.index),
            None => Ok(None),
        }
    }

    fn wrong_prediction(&self, packet: &PublicPacket) -> Result<Option<Vec<u8>>> {
        let Some(direction) = self.directions.get(&(packet.sender, packet.epoch - 1)) else {
            return Ok(None);
        };
        let mut wrong = direction.clone();
        if let Some(byte) = wrong.next.first_mut() {
            *byte ^= 1;
        }
        for key in wrong.retained.values_mut() {
            if let Some(byte) = key.first_mut() {
                *byte ^= 1;
            }
        }
        wrong.predict(packet.index)
    }
}

#[derive(Default)]
pub struct Experiment {
    snapshots: Vec<Snapshot>,
    packets: Vec<PublicPacket>,
    // Ground truth stays outside the attacker interface and is never serialized.
    expected: Vec<Vec<u8>>,
}

impl Experiment {
    pub fn capture(&mut self, sequence: usize, states: &[SerializedState; 2]) -> Result<()> {
        if CUTS.contains(&sequence) {
            for (owner, state) in states.iter().enumerate() {
                self.snapshots
                    .push(Snapshot::capture(sequence, owner, state)?);
            }
        }
        Ok(())
    }

    pub fn sent(&mut self, sequence: usize, sender: usize, wire: &[u8], key: &[u8]) -> Result<()> {
        require(
            sequence == self.packets.len() && key.len() == 32,
            "compromise packet order/key",
        )?;
        self.packets
            .push(PublicPacket::decode(sequence, sender, wire)?);
        self.expected.push(key.to_vec());
        Ok(())
    }

    pub fn report(self, scenario: &str) -> Result<Value> {
        require(self.snapshots.len() == CUTS.len() * 2, "snapshot coverage")?;
        let mut cases = Vec::new();
        for mut snapshot in self.snapshots {
            let recovered = snapshot.recover_pending(&self.packets)?;
            let mut predicted = Vec::new();
            let mut unknown = Vec::new();
            let mut counterfactual_mismatch = None;
            let cut = snapshot.cut;
            for packet in self.packets.iter().filter(|p| p.sequence >= cut) {
                let wrong = if counterfactual_mismatch.is_none() {
                    snapshot.wrong_prediction(packet)?
                } else {
                    None
                };
                match snapshot.predict(packet)? {
                    Some(key) => {
                        let expected =
                            need(self.expected.get(packet.sequence), "missing ground truth")?;
                        require(
                            &key == expected,
                            "snapshot attacker predicted an incorrect message key",
                        )?;
                        // A wrong stolen chain key must not receive the same success label.
                        if counterfactual_mismatch.is_none() {
                            let wrong = need(wrong, "wrong stolen chain did not derive a key")?;
                            require(&wrong != expected, "negative control unexpectedly matched")?;
                            counterfactual_mismatch = Some(packet.sequence);
                        }
                        predicted.push(packet.sequence);
                    }
                    None => unknown.push(packet.sequence),
                }
            }
            require(
                !predicted.is_empty(),
                "snapshot failed to expose any future chain key",
            )?;
            if scenario == "one_way" {
                require(
                    unknown.is_empty(),
                    "one-way chain unexpectedly escaped predictor",
                )?;
            }
            cases.push(json!({"cut_before_send":snapshot.cut,"owner":snapshot.owner,
                "snapshot_chain_epoch":snapshot.current_epoch,"snapshot_braid_state":snapshot.state_kind,
                "stolen_pending_dk_epoch":snapshot.pending_dk.as_ref().map(|(epoch,_)|epoch),
                "recovered_pending_epoch":recovered,"predicted_sequences":predicted,
                "not_derived_sequences":unknown,"wrong_key_control_mismatch_at":counterfactual_mismatch}));
        }
        Ok(
            json!({"schema":1,"scenario":scenario,"upstream_revision":crate::REVISION,"public_test_entropy":true,
            "threat":"one endpoint state snapshot; passive full public transcript; no future private state or RNG",
            "interpretation":"retrospective key derivation, not a security proof or recovery claim",
            "cases":cases}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spqr::{chain::Chain, ChainParams, EpochSecret};

    #[test]
    fn independent_chain_kdf_matches_both_directions_and_epochs() -> Result<()> {
        for (sender, direction) in [(0, spqr::Direction::A2B), (1, spqr::Direction::B2A)] {
            let mut actual =
                Chain::new(&[41; 32], direction, ChainParams::default().into_pb_test())?;
            let initial = crate::initial(direction, &[41; 32])?;
            let mut attacker = Snapshot::capture(0, sender, &initial)?;
            for _ in 0..9 {
                let (index, key) = actual.send_key(0)?;
                let chain = need(attacker.directions.get_mut(&(sender, 0)), "test chain")?;
                require(chain.predict(index)? == Some(key), "independent chain KDF")?;
            }
            let secret = vec![17; 32];
            actual.add_epoch(EpochSecret {
                epoch: 1,
                secret: secret.clone(),
            });
            let expanded = kdf(
                &attacker.next_root,
                &secret,
                b"Signal PQ Ratchet V1 Chain Add Epoch",
                96,
            )?;
            let (_, pair) = expanded.split_at(32);
            let (a, b) = pair.split_at(32);
            let mut next = Direction::fresh(if sender == 0 { a } else { b });
            let (index, key) = actual.send_key(1)?;
            require(next.predict(index)? == Some(key), "independent epoch KDF")?;
        }
        Ok(())
    }

    #[test]
    fn erased_and_consumed_keys_are_distinct_from_retained_keys() -> Result<()> {
        let retained = [1u32.to_be_bytes().as_slice(), &[29; 32]].concat();
        let mut direction = Direction::from_snapshot(pb::chain::epoch::EpochDirection {
            ctr: 5,
            next: Vec::new(),
            prev: retained,
        })?;
        require(
            direction.predict(1)? == Some(vec![29; 32]),
            "retained skipped key",
        )?;
        require(
            direction.predict(3)?.is_none(),
            "consumed key was recreated",
        )?;
        require(
            direction.predict(6)?.is_none(),
            "erased chain was recreated",
        )?;
        Ok(())
    }

    #[test]
    fn public_decoder_rejects_ambiguous_or_truncated_wire() {
        for wire in [
            vec![],
            vec![0, 1, 1, 0],
            vec![1, 0, 1, 0],
            vec![1, 1, 0, 0],
            vec![1, 0x81, 0, 1, 0],
            vec![1, 1, 1, 7],
            vec![1, 1, 1, 0, 0],
            vec![1, 1, 1, 5, 0],
            vec![
                1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 1, 0,
            ],
        ] {
            assert!(PublicPacket::decode(0, 0, &wire).is_err());
        }
    }
}
