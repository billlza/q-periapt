// SPDX-License-Identifier: AGPL-3.0-only
//! Reference-only driver. Public deterministic test seeds; no production key inputs.
use prost::Message;
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spqr::{ChainParams, Direction, Params, SerializedState, Version};
use std::{
    collections::BTreeSet,
    error::Error,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::Path,
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const REVISION: &str = "f2589fef855c10f39d72634dab3d14654dd410bf";
const MESSAGES: usize = 2048;
const SEED: u64 = 0x5143505153524546;

fn require(value: bool, detail: &str) -> Result<()> {
    if !value {
        return Err(io::Error::other(detail).into());
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn initial(direction: Direction, auth: &[u8]) -> Result<SerializedState> {
    Ok(spqr::initial_state(Params {
        direction,
        version: Version::V1,
        min_version: Version::V1,
        auth_key: auth,
        chain_params: ChainParams::default(),
    })?)
}
fn metadata(state: &SerializedState) -> Result<Value> {
    let decoded = spqr::proto::pq_ratchet::PqRatchetState::decode(state.as_slice())?;
    let (epoch, send_epoch) = decoded
        .chain
        .map_or((0, 0), |chain| (chain.current_epoch, chain.send_epoch));
    Ok(json!({"epoch":epoch,"send_epoch":send_epoch,"bytes":state.len()}))
}
fn event(writer: &mut BufWriter<File>, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}
struct Packet {
    sequence: usize,
    sender: usize,
    wire: Vec<u8>,
    key: Vec<u8>,
}
struct Run {
    states: [SerializedState; 2],
    writer: BufWriter<File>,
    sent_keys: BTreeSet<Vec<u8>>,
    send_ns: Vec<u128>,
    receive_ns: Vec<u128>,
    delivered: usize,
    dropped: usize,
    duplicates: usize,
    bytes: usize,
    peak_wire: usize,
    peak_state: usize,
}
impl Run {
    fn send(&mut self, sequence: usize, sender: usize, rng: &mut StdRng) -> Result<Packet> {
        let state = self
            .states
            .get_mut(sender)
            .ok_or_else(|| io::Error::other("sender"))?;
        let start = Instant::now();
        let result = spqr::send(state, rng)?;
        self.send_ns.push(start.elapsed().as_nanos());
        let key = result
            .key
            .ok_or_else(|| io::Error::other("required v1 did not produce a message key"))?;
        require(
            key.len() == 32 && self.sent_keys.insert(key.clone()),
            "repeated or malformed message key",
        )?;
        *state = result.state;
        self.bytes += result.msg.len();
        self.peak_wire = self.peak_wire.max(result.msg.len());
        self.peak_state = self.peak_state.max(state.len());
        event(
            &mut self.writer,
            &json!({"event":"send","sequence":sequence,"sender":sender,
            "wire":hex(&result.msg),"state":metadata(state)?}),
        )?;
        Ok(Packet {
            sequence,
            sender,
            wire: result.msg,
            key,
        })
    }
    fn receive(&mut self, packet: Packet, duplicate: bool) -> Result<()> {
        let receiver = 1 - packet.sender;
        let state = self
            .states
            .get_mut(receiver)
            .ok_or_else(|| io::Error::other("receiver"))?;
        let start = Instant::now();
        let result = spqr::recv(state, &packet.wire)?;
        self.receive_ns.push(start.elapsed().as_nanos());
        require(
            result.key.as_deref() == Some(packet.key.as_slice()),
            "sender/receiver message keys differ",
        )?;
        *state = result.state;
        self.peak_state = self.peak_state.max(state.len());
        self.delivered += 1;
        event(
            &mut self.writer,
            &json!({"event":"receive","sequence":packet.sequence,"receiver":receiver,
            "key_matches":true,"state":metadata(state)?}),
        )?;
        if duplicate {
            require(
                matches!(
                    spqr::recv(state, &packet.wire),
                    Err(spqr::Error::KeyAlreadyRequested(_))
                ),
                "immediate duplicate returned another key",
            )?;
            self.duplicates += 1;
            event(
                &mut self.writer,
                &json!({"event":"duplicate","sequence":packet.sequence,
                "receiver":receiver,"outcome":"KeyAlreadyRequested"}),
            )?;
        }
        Ok(())
    }
}
fn timings(values: &[u128]) -> Value {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let quantile = |n: usize| {
        sorted
            .get((sorted.len().saturating_sub(1) * n) / 100)
            .copied()
    };
    json!({"samples":values.len(),"p50_ns":quantile(50),"p95_ns":quantile(95),
        "p99_ns":quantile(99),"max_ns":sorted.last(),"raw_ns":values})
}
fn scenario(output: &Path, name: &str) -> Result<Value> {
    let trace_path = output.join(format!("{name}.jsonl"));
    let file = File::create_new(&trace_path)?;
    let mut run = Run {
        states: [
            initial(Direction::A2B, &[41; 32])?,
            initial(Direction::B2A, &[41; 32])?,
        ],
        writer: BufWriter::new(file),
        sent_keys: BTreeSet::new(),
        send_ns: Vec::new(),
        receive_ns: Vec::new(),
        delivered: 0,
        dropped: 0,
        duplicates: 0,
        bytes: 0,
        peak_wire: 0,
        peak_state: 0,
    };
    event(
        &mut run.writer,
        &json!({"event":"configuration","schema":1,"upstream":REVISION,
        "scenario":name,"seed":SEED,"messages":MESSAGES,"version":1,"minimum_version":1,
        "max_jump":25000,"max_out_of_order":2000,"chunk_bytes":32}),
    )?;
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut queue = Vec::new();
    for sequence in 0..MESSAGES {
        let sender = match name {
            "one_way" => 0,
            "asymmetric" => usize::from(sequence % 10 == 9),
            "offline_then_exchange" if sequence < 256 => 0,
            _ => sequence % 2,
        };
        let packet = run.send(sequence, sender, &mut rng)?;
        if name == "lossy" && sequence % 10 == 4 {
            run.dropped += 1;
            event(
                &mut run.writer,
                &json!({"event":"drop","sequence":sequence}),
            )?;
        } else if name == "reordered" {
            queue.push(packet);
            if sequence % 7 == 6 {
                while let Some(packet) = queue.pop() {
                    run.receive(packet, false)?;
                }
            }
        } else if name == "offline_then_exchange" && sequence < 256 {
            queue.push(packet);
        } else {
            // Offline transport retains exact bytes and delivers before resumed conversation.
            if name == "offline_then_exchange" && sequence == 256 {
                for packet in queue.drain(..) {
                    run.receive(packet, false)?;
                }
            }
            run.receive(packet, name == "duplicates" && sequence % 13 == 0)?;
        }
    }
    for packet in queue {
        run.receive(packet, false)?;
    }
    let a = metadata(
        run.states
            .first()
            .ok_or_else(|| io::Error::other("state A"))?,
    )?;
    let b = metadata(
        run.states
            .get(1)
            .ok_or_else(|| io::Error::other("state B"))?,
    )?;
    let epoch_a = a
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| io::Error::other("epoch A"))?;
    let epoch_b = b
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or_else(|| io::Error::other("epoch B"))?;
    require(run.delivered + run.dropped == MESSAGES, "packet accounting")?;
    if name == "one_way" {
        require(
            epoch_a == 0 && epoch_b == 0,
            "one-way schedule claimed fresh PQ progress",
        )?;
    } else {
        require(
            epoch_a >= 3 && epoch_b >= 3,
            "duplex corpus did not reach three fresh epochs",
        )?;
    }
    let summary = json!({"event":"summary","scenario":name,"sent":MESSAGES,"delivered":run.delivered,
        "dropped":run.dropped,"duplicates_rejected":run.duplicates,"unique_message_keys":run.sent_keys.len(),
        "wire_bytes":run.bytes,"peak_wire_bytes":run.peak_wire,"peak_serialized_state_bytes":run.peak_state,
        "final_a":a,"final_b":b});
    event(&mut run.writer, &summary)?;
    run.writer.flush()?;
    run.writer.get_ref().sync_all()?;
    Ok(
        json!({"summary":summary,"trace_sha256":hex(&Sha256::digest(fs::read(trace_path)?)),
        "send":timings(&run.send_ns),"receive":timings(&run.receive_ns)}),
    )
}
fn controls() -> Result<Value> {
    let a = initial(Direction::A2B, &[41; 32])?;
    let b = initial(Direction::B2A, &[41; 32])?;
    require(
        matches!(spqr::recv(&b, &vec![0]), Err(spqr::Error::MinimumVersion)),
        "downgrade accepted",
    )?;
    let future = spqr::recv(&b, &vec![255])?;
    require(
        future.state == b && future.key.is_none(),
        "unknown version changed state or produced a key",
    )?;
    let mut wrong = initial(Direction::B2A, &[42; 32])?;
    let mut sender = a;
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut provisional = 0;
    let mut rejected_at = None;
    for sequence in 0..4 {
        let result = spqr::send(&sender, &mut rng)?;
        sender = result.state;
        match spqr::recv(&wrong, &result.msg) {
            Ok(received) => {
                require(
                    received.key != result.key,
                    "wrong initial secret yielded same key",
                )?;
                wrong = received.state;
                provisional += 1;
            }
            Err(spqr::Error::MacVerifyFailed) => {
                rejected_at = Some(sequence);
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    require(
        rejected_at.is_some(),
        "wrong authenticator never rejected completed header",
    )?;
    Ok(
        json!({"downgrade":"MinimumVersion","unknown_version":"ignored_without_key_or_state_change",
        "wrong_auth_provisional_key_mismatches":provisional,"wrong_auth_mac_rejected_at":rejected_at,
        "outer_message_authentication_required_before_state_commit":true}),
    )
}
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let output = args
        .next()
        .ok_or_else(|| io::Error::other("usage: q-periapt-spqr-reference NEW_OUTPUT_DIRECTORY"))?;
    require(args.next().is_none(), "unexpected arguments")?;
    let output = Path::new(&output);
    fs::create_dir(output)?;
    let mut results = Vec::new();
    for name in [
        "ping_pong",
        "lossy",
        "reordered",
        "duplicates",
        "asymmetric",
        "offline_then_exchange",
        "one_way",
    ] {
        results.push(scenario(output, name)?);
    }
    let report = json!({"schema":1,"upstream_revision":REVISION,"driver":"public_api_v1",
        "measurement":"single-process reference component CPU time; no transport, storage, energy or application AEAD",
        "production_claim_eligible":false,"controls":controls()?,"runs":results});
    let mut file = File::create_new(output.join("report.json"))?;
    serde_json::to_writer_pretty(&mut file, &report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!(
        "SPQR_REFERENCE_PASS scenarios=7 sends={} minimum_version=1",
        MESSAGES * 7
    );
    Ok(())
}
