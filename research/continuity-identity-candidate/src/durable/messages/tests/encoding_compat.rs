// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Frozen pre-change State/Traffic byte reference from d71c6fc126fa78b56ab1073a574b13e7a99168e1.
//! The old growing serializers are test-only; every unit-test State encoding compares
//! its bytes here, including reserved/control phases reached by existing fault tests.
use super::*;

pub(in crate::durable::messages) fn check(state: &State, encoded: &[u8]) {
    assert!(
        encoded == legacy_state(state).as_slice(),
        "persisted session bytes changed"
    );
}

fn legacy_state(state: &State) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(STATE_TAG.to_vec());
    bytes.extend_from_slice(&state.source);
    bytes.extend_from_slice(&state.session);
    bytes.push(state.role);
    bytes.extend_from_slice(state.rekey.as_bytes());
    bytes.extend_from_slice(&state.send_epoch.to_be_bytes());
    bytes.extend_from_slice(&state.receive_epoch.to_be_bytes());
    bytes.push(state.epochs.len() as u8);
    for value in state.epochs.values() {
        let encoded = legacy_traffic(value);
        bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    state.control.encode(&mut bytes);
    crate::durable::messages::closure::encode_pending(&state.closure, &mut bytes);
    bytes
}

fn legacy_traffic(traffic: &Traffic) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(b"QPTEPO04".to_vec());
    bytes.extend_from_slice(&traffic.epoch.to_be_bytes());
    bytes.push(u8::from(traffic.send_closed));
    bytes.push(u8::from(traffic.receive_limit.is_some()));
    if let Some(limit) = traffic.receive_limit {
        bytes.extend_from_slice(&limit.to_be_bytes());
    }
    traffic.resolution.encode(&mut bytes);
    bytes.push(u8::from(traffic.resolution_key.is_some()));
    if let Some(key) = &traffic.resolution_key {
        bytes.extend_from_slice(key.as_bytes());
    }
    for k in [
        &traffic.send,
        &traffic.receive,
        &traffic.send_ack,
        &traffic.receive_ack,
    ] {
        bytes.extend_from_slice(k.as_bytes());
    }
    bytes.extend_from_slice(&traffic.send_floor.to_be_bytes());
    bytes.extend_from_slice(&traffic.receive_floor.to_be_bytes());
    bytes.extend_from_slice(&traffic.sent.to_be_bytes());
    bytes.extend_from_slice(&traffic.received.to_be_bytes());
    bytes.extend_from_slice(&(traffic.skipped.len() as u16).to_be_bytes());
    for (index, k) in &traffic.skipped {
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(k.as_bytes());
    }
    bytes.push(u8::from(traffic.pending.is_some()));
    if let Some(plan) = &traffic.pending {
        bytes.extend_from_slice(&plan.id.0);
        bytes.push(u8::from(plan.fanout.is_some()));
        if let Some(fanout) = plan.fanout {
            bytes.extend_from_slice(fanout.as_bytes());
        }
        bytes.extend_from_slice(&(plan.plaintext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&plan.plaintext);
        bytes.extend_from_slice(&(plan.ad.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&plan.ad);
    }
    bytes.extend_from_slice(&(traffic.outgoing.len() as u16).to_be_bytes());
    for (id, saved) in &traffic.outgoing {
        bytes.extend_from_slice(&id.0);
        bytes.extend_from_slice(saved.intent.as_ref());
        bytes.extend_from_slice(&(saved.wire.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&saved.wire);
    }
    bytes.extend_from_slice(&(traffic.incoming.len() as u16).to_be_bytes());
    for (id, saved) in &traffic.incoming {
        bytes.extend_from_slice(&id.0);
        bytes.extend_from_slice(&saved.index.to_be_bytes());
        bytes.extend_from_slice(saved.intent.as_ref());
        bytes.push(u8::from(saved.consumed));
        bytes.extend_from_slice(&(saved.plaintext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&saved.plaintext);
    }
    bytes
}

#[test]
#[should_panic(expected = "persisted session bytes changed")]
fn legacy_state_oracle_rejects_an_altered_encoding() {
    let mut pair = Pair::new();
    pair.activate();
    let state = state(&mut pair.ji, &pair.session);
    let mut encoded = state.encode().expect("state encoding");
    *encoded.first_mut().expect("tag byte") ^= 1;
    check(&state, &encoded);
}
