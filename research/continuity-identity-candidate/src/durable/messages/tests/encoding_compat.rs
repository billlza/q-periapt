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

#[test]
fn intent_hash_keeps_frozen_field_and_domain_bindings() {
    // Independently computed SHA3-256 vectors for the pre-streaming encoding.
    struct Vector {
        domain: &'static [u8],
        first: &'static [u8],
        second: &'static [u8],
        expected: &'static str,
    }
    let cases = [
        Vector {
            domain: b"send-intent",
            first: b"",
            second: b"",
            expected: "1e69c70e9e2c7274d7749c2f4a69a202c4b13f724f1baad425a1a0c519fb7809",
        },
        Vector {
            domain: b"send-intent",
            first: b"a",
            second: b"bc",
            expected: "dfc649642521b991d27415bbd8bf2acaefa66788fd53e3d76c1ba00fa80ab09c",
        },
        Vector {
            domain: b"send-intent",
            first: b"ab",
            second: b"c",
            expected: "a9d19688fe32d08589a53a360ddb074467fd9acc19366f0f558bca31b33f0840",
        },
        Vector {
            domain: b"receive-intent",
            first: b"message",
            second: b"metadata",
            expected: "1983f4a9d1c9df8b5f6d8bd761ba7c0a09c4ccabaa9488551f6d46bafe3bcc7a",
        },
    ];
    for vector in cases {
        let actual: String = intent(vector.domain, vector.first, vector.second)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(actual, vector.expected);
    }
}

#[test]
fn intent_hash_matches_legacy_framing_at_rate_and_message_boundaries() {
    let maximum_wire = MAX_PLAINTEXT + MESSAGE_HEADER + 16;
    let first: Vec<u8> = (0..maximum_wire).map(|i| (i % 251) as u8).collect();
    let second = vec![0x7b; MAX_AD];
    for length in [
        0,
        1,
        7,
        8,
        127,
        128,
        135,
        136,
        137,
        255,
        256,
        271,
        272,
        273,
        1024,
        MAX_PLAINTEXT,
        maximum_wire,
    ] {
        for ad_length in [0, 1, 135, 136, 137, MAX_AD] {
            for name in [b"send-intent".as_slice(), b"receive-intent".as_slice()] {
                let plaintext = first.get(..length).expect("message boundary");
                let ad = second.get(..ad_length).expect("AD boundary");
                let mut legacy = Zeroizing::new(Vec::new());
                legacy.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
                legacy.extend_from_slice(plaintext);
                legacy.extend_from_slice(ad);
                assert_eq!(*intent(name, plaintext, ad), digest(&label(name), &legacy));
            }
        }
    }
}
