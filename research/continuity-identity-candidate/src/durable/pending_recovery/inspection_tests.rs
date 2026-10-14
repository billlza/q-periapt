// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public control-plane inspection is bounded and cannot substitute approval.
use super::*;
use crate::{
    retired_device as report, AnchorSubject, BootstrapRole, LeafKind, RosterCheckpoint, Validity,
};

fn scope() -> PendingWriteRecoveryScope {
    PendingWriteRecoveryScope {
        witness: [1; 32],
        subject: AnchorSubject::from_trusted_state(&[2; 96]).expect("valid inspection fixture"),
        expected: AnchorHead::from_trusted_state(1, 3, [3; 32]).expect("valid inspection fixture"),
        target: AnchorHead::from_trusted_state(1, 4, [4; 32]).expect("valid inspection fixture"),
        authority: [5; 32],
        policy: [6; 32],
        policy_authorization: Some([7; 32]),
        intent: [8; 32],
    }
}
fn message(value: u8) -> MessageId {
    MessageId::from_trusted_state([value; 32]).expect("valid inspection fixture")
}
fn checkpoint(version: u64) -> RosterCheckpoint {
    RosterCheckpoint::from_trusted_state(version, [9; 32]).expect("valid inspection fixture")
}
fn entry(
    id: u8,
    phase: DurableStatus,
    metadata: report::RecordMetadata,
) -> report::RecordMetadataEntry {
    report::RecordMetadataEntry {
        id: [id; 32],
        context: [10; 32],
        phase,
        authorities: vec![],
        one_time_claims: vec![],
        inventory_references: vec![],
        metadata,
    }
}
fn records() -> Vec<report::RecordMetadataEntry> {
    let operation =
        BootstrapOperationId::from_trusted_state([11; 32]).expect("valid inspection fixture");
    let bootstrap = BootstrapEntry {
        operation,
        context: [12; 32],
        role: BootstrapRole::Initiator,
        status: DurableStatus::BootstrapCancelled,
    };
    let flights = report::BootstrapFlights {
        initial: Some([13; 32]),
        reply: Some([14; 32]),
        final_confirmation: None,
        session: Some([15; 32]),
    };
    let cancelled = BootstrapCancellation {
        entry: bootstrap.clone(),
        previous: DurableStatus::AwaitingFinal,
        report: [16; 32],
        initial_hash: flights.initial,
        reply_hash: flights.reply,
        final_hash: flights.final_confirmation,
        session: flights.session,
        one_time_claims: vec![[17; 32]],
        inventory: vec![BootstrapPrekeyUse {
            request: PrekeyId::from_trusted_state([18; 32]).expect("valid inspection fixture"),
            kind: LeafKind::OneTimeClassical,
            disposition: BootstrapPrekeyDisposition::AbandonedByCancellation,
        }],
    };
    let empty = report::Epoch {
        accounting: AbandonedEpoch {
            epoch: 0,
            acknowledged_before: 0,
            sent: 0,
            consumed_before: 0,
            received: 0,
            peer_sent: None,
            resolution: EpochResolutionStatus::Unrequested,
            unconfirmed: vec![],
            deliveries: vec![],
            skipped: vec![],
        },
        consumed_out_of_order: vec![],
        reservation: None,
        send_closed: false,
    };
    let rich = report::Epoch {
        accounting: AbandonedEpoch {
            epoch: 1,
            acknowledged_before: 2,
            sent: 7,
            consumed_before: 3,
            received: 10,
            peer_sent: Some(12),
            resolution: EpochResolutionStatus::Pending(
                EpochResolutionId::from_trusted_state([19; 32]).expect("valid inspection fixture"),
            ),
            unconfirmed: vec![UnconfirmedMessage::from_recorded_metadata(
                message(20),
                [21; 32],
            )],
            deliveries: vec![AbandonedDelivery {
                message: message(22),
                index: 6,
                plaintext_bytes: 15,
            }],
            skipped: vec![9],
        },
        consumed_out_of_order: vec![report::ConsumedDelivery {
            message: message(23),
            index: 8,
        }],
        reservation: Some(report::Reservation {
            input: ReservedAbandonment {
                message: message(24),
                plaintext_bytes: 13,
                associated_data_bytes: 17,
            },
            fanout: Some(FanoutId::from_trusted_state([25; 32]).expect("valid inspection fixture")),
        }),
        send_closed: true,
    };
    let session = report::Session {
        source: operation,
        session: [26; 32],
        role: 1,
        peer_account: [27; 32],
        peer_device: [28; 16],
        peer_generation: 3,
        progress: RekeyProgress {
            confirmed_epoch: 0,
            sending_epoch: 1,
            receiving_epoch: 1,
            pending_epoch: Some(2),
        },
        state: report::SessionState::Live {
            epochs: vec![empty, rich],
            previous_closure: Some(
                SessionClosureId::from_trusted_state([29; 32]).expect("valid inspection fixture"),
            ),
        },
    };
    let terminal = report::Session {
        state: report::SessionState::Terminal {
            report: [30; 32],
            batch: Some(FanoutId::from_trusted_state([31; 32]).expect("valid inspection fixture")),
            pending: Some(message(32)),
            epochs: vec![report::TerminalEpoch {
                epoch: 0,
                sent: 9,
                acknowledged: 4,
                reservation_abandoned: true,
            }],
        },
        ..session.clone()
    };
    let members = [
        report::MemberState::Reserved,
        report::MemberState::Retained(FanoutMemberState::Committed),
        report::MemberState::Retained(FanoutMemberState::Acknowledged),
        report::MemberState::Retained(FanoutMemberState::ResolutionPending),
        report::MemberState::Retained(FanoutMemberState::DeliveryUnknown),
        report::MemberState::Retained(FanoutMemberState::HistoryRetired),
        report::MemberState::Retained(FanoutMemberState::ReservationAbandoned),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, state)| report::Member {
        device: [u8::try_from(i + 1).expect("valid inspection fixture"); 16],
        generation: u64::try_from(i + 1).expect("valid inspection fixture"),
        credential: [33; 32],
        context: [34; 32],
        session: [35; 32],
        role: 2,
        message: message(36 + u8::try_from(i).expect("valid inspection fixture")),
        state,
        ciphertext_digest: if i == 0 || i == 6 {
            None
        } else {
            Some([44; 32])
        },
    })
    .collect();
    vec![
        entry(
            1,
            DurableStatus::BootstrapCancelled,
            report::RecordMetadata::Bootstrap {
                entry: bootstrap,
                request: Some(
                    InitiationId::from_trusted_state([45; 32]).expect("valid inspection fixture"),
                ),
                flights,
                cancellation: Some(Box::new(cancelled)),
            },
        ),
        entry(
            2,
            DurableStatus::PrekeyConsumed,
            report::RecordMetadata::Prekey {
                request: PrekeyId::from_trusted_state([46; 32]).expect("valid inspection fixture"),
                kind: LeafKind::OneTimePq,
                validity: Validity::new(100, 200).expect("valid inspection fixture"),
                public_fingerprint: Some([47; 32]),
                source: Some(operation),
            },
        ),
        entry(
            3,
            DurableStatus::Messages,
            report::RecordMetadata::Session(session),
        ),
        entry(
            4,
            DurableStatus::MessagesClosed,
            report::RecordMetadata::Session(terminal),
        ),
        entry(
            5,
            DurableStatus::Roster,
            report::RecordMetadata::Roster {
                account: [48; 32],
                checkpoint: checkpoint(2),
                public_history: b"opaque public signed roster bytes".to_vec(),
            },
        ),
        entry(
            6,
            DurableStatus::FanoutAbandoned,
            report::RecordMetadata::Fanout {
                batch: FanoutId::from_trusted_state([49; 32]).expect("valid inspection fixture"),
                account: [48; 32],
                roster: checkpoint(2),
                status: FanoutStatus::Abandoned(
                    FanoutAbandonmentId::from_trusted_state([50; 32])
                        .expect("valid inspection fixture"),
                ),
                members,
            },
        ),
        entry(
            7,
            DurableStatus::PublicationRegistry,
            report::RecordMetadata::PrekeyPublications {
                next_epoch: 42,
                public_history: b"opaque public publication registry".to_vec(),
            },
        ),
    ]
}
fn encoded(records: &[report::RecordMetadataEntry]) -> (Vec<u8>, Vec<u8>) {
    let scope = scope();
    (
        report::encode_public_view(scope.expected, [51; 32], 8, records)
            .expect("valid inspection fixture"),
        report::encode_public_view(scope.target, [51; 32], 9, records)
            .expect("valid inspection fixture"),
    )
}
fn proposal(source: &[u8], target: &[u8]) -> (AnchorPendingWriteRecoveryProposal, Vec<u8>) {
    let scope = scope();
    let mut metadata = scope.metadata_prefix().expect("valid inspection fixture");
    for view in [source, target] {
        metadata.extend_from_slice(
            &u64::try_from(view.len())
                .expect("valid inspection fixture")
                .to_be_bytes(),
        );
        metadata.extend_from_slice(view);
    }
    (
        scope.proposal(&metadata).expect("valid inspection fixture"),
        metadata,
    )
}
#[test]
fn inspection_preserves_every_record_field_and_unknown_outcome() {
    let records = records();
    let (source, target) = encoded(&records);
    let (p, bytes) = proposal(&source, &target);
    let inspected = p
        .inspect_metadata(&bytes)
        .expect("valid inspection fixture");
    assert_eq!(inspected.source().records, records);
    assert_eq!(inspected.target().records, records);
    assert_eq!(inspected.source().head, p.expected_head());
    assert_eq!(inspected.target().head, p.target_head());
    assert_eq!(
        (
            inspected.source().next_fanout_ordinal,
            inspected.target().next_fanout_ordinal
        ),
        (8, 9)
    );
    assert_eq!(inspected.source().local_account, [51; 32]);
    // This intentionally unsigned fixture can be inspected. No sender, witness
    // state or independent approval is fabricated by the read-only result.
    assert_eq!(
        p.to_bytes().len(),
        AnchorPendingWriteRecoveryProposal::ENCODED_BYTES
    );
}
#[test]
fn inspection_binds_complete_metadata_and_both_original_heads() {
    let (source, target) = encoded(&records());
    let (p, bytes) = proposal(&source, &target);
    let mut damaged = bytes.clone();
    *damaged.last_mut().expect("valid inspection fixture") ^= 1;
    assert_eq!(p.inspect_metadata(&damaged), Err(Error::Authentication));
    assert!(p
        .inspect_metadata(bytes.get(..bytes.len() - 1).expect("truncated input"))
        .is_err());
    damaged = bytes.clone();
    damaged.push(0);
    assert!(p.inspect_metadata(&damaged).is_err());
    for source_head in [false, true] {
        let (mut a, mut b) = (source.clone(), target.clone());
        if source_head {
            *a.get_mut(16).expect("source head") ^= 1;
        } else {
            *b.get_mut(16).expect("target head") ^= 1;
        }
        let (changed, metadata) = proposal(&a, &b);
        assert_eq!(changed.inspect_metadata(&metadata), Err(Error::Scope));
    }
}
#[test]
fn inspection_refuses_count_overflow_unknown_tags_and_view_tails() {
    let (source, target) = encoded(&records());
    for offset in [88, 96 + 65] {
        // record count, first record authority count
        let mut a = source.clone();
        a.get_mut(offset..offset + 8)
            .expect("count field")
            .copy_from_slice(&u64::MAX.to_be_bytes());
        let (p, bytes) = proposal(&a, &target);
        assert_eq!(p.inspect_metadata(&bytes), Err(Error::Encoding));
    }
    let mut a = source.clone();
    *a.get_mut(96 + 64).expect("phase field") = 255;
    let (p, bytes) = proposal(&a, &target);
    assert_eq!(p.inspect_metadata(&bytes), Err(Error::Encoding));
    let mut a = source;
    a.push(0);
    let (p, bytes) = proposal(&a, &target);
    assert_eq!(p.inspect_metadata(&bytes), Err(Error::Encoding));
}
#[test]
fn inspection_refuses_noncanonical_options_order_and_session_role() {
    let records = records();
    let (mut source, target) = encoded(records.get(1..2).expect("prekey record"));
    assert_eq!(source.get(235), Some(&1));
    *source.get_mut(235).expect("optional tag") = 2; // prekey optional public fingerprint
    let (p, bytes) = proposal(&source, &target);
    assert_eq!(p.inspect_metadata(&bytes), Err(Error::Encoding));
    let duplicated = vec![
        records.first().expect("bootstrap record").clone(),
        records.first().expect("bootstrap record").clone(),
    ];
    let (a, b) = encoded(&duplicated);
    let (p, bytes) = proposal(&a, &b);
    assert_eq!(p.inspect_metadata(&bytes), Err(Error::Encoding));
    let mut changed = records;
    let session = changed
        .get_mut(2)
        .and_then(|record| match &mut record.metadata {
            report::RecordMetadata::Session(session) => Some(session),
            _ => None,
        })
        .expect("session fixture");
    session.role = 0;
    let (a, b) = encoded(&changed);
    let (p, bytes) = proposal(&a, &b);
    assert_eq!(p.inspect_metadata(&bytes), Err(Error::Encoding));
}

#[test]
fn inspection_refuses_more_records_than_any_original_journal_can_hold() {
    let maximum = crate::contract::MAX_SESSION_OPERATION_RECORDS
        + crate::contract::MAX_PREKEY_RECORDS
        + crate::contract::MAX_ACCOUNT_ROSTER_RECORDS
        + 1;
    let template = records().get(1).expect("prekey fixture").clone();
    let oversized: Vec<_> = (1..=maximum + 1)
        .map(|index| {
            let mut record = template.clone();
            let ordinal = u16::try_from(index).expect("bounded fixture ordinal");
            record.id = [0; 32];
            record
                .id
                .get_mut(30..)
                .expect("ordinal suffix")
                .copy_from_slice(&ordinal.to_be_bytes());
            record
        })
        .collect();
    let (a, b) = encoded(&oversized);
    let (p, bytes) = proposal(&a, &b);
    assert_eq!(p.inspect_metadata(&bytes), Err(Error::Encoding));
}

#[test]
fn inspection_mutations_never_silently_drop_or_relabel_encoded_fields() {
    let (source, target) = encoded(&records());
    // Rebind the public commitment after mutation so malformed nested fields
    // reach the actual decoder rather than stopping at the outer digest check.
    for index in 0..source.len() {
        for mask in [1, 128, 255] {
            let mut modified = source.clone();
            *modified.get_mut(index).expect("mutation position") ^= mask;
            let (p, bytes) = proposal(&modified, &target);
            if let Ok(inspected) = p.inspect_metadata(&bytes) {
                for (view, encoded) in [
                    (inspected.source(), &modified),
                    (inspected.target(), &target),
                ] {
                    assert_eq!(
                        report::encode_public_view(
                            view.head,
                            view.local_account,
                            view.next_fanout_ordinal,
                            &view.records
                        )
                        .expect("complete decoded view"),
                        *encoded
                    );
                }
            }
        }
    }
}
