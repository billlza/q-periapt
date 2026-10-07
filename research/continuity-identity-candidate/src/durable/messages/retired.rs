// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Pure historical projections; no mutation, release check or lifecycle transition.
use super::*;
use crate::durable::retired_report::{
    ConsumedDelivery, Epoch, RecordMetadata, Reservation, Session, SessionState,
};

pub(in crate::durable) fn historical_session(
    image: &Image,
    key: &JournalKey,
    record: &Record,
    archives: &mut crate::SessionArchiveStore,
) -> Result<RecordMetadata, DurableError> {
    let (source, session, role, progress, state) = match record.phase {
        DurableStatus::Messages
        | DurableStatus::MessagesClosing
        | DurableStatus::MessagesAbandoning => {
            let state = State::decode(&record.payload)?;
            let epochs = fanout::epoch_accounting(&state)
                .into_iter()
                .map(|accounting| {
                    let traffic = state
                        .epochs
                        .get(&accounting.epoch)
                        .ok_or(DurableError::Corrupt)?;
                    Ok(Epoch {
                        accounting,
                        consumed_out_of_order: traffic
                            .incoming
                            .iter()
                            .filter(|(_, s)| s.consumed)
                            .map(|(message, s)| ConsumedDelivery {
                                message: *message,
                                index: s.index,
                            })
                            .collect(),
                        reservation: traffic.pending.as_ref().map(|p| Reservation {
                            input: ReservedAbandonment {
                                message: p.id,
                                plaintext_bytes: p.plaintext.len(),
                                associated_data_bytes: p.ad.len(),
                            },
                            fanout: p.fanout,
                        }),
                        send_closed: traffic.send_closed,
                    })
                })
                .collect::<Result<Vec<_>, DurableError>>()?;
            let public = SessionState::Live {
                epochs,
                previous_closure: state.closure.as_ref().map(closure::Pending::report_id),
            };
            (
                state.source,
                state.session,
                state.role,
                fanout::abandoned_progress(&state)?,
                public,
            )
        }
        DurableStatus::MessagesClosed | DurableStatus::MessagesAbandoned => {
            let state = Retired::decode(&record.payload)?;
            let (progress, epochs) = state.historical_counts();
            (
                state.source,
                state.session,
                state.role,
                progress,
                SessionState::Terminal {
                    report: state.report,
                    batch: state.batch,
                    pending: state.pending,
                    epochs,
                },
            )
        }
        _ => return Err(DurableError::Corrupt),
    };
    let archive = archives.get(session).map_err(|e| {
        if matches!(e, DurableError::Absent) {
            DurableError::ArchiveRequired
        } else {
            e
        }
    })?;
    let (peer_account, peer_device, peer_generation) =
        archive.authenticate_historical(key, image, session)?;
    Ok(RecordMetadata::Session(Session {
        source: BootstrapOperationId::from_trusted_state(source)?,
        session,
        role,
        peer_account,
        peer_device,
        peer_generation,
        progress,
        state,
    }))
}
