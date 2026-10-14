// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(super) fn session(value: &r::Session) -> String {
    let r::Session {
        source,
        session,
        role,
        peer_account,
        peer_device,
        peer_generation,
        progress: current,
        state,
    } = value;
    let state = match state {
        r::SessionState::Live {
            epochs,
            previous_closure,
        } => object(&[
            ("kind", label("live")),
            (
                "previous_closure",
                optional(previous_closure.as_ref().map(|v| hex(v.as_bytes()))),
            ),
            (
                "epochs",
                array_json(epochs.iter().map(|value| {
                    let r::Epoch {
                        accounting,
                        consumed_out_of_order,
                        reservation,
                        send_closed,
                    } = value;
                    object(&[
                        ("accounting", epoch(accounting)),
                        ("send_closed", send_closed.to_string()),
                        (
                            "consumed_out_of_order",
                            array_json(consumed_out_of_order.iter().map(|value| {
                                let r::ConsumedDelivery { message, index } = value;
                                object(&[
                                    ("message", hex(message.as_bytes())),
                                    ("index", integer(*index)),
                                ])
                            })),
                        ),
                        (
                            "reservation",
                            optional(reservation.as_ref().map(|value| {
                                let r::Reservation { input, fanout } = value;
                                object(&[
                                    ("input", reserved(input)),
                                    (
                                        "fanout",
                                        optional(fanout.as_ref().map(|v| hex(v.as_bytes()))),
                                    ),
                                ])
                            })),
                        ),
                    ])
                })),
            ),
        ]),
        r::SessionState::Terminal {
            report,
            batch,
            pending,
            epochs,
        } => object(&[
            ("kind", label("terminal")),
            ("report", hex(report)),
            ("batch", optional(batch.as_ref().map(|v| hex(v.as_bytes())))),
            (
                "pending",
                optional(pending.as_ref().map(|v| hex(v.as_bytes()))),
            ),
            (
                "epochs",
                array_json(epochs.iter().map(|value| {
                    let r::TerminalEpoch {
                        epoch,
                        sent,
                        acknowledged,
                        reservation_abandoned,
                    } = value;
                    object(&[
                        ("epoch", integer(*epoch)),
                        ("sent", integer(*sent)),
                        ("acknowledged", integer(*acknowledged)),
                        ("reservation_abandoned", reservation_abandoned.to_string()),
                    ])
                })),
            ),
        ]),
    };
    object(&[
        ("source", hex(source.as_bytes())),
        ("session", hex(session)),
        ("role", role.to_string()),
        ("peer_account", hex(peer_account)),
        ("peer_device", hex(peer_device)),
        ("peer_generation", integer(*peer_generation)),
        ("progress", progress(current)),
        ("state", state),
    ])
}
