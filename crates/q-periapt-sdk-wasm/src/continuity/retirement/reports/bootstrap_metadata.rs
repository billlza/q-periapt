// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(super) fn bootstrap(value: &engine::BootstrapEntry) -> String {
    let engine::BootstrapEntry {
        operation,
        context,
        role,
        status,
    } = value;
    object(&[
        ("operation", hex(operation.as_bytes())),
        ("context", hex(context)),
        (
            "role",
            label(match role {
                engine::BootstrapRole::Initiator => "initiator",
                engine::BootstrapRole::Responder => "responder",
            }),
        ),
        ("status", (*status as u8).to_string()),
    ])
}
pub(super) fn cancellation(value: &engine::BootstrapCancellation) -> String {
    let engine::BootstrapCancellation {
        entry,
        previous,
        report,
        initial_hash,
        reply_hash,
        final_hash,
        session,
        one_time_claims,
        inventory,
    } = value;
    object(&[
        ("entry", bootstrap(entry)),
        ("previous", (*previous as u8).to_string()),
        ("report", hex(report)),
        (
            "initial_hash",
            optional(initial_hash.as_ref().map(|v| hex(v))),
        ),
        ("reply_hash", optional(reply_hash.as_ref().map(|v| hex(v)))),
        ("final_hash", optional(final_hash.as_ref().map(|v| hex(v)))),
        ("session", optional(session.as_ref().map(|v| hex(v)))),
        (
            "one_time_claims",
            array_json(one_time_claims.iter().map(|v| hex(v))),
        ),
        (
            "inventory",
            array_json(inventory.iter().map(|value| {
                let engine::BootstrapPrekeyUse {
                    request,
                    kind,
                    disposition,
                } = value;
                object(&[
                    ("request", hex(request.as_bytes())),
                    ("kind", (*kind as u8).to_string()),
                    (
                        "disposition",
                        label(match disposition {
                            engine::BootstrapPrekeyDisposition::AbandonedByCancellation => {
                                "abandoned_by_cancellation"
                            }
                            engine::BootstrapPrekeyDisposition::AlreadyConsumed => {
                                "already_consumed"
                            }
                            engine::BootstrapPrekeyDisposition::ReusableUnchanged => {
                                "reusable_unchanged"
                            }
                        }),
                    ),
                ])
            })),
        ),
    ])
}
