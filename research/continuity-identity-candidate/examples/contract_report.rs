// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Emit the actual shared constants for comparison with the binding contract.
use q_periapt_continuity_identity_candidate::{contract as c, MAX_DEVICES, MAX_PREKEYS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = c::rekey_profile_digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!(
        concat!(
            "{{\"schema_version\":1,\"frozen_product_contract\":false,",
            "\"signature_context\":\"{}\",\"rekey_profile\":\"{}\",",
            "\"rekey_profile_sha3_256\":\"{}\",\"message_domain\":\"{}\",",
            "\"maximums\":{{\"signed_body_bytes\":{},\"bootstrap_bundle_bytes\":{},",
            "\"bootstrap_field_bytes\":{},\"plaintext_bytes\":{},\"associated_data_bytes\":{},",
            "\"skipped_keys_per_direction_epoch\":{},\"outstanding_messages_per_direction_epoch\":{},",
            "\"retained_traffic_epochs\":{},\"control_body_bytes\":{},\"connection_frame_bytes\":{},",
            "\"session_operation_records\":{},\"prekey_records\":{},\"account_roster_records\":{},\"device_history_per_account\":{},\"journal_image_bytes\":{},\"network_exchanges\":{},",
            "\"run_timeout_seconds\":{},\"connect_timeout_seconds\":{},",
            "\"roster_devices\":{},\"manifest_prekeys\":{}}}}}"
        ),
        std::str::from_utf8(c::SIGNATURE_CONTEXT)?,
        std::str::from_utf8(c::REKEY_PROFILE)?,
        profile,
        std::str::from_utf8(c::MESSAGE_DOMAIN)?,
        c::MAX_SIGNED_BODY_BYTES,
        c::MAX_BOOTSTRAP_BUNDLE_BYTES,
        c::MAX_BOOTSTRAP_FIELD_BYTES,
        c::MAX_PLAINTEXT_BYTES,
        c::MAX_ASSOCIATED_DATA_BYTES,
        c::MAX_SKIPPED_MESSAGE_KEYS,
        c::MAX_OUTSTANDING_MESSAGES,
        c::MAX_TRAFFIC_EPOCHS,
        c::MAX_CONTROL_BYTES,
        c::MAX_CONNECTION_FRAME_BYTES,
        c::MAX_SESSION_OPERATION_RECORDS,
        c::MAX_PREKEY_RECORDS,
        c::MAX_ACCOUNT_ROSTER_RECORDS,
        c::MAX_DEVICE_HISTORY_PER_ACCOUNT,
        c::MAX_JOURNAL_IMAGE_BYTES,
        c::MAX_NETWORK_EXCHANGES,
        c::MAX_RUN_TIMEOUT_SECONDS,
        c::MAX_CONNECT_TIMEOUT_SECONDS,
        MAX_DEVICES,
        MAX_PREKEYS,
    );
    Ok(())
}
