// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real-clock expiry composition for independently configured consumers.
use crate::receiver_policy::historical;
pub(crate) use crate::receiver_policy::prepare_receiver_metadata;
use crate::{fixture, run, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::fs;

pub(crate) fn wait_and_refuse_expired(
    case: &crate::first_connection::Case<'_>,
    original: &[u8],
) -> Result<()> {
    let until = historical(case.source)?.validity().until();
    let remaining = until.saturating_sub(fixture::now()?);
    if remaining > 300 {
        return Err("policy fixture wait exceeds five minutes".into());
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(remaining + 15);
    while fixture::now()? < until {
        if std::time::Instant::now() >= deadline {
            return Err("policy expiry deadline".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let at = fixture::now()?;
    let refused = case.base.join("expired-activation");
    case.invoke("activate-expired", &refused)?;
    assert_eq!(fs::read(&refused)?, 104i32.to_ne_bytes());
    let replay = case.base.join("expired-original-request");
    case.invoke("resume", &replay)?;
    assert_eq!(fs::read(replay)?, original);
    let adopted = fixture::array::<8>(case.base, "receiver-policy-adopted")?;
    let mut observed = until.to_be_bytes().to_vec();
    observed.extend_from_slice(&at.to_be_bytes());
    observed.extend_from_slice(&adopted);
    publish_private_bytes(&case.base.join("expired-policy-observation"), &observed)?;
    println!("\nINDEPENDENT_CONFIGURATION_EXPIRED_POLICY_PASS language={} carrier={} profile={} old_activation_refused=true original_request=true receiver_adopted_before_expiry=true", case.language, case.carrier.unwrap_or("local"), case.profile);
    Ok(())
}

pub(crate) fn renew_receiver_before_expiry(
    case: &crate::first_connection::Case<'_>,
    reference: &fixture::Setup,
    witness: Option<&fixture::WitnessFixture>,
) -> Result<()> {
    crate::receiver_policy::renew_receiver_before_expiry(
        &crate::receiver_policy::ReceiverPolicy {
            source: case.source,
            receiver: case.receiver,
            base: case.base,
            carrier: case.carrier,
        },
        reference,
        witness,
        &|inputs, target, output| {
            run(
                case.client,
                "policy-target-create",
                "fixed",
                inputs,
                target,
                output,
            )
        },
    )
}
