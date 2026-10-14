// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Compose pending-write recovery with the existing independently approved renewal.
use super::*;

pub(crate) fn prepare(case: &Case<'_>) -> Result<Vec<u8>> {
    assert!(fixture::now()? < case.policy.validity().until());
    let identity = case.run("policy-identity", "original.identity")?;
    assert_eq!(identity.len(), 64);
    let traffic = traffic::Traffic::retained(case)?;
    traffic.renew_receiver(case)?;
    publish_private_bytes(
        &case.output("policy-effect-before"),
        &fs::read(case.base.join("roster-effect-before"))?,
    )?;
    Ok(identity)
}

pub(crate) fn resume(case: &Case<'_>, identity: &[u8]) -> Result<()> {
    flow::renew_expired(case, identity)?;
    let traffic = traffic::Traffic::retained(case)?;
    traffic.resume(case)?;
    traffic.rekey_and_send(case)?;
    assert_eq!(case.run("policy-identity", "final.identity")?, identity);
    assert_eq!(case.calls.get(), 37);
    publish_private_bytes(
        &case.output("policy-process-count"),
        &case.calls.get().to_be_bytes(),
    )?;
    Ok(())
}
