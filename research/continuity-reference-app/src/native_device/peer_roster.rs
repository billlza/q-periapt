// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit remote roster admission through the original live device owner.
use super::*;

impl ActiveDevice {
    /// Install an independently selected signed roster for an already known
    /// remote account. The SDK checks the retained root/family, monotonic head,
    /// current local authority and witness around the durable operation.
    ///
    /// Retain this exact target after any error: failure may follow commit. A
    /// successful retry reports the currently installed target, not whether this
    /// invocation first committed it. No session or traffic permission is returned.
    /// The local account must use its separate enrollment roster transaction.
    pub fn admit_peer_roster(
        &mut self,
        target: &RootInfo,
        policy: &sdk::VerifiedSessionPolicy,
        now: u64,
    ) -> Result<Checkpoint> {
        let result = (|| {
            if target.revision == 0 || target.family != policy.family() {
                return Err("Peer roster authority differs from the current policy".into());
            }
            let selected = target
                .roster
                .as_ref()
                .ok_or("Explicit peer roster is required")?;
            let pin = sdk::AccountPin::new(
                target.account,
                sdk::PublicKey::decode(&target.public_key)?,
                selected.checkpoint.as_sdk()?,
                target.family,
            )?;
            let roster = pin.verify_roster(&selected.bytes, now)?;
            Ok(self
                .owner
                .parts()?
                .0
                .admit_peer_roster(&roster, policy, now)?
                .into())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
