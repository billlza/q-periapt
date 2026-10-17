// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Controlled browser inventory; observations and retirement do not grant traffic authority.
use super::*;
use crate::{LeafKind, PrekeyId, PrekeyStatus, Validity};

impl BrowserDevice {
    /// Generate/recover an original public prekey through the controlled SDK owner.
    /// This does not advertise a key or establish a remote publication receipt.
    pub async fn generate_prekey(
        &self,
        policy: &VerifiedSessionPolicy,
        id: PrekeyId,
        kind: LeafKind,
        validity: Validity,
        now: u64,
    ) -> Result<Vec<u8>, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let active = op.active()?;
            let (service, _, device) = active.parts()?;
            Ok(service
                .stores()?
                .0
                .generate_prekey(policy, device, id, kind, validity, now)
                .await?
                .public_key()
                .to_vec())
        }
        .await;
        op.finish(result).await
    }
    /// Observe original inventory without granting permission to advertise or use it.
    pub async fn prekey_status(
        &self,
        policy: &VerifiedSessionPolicy,
        id: PrekeyId,
    ) -> Result<PrekeyStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.parts()?.0.prekey_status(policy, id).await }.await;
        op.finish(result).await
    }
    /// Retire an original inventory operation through its retained installation authority.
    /// Pending responses still block; consumed/abandoned tombstones are never reset.
    pub async fn retire_prekey(
        &self,
        policy: &VerifiedSessionPolicy,
        id: PrekeyId,
    ) -> Result<PrekeyStatus, JsValue> {
        let mut op = self.operation()?;
        let result = async { op.active()?.parts()?.0.retire_prekey(policy, id).await }.await;
        op.finish(result).await
    }
}
