// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public policy issuer materials from the original enrollment and journal.
use super::*;
use crate::{HistoricalSessionPolicy, PolicyRenewalId, PolicyRenewalRequest};

impl BrowserDevice {
    /// Read local-protection predecessor metadata without releasing an owner.
    /// Retain the operation before issuer approval; this does not reserve a change.
    pub async fn policy_renewal_request(
        &self,
        operation: PolicyRenewalId,
        original: &HistoricalSessionPolicy,
    ) -> Result<PolicyRenewalRequest, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .policy_renewal_request(operation, original)
                .await
        }
        .await;
        op.finish(result).await
    }

    /// Read required-witness predecessor metadata under the original service lease.
    /// The native policy-only restrictions also apply here, including refusal of
    /// installations that have adopted a credential renewal. Neither a transport
    /// failure nor unsupported lineage permits falling back to local protection.
    pub async fn witnessed_policy_renewal_request(
        &self,
        operation: PolicyRenewalId,
        original: &HistoricalSessionPolicy,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<PolicyRenewalRequest, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let enrollment = op.enrollment()?;
            let client = enrollment
                .policy_renewal_anchor_client(original, witness.0, witness.1, witness.2)
                .await?;
            enrollment
                .witnessed_policy_renewal_request(operation, original, client)
                .await
        }
        .await;
        op.finish(result).await
    }
}
