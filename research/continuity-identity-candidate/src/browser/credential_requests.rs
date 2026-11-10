// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original issuer inputs without releasing a signer, journal or traffic owner.
use super::*;
use crate::{CredentialRenewalId, CredentialRenewalRequest, HistoricalSessionPolicy};

impl BrowserDevice {
    /// Local protection only; required witness is never silently omitted.
    pub async fn credential_renewal_request(
        &self,
        operation: CredentialRenewalId,
        original: &HistoricalSessionPolicy,
    ) -> Result<CredentialRenewalRequest, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            op.enrollment()?
                .credential_renewal_request(operation, original)
                .await
        }
        .await;
        op.finish(result).await
    }
    /// Read the real witnessed predecessor through the original registration.
    /// Close an operational owner, reopen that registration, and retain the same
    /// request ID. The issuer must independently approve/serialize/deduplicate.
    pub async fn witnessed_credential_renewal_request(
        &self,
        operation: CredentialRenewalId,
        original: &HistoricalSessionPolicy,
        witness: (AnchorPin, Box<dyn AnchorTransport>, Duration),
    ) -> Result<CredentialRenewalRequest, JsValue> {
        let mut op = self.operation()?;
        let result = async {
            let enrollment = op.enrollment()?;
            let client = enrollment
                .credential_renewal_request_anchor_client(original, witness.0, witness.1, witness.2)
                .await?;
            enrollment
                .witnessed_credential_renewal_request(operation, original, client)
                .await
        }
        .await;
        op.finish(result).await
    }
}
