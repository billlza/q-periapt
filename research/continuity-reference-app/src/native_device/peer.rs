// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public peer inputs selected by the host, separately from the received bundle.
use super::*;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceExpectation {
    current: RootInfo,
    device: [u8; 16],
    generation: u64,
}
impl DeviceExpectation {
    fn pin(&self, family: [u8; 32]) -> Result<sdk::AccountPin> {
        if self.current.family != family || self.current.revision == 0 {
            return Err("Peer root scope differs from policy".into());
        }
        Ok(sdk::AccountPin::new(
            self.current.account,
            sdk::PublicKey::decode(&self.current.public_key)?,
            self.current
                .roster
                .as_ref()
                .ok_or("Current peer roster is required")?
                .checkpoint
                .as_sdk()?,
            family,
        )?)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerTrust {
    schema: String,
    initiator: DeviceExpectation,
    responder: DeviceExpectation,
    directory: [u8; 32],
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExchangeOperation {
    Bootstrap,
    Message { session: [u8; 32] },
    Control { session: [u8; 32] },
}
impl ActiveDevice {
    pub fn exchange(
        &mut self,
        trust: &PeerTrust,
        bundle: &sdk::BootstrapBundle,
        policy: Arc<sdk::VerifiedSessionPolicy>,
        operation: &ExchangeOperation,
        request: &[u8],
        consumer: &mut impl sdk::session_exchange::Consumer,
    ) -> Result<Vec<u8>> {
        let result = (|| {
            if trust.schema != "qperiapt-native-peer-trust/1" {
                return Err("Unknown peer trust schema".into());
            }
            let initiator = trust.initiator.pin(policy.family())?;
            let responder = trust.responder.pin(policy.family())?;
            let required = sdk::BootstrapRequirements {
                initiator: sdk::ExpectedDevice::new(
                    &initiator,
                    trust.initiator.device,
                    trust.initiator.generation,
                )?,
                responder: sdk::ExpectedDevice::new(
                    &responder,
                    trust.responder.device,
                    trust.responder.generation,
                )?,
                quality: sdk::PrekeyQuality::ReusableBoth,
                directory: sdk::DirectoryExpectation::from_trusted_state(trust.directory)?,
            };
            let cancel = sdk::Cancellation::default();
            let run = sdk::session_exchange::Run::new(&cancel, Duration::from_secs(30))?;
            match operation {
                ExchangeOperation::Bootstrap => {
                    let context = Arc::new(bundle.verify(policy, required, clock()?)?);
                    let peer = self.owner.parts()?.0.admit_peer(
                        context,
                        sdk::BootstrapRole::Responder,
                        clock()?,
                    )?;
                    Ok(self
                        .owner
                        .serve_session_exchange(&peer, request, consumer, &run, clock)?)
                }
                ExchangeOperation::Message { session } | ExchangeOperation::Control { session } => {
                    let reopened = self.owner.parts()?.0.reopen_peer_bundle(
                        bundle,
                        policy,
                        required,
                        sdk::BootstrapRole::Responder,
                        *session,
                        clock()?,
                    )?;
                    let session = sdk::session_exchange::Session::from_reopened(&reopened);
                    match operation {
                        ExchangeOperation::Message { .. } => Ok(self
                            .owner
                            .serve_session_message(&session, request, consumer, &run, clock)?),
                        ExchangeOperation::Control { .. } => Ok(self
                            .owner
                            .serve_session_control(&session, request, &run, clock)?),
                        ExchangeOperation::Bootstrap => Err("Exchange operation changed".into()),
                    }
                }
            }
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
