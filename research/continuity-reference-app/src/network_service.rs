// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Reference service for one independently configured peer context. Incoming
//! frames route original sessions; they never select a root, policy or new store.
use super::operator_io::{print, read};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    enrollment::{Invitation, RootInfo},
    native_device::{clock, ExchangeOperation, ExchangeRequest, Mailbox, NativeDevice, PeerTrust},
    network::{self, Limits},
    policy_publisher::{PolicyMaterials, PolicyPins},
};
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    listen: SocketAddr,
    device_directory: PathBuf,
    wrapping_key: PathBuf,
    invitation: PathBuf,
    current_root: PathBuf,
    policy_pins: PathBuf,
    policy_materials: PathBuf,
    witness_endpoint: String,
    peer_trust: PathBuf,
    bundle: PathBuf,
    inbox: PathBuf,
}
fn json<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T> {
    Ok(serde_json::from_slice(&read(path, maximum)?)?)
}
struct Prepared {
    owner: q_periapt_continuity_reference_app::native_device::ActiveDevice,
    policy: Arc<sdk::VerifiedSessionPolicy>,
    trust: PeerTrust,
    bundle: sdk::BootstrapBundle,
    inbox: Mailbox,
}
impl Configuration {
    fn open(&self, run: &sdk::session_exchange::Run<'_>) -> Result<Prepared> {
        let invitation: Invitation = json(&self.invitation, 16384)?;
        let owner = NativeDevice::open_in_run(
            &self.device_directory,
            &self.wrapping_key,
            &invitation,
            run,
        )?;
        let trust: PeerTrust = json(&self.peer_trust, 128 * 1024)?;
        let bundle = sdk::BootstrapBundle::from_bytes(&read(
            &self.bundle,
            sdk::MAX_BOOTSTRAP_BUNDLE_BYTES,
        )?)?;
        let current: RootInfo = json(&self.current_root, 128 * 1024)?;
        let pins: PolicyPins = json(&self.policy_pins, 16384)?;
        let materials: PolicyMaterials = json(&self.policy_materials, 128 * 1024)?;
        let (policy, witness) = pins.verify(&materials, invitation.family, clock()?)?;
        let endpoint = match self.witness_endpoint.as_str() {
            "none" => None,
            value => Some(value.parse()?),
        };
        if endpoint.is_some() != witness.is_some() {
            return Err("Witness endpoint differs from pinned policy".into());
        }
        run.check()?;
        let active = owner.activate(&current, &policy, witness, endpoint, clock()?)?;
        let inbox = Mailbox::open(&self.inbox, active.journal())?;
        Ok(Prepared {
            owner: active,
            policy: Arc::new(policy),
            trust,
            bundle,
            inbox,
        })
    }
    fn exchange(&self, frame: &[u8], run: &sdk::session_exchange::Run<'_>) -> Result<Vec<u8>> {
        run.check()?;
        let operation = ExchangeOperation::inspect(frame)?;
        let mut prepared = self.open(run)?;
        run.check()?;
        prepared.owner.exchange_in_run(
            &prepared.trust,
            &prepared.bundle,
            prepared.policy,
            ExchangeRequest {
                operation: &operation,
                frame,
            },
            &mut prepared.inbox,
            run,
        )
    }
}

pub(super) fn serve(path: &Path) -> Result<()> {
    let input: Configuration = json(path, 16384)?;
    if input.schema != "qperiapt-native-service/1"
        || input.listen.ip().is_multicast()
        || matches!(input.listen.ip(),std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err("Unknown network service schema or listen address".into());
    }
    // Fail startup on invalid original device/inbox configuration. Each actual
    // operation reopens and checks current independent inputs; no state is reset.
    let startup_cancel = sdk::Cancellation::default();
    let startup =
        sdk::session_exchange::Run::new(&startup_cancel, std::time::Duration::from_secs(30))?;
    drop(input.open(&startup)?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener=tokio::net::TcpListener::bind(input.listen).await?;
        print(&serde_json::json!({"service":"Listening","carrier":"QPCXCH01/TCP","address":listener.local_addr()?.to_string()}))?;
        io::stdout().flush()?;
        let stop=sdk::Cancellation::default();
        let service=network::serve(listener,Limits::default(),stop.clone(),move |frame,run|
            input.exchange(frame,run).map_err(|error|io::Error::other(error.to_string())));
        tokio::pin!(service);
        let stats=tokio::select! {
            result=&mut service=>result?,
            signal=tokio::signal::ctrl_c()=>{
                stop.cancel();let result=service.await;signal?;result?
            }
        };
        print(&serde_json::json!({"service":"Stopped","stats":stats}))
    })
}
