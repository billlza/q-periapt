// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original native outgoing operations through a bounded private-file carrier.
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    enrollment::{Invitation, RootInfo},
    native_device::{clock, ActiveDevice, NativeDevice, PeerTrust},
    policy_publisher::{PolicyMaterials, PolicyPins},
};
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
#[path = "../operator_io.rs"]
mod operator_io;
#[path = "../outgoing_files.rs"]
mod outgoing_files;
use operator_io::{identifier, print, read};
use outgoing_files::FileTransport;
use q_periapt_continuity_reference_app::network::TcpTransport;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    schema: String,
    device_directory: PathBuf,
    wrapping_key: PathBuf,
    invitation: PathBuf,
    current_root: PathBuf,
    policy_pins: PathBuf,
    policy_materials: PathBuf,
    witness_endpoint: String,
    peer_trust: PathBuf,
    bundle: PathBuf,
    action: Action,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Next,
    Status {
        message: [u8; 32],
    },
    Deliver {
        message: [u8; 32],
        plaintext: Vec<u8>,
        associated_data: Vec<u8>,
        request_directory: PathBuf,
        response_directory: PathBuf,
    },
    Rekey {
        target: u64,
        exchanges: u16,
        request_directory: PathBuf,
        response_directory: PathBuf,
    },
    DeliverTcp {
        message: [u8; 32],
        plaintext: Vec<u8>,
        associated_data: Vec<u8>,
        address: std::net::SocketAddr,
    },
    RekeyTcp {
        target: u64,
        exchanges: u16,
        address: std::net::SocketAddr,
    },
}
enum Carrier {
    Files(FileTransport),
    Tcp(TcpTransport),
}
impl sdk::session_exchange::Transport for Carrier {
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: sdk::MonotonicInstant,
        cancel: &sdk::Cancellation,
    ) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Files(value) => value.exchange(request, deadline, cancel),
            Self::Tcp(value) => value.exchange(request, deadline, cancel),
        }
    }
}
impl Action {
    fn preflight(&self) -> Result<Option<Carrier>> {
        let directories = match self {
            Self::Next => return Ok(None),
            Self::Status { message } => {
                sdk::MessageId::from_trusted_state(*message)?;
                return Ok(None);
            }
            Self::Deliver {
                message,
                plaintext,
                associated_data,
                request_directory,
                response_directory,
            } => {
                sdk::MessageId::from_trusted_state(*message)?;
                if plaintext.len() > 16384 || associated_data.len() > 1024 {
                    return Err("Outgoing message capacity".into());
                }
                (request_directory, response_directory)
            }
            Self::Rekey {
                target,
                exchanges,
                request_directory,
                response_directory,
            } => {
                if *target == 0 || *target == u64::MAX || !(1..=128).contains(exchanges) {
                    return Err("Outgoing rekey target or allowance".into());
                }
                (request_directory, response_directory)
            }
            Self::DeliverTcp {
                message,
                plaintext,
                associated_data,
                address,
            } => {
                sdk::MessageId::from_trusted_state(*message)?;
                if plaintext.len() > 16384 || associated_data.len() > 1024 {
                    return Err("Outgoing message capacity".into());
                }
                return Ok(Some(Carrier::Tcp(TcpTransport::new(*address)?)));
            }
            Self::RekeyTcp {
                target,
                exchanges,
                address,
            } => {
                if *target == 0 || *target == u64::MAX || !(1..=128).contains(exchanges) {
                    return Err("Outgoing rekey target or allowance".into());
                }
                return Ok(Some(Carrier::Tcp(TcpTransport::new(*address)?)));
            }
        };
        Ok(Some(Carrier::Files(FileTransport::new(
            directories.0,
            directories.1,
        )?)))
    }
}
fn json<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T> {
    Ok(serde_json::from_slice(&read(path, maximum)?)?)
}
impl Invocation {
    fn open(
        &self,
        session_id: [u8; 32],
        run: &sdk::session_exchange::Run<'_>,
    ) -> Result<(ActiveDevice, sdk::session_exchange::Session)> {
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
        let mut active = owner.activate(&current, &policy, witness, endpoint, clock()?)?;
        let session = active.reopen_session(&trust, &bundle, Arc::new(policy), session_id)?;
        Ok((active, session))
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err(
            "q-periapt-native-outgoing <absolute-invocation-json> <original-session-base64url>"
                .into(),
        );
    }
    let input: Invocation = json(Path::new(&args[1]), 128 * 1024)?;
    let session_id = identifier(&args[2])?;
    if input.schema != "qperiapt-native-outgoing/1" {
        return Err("Unknown outgoing schema".into());
    }
    // Validate all static payload/carrier options before opening or activating.
    let mut transport = input.action.preflight()?;
    let cancel = sdk::Cancellation::default();
    let run = sdk::session_exchange::Run::new(&cancel, Duration::from_secs(30))?;
    let result = match &input.action {
        Action::Next => {
            let (mut active, session) = input.open(session_id, &run)?;
            serde_json::json!({"message":active.next_message(&session)?.as_bytes()})
        }
        Action::Status { message } => {
            let (mut active, session) = input.open(session_id, &run)?;
            serde_json::json!({"status":format!("{:?}",active.message_status(&session,sdk::MessageId::from_trusted_state(*message)?)?)})
        }
        Action::Deliver {
            message,
            plaintext,
            associated_data,
            ..
        }
        | Action::DeliverTcp {
            message,
            plaintext,
            associated_data,
            ..
        } => {
            let prepared = {
                run.check()?;
                let (mut active, session) = input.open(session_id, &run)?;
                active.prepare_delivery(
                    &session,
                    sdk::session_exchange::Submission {
                        message: sdk::MessageId::from_trusted_state(*message)?,
                        plaintext,
                        associated_data,
                    },
                    &run,
                )?
            };
            // No original owner or private store lease is retained while the
            // peer handles these already-committed public ciphertext bytes.
            run.check()?;
            let reply = sdk::session_exchange::Transport::exchange(
                transport.as_mut().ok_or("Missing outgoing carrier")?,
                prepared.as_bytes(),
                run.deadline(),
                &cancel,
            )
            .map_err(sdk::session_exchange::Error::Transport)?;
            run.check()?;
            let outcome = {
                let (mut active, session) = input.open(session_id, &run)?;
                active.complete_delivery(&session, &prepared, &reply, &run)?
            };
            run.check()?;
            serde_json::json!({"consumption":format!("{outcome:?}")})
        }
        Action::Rekey {
            target, exchanges, ..
        }
        | Action::RekeyTcp {
            target, exchanges, ..
        } => {
            let mut step = {
                run.check()?;
                let (mut active, session) = input.open(session_id, &run)?;
                active.prepare_rekey(&session, *target, &run)?
            };
            let mut attempted = 0;
            loop {
                run.check()?;
                let prepared = match step {
                    sdk::session_exchange::RekeyDeliveryStep::LocallyConfirmed(epoch) => {
                        break serde_json::json!({"epoch":epoch,"exchanges":attempted});
                    }
                    sdk::session_exchange::RekeyDeliveryStep::Output(prepared) => prepared,
                };
                if attempted == *exchanges {
                    return Err(sdk::session_exchange::Error::ExchangeLimit.into());
                }
                attempted += 1;
                let reply = sdk::session_exchange::Transport::exchange(
                    transport.as_mut().ok_or("Missing outgoing carrier")?,
                    prepared.as_bytes(),
                    run.deadline(),
                    &cancel,
                )
                .map_err(sdk::session_exchange::Error::Transport)?;
                run.check()?;
                step = {
                    let (mut active, session) = input.open(session_id, &run)?;
                    active.complete_rekey(&session, &prepared, &reply, &run)?
                };
            }
        }
    };
    print(&result)
}
