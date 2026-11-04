// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local reference directory. Its authority is the operator's private approval
//! input, supplied independently from the submitted request and publication.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_continuity_reference_app::{
    directory_ledger::{Action, DirectoryAuthorization, DirectoryLedger, Error as LedgerError},
    native_device::{clock, Publication, PublicationPlan, PublicationTrust},
    policy_publisher::{PolicyMaterials, PolicyPins},
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use serde::{de::DeserializeOwned, Deserialize};
use std::{ffi::OsString, path::PathBuf};
#[path = "../operator_io.rs"]
mod operator_io;
use operator_io::{identifier, print, read, Result};

const USAGE: &str = "Usage: q-periapt-prekey-directory <prepare-key|show-key|init|inspect|issue|lookup|cancel|check-receipt|check-historical-receipt|prove-conflict|check-conflict> ... (see DIRECTORY_LEASES.md)";

fn json<T: DeserializeOwned>(path: &OsString, maximum: usize) -> Result<T> {
    Ok(serde_json::from_slice(&read(path.as_ref(), maximum)?)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    schema: String,
    service: [u8; 32],
    public_key: String,
}
impl Pin {
    fn verified(&self) -> Result<sdk::DirectoryPin> {
        let key = URL_SAFE_NO_PAD.decode(&self.public_key)?;
        if self.schema != "qperiapt-directory-pin/1"
            || URL_SAFE_NO_PAD.encode(&key) != self.public_key
        {
            return Err("Invalid directory pin".into());
        }
        Ok(sdk::DirectoryPin::new(
            self.service,
            sdk::PublicKey::decode(&key)?,
        )?)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Service {
    schema: String,
    pin: Pin,
    database: PathBuf,
    signer: PathBuf,
    wrapping: PathBuf,
    signing_id: [u8; 32],
}
impl Service {
    fn check(&self) -> Result<sdk::DirectoryPin> {
        if self.schema != "qperiapt-directory-service/1"
            || !self.database.is_absolute()
            || !self.signer.is_absolute()
            || !self.wrapping.is_absolute()
        {
            return Err("Expected a local operator configuration with absolute paths".into());
        }
        self.pin.verified()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    schema: String,
    trust: PublicationTrust,
    plan: PublicationPlan,
    policy_pins: PolicyPins,
    policy_materials: PolicyMaterials,
}
impl Admission {
    fn verify(
        &self,
        publication: &Publication,
        now: u64,
    ) -> Result<(
        sdk::VerifiedDevice,
        sdk::AuthenticatedPrekeySelection,
        sdk::VerifiedSessionPolicy,
    )> {
        if self.schema != "qperiapt-directory-admission/1" {
            return Err("Unknown directory admission schema".into());
        }
        let (policy, _) =
            self.policy_pins
                .verify(&self.policy_materials, self.trust.family(), now)?;
        let (device, selection) =
            self.trust
                .verify_for_directory(publication, &self.plan, &policy, now)?;
        if selection.quality() != sdk::PrekeyQuality::OneTimeBoth {
            return Err("A directory lease requires both one-time roles".into());
        }
        Ok((device, selection, policy))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation: [u8; 32],
    requester: [u8; 32],
    checkpoint: [u8; 32],
    valid_from: u64,
    valid_until: u64,
}
impl Request {
    fn checked(&self) -> Result<sdk::DirectoryLeaseRequest> {
        Ok(sdk::DirectoryLeaseRequest::new(
            self.operation,
            self.requester,
            self.checkpoint,
            sdk::Validity::new(self.valid_from, self.valid_until)?,
        )?)
    }
}

// A separate operator input. Never deserialize this from a client envelope.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    schema: String,
    action: String,
    service_binding: [u8; 32],
    selection_digest: [u8; 32],
    request: Request,
    not_before: u64,
    not_after: u64,
}
struct Approval {
    action: Action,
    request: sdk::DirectoryLeaseRequest,
    window: sdk::Validity,
}
impl Grant {
    fn bind(
        &self,
        action: Action,
        pin: &sdk::DirectoryPin,
        selection: [u8; 32],
    ) -> Result<Approval> {
        let label = match action {
            Action::Issue => "issue",
            Action::Cancel => "cancel",
        };
        if self.schema != "qperiapt-directory-approval/1"
            || self.action != label
            || self.service_binding != pin.binding()
            || self.selection_digest != selection
        {
            return Err("Approval scope differs from the independently selected operation".into());
        }
        Ok(Approval {
            action,
            request: self.request.checked()?,
            window: sdk::Validity::new(self.not_before, self.not_after)?,
        })
    }
}
impl DirectoryAuthorization for Approval {
    fn authorize(
        &self,
        action: Action,
        request: &sdk::DirectoryLeaseRequest,
        now: u64,
    ) -> std::result::Result<(), LedgerError> {
        if self.action != action
            || self.request != *request
            || now < self.window.from()
            || now >= self.window.until()
        {
            return Err(LedgerError::Unauthorized);
        }
        Ok(())
    }
}
fn trusted_clock() -> std::result::Result<u64, LedgerError> {
    clock().map_err(|_| LedgerError::Clock)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (command, args) = args.split_first().ok_or(USAGE)?;
    match (command.to_str(), args) {
        (Some(command @ ("prepare-key" | "show-key")), [service, id, wrapping, signer]) => {
            let service = identifier(service)?;
            let id = sdk::SigningKeyId::from_trusted_state(identifier(id)?)?;
            let wrap = sdk::JournalKey::open(wrapping.as_ref())?;
            let key = if command == "prepare-key" {
                sdk::DirectorySigningKey::provision(signer.as_ref(), &wrap, id)?
            } else {
                sdk::DirectorySigningKey::open(signer.as_ref(), &wrap, id)?
            };
            print(
                &serde_json::json!({"schema":"qperiapt-directory-pin/1","service":service,
                "public_key":URL_SAFE_NO_PAD.encode(key.public_key()?.encode())}),
            )
        }
        (Some("init"), [pin, db, capacity]) => {
            let pin = json::<Pin>(pin, 16384)?.verified()?;
            let limit = capacity
                .to_str()
                .ok_or("Invalid capacity")?
                .parse::<u64>()?;
            drop(DirectoryLedger::provision(db.as_ref(), &pin, limit)?);
            print(&serde_json::json!({"initialized":true,"service_binding":pin.binding()}))
        }
        (Some("check-historical-receipt"), [pin, receipt]) => {
            // Historical verification needs only the independent pin and original wire.
            // No service owner, current policy, clock or cancellation status is consulted.
            let pin = json::<Pin>(pin, 16384)?.verified()?;
            let verified = pin.verify_historical_lease(&read(receipt.as_ref(), 8192)?)?;
            let request = verified.request();
            print(&serde_json::json!({
                "historical": true,
                "original_statement": verified.statement_digest(),
                "service_binding": verified.service_binding(),
                "request": {
                    "operation": request.operation(),
                    "requester": request.requester(),
                    "checkpoint": request.checkpoint(),
                    "valid_from": request.validity().from(),
                    "valid_until": request.validity().until(),
                },
                "manifest_digest": verified.manifest_digest(),
                "selection_digest": verified.selection_digest(),
                "classical_fingerprint": verified.classical_fingerprint(),
                "post_quantum_fingerprint": verified.post_quantum_fingerprint(),
            }))
        }
        (Some("inspect"), [pin, admission, publication]) => {
            let pin = json::<Pin>(pin, 16384)?.verified()?;
            let (_, selected, _) = json::<Admission>(admission, 512 * 1024)?
                .verify(&json(publication, 4 * 1024 * 1024)?, clock()?)?;
            print(
                &serde_json::json!({"service_binding":pin.binding(),"selection_digest":selected.digest(),
                "checkpoint":selected.manifest_context().directory_checkpoint()}),
            )
        }
        (Some("issue"), [service, grant, request, admission, publication, output]) => {
            let service: Service = json(service, 32768)?;
            let pin = service.check()?;
            let request = json::<Request>(request, 8192)?.checked()?;
            let (device, selection, policy) = json::<Admission>(admission, 512 * 1024)?
                .verify(&json(publication, 4 * 1024 * 1024)?, clock()?)?;
            let approval =
                json::<Grant>(grant, 16384)?.bind(Action::Issue, &pin, selection.digest())?;
            let wrap = sdk::JournalKey::open(&service.wrapping)?;
            let key = sdk::DirectorySigningKey::open(
                &service.signer,
                &wrap,
                sdk::SigningKeyId::from_trusted_state(service.signing_id)?,
            )?;
            let mut ledger = DirectoryLedger::open(&service.database, &pin)?;
            let record = ledger.issue(
                &key,
                request,
                &selection,
                &device,
                &policy,
                &approval,
                trusted_clock,
            )?;
            // Publishing the output may fail after commit: retry the original op.
            publish_private_bytes(output.as_ref(), record.wire())?;
            print(&serde_json::json!({"receipt_exported":true,"service_binding":pin.binding()}))
        }
        (Some("lookup"), [pin, db, operation, output]) => {
            let pin = json::<Pin>(pin, 16384)?.verified()?;
            let mut ledger = DirectoryLedger::open(db.as_ref(), &pin)?;
            let record = ledger
                .lookup(identifier(operation)?)?
                .ok_or("Unknown original operation")?;
            publish_private_bytes(output.as_ref(), record.wire())?;
            print(&serde_json::json!({"historical":true,"cancelled":record.cancelled()}))
        }
        (Some("cancel"), [pin, db, operation, grant]) => {
            let pin = json::<Pin>(pin, 16384)?.verified()?;
            let mut ledger = DirectoryLedger::open(db.as_ref(), &pin)?;
            let operation = identifier(operation)?;
            let prior = ledger
                .lookup(operation)?
                .ok_or("Unknown original operation")?;
            let receipt = pin.verify_historical_lease(prior.wire())?;
            let approval = json::<Grant>(grant, 16384)?.bind(
                Action::Cancel,
                &pin,
                receipt.selection_digest(),
            )?;
            let record = ledger.cancel(operation, &approval, trusted_clock)?;
            print(&serde_json::json!({"cancelled":record.cancelled()}))
        }
        (Some("check-receipt"), [pin, request, admission, publication, receipt]) => {
            let pin = json::<Pin>(pin, 16384)?.verified()?;
            let now = clock()?;
            let (device, selection, policy) = json::<Admission>(admission, 512 * 1024)?
                .verify(&json(publication, 4 * 1024 * 1024)?, now)?;
            let verified = pin.verify_lease(
                &read(receipt.as_ref(), 8192)?,
                json::<Request>(request, 8192)?.checked()?,
                &selection,
                &device,
                &policy,
                now,
            )?;
            print(
                &serde_json::json!({"signature_and_scope":true,"statement":verified.statement_digest()}),
            )
        }
        (Some("prove-conflict"), [pin, first, second, output]) => {
            let pin = json::<Pin>(pin, 16384)?.verified()?;
            let proof = sdk::DirectoryLeaseConflict::verify(
                &pin,
                &read(first.as_ref(), 8192)?,
                &read(second.as_ref(), 8192)?,
            )?;
            let directory = PathBuf::from(output);
            operator_io::export_directory(&directory)?;
            publish_private_bytes(&directory.join("conflict.bin"), &proof.to_bytes())?;
            print(&serde_json::json!({"conflicting_issuance":true}))
        }
        (Some("check-conflict"), [pin, proof]) => {
            let pin = json::<Pin>(pin, 16384)?.verified()?;
            sdk::DirectoryLeaseConflict::from_bytes(&pin, &read(proof.as_ref(), 16384)?)?;
            print(&serde_json::json!({"conflicting_issuance":true}))
        }
        _ => Err(USAGE.into()),
    }
}
