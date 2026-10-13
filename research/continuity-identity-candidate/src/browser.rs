// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Browser ownership of the shared enrollment and operational installation.
use crate::{
    storage::Storage, AccountPin, AnchorClient, AnchorPin, AnchorTransport, Cancellation,
    DeviceEnrollment, DurableError, EnrolledDevice, Error, InstallationPreparation,
    JournalIdentity, LeafKind, PrekeyId, Validity, VerifiedSessionPolicy,
};
use std::{
    cell::{Cell, RefCell},
    time::Duration,
};
use wasm_bindgen::JsValue;
mod errors;
mod opening;
mod publication;
pub use errors::{failure, input_failure};

fn cleanup_error(primary: DurableError, cleanup: Result<(), DurableError>) -> JsValue {
    match cleanup {
        Ok(()) => failure(&primary),
        Err(cleanup) => Storage::combine_failures(&failure(&primary), &failure(&cleanup)),
    }
}
enum State {
    Enrollment(Box<DeviceEnrollment>),
    Active(EnrolledDevice),
}

/// One original browser device, from enrollment through operational ownership.
/// Concurrent operations are refused. Failure, close or dropping a pending
/// operation closes this owner; recovery reopens the original persistent identity.
pub struct BrowserDevice {
    state: RefCell<Option<State>>,
    storage: Storage,
    closed: Cell<bool>,
    cancellation: Cancellation,
}
impl BrowserDevice {
    /// Whether this handle is permanently closed; not a resource-release or commit receipt.
    pub fn is_closed(&self) -> bool {
        self.closed.get()
    }
    /// Read authenticated original progress without granting traffic authority.
    pub async fn status(&self) -> Result<crate::EnrollmentStatus, JsValue> {
        let mut op = self.operation()?;
        let result = match op.state.as_mut() {
            Some(State::Enrollment(owner)) => owner.status(),
            Some(State::Active(owner)) => owner.enrollment_status(),
            None => Err(DurableError::Closed),
        };
        op.finish(result).await
    }
    /// Shared one-way signal for this owner's witness/peer transports.
    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
    /// Return the original committed signed enrollment request.
    pub async fn request(&self, now: u64) -> Result<Vec<u8>, JsValue> {
        let mut op = self.operation()?;
        let result = match op.enrollment() {
            Ok(owner) => owner.request(now).await,
            Err(e) => Err(e),
        };
        op.finish(result).await
    }
    /// Verify independent account/roster and policy admission before accepting a grant.
    pub async fn accept(
        &self,
        certificate: &[u8],
        roster: &[u8],
        pin: &AccountPin,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<JournalIdentity, JsValue> {
        let mut op = self.operation()?;
        let result = match op.enrollment() {
            Ok(owner) => owner.accept(certificate, roster, pin, policy, now).await,
            Err(e) => Err(e),
        };
        op.finish(result).await
    }
    /// Prepare the original child stores and return any required witness genesis.
    pub async fn prepare(
        &self,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<InstallationPreparation, JsValue> {
        let mut op = self.operation()?;
        let result = match op.enrollment() {
            Ok(owner) => owner.prepare(policy, now).await,
            Err(e) => Err(e),
        };
        op.finish(result).await
    }
    /// Activate the original installation without releasing a raw signer or store.
    /// A required witness must be independently enrolled and pinned; none means
    /// local policy only, never fallback from a missing or failed witness.
    pub async fn activate(
        &self,
        policy: &VerifiedSessionPolicy,
        now: u64,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<JournalIdentity, JsValue> {
        let mut op = self.operation()?;
        let result = self.activate_attempt(&mut op, policy, now, witness).await;
        op.finish(result).await
    }
    async fn activate_attempt(
        &self,
        op: &mut Operation<'_>,
        policy: &VerifiedSessionPolicy,
        now: u64,
        witness: Option<(AnchorPin, Box<dyn AnchorTransport>, Duration)>,
    ) -> Result<JournalIdentity, DurableError> {
        let anchor: Option<AnchorClient> = match witness {
            Some((pin, carrier, timeout)) => Some(
                op.enrollment()?
                    .anchor_client(policy, now, pin, carrier, timeout)
                    .await?,
            ),
            None => None,
        };
        let Some(State::Enrollment(owner)) = op.state.take() else {
            return Err(Error::State.into());
        };
        let mut active = (*owner).activate(policy, now, anchor).await?;
        let journal = active.parts()?.0.stores()?.0.identity()?;
        op.state = Some(State::Active(active));
        Ok(journal)
    }
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
            let Some(State::Active(active)) = op.state.as_mut() else {
                return Err(Error::State.into());
            };
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
    /// Close descendants, cancel pending transports, and await real storage release.
    pub async fn close(&self) -> Result<(), JsValue> {
        self.begin_close();
        self.storage
            .close()
            .await
            .map_err(|e| errors::owned(failure(&e), true))
    }
    fn begin_close(&self) {
        self.closed.set(true);
        self.cancellation.cancel();
        self.state.borrow_mut().take();
        self.storage.begin_close();
    }
    fn operation(&self) -> Result<Operation<'_>, JsValue> {
        if self.closed.get() {
            return Err(errors::owned(failure(&DurableError::Closed), true));
        }
        let state = self.state.borrow_mut().take().ok_or_else(|| {
            errors::owned(
                failure(&DurableError::Io(std::io::ErrorKind::WouldBlock.into())),
                false,
            )
        })?;
        Ok(Operation {
            owner: self,
            state: Some(state),
            armed: true,
        })
    }
}
impl Drop for BrowserDevice {
    fn drop(&mut self) {
        self.begin_close();
    }
}
struct Operation<'a> {
    owner: &'a BrowserDevice,
    state: Option<State>,
    armed: bool,
}
impl Operation<'_> {
    fn active(&mut self) -> Result<&mut EnrolledDevice, DurableError> {
        match self.state.as_mut() {
            Some(State::Active(owner)) => Ok(owner),
            _ => Err(Error::State.into()),
        }
    }
    fn enrollment(&mut self) -> Result<&mut DeviceEnrollment, DurableError> {
        match self.state.as_mut() {
            Some(State::Enrollment(owner)) => Ok(owner),
            _ => Err(Error::State.into()),
        }
    }
    async fn finish<T>(self, result: Result<T, DurableError>) -> Result<T, JsValue> {
        self.finish_failure(result.map_err(|error| failure(&error)))
            .await
    }
    async fn finish_failure<T>(mut self, result: Result<T, JsValue>) -> Result<T, JsValue> {
        match result {
            Ok(value) if !self.owner.closed.get() => {
                *self.owner.state.borrow_mut() = self.state.take();
                self.armed = false;
                Ok(value)
            }
            other => {
                self.state.take();
                self.owner.begin_close();
                let cleanup = self.owner.storage.close().await;
                self.armed = false;
                let primary = other
                    .err()
                    .unwrap_or_else(|| failure(&DurableError::Closed));
                let error = match cleanup {
                    Ok(()) => primary,
                    Err(cleanup) => Storage::combine_failures(&primary, &failure(&cleanup)),
                };
                Err(errors::owned(error, true))
            }
        }
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.state.take();
            self.owner.begin_close();
        }
    }
}
