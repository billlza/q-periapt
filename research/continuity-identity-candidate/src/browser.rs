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
mod opening;

/// Preserve storage receipt and cleanup errors at a JavaScript boundary.
pub fn failure(error: &DurableError) -> JsValue {
    Storage::failure_value(error)
}
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
        self.storage.close().await.map_err(|e| failure(&e))
    }
    fn begin_close(&self) {
        self.closed.set(true);
        self.cancellation.cancel();
        self.state.borrow_mut().take();
        self.storage.begin_close();
    }
    fn operation(&self) -> Result<Operation<'_>, JsValue> {
        if self.closed.get() {
            return Err(failure(&DurableError::Closed));
        }
        let state = self
            .state
            .borrow_mut()
            .take()
            .ok_or_else(|| failure(&DurableError::Io(std::io::ErrorKind::WouldBlock.into())))?;
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
    fn enrollment(&mut self) -> Result<&mut DeviceEnrollment, DurableError> {
        match self.state.as_mut() {
            Some(State::Enrollment(owner)) => Ok(owner),
            _ => Err(Error::State.into()),
        }
    }
    async fn finish<T>(mut self, result: Result<T, DurableError>) -> Result<T, JsValue> {
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
                Err(cleanup_error(
                    other.err().unwrap_or(DurableError::Closed),
                    cleanup,
                ))
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
