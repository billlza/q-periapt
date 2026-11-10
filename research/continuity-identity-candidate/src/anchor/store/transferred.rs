// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::anchor::transferred;
impl AnchorStore {
    pub(super) fn handle_transferred(
        &mut self,
        wire: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, AnchorError> {
        let pin = self.pin()?;
        let parsed = transferred::incoming(&pin, wire)?;
        let request = &parsed.request;
        let mut image = self.image()?;
        if image.subject_retired(request.subject) || image.subject_frozen(request.subject) {
            return Err(Error::Scope.into());
        }
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let context = active
            .transferred
            .as_ref()
            .ok_or(DurableError::Suspended)?
            .client_context(request.subject)?;
        if context != parsed.context {
            return Err(Error::Scope.into());
        }
        let id = request.subject.id(&image.namespace);
        if !image.inherited.contains(&id) {
            return Err(Error::Scope.into());
        }
        let entry = image.entries.get_mut(&id).ok_or(Error::Scope)?;
        if entry.subject != request.subject {
            return Err(Error::Scope.into());
        }
        entry.device.verify(
            Purpose::AnchorTransferredRequest,
            request.body,
            request.signature,
        )?;
        let (outcome, changed) = entry.execute(request, now)?;
        let (head, last) = (entry.head, entry.last);
        if changed {
            self.persist(&mut image)?;
        }
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        match transferred::reply(&pin, &active.signer, &parsed, outcome, head, last) {
            Ok(wire) => Ok(wire),
            Err(error) => {
                self.close();
                Err(AnchorError::ReplyUnavailable(error))
            }
        }
    }
}
