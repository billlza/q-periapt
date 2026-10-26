// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Distinguish a future snapshot from one exact already signed account freeze.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PreparedTarget {
    Future(Box<AnchorAccountReplacementPlan>),
    Frozen {
        request: Box<AnchorAccountFreezeRequest>,
        // The exact freeze digest replaces its subject vector only in this
        // preparation. Binding restores the complete original signed snapshot.
        target: Box<AnchorAccountReplacementProposal>,
    },
}
impl PreparedTarget {
    pub(super) const MAX_BYTES: usize =
        AnchorAccountFreezeRequest::WIRE_BYTES + 4 + AnchorAccountReplacementPlan::MAX_BYTES;

    pub(super) fn frozen(
        frozen: &AnchorFrozenAccount,
        mut target: AnchorAccountReplacementProposal,
    ) -> Result<Self, DurableError> {
        if target.preparation != Some(frozen.binding()?) {
            return Err(DurableError::Conflict);
        }
        target.frozen.clear();
        Ok(Self::Frozen {
            request: Box::new(frozen.request().clone()),
            target: Box::new(target),
        })
    }
    pub(super) fn tag(&self) -> &'static [u8; 8] {
        match self {
            Self::Future(_) => b"QPTARP01",
            Self::Frozen { .. } => b"QPTARP02",
        }
    }
    pub(super) fn request(&self) -> &AnchorAccountFreezeRequest {
        match self {
            Self::Future(p) => p.request(),
            Self::Frozen { request, .. } => request,
        }
    }
    pub(super) fn proposal(&self) -> &AnchorAccountReplacementProposal {
        match self {
            Self::Future(p) => p.target(),
            Self::Frozen { target, .. } => target,
        }
    }
    fn check_shape(&self) -> Result<(), Error> {
        match self {
            Self::Future(p) => p.to_bytes().map(|_| ()),
            Self::Frozen { request, target } => {
                target.check_shape()?;
                if target.previous_account() != request.account()
                    || target.preparation.is_none()
                    || !target.frozen.is_empty()
                {
                    return Err(Error::Scope);
                }
                if target.to_bytes()?.len() > AnchorAccountReplacementPlan::MAX_BYTES {
                    return Err(Error::Capacity);
                }
                Ok(())
            }
        }
    }
    pub(super) fn check(&self, history: &AnchorHandoffHistory) -> Result<(), DurableError> {
        self.check_shape()?;
        self.request()
            .check_transferred_target(&self.proposal().previous_root, history)?;
        Ok(())
    }
    pub(super) fn bind(
        &self,
        frozen: &AnchorFrozenAccount,
        history: &AnchorHandoffHistory,
    ) -> Result<AnchorAccountReplacementProposal, DurableError> {
        match self {
            Self::Future(p) => p.bind_transferred(frozen, history),
            Self::Frozen { request, target } => {
                self.check(history)?;
                frozen.require_transfer_proof(history)?;
                if frozen.request() != request.as_ref()
                    || target.preparation != Some(frozen.binding()?)
                {
                    return Err(DurableError::Conflict);
                }
                let mut proposal = target.as_ref().clone();
                proposal.frozen = frozen.subjects().collect();
                proposal.check_shape()?;
                Ok(proposal)
            }
        }
    }
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.check_shape()?;
        match self {
            Self::Future(p) => out.extend_from_slice(&p.to_bytes()?),
            Self::Frozen { request, target } => {
                out.extend_from_slice(&request.to_bytes());
                let wire = target.to_bytes()?;
                out.extend_from_slice(
                    &u32::try_from(wire.len())
                        .map_err(|_| Error::Capacity)?
                        .to_be_bytes(),
                );
                out.extend_from_slice(&wire);
            }
        }
        Ok(())
    }
    pub(super) fn decode(tag: [u8; 8], bytes: &[u8]) -> Result<Self, Error> {
        let result = match &tag {
            b"QPTARP01" => Self::Future(Box::new(
                AnchorAccountReplacementPlan::from_trusted_state(bytes)?,
            )),
            b"QPTARP02" => {
                if bytes.len() > Self::MAX_BYTES {
                    return Err(Error::Capacity);
                }
                let mut d = Decoder::new(bytes);
                let request = AnchorAccountFreezeRequest::from_bytes(
                    d.take(AnchorAccountFreezeRequest::WIRE_BYTES)?,
                )?;
                let size =
                    usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| Error::Capacity)?;
                if size > AnchorAccountReplacementPlan::MAX_BYTES {
                    return Err(Error::Capacity);
                }
                let target = AnchorAccountReplacementProposal::from_trusted_state(d.take(size)?)?;
                d.finish()?;
                Self::Frozen {
                    request: Box::new(request),
                    target: Box::new(target),
                }
            }
            _ => return Err(Error::Encoding),
        };
        result.check_shape()?;
        Ok(result)
    }
}
