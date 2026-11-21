// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native research entry points. The speculative worker never receives a signer.
use super::*;

impl DeviceJournal {
    fn stage4_state(
        &mut self,
        context: &BootstrapContext,
        session: &[u8; 32],
        offer: &[u8],
        now: u64,
    ) -> Result<(Image, State), DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, session, now)?;
        if state.role == proposer(state.control.target()?)? {
            return Err(Error::State.into());
        }
        verify_offer(&state, context, offer)?;
        match &state.control.plan {
            None => (),
            Some(super::super::Plan::Response(p)) if p.offer == offer => (),
            _ => return Err(DurableError::Conflict),
        }
        Ok((image, state))
    }

    /// Bind the exact authenticated rekey input. The surrounding record binds the
    /// session, role, epoch, predecessor and original journal. Phase 10 encodes only the offer.
    pub fn stage4_bind(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        offer: &[u8],
        now: u64,
    ) -> Result<RekeyResponseStatus, DurableError> {
        let (mut image, mut state) = self.stage4_state(context, &session, offer, now)?;
        if let Some(super::super::Plan::Response(p)) = &state.control.plan {
            return Ok(p.status());
        }
        state.admit_history_retirement()?;
        state.control.plan = Some(super::super::Plan::Response(Plan {
            offer: offer.to_vec(),
            stage: Stage::InputBound,
        }));
        self.store_message_state(&mut image, &state)?;
        Ok(RekeyResponseStatus::InputBound)
    }

    /// Select the response body, pending root and original phase-5 signing reservation.
    /// The callback is a trusted computation with only public inputs. It runs
    /// only in the exclusively owned, authenticated input-only state.
    pub fn stage4_select(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        offer: &[u8],
        now: u64,
        compute: impl FnOnce(
            &PublicKey,
            [u8; 32],
            q_periapt_policy::TrustedPolicyState,
        ) -> Result<(Ciphertext, ZeroizingBytes<32>), DurableError>,
    ) -> Result<Vec<u8>, DurableError> {
        let (mut image, mut state) = self.stage4_state(context, &session, offer, now)?;
        let Some(super::super::Plan::Response(p)) = &state.control.plan else {
            return Err(DurableError::Suspended);
        };
        match &p.stage {
            Stage::Signing { body, .. } => return Ok(body.clone()),
            Stage::Ready { wire, .. } => return Ok(open_envelope(wire)?.0.to_vec()),
            Stage::Encapsulation(_) => return Err(DurableError::Suspended),
            Stage::InputBound => (),
        }
        let (body, _) = open_envelope(offer)?;
        let peer = PublicKey::from_bytes(
            body.get(BODY_LEN - PUBLIC_KEY_LEN..)
                .ok_or(Error::Encoding)?,
        )
        .map_err(Error::from)?;
        let policy = context.current_policy()?;
        if !policy.runtime.is_enabled().map_err(Error::from)? {
            return Err(Error::PolicyDenied.into());
        }
        let (ciphertext, shared) =
            compute(&peer, kem_context(offer), policy.runtime.trusted_state())?;
        rosters::authorize_session_context(&image, context, now)?;
        let (body, root) = contribution(
            &state,
            &session,
            &context.digest(),
            offer,
            &ciphertext,
            &shared,
        )?;
        #[cfg(feature = "stage4-observation")]
        observe("QPERIAPT_STAGE4_PROPOSAL", "unsigned-body", &body)?;
        let scope = operation_scope(&image, &state, context, &session, offer)?;
        let signing = SigningReservation::reserve(
            &device(context, state.role)?.key,
            &hash(b"response-sign", &scope),
            Purpose::RekeyResponse,
            &body,
        )?;
        state.control.plan = Some(super::super::Plan::Response(Plan {
            offer: offer.to_vec(),
            stage: Stage::Signing {
                body: body.clone(),
                root,
                signing,
            },
        }));
        self.store_message_state(&mut image, &state)?;
        Ok(body)
    }

    /// Gate signing on the authoritative selected record. The argument is an
    /// equality check only. The existing signer gets its body and coins from
    /// the independently reloaded original record under the same owner lease.
    pub fn stage4_sign_selected(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        offer: &[u8],
        expected: &[u8],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, &session, now)?;
        let selected = if let Some(last) = state
            .control
            .last
            .as_ref()
            .filter(|last| last.offer == offer)
        {
            open_envelope(&last.response)?.0
        } else {
            match &state.control.plan {
                Some(super::super::Plan::Response(p)) if p.offer == offer => match &p.stage {
                    Stage::Signing { body, .. } => body.as_slice(),
                    Stage::Ready { wire, .. } => open_envelope(wire)?.0,
                    _ => return Err(DurableError::Suspended),
                },
                Some(super::super::Plan::Completing(p)) if p.inputs().0 == offer => {
                    open_envelope(p.inputs().1)?.0
                }
                Some(_) => return Err(DurableError::Conflict),
                None => return Err(DurableError::Suspended),
            }
        };
        if selected != expected {
            return Err(DurableError::Conflict);
        }
        self.respond_rekey_offer(context, session, offer, signer, now)
    }
}

#[cfg(feature = "stage4-observation")]
pub(super) fn observe(variable: &str, name: &str, wire: &[u8]) -> Result<(), DurableError> {
    use std::io::Write;
    let Some(dir) = std::env::var_os(variable) else {
        return Ok(());
    };
    let path = std::path::Path::new(&dir);
    let mut out = std::fs::File::create_new(path.join(format!("{name}.tmp")))?;
    out.write_all(wire)?;
    out.sync_all()?;
    drop(out);
    std::fs::rename(path.join(format!("{name}.tmp")), path.join(name))?;
    if path.join("stop").exists() {
        loop {
            std::thread::park();
        }
    }
    Ok(())
}
