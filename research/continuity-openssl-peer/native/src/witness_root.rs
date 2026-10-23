// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently approved fixture target on the local test-control pipe.
//! Remote session traffic cannot select a root, plan, or genesis through this API.
use super::*;
use q_periapt_continuity_identity_candidate::{
    AccountPin, AnchorAccountReplacementPlan, AnchorAccountReplacementProposal,
    AnchorAccountReplacementState, BootstrapContext, ClassicalChoice, DirectoryExpectation,
    LeafProof, PqChoice, PublicKey, RosterCheckpoint, VerifiedDevice, VerifiedSessionPolicy,
};

struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let (value, rest) = self
            .0
            .split_at_checked(count)
            .ok_or("root control truncated")?;
        self.0 = rest;
        Ok(value)
    }
    fn field(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let count = usize::try_from(u32::from_be_bytes(self.take(4)?.try_into()?))?;
        if count == 0 || count > maximum {
            return Err("root control field capacity".into());
        }
        self.take(count)
    }
}

struct Target {
    previous: PublicKey,
    plan: AnchorAccountReplacementPlan,
    genesis: AnchorGenesis,
    device: VerifiedDevice,
    policy: Arc<VerifiedSessionPolicy>,
}
impl Target {
    fn read(
        input: &mut Input<'_>,
        fixture: &Fixture,
        pin: &AnchorPin,
        previous_account: [u8; 32],
    ) -> Result<Self> {
        let previous = PublicKey::decode(input.take(1985)?)?;
        let account = input.take(32)?.try_into()?;
        let next = PublicKey::decode(input.take(1985)?)?;
        let version = u64::from_be_bytes(input.take(8)?.try_into()?);
        let checkpoint =
            RosterCheckpoint::from_trusted_state(version, input.take(32)?.try_into()?)?;
        let policy_version = u64::from_be_bytes(input.take(8)?.try_into()?);
        let policy = if policy_version == fixture.policy.checkpoint().version() {
            Arc::clone(&fixture.policy)
        } else {
            fixture
                .policy_renewal
                .as_ref()
                .ok_or("root target policy unavailable")?
                .policy(policy_version)?
        };
        let next_pin = AccountPin::new(account, next, checkpoint, policy.family())?;
        // Authenticate complete historical materials. First freeze/commit below
        // additionally requires live target admission; exact terminal retry does not.
        let certificate = input.field(8192)?;
        let roster = input.field(8192)?;
        let device = next_pin.verify_historical_device(certificate, roster)?;
        let genesis = AnchorGenesis::from_trusted_state(
            AnchorSubject::from_trusted_state(input.take(96)?)?,
            input.take(32)?.try_into()?,
        )?;
        let plan = AnchorAccountReplacementPlan::from_trusted_state(input.field(8192)?)?;
        if plan.request().account() != previous_account {
            return Err("root control changes original account".into());
        }
        plan.verify_target(&previous, &genesis, &device, &policy, pin)?;
        Ok(Self {
            previous,
            plan,
            genesis,
            device,
            policy,
        })
    }
}

fn pack(parts: &[&[u8]]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for part in parts {
        output.extend_from_slice(&u32::try_from(part.len())?.to_be_bytes());
        output.extend_from_slice(part);
    }
    Ok(output)
}

impl Witness {
    /// Explicit test-controller approval; ordinary session bytes cannot call this.
    pub(crate) fn successor_context(
        &self,
        fixture: &Fixture,
        payload: &[u8],
    ) -> Result<(Arc<BootstrapContext>, u64)> {
        let mut input = Input(payload);
        let target = Target::read(
            &mut input,
            fixture,
            &self.pin,
            fixture
                .context
                .device(BootstrapRole::Initiator)
                .account_id(),
        )?;
        let proposal = AnchorAccountReplacementProposal::from_trusted_state(input.field(65536)?)?;
        let manifest = input.field(8192)?;
        let classical = LeafProof::decode(input.field(2048)?)?;
        let pq = LeafProof::decode(input.field(2048)?)?;
        if !input.0.is_empty() {
            return Err("successor peer control trailing data".into());
        }
        let now = self.now.load(Ordering::SeqCst);
        let mut guard = self.store.lock().map_err(|_| "witness lock poisoned")?;
        let store = guard.as_mut().ok_or("closed witness")?;
        if store.account_root_replacement_status(&proposal)?
            != AnchorAccountReplacementState::Committed
        {
            return Err("successor peer requires committed root retirement".into());
        }
        let receipt = store.retired_account_receipt(&proposal)?;
        target
            .plan
            .verify_retirement(&self.pin.verify_retired_account(&proposal, &receipt)?)?;
        let verified = fixture.responder.verify_manifest(manifest, now)?;
        let selection = verified.select_prekeys(
            &classical,
            &pq,
            ClassicalChoice::SignedOnly,
            PqChoice::LastResort,
            now,
        )?;
        let actual = fixture.prekey.public_key()?.to_bytes();
        let (expected_pq, expected_classical) =
            actual.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
        if selection.post_quantum().public_key() != expected_pq
            || selection.classical().public_key() != expected_classical
        {
            return Err("successor peer prekey differs from retained native key".into());
        }
        let context = BootstrapContext::new(
            target.policy,
            Arc::new(target.device),
            Arc::clone(&fixture.responder),
            Arc::new(selection),
            DirectoryExpectation::from_trusted_state([99; 32])?,
            now,
        )?;
        Ok((Arc::new(context), now))
    }

    pub(crate) fn root_command(
        &self,
        fixture: &Fixture,
        command: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let mut input = Input(payload);
        let now = self.now.load(Ordering::SeqCst);
        let mut guard = self.store.lock().map_err(|_| "witness lock poisoned")?;
        let store = guard.as_mut().ok_or("closed witness")?;
        let original_account = fixture
            .context
            .device(BootstrapRole::Initiator)
            .account_id();
        let previous_account = if matches!(command, 54 | 55) {
            // A later test-controller approval must continue the exact original
            // committed transition. An arbitrary account is never admitted here.
            let predecessor =
                AnchorAccountReplacementProposal::from_trusted_state(input.field(65536)?)?;
            if predecessor.previous_account() != original_account
                || store.account_root_replacement_status(&predecessor)?
                    != AnchorAccountReplacementState::Committed
            {
                return Err("later root requires original committed predecessor".into());
            }
            self.pin.verify_retired_account(
                &predecessor,
                &store.retired_account_receipt(&predecessor)?,
            )?;
            predecessor.successor_account()
        } else {
            original_account
        };
        let target = Target::read(&mut input, fixture, &self.pin, previous_account)?;
        let proposal = if matches!(command, 51 | 55) {
            Some(AnchorAccountReplacementProposal::from_trusted_state(
                input.field(65536)?,
            )?)
        } else {
            None
        };
        if !input.0.is_empty() || !matches!(command, 50 | 51 | 54 | 55) {
            return Err("root control trailing data or command".into());
        }
        if matches!(command, 50 | 54) {
            match store.account_freeze(target.plan.request()) {
                Ok(_) => {} // Exact persisted request: return its original historical freeze.
                Err(DurableError::Absent) => {
                    let canonical = store.account_replacement_plan(
                        target.plan.operation(),
                        target.plan.request().clone(),
                        &target.genesis,
                        &target.device,
                        &target.policy,
                        now,
                    )?;
                    if canonical != target.plan {
                        return Err("independent root plan differs".into());
                    }
                    store.freeze_account(target.plan.request())?;
                }
                Err(error) => return Err(error.into()),
            }
            let receipt = store.account_freeze_receipt(target.plan.request())?;
            self.pin
                .verify_account_freeze(target.plan.request(), &receipt)?;
            return pack(&[&target.plan.to_bytes()?, &receipt]);
        }
        let proposal = proposal.ok_or("root retirement requires original decision")?;
        match store.account_root_replacement_status(&proposal)? {
            AnchorAccountReplacementState::Unavailable => {
                let frozen = store.account_freeze(target.plan.request())?;
                let canonical = store.frozen_account_replacement_proposal(
                    target.plan.operation(),
                    &frozen,
                    &target.genesis,
                    &target.device,
                    &target.policy,
                    now,
                )?;
                if canonical != proposal {
                    return Err("root decision differs from approved target and freeze".into());
                }
            }
            AnchorAccountReplacementState::Committed => {}
            AnchorAccountReplacementState::Closed => {
                return Err("root decision already closed".into())
            }
        }
        if store.replace_account_root(
            &proposal,
            &target.previous,
            &target.genesis,
            &target.device,
            &target.policy,
            now,
        )? != AnchorAccountReplacementState::Committed
        {
            return Err("root retirement did not commit".into());
        }
        let receipt = store.retired_account_receipt(&proposal)?;
        let retired = self.pin.verify_retired_account(&proposal, &receipt)?;
        target.plan.verify_retirement(&retired)?;
        pack(&[&proposal.to_bytes()?, &receipt])
    }
}
