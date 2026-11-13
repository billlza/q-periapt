// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Existing enrollment APIs compose G with an independently retained P.
use super::*;

impl Configuration {
    pub fn refresh_under_policy(
        &self,
        fixture: &Fixture,
        version: u64,
        now: u64,
        session: [u8; 32],
    ) -> Result<(EnrolledDevice, Arc<BootstrapContext>)> {
        let policy = fixture
            .policy_renewal
            .as_ref()
            .ok_or("policy test issuer unavailable")?
            .policy(version)?;
        let mut owner = self.open()?;
        let admission = owner.public_admission()?;
        let previous = self
            .pin(fixture, admission.checkpoint())?
            .verify_historical_device(admission.certificate(), admission.roster())?;
        let pin = self.pin(fixture, self.checkpoint(4)?)?;
        let roster = fs::read(self.public.join("account/roster-4"))?;
        let target = pin.verify_device(admission.certificate(), &roster, now)?;
        if let Some(w) = &fixture.witness {
            let client = owner.roster_refresh_anchor_client(
                fixture.policy.historical(),
                w.pin.clone(),
                w.transport(),
                Duration::from_secs(10),
            )?;
            let proposal = owner.prepare_witnessed_roster_refresh(
                RosterRefreshId::generate()?,
                fixture.policy.historical(),
                &policy,
                &target,
                now,
                client,
            )?;
            w.approve_roster(proposal, &previous, &target, &policy)?;
            let mut client = owner.roster_refresh_anchor_client(
                fixture.policy.historical(),
                w.pin.clone(),
                w.transport(),
                Duration::from_secs(10),
            )?;
            owner.commit_witnessed_roster_refresh(
                &proposal,
                fixture.policy.historical(),
                &policy,
                now,
                &mut client,
            )?;
        } else {
            owner.refresh_roster(admission.checkpoint(), &roster, &pin, &policy, now)?;
        }
        owner.close();
        self.renew_policy(fixture, version, now, session)
    }

    pub fn renew_under_policy(
        &self,
        fixture: &Fixture,
        cycle: u64,
        version: u64,
        now: u64,
        session: [u8; 32],
    ) -> Result<(EnrolledDevice, Arc<BootstrapContext>)> {
        let policy = fixture
            .policy_renewal
            .as_ref()
            .ok_or("policy test issuer unavailable")?
            .policy(version)?;
        let grants = self.credential_grants(fixture, cycle, now)?;
        let local = grants.get(1).ok_or("native local grant missing")?;
        let companions = grants
            .iter()
            .enumerate()
            .filter_map(|(i, g)| (i != 1).then_some(g))
            .collect::<Vec<_>>();
        let mut owner = self.open()?;
        owner.stage_account_credential_renewal(
            local,
            &companions,
            local.operation(),
            &policy,
            now,
        )?;
        if let Some(w) = &fixture.witness {
            let client = owner.credential_renewal_anchor_client(
                fixture.policy.historical(),
                now,
                w.pin.clone(),
                w.transport(),
                Duration::from_secs(10),
            )?;
            let proposal = owner.prepare_witnessed_policy_continuation(
                fixture.policy.historical(),
                &policy,
                now,
                client,
            )?;
            w.approve_credential_under_policy(
                proposal,
                local,
                fixture.policy.historical(),
                &policy,
            )?;
            let mut client = owner.credential_renewal_anchor_client(
                fixture.policy.historical(),
                now,
                w.pin.clone(),
                w.transport(),
                Duration::from_secs(10),
            )?;
            owner.commit_witnessed_policy_continuation(
                &proposal,
                fixture.policy.historical(),
                &policy,
                now,
                &mut client,
            )?;
        }
        owner.close();
        // Re-enter the same policy completion and original session. Local
        // activation also reconciles the staged complete-account G.
        self.renew_policy(fixture, version, now, session)
    }
}
