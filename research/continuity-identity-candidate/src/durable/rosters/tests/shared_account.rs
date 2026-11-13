// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact account-wide roster changes need every affected credential authority.
//! Explicit fixture times test the transition contract, not a real-time expiry.
use super::*;
use crate::{
    CredentialRenewalAuthorization, CredentialRenewalMaterials, DeviceDescription,
    DeviceSigningKey, IssuedRoster,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const FAMILY: [u8; 32] = [8; 32];
const POLICY: [u8; 32] = [9; 32];

struct Case {
    root: RootSigningKey,
    old: [Vec<u8>; 2],
    new: [Vec<u8>; 2],
    initial: IssuedRoster,
    middle: IssuedRoster,
    target: IssuedRoster,
}
impl Case {
    fn new() -> Result<Self> {
        let root = RootSigningKey::generate()?;
        let mut old = Vec::new();
        let mut new = Vec::new();
        for id in [1u8, 2] {
            let key = DeviceSigningKey::generate()?;
            let certificate = |until| {
                root.issue_device(
                    DeviceDescription::new([id; 16], 1, FAMILY, Validity::new(100, until)?)?,
                    key.public_key()?,
                )
            };
            old.push(certificate(200)?);
            new.push(certificate(300)?);
        }
        let old: [Vec<u8>; 2] = old.try_into().map_err(|_| "original pair")?;
        let new: [Vec<u8>; 2] = new.try_into().map_err(|_| "successor pair")?;
        let roster = |version, members: &[&[u8]]| -> Result<IssuedRoster> {
            let entries = members
                .iter()
                .map(|certificate| root.roster_entry(certificate))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(root.issue_roster(version, Validity::new(100, 400)?, &entries)?)
        };
        let initial = roster(1, &[&old[0], &old[1]])?;
        let middle = roster(2, &[&new[0], &old[1]])?;
        let target = roster(3, &[&new[0], &new[1]])?;
        Ok(Self {
            root,
            old,
            new,
            initial,
            middle,
            target,
        })
    }
    fn pin(&self, roster: &IssuedRoster) -> Result<AccountPin> {
        Ok(AccountPin::new(
            self.root.account_id()?,
            self.root.public_key()?,
            roster.checkpoint(),
            FAMILY,
        )?)
    }
    fn roster(&self, roster: &IssuedRoster) -> Result<VerifiedRoster> {
        Ok(self.pin(roster)?.verify_roster(roster.as_bytes(), 150)?)
    }
    fn grant(
        &self,
        index: usize,
        predecessor: &IssuedRoster,
        target: &IssuedRoster,
    ) -> Result<VerifiedCredentialRenewal> {
        self.grant_in_policy(index, predecessor, target, POLICY)
    }
    fn grant_in_policy(
        &self,
        index: usize,
        predecessor: &IssuedRoster,
        target: &IssuedRoster,
        policy: [u8; 32],
    ) -> Result<VerifiedCredentialRenewal> {
        let old = self.old.get(index).ok_or("original member")?;
        let new = self.new.get(index).ok_or("successor member")?;
        let authorization = CredentialRenewalAuthorization {
            operation: CredentialRenewalId::from_trusted_state([u8::try_from(index)? + 11; 32])?,
            previous: predecessor.checkpoint(),
            policy_digest: policy,
        };
        let pin = self.pin(target)?;
        let grant = self.root.issue_credential_renewal(
            CredentialRenewalMaterials {
                original_credential: old,
                previous_credential: old,
                successor_credential: new,
                previous_roster: predecessor.as_bytes(),
                successor_roster: target.as_bytes(),
            },
            &authorization,
            &pin,
            150,
        )?;
        Ok(VerifiedCredentialRenewal::verify(
            grant.as_bytes(),
            &pin,
            policy,
            150,
        )?)
    }
}

#[test]
fn one_valid_grant_cannot_authorize_two_same_account_credential_changes() -> Result {
    let case = Case::new()?;
    let original = case.roster(&case.initial)?;
    let target = case.roster(&case.target)?;
    // Both root grants are individually authentic and name the same complete
    // target. Passing only either one must not authorize the other member.
    for index in 0..2 {
        let grant = case.grant(index, &case.initial, &case.target)?;
        assert_eq!(
            grant.successor_device().roster().checkpoint(),
            target.checkpoint()
        );
        assert!(matches!(
            Stored::initial(&original).advance_with_renewal(&target, Some(&grant)),
            Err(DurableError::Protocol(Error::Checkpoint))
        ));
    }
    Ok(())
}

#[test]
fn complete_original_successor_chain_updates_the_single_shared_roster() -> Result {
    let case = Case::new()?;
    let original = case.roster(&case.initial)?;
    let middle = case.roster(&case.middle)?;
    let target = case.roster(&case.target)?;
    let first = case.grant(0, &case.initial, &case.middle)?;
    let second = case.grant(1, &case.middle, &case.target)?;
    assert!(matches!(
        Stored::initial(&original).advance_with_renewal(&target, Some(&second)),
        Err(DurableError::Conflict)
    ));
    let stored = Stored::initial(&original).advance_with_renewal(&middle, Some(&first))?;
    assert_eq!(stored.roster.checkpoint(), middle.checkpoint());
    let stored = stored.advance_with_renewal(&target, Some(&second))?;
    assert_eq!(stored.roster.checkpoint(), target.checkpoint());
    assert_eq!(stored.renewals.len(), 2);
    let restored = decode(&id(&target.account_id()), &stored.record()?)?;
    assert_eq!(restored.roster.checkpoint(), target.checkpoint());
    for grant in [&first, &second] {
        let member = grant.successor_device();
        assert_eq!(
            restored.history.get(&member.device_id()),
            Some(&(member.generation(), member.credential_digest()))
        );
        assert_eq!(
            restored
                .renewals
                .get(&member.device_id())
                .ok_or("retained grant")?
                .statement_digest(),
            grant.statement_digest()
        );
        target.authorize_device(member, 150)?;
    }
    Ok(())
}

#[test]
fn complete_common_target_grants_are_order_independent_and_missing_duplicates_or_mixed_heads_fail(
) -> Result {
    let case = Case::new()?;
    let original = case.roster(&case.initial)?;
    let target = case.roster(&case.target)?;
    let first = case.grant(0, &case.initial, &case.target)?;
    let second = case.grant(1, &case.initial, &case.target)?;
    let apply = |grants: &[&VerifiedCredentialRenewal]| {
        Stored::initial(&original).advance_with_renewals(&target, grants)
    };
    let forward = apply(&[&first, &second])?;
    let reverse = apply(&[&second, &first])?;
    assert_eq!(forward.record()?.payload, reverse.record()?.payload);
    let restored = decode(&id(&target.account_id()), &forward.record()?)?;
    assert_eq!(restored.roster.checkpoint(), target.checkpoint());
    assert_eq!(restored.renewals.len(), 2);
    for grant in [&first, &second] {
        let device = grant.successor_device();
        assert_eq!(
            restored.history.get(&device.device_id()),
            Some(&(device.generation(), device.credential_digest()))
        );
        assert_eq!(
            restored
                .renewals
                .get(&device.device_id())
                .ok_or("complete grant")?
                .statement_digest(),
            grant.statement_digest()
        );
    }
    for incomplete in [
        vec![],
        vec![&first],
        vec![&second],
        vec![&first, &first],
        vec![&first, &second, &second],
    ] {
        assert!(apply(&incomplete).is_err());
    }
    let intermediate = case.grant(0, &case.initial, &case.middle)?;
    let later = case.grant(1, &case.middle, &case.target)?;
    assert!(apply(&[&intermediate, &second]).is_err());
    assert!(apply(&[&first, &later]).is_err());
    // A grant from another independently valid account cannot fill a missing
    // local member, even when its device IDs and roster versions are identical.
    let other = Case::new()?;
    let foreign = other.grant(1, &other.initial, &other.target)?;
    assert!(apply(&[&first, &foreign]).is_err());
    let other_policy = case.grant_in_policy(1, &case.initial, &case.target, [10; 32])?;
    assert!(apply(&[&first, &other_policy]).is_err());
    Ok(())
}
