// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[test]
fn managed_enrollment_roster_commit_requires_the_live_original_registry_before_dispatch() {
    for closed in [false, true] {
        let c = case(false);
        let (mut registry, authority) =
            crate::enrollment::tests::witness_renewal::managed::bind(&c.f);
        let managed = || {
            open(&c.f.c)
                .with_account_authority(authority.clone())
                .expect("original descriptor")
        };
        let mut owner = managed();
        let client = policy_client(&c.f, &mut owner);
        let proposal = owner
            .prepare_witnessed_roster_refresh(
                RosterRefreshId::generate().expect("original operation"),
                c.f.c.policy.historical(),
                &c.policy,
                &c.target,
                150,
                client,
            )
            .expect("managed roster preparation");
        owner.close();
        witness_prepare(&c, proposal);
        let mut owner = if closed { managed() } else { open(&c.f.c) };
        let mut client = policy_client(&c.f, &mut owner);
        if closed {
            registry.close();
        }
        let before = c.f.carrier.requests.lock().expect("requests").len();
        let result = owner.commit_witnessed_roster_refresh(
            &proposal,
            c.f.c.policy.historical(),
            &c.policy,
            150,
            &mut client,
        );
        assert!(if closed {
            matches!(result, Err(DurableError::Closed))
        } else {
            matches!(result, Err(DurableError::Conflict))
        });
        assert_eq!(
            c.f.carrier.requests.lock().expect("requests").len(),
            before,
            "no new roster command without original registry"
        );
        owner.close();
        if !closed {
            let mut owner = managed();
            let mut client = policy_client(&c.f, &mut owner);
            assert_eq!(
                owner
                    .commit_witnessed_roster_refresh(
                        &proposal,
                        c.f.c.policy.historical(),
                        &c.policy,
                        150,
                        &mut client
                    )
                    .expect("original authorized roster commit"),
                RState::Applied
            );
            owner.close();
        }
        registry.close();
    }
}
