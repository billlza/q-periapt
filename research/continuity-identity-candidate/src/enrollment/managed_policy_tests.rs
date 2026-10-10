// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[test]
fn managed_enrollment_policy_commit_requires_the_live_original_registry_before_dispatch() {
    for closed in [false, true] {
        let f = fixture();
        let (mut registry, authority) = super::super::managed::bind(&f);
        let managed = || {
            open(&f.c)
                .with_account_authority(authority.clone())
                .expect("original descriptor")
        };
        let mut owner = managed();
        let a = approval_with_owner(&f, &mut owner);
        let mut owner = managed();
        owner
            .stage_policy_renewal(
                &a.proof,
                a.proof.scope().operation,
                f.c.policy.historical(),
                &a.target,
                150,
            )
            .expect("original policy intent");
        let client = policy_client(&f, &mut owner);
        let proposal = owner
            .prepare_witnessed_policy_renewal(
                f.c.policy.historical(),
                f.c.policy.historical(),
                &a.target,
                150,
                client,
            )
            .expect("managed policy preparation");
        owner.close();
        approve_witness(&f, &a, proposal);
        let mut owner = if closed { managed() } else { open(&f.c) };
        let mut client = policy_client(&f, &mut owner);
        if closed {
            registry.close();
        }
        let before = f.carrier.requests.lock().expect("requests").len();
        let result = owner.commit_witnessed_policy_renewal(
            &proposal,
            f.c.policy.historical(),
            &a.target,
            150,
            &mut client,
        );
        assert!(if closed {
            matches!(result, Err(DurableError::Closed))
        } else {
            matches!(result, Err(DurableError::Conflict))
        });
        assert_eq!(
            f.carrier.requests.lock().expect("requests").len(),
            before,
            "no new policy command without registry admission"
        );
        owner.close();
        if !closed {
            let mut owner = managed();
            let mut client = policy_client(&f, &mut owner);
            assert_eq!(
                owner
                    .commit_witnessed_policy_renewal(
                        &proposal,
                        f.c.policy.historical(),
                        &a.target,
                        150,
                        &mut client
                    )
                    .expect("original authorized policy commit"),
                State::Applied
            );
            owner.close();
        }
        registry.close();
    }
}
