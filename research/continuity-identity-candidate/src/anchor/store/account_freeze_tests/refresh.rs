// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[test]
fn account_freeze_preserves_pending_roster_and_refuses_trusted_refresh_and_network_commands() {
    let mut c = required_case();
    let original = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original device")
        .1
        .clone();
    let (refreshed, _) = signed_device(&original, original.description.clone(), 2, 96, &[]);
    assert_eq!(storage_owner(&refreshed), storage_owner(&original));
    let policy = c.peer.responder.current_policy().expect("policy");
    let roster = crate::AnchorRosterRefreshProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        crate::RosterRefreshScope {
            operation: crate::RosterRefreshId::generate().expect("original roster operation"),
            previous: original.roster().checkpoint(),
            target: refreshed.roster().checkpoint(),
            policy: policy.checkpoint(),
            policy_authorization: None,
        },
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [187; 32]).expect("exact original target"),
    )
    .expect("original roster proposal");
    c.store
        .prepare_roster_refresh(roster, &original, &refreshed, policy, 150)
        .expect("actual pending refresh");
    let request = freeze_request(&c, original_root(&c), 180);
    let frozen = c
        .store
        .freeze_account(&request)
        .expect("freeze includes pending refresh");
    c.store.close();
    c.store = reopen(&c.server);
    let before = c.store.image().expect("frozen pending refresh").digest;
    for operation in [
        AnchorOperation::commit_roster_refresh(&roster),
        AnchorOperation::roster_refresh_status(&roster),
        AnchorOperation::close_roster_refresh(&roster),
        AnchorOperation::acknowledge_roster_refresh(&roster),
    ] {
        assert_retired(&mut c, operation);
    }
    let policy = c.peer.responder.current_policy().expect("policy");
    assert!(matches!(
        c.store
            .prepare_roster_refresh(roster, &original, &refreshed, policy, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        c.store
            .close_roster_refresh(roster, &original, &refreshed, policy.historical()),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        c.store.update_roster_authority(
            c.genesis.subject(),
            original.roster().checkpoint(),
            &refreshed,
            policy,
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        c.store.enroll(&c.genesis, &original, policy, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(c.store.image().expect("no refresh mutation").digest, before);
    assert_eq!(
        c.store
            .account_freeze(&request)
            .expect("exact pending metadata still retained"),
        frozen
    );
}
