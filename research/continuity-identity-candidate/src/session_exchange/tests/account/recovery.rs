// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{EnrollmentRecovery, EnrollmentStatus, SessionClosureStatus};

fn enrollment(group: &Group) -> DeviceEnrollment {
    DeviceEnrollment::open(group.sender.paths.clone(), group.sender.intent.clone())
        .expect("original enrollment")
}
fn account(group: &Group, id: FanoutId) -> EnrollmentRecovery {
    enrollment(group)
        .recover_account(id, group.policy.historical(), None)
        .expect("original restricted aggregate")
}

#[test]
fn enrolled_cleanup_accounts_original_members_with_closed_policy_and_retained_leases() {
    let mut group = Group::new();
    let id = group
        .sender
        .owner
        .next_account_message_id()
        .expect("original ID");
    assert!(matches!(
        group.deliver(id, 0, true),
        Err(Error::Transport(_))
    ));
    group.sender.owner.close();
    group.policy.close();

    // A different valid policy cannot reinterpret the immutable original binding.
    let (_, issued, pin, runtime) =
        crate::tests::session_policy_fixture(&[PrekeyQuality::ReusableBoth]);
    let other = pin
        .verify(issued.as_bytes(), runtime, 150)
        .expect("different valid policy");
    assert_ne!(
        other.checkpoint(),
        group.policy.checkpoint(),
        "negative fixture must differ"
    );
    assert!(matches!(
        enrollment(&group).recover_account(id, other.historical(), None),
        Err(DurableError::Conflict)
    ));
    let mut owner = account(&group, id);
    assert!(matches!(
        owner.enrollment_status(),
        Ok(EnrollmentStatus::Active(_))
    ));
    assert!(
        DeviceEnrollment::open(group.sender.paths.clone(), group.sender.intent.clone()).is_err(),
        "cleanup must retain the original enrollment lease"
    );
    assert!(matches!(
        owner.session(),
        Err(DurableError::Protocol(crate::Error::State))
    ));
    let original = owner
        .account()
        .expect("account")
        .reconcile_members()
        .expect("members");
    assert_eq!(original.members.len(), 2);
    assert!(original
        .members
        .iter()
        .all(|member| member.state == FanoutMemberState::Committed));
    assert!(matches!(
        owner.account().expect("account").begin(),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        owner.account().expect("account").retire_metadata(),
        Err(DurableError::Suspended)
    ));
    assert_eq!(
        owner
            .account()
            .expect("account")
            .reconcile_members()
            .expect("unchanged"),
        original
    );
    owner.close();
    assert!(matches!(owner.account(), Err(DurableError::Closed)));

    for member in &original.members {
        let open = || {
            enrollment(&group)
                .recover_session(member.session, group.policy.historical(), None)
                .expect("original restricted session")
        };
        let mut session = open();
        let report = session
            .session()
            .expect("session")
            .begin()
            .expect("frozen loss report");
        assert_eq!(report.session, member.session);
        assert!(report.reserved.is_empty());
        let unknown = report
            .epochs
            .iter()
            .flat_map(|epoch| &epoch.unconfirmed)
            .map(crate::UnconfirmedMessage::message_id)
            .collect::<Vec<_>>();
        assert_eq!(unknown, vec![member.message]);
        session.close();
        let mut session = open();
        assert_eq!(
            session
                .session()
                .expect("session")
                .status()
                .expect("pending"),
            SessionClosureStatus::Pending(report.report)
        );
        assert_eq!(
            session
                .session()
                .expect("session")
                .begin()
                .expect("same full report"),
            report
        );
        // In this fixture retaining the complete owned report models the host's
        // accounting receipt. It does not claim remote business consumption.
        session
            .session()
            .expect("session")
            .acknowledge(report.report)
            .expect("accounted");
        assert_eq!(
            session
                .session()
                .expect("session")
                .status()
                .expect("closed"),
            SessionClosureStatus::Closed(report.report)
        );
        session.close();
    }
    let mut owner = account(&group, id);
    let accounted = owner
        .account()
        .expect("account")
        .reconcile_members()
        .expect("all outcomes");
    assert_eq!(accounted.batch, original.batch);
    for (actual, original) in accounted.members.iter().zip(&original.members) {
        assert_eq!(
            (actual.device, actual.session, actual.message),
            (original.device, original.session, original.message)
        );
        assert_eq!(actual.state, FanoutMemberState::DeliveryUnknown);
    }
    owner
        .account()
        .expect("account")
        .retire_metadata()
        .expect("retire settled batch");
    assert_eq!(
        owner.account().expect("account").status().expect("retired"),
        FanoutStatus::Retired
    );
    owner.close();
    assert!(matches!(
        enrollment(&group).recover_account(id, group.policy.historical(), None),
        Err(DurableError::Protocol(crate::Error::Retired))
    ));
    assert!(
        enrollment(&group)
            .activate(&group.policy, 150, None)
            .is_err(),
        "cleanup must not restore the closed operational policy"
    );
}
