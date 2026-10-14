// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{FanoutId, FanoutMemberState, FanoutStatus};

struct Group {
    sender: Device,
    recipients: Vec<Device>,
    sessions: Vec<Session>,
    remote: Vec<Session>,
    policy: Arc<VerifiedSessionPolicy>,
    effects: Vec<Effects>,
    wires: Vec<Vec<Vec<u8>>>,
}
impl Group {
    fn new() -> Self {
        let (_, issued, pin, runtime) =
            crate::tests::session_policy_fixture(&[PrekeyQuality::OneTimeBoth]);
        let policy = Arc::new(pin.verify(issued.as_bytes(), runtime, 150).expect("policy"));
        let mut sender = Device::new(&policy);
        let mut recipients = Device::account(&policy, 2);
        let mut sessions = Vec::new();
        let mut remote = Vec::new();
        for (index, recipient) in recipients.iter_mut().enumerate() {
            let bundle = bundle(&sender, recipient, &policy);
            let required = || BootstrapRequirements {
                initiator: ExpectedDevice::new(&sender.pin, [7; 16], 1).expect("sender"),
                responder: ExpectedDevice::new(&recipient.pin, [7 + index as u8; 16], 1)
                    .expect("recipient"),
                quality: PrekeyQuality::OneTimeBoth,
                directory: DirectoryExpectation::from_trusted_state([77; 32]).expect("directory"),
            };
            let context = Arc::new(
                bundle
                    .verify(Arc::clone(&policy), required(), 150)
                    .expect("bundle"),
            );
            let a = sender
                .owner
                .parts()
                .expect("owner")
                .0
                .admit_peer(Arc::clone(&context), BootstrapRole::Initiator, 150)
                .expect("sender peer");
            let b = recipient
                .owner
                .parts()
                .expect("owner")
                .0
                .admit_peer(Arc::clone(&context), BootstrapRole::Responder, 150)
                .expect("receiver peer");
            let cancel = Cancellation::default();
            let mut effects = Effects::default();
            let mut carrier = Carrier {
                owner: &mut recipient.owner,
                peer: &b,
                effects: &mut effects,
                corrupt: false,
                lose: false,
                requests: vec![],
            };
            let session = sender
                .owner
                .establish_session(
                    &a,
                    InitiationId::generate().expect("request"),
                    &mut carrier,
                    &run(&cancel),
                    || Ok(150),
                )
                .expect("session");
            drop(carrier);
            let request = bundle
                .request_reopen(
                    Arc::clone(&policy),
                    required(),
                    BootstrapRole::Responder,
                    session.id(),
                    150,
                )
                .expect("retained descriptor");
            remote.push(Session::from_reopened(
                &recipient
                    .owner
                    .parts()
                    .expect("owner")
                    .0
                    .reopen_peer(request, 150)
                    .expect("reopen"),
            ));
            sessions.push(session);
        }
        Self {
            sender,
            recipients,
            sessions,
            remote,
            policy,
            effects: vec![Effects::default(), Effects::default()],
            wires: vec![vec![], vec![]],
        }
    }
    fn deliver(
        &mut self,
        id: FanoutId,
        selected: usize,
        lose: bool,
    ) -> Result<(AccountDelivered, Vec<Vec<u8>>), Error> {
        let account = self.recipients.first().expect("first recipient").account;
        let cancel = Cancellation::default();
        let mut carrier = Delivery {
            owner: &mut self
                .recipients
                .get_mut(selected)
                .expect("selected recipient")
                .owner,
            session: self.remote.get(selected).expect("selected remote session"),
            effects: self.effects.get_mut(selected).expect("selected effects"),
            lose,
            requests: vec![],
        };
        let result = self.sender.owner.deliver_account_member(
            AccountSubmission {
                id,
                account,
                sessions: &self.sessions,
                plaintext: b"all devices",
                associated_data: b"account/v1",
            },
            selected,
            &mut carrier,
            &run(&cancel),
            || Ok(150),
        );
        self.wires
            .get_mut(selected)
            .expect("selected wire history")
            .extend(carrier.requests.iter().cloned());
        result.map(|value| (value, carrier.requests))
    }
}
struct Delivery<'a> {
    owner: &'a mut EnrolledDevice,
    session: &'a Session,
    effects: &'a mut Effects,
    lose: bool,
    requests: Vec<Vec<u8>>,
}
impl Transport for Delivery<'_> {
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: Instant,
        cancel: &Cancellation,
    ) -> io::Result<Vec<u8>> {
        self.requests.push(request.to_vec());
        let reply = self
            .owner
            .serve_session_message(
                self.session,
                request,
                self.effects,
                &Run { deadline, cancel },
                || Ok(150),
            )
            .map_err(io::Error::other)?;
        if self.lose {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(reply)
    }
}
#[derive(Default)]
struct NoDispatch {
    calls: usize,
}
impl Transport for NoDispatch {
    fn exchange(&mut self, _: &[u8], _: Instant, _: &Cancellation) -> io::Result<Vec<u8>> {
        self.calls += 1;
        Err(io::Error::other("unexpected aggregate dispatch"))
    }
}

#[test]
fn portable_account_commits_all_members_and_recovers_original_after_lost_reply() {
    let mut group = Group::new();
    let id = group
        .sender
        .owner
        .next_account_message_id()
        .expect("next aggregate");
    let original_messages = group
        .sessions
        .iter()
        .map(|s| {
            group
                .sender
                .owner
                .next_session_message_id(s, 150)
                .expect("next message")
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        group.deliver(id, 0, true),
        Err(Error::Transport(_))
    ));
    assert!(
        group.sender.owner.parts().is_err(),
        "failed delivery closes sender"
    );
    assert_eq!(
        group.effects.first().expect("first effects").entries.len(),
        1
    );
    group.sender.reopen(&group.policy);
    assert_eq!(
        group
            .sender
            .owner
            .account_message_status(id)
            .expect("status"),
        FanoutStatus::Committed
    );
    let members = group
        .sender
        .owner
        .reconcile_account_message(id, &group.sessions)
        .expect("all original members");
    assert_eq!(members.members.len(), 2);
    for (member, original) in members.members.iter().zip(&original_messages) {
        assert_eq!(member.message, *original);
        assert_eq!(member.state, FanoutMemberState::Committed);
    }
    let delivered = group.deliver(id, 0, false).expect("same original retry").0;
    assert_eq!(
        delivered.message,
        *original_messages.first().expect("first original message")
    );
    assert_eq!(group.wires.first().expect("first wire history").len(), 2);
    assert_eq!(
        group
            .wires
            .first()
            .expect("first wire history")
            .first()
            .expect("original wire"),
        group
            .wires
            .first()
            .expect("first wire history")
            .get(1)
            .expect("replayed wire"),
        "exact original ciphertext replay"
    );
    assert_eq!(
        delivered.outcome,
        AccountDeliveryOutcome::Consumption(Consumption::Confirmed)
    );
    assert_eq!(
        group.effects.first().expect("first effects").calls,
        1,
        "committed inbox does not re-release plaintext"
    );
    assert_eq!(
        group.effects.first().expect("first effects").entries.len(),
        1
    );
    let cancel = Cancellation::default();
    let mut no_dispatch = NoDispatch::default();
    let repeat = group
        .sender
        .owner
        .deliver_account_member(
            AccountSubmission {
                id,
                account: group.recipients.first().expect("first recipient").account,
                sessions: &group.sessions,
                plaintext: b"all devices",
                associated_data: b"account/v1",
            },
            0,
            &mut no_dispatch,
            &run(&cancel),
            || Ok(150),
        )
        .expect("retained consumption");
    assert_eq!(no_dispatch.calls, 0);
    assert_eq!(repeat.exchanges, 0);
    assert_eq!(
        repeat.message,
        *original_messages.first().expect("first original message")
    );
    assert!(
        group.sender.owner.parts().is_ok(),
        "retained successful outcome must keep owner active"
    );
    let delivered = group
        .deliver(id, 1, false)
        .expect("second original member")
        .0;
    assert_eq!(
        delivered.message,
        *original_messages.get(1).expect("second original message")
    );
    let members = group
        .sender
        .owner
        .reconcile_account_message(id, &group.sessions)
        .expect("all confirmed");
    assert!(members
        .members
        .iter()
        .all(|m| m.state == FanoutMemberState::Acknowledged));
    group
        .sender
        .owner
        .retire_account_message(id, &group.sessions)
        .expect("complete retirement");
    assert_eq!(
        group
            .sender
            .owner
            .account_message_status(id)
            .expect("retired"),
        FanoutStatus::Retired
    );
    assert_ne!(
        group.sender.owner.next_account_message_id().expect("next"),
        id
    );
}

#[test]
fn portable_account_missing_or_duplicate_member_cannot_reserve_a_subset() {
    for duplicate in [false, true] {
        let mut group = Group::new();
        let id = group
            .sender
            .owner
            .next_account_message_id()
            .expect("next aggregate");
        let original = group
            .sessions
            .iter()
            .map(|s| {
                group
                    .sender
                    .owner
                    .next_session_message_id(s, 150)
                    .expect("next message")
            })
            .collect::<Vec<_>>();
        let mut invalid = vec![group.sessions.first().expect("first session").clone()];
        if duplicate {
            invalid.push(group.sessions.first().expect("first session").clone());
        }
        let cancel = Cancellation::default();
        let mut no_dispatch = NoDispatch::default();
        let result = group.sender.owner.deliver_account_member(
            AccountSubmission {
                id,
                account: group.recipients.first().expect("first recipient").account,
                sessions: &invalid,
                plaintext: b"all devices",
                associated_data: b"account/v1",
            },
            0,
            &mut no_dispatch,
            &run(&cancel),
            || Ok(150),
        );
        assert!(result.is_err());
        assert_eq!(no_dispatch.calls, 0, "invalid target set dispatched");
        assert!(group.sender.owner.parts().is_err());
        group.sender.reopen(&group.policy);
        assert_eq!(
            group
                .sender
                .owner
                .account_message_status(id)
                .expect("not reserved"),
            FanoutStatus::Absent
        );
        for (session, next) in group.sessions.iter().zip(original) {
            assert_eq!(
                group
                    .sender
                    .owner
                    .next_session_message_id(session, 150)
                    .expect("unchanged slot"),
                next
            );
        }
    }
}
