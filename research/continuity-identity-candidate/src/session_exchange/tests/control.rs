// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn established() -> (Pair, Session, Session) {
    let mut pair = Pair::new();
    let (a, b) = pair.peers();
    let cancel = Cancellation::default();
    let mut effects = Effects::default();
    let mut carrier = Carrier {
        owner: &mut pair.b.owner,
        peer: &b,
        effects: &mut effects,
        corrupt: false,
        lose: false,
        requests: vec![],
    };
    let session = pair
        .a
        .owner
        .establish_session(
            &a,
            InitiationId::generate().expect("id"),
            &mut carrier,
            &run(&cancel),
            || Ok(150),
        )
        .expect("establish");
    let (a, b) = pair.reopened(session.id());
    (pair, a, b)
}
struct Control<'a> {
    owner: &'a mut EnrolledDevice,
    session: &'a Session,
    drop_at: Option<usize>,
    before: bool,
    replace: Option<Vec<u8>>,
    requests: Vec<Vec<u8>>,
    replies: Vec<Vec<u8>>,
}
impl<'a> Control<'a> {
    fn new(owner: &'a mut EnrolledDevice, session: &'a Session) -> Self {
        Self {
            owner,
            session,
            drop_at: None,
            before: false,
            replace: None,
            requests: vec![],
            replies: vec![],
        }
    }
}
impl Transport for Control<'_> {
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: Instant,
        cancel: &Cancellation,
    ) -> io::Result<Vec<u8>> {
        self.requests.push(request.to_vec());
        let drop = self.drop_at == Some(self.requests.len());
        if drop && self.before {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let reply = self
            .owner
            .serve_session_control(self.session, request, &Run { deadline, cancel }, || Ok(150))
            .map_err(io::Error::other)?;
        self.replies.push(reply.clone());
        if drop {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(self.replace.as_ref().unwrap_or(&reply).clone())
    }
}
fn progress(owner: &mut EnrolledDevice, session: &Session, epoch: u64) {
    let observed = owner.session_rekey_progress(session).expect("progress");
    assert_eq!(observed.confirmed_epoch, epoch);
    assert_eq!(observed.sending_epoch, epoch);
    assert_eq!(observed.receiving_epoch, epoch);
    assert_eq!(observed.pending_epoch, None);
}
fn drive(pair: &mut Pair, a: &Session, b: &Session, target: u64) -> Vec<Vec<u8>> {
    let cancel = Cancellation::default();
    let mut carrier = Control::new(&mut pair.b.owner, b);
    let completed = pair
        .a
        .owner
        .drive_session_rekey(a, target, 4, &mut carrier, &run(&cancel), || Ok(150))
        .expect("target");
    assert_eq!(completed.epoch, target);
    assert_eq!(usize::from(completed.exchanges), carrier.requests.len());
    carrier.replies
}

#[test]
fn rekey_both_roles_reopens_and_uses_the_new_epoch_for_real_messages() {
    let (mut pair, a, b) = established();
    for target in 1..=3 {
        let replies = drive(&mut pair, &a, &b, target);
        assert_eq!(replies.len(), if target % 2 == 1 { 2 } else { 3 });
        progress(&mut pair.a.owner, &a, target);
        progress(&mut pair.b.owner, &b, target);
        pair.a.reopen(&pair.policy);
        pair.b.reopen(&pair.policy);
    }
    let id = pair.a.owner.next_session_message_id(&a, 150).expect("id");
    assert_eq!(crate::durable::message_epoch(id).expect("epoch"), 3);
    struct Data<'a> {
        owner: &'a mut EnrolledDevice,
        session: &'a Session,
        effects: Effects,
    }
    impl Transport for Data<'_> {
        fn exchange(
            &mut self,
            request: &[u8],
            deadline: Instant,
            cancel: &Cancellation,
        ) -> io::Result<Vec<u8>> {
            self.owner
                .serve_session_message(
                    self.session,
                    request,
                    &mut self.effects,
                    &Run { deadline, cancel },
                    || Ok(150),
                )
                .map_err(io::Error::other)
        }
    }
    let mut data = Data {
        owner: &mut pair.b.owner,
        session: &b,
        effects: Effects::default(),
    };
    assert_eq!(
        pair.a
            .owner
            .deliver_session_message(
                &a,
                Submission {
                    message: id,
                    plaintext: b"epoch three",
                    associated_data: b"rekey"
                },
                &mut data,
                &run(&Cancellation::default()),
                || Ok(150)
            )
            .expect("send"),
        Consumption::Confirmed
    );
    assert_eq!(
        data.effects.entries.get(&id).expect("effect"),
        b"epoch three"
    );
}

#[test]
fn every_control_request_and_reply_loss_resumes_exact_original_bytes() {
    for before in [true, false] {
        for (target, cut) in [(1, 1), (1, 2), (2, 1), (2, 2), (2, 3)] {
            let (mut pair, a, b) = established();
            if target == 2 {
                drive(&mut pair, &a, &b, 1);
            }
            let cancel = Cancellation::default();
            let mut carrier = Control::new(&mut pair.b.owner, &b);
            carrier.drop_at = Some(cut);
            carrier.before = before;
            assert!(matches!(
                pair.a.owner.drive_session_rekey(
                    &a,
                    target,
                    4,
                    &mut carrier,
                    &run(&cancel),
                    || Ok(150)
                ),
                Err(Error::Transport(_))
            ));
            let original = carrier.requests.last().expect("failed original").clone();
            assert!(matches!(pair.a.owner.parts(), Err(DurableError::Closed)));
            pair.a.reopen(&pair.policy);
            pair.b.reopen(&pair.policy);
            let mut retry = Control::new(&mut pair.b.owner, &b);
            let done = pair
                .a
                .owner
                .drive_session_rekey(&a, target, 4, &mut retry, &run(&cancel), || Ok(150))
                .expect("original target retry");
            assert_eq!(done.epoch, target);
            assert_eq!(retry.requests.first().expect("replay"), &original);
            progress(&mut pair.a.owner, &a, target);
            progress(&mut pair.b.owner, &b, target);
        }
    }
}

#[test]
fn empty_carrier_marker_and_previous_target_receipt_cannot_complete_new_work() {
    let (mut pair, a, b) = established();
    let cancel = Cancellation::default();
    let mut carrier = Control::new(&mut pair.b.owner, &b);
    carrier.replace = Some(frame(codec::CONTROL_REPLY, &[0]).expect("marker"));
    assert!(matches!(
        pair.a
            .owner
            .drive_session_rekey(&a, 1, 4, &mut carrier, &run(&cancel), || Ok(150)),
        Err(Error::Durable(DurableError::Protocol(
            crate::Error::Authentication
        )))
    ));
    assert!(matches!(pair.a.owner.parts(), Err(DurableError::Closed)));
    pair.a.reopen(&pair.policy);
    assert_eq!(
        pair.a
            .owner
            .session_rekey_progress(&a)
            .expect("progress")
            .confirmed_epoch,
        0
    );
    let replies = drive(&mut pair, &a, &b, 1);
    let mut carrier = Control::new(&mut pair.b.owner, &b);
    carrier.replace = Some(replies.last().expect("receipt").clone());
    assert!(matches!(
        pair.a
            .owner
            .drive_session_rekey(&a, 2, 4, &mut carrier, &run(&cancel), || Ok(150)),
        Err(Error::Durable(DurableError::Protocol(crate::Error::Scope)))
    ));
    pair.a.reopen(&pair.policy);
    assert_eq!(
        pair.a
            .owner
            .session_rekey_progress(&a)
            .expect("progress")
            .confirmed_epoch,
        1
    );
    drive(&mut pair, &a, &b, 2);
}

#[test]
fn exhausted_exchange_allowance_preserves_the_pending_target_and_closes_owner() {
    let (mut pair, a, b) = established();
    let cancel = Cancellation::default();
    let mut carrier = Control::new(&mut pair.b.owner, &b);
    assert!(matches!(
        pair.a
            .owner
            .drive_session_rekey(&a, 1, 1, &mut carrier, &run(&cancel), || Ok(150)),
        Err(Error::ExchangeLimit)
    ));
    assert_eq!(carrier.requests.len(), 1);
    assert!(matches!(pair.a.owner.parts(), Err(DurableError::Closed)));
    pair.a.reopen(&pair.policy);
    assert_eq!(
        pair.a
            .owner
            .session_rekey_progress(&a)
            .expect("progress")
            .pending_epoch,
        Some(1)
    );
    drive(&mut pair, &a, &b, 1);
    progress(&mut pair.a.owner, &a, 1);
    progress(&mut pair.b.owner, &b, 1);
}
