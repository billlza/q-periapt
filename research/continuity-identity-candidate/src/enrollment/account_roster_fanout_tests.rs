// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete remote-account updates preserve original sessions and fixed fanout meaning.
use super::*;
use crate::{CredentialRenewalAuthorization, CredentialRenewalMaterials, RosterRefreshId};
#[path = "account_peer_renewal_boundary_tests.rs"]
mod boundaries;

fn consume_first(a: &mut Endpoint, peers: &mut [Endpoint], links: &[Link], sent: &[FanoutMember]) {
    let item = sent.first().expect("first original member");
    let link = links.first().expect("first original session");
    let peer = peers.first_mut().expect("first original recipient");
    let receiver = journal(&mut peer.owner);
    receiver
        .receive_message(&link.receiver, item.session, wire(item), b"cohort", 150)
        .expect("first original delivery");
    receiver
        .consume_message(&link.receiver, item.session, item.message, 150)
        .expect("actual host consumption");
    let ack = receiver
        .message_acknowledgement(&link.receiver, item.session, 150)
        .expect("authenticated consumption");
    journal(&mut a.owner)
        .accept_message_acknowledgement(&link.sender, item.session, &ack, 150)
        .expect("original consumption retained");
}

fn grants(peers: &[Endpoint]) -> Vec<VerifiedCredentialRenewal> {
    let first = peers.first().expect("account owner");
    let root = &first.f.c.root;
    let successors = peers
        .iter()
        .map(|p| {
            root.issue_credential_extension(&p.f.original, 500, 150)
                .expect("explicit same-key extension")
        })
        .collect::<Vec<_>>();
    let entries = successors
        .iter()
        .map(|c| root.roster_entry(c).expect("member"))
        .collect::<Vec<_>>();
    let target = root
        .issue_roster(2, interval(), &entries)
        .expect("complete common target");
    let pin = AccountPin::new(
        first.f.original.account_id(),
        first.f.c.intent.root.clone(),
        target.checkpoint(),
        first.f.c.policy.family(),
    )
    .expect("independently selected account target");
    peers
        .iter()
        .zip(successors)
        .map(|(p, successor)| {
            let issued = root
                .issue_credential_renewal(
                    CredentialRenewalMaterials {
                        original_credential: &p.certificate,
                        previous_credential: &p.certificate,
                        successor_credential: &successor,
                        previous_roster: p.f.original.roster().as_bytes(),
                        successor_roster: target.as_bytes(),
                    },
                    &CredentialRenewalAuthorization {
                        operation: crate::CredentialRenewalId::generate().expect("original G ID"),
                        previous: p.f.original.roster().checkpoint(),
                        policy_digest: p.f.c.policy.checkpoint().digest(),
                    },
                    &pin,
                    155,
                )
                .expect("independent complete grant");
            VerifiedCredentialRenewal::verify(
                issued.as_bytes(),
                &pin,
                p.f.c.policy.checkpoint().digest(),
                155,
            )
            .expect("verified grant")
        })
        .collect()
}
fn renew(p: &mut Endpoint, index: usize, grants: &[VerifiedCredentialRenewal]) {
    p.owner.close();
    let g = grants.get(index).expect("original owning grant");
    let companions = grants
        .iter()
        .enumerate()
        .filter_map(|(i, g)| (i != index).then_some(g))
        .collect::<Vec<_>>();
    let mut owner = open(&p.f.c);
    owner
        .stage_account_credential_renewal(g, &companions, g.operation(), &p.f.c.policy, 155)
        .expect("complete owning intent");
    let anchor = client(&p.f, &mut owner, 155);
    let proposal = owner
        .prepare_witnessed_credential_renewal(&p.f.c.policy, 155, anchor)
        .expect("actual complete target");
    p.f.carrier
        .store
        .lock()
        .expect("witness")
        .prepare_credential_renewal(proposal, g, &p.f.c.policy, 155)
        .expect("independent original subject approval");
    let mut anchor = client(&p.f, &mut owner, 155);
    owner
        .commit_witnessed_credential_renewal(
            g.operation(),
            g.statement_digest(),
            &p.f.c.policy,
            155,
            &mut anchor,
        )
        .expect("original complete commit");
    let anchor = client(&p.f, &mut owner, 155);
    p.owner = owner
        .activate(&p.f.c.policy, 155, Some(anchor))
        .expect("same original owner");
}
fn reopen(
    a: &mut Endpoint,
    b: &mut Endpoint,
    link: &Link,
) -> (Arc<BootstrapContext>, Arc<BootstrapContext>) {
    let request = |role| {
        link.bundle
            .request_reopen(
                Arc::new(policy(&a.f.c, 1, a.f.c.policy.validity().until(), 155)),
                requirements(a, b),
                role,
                link.session,
                155,
            )
            .expect("original transcript request")
    };
    let left = request(BootstrapRole::Initiator);
    let right = request(BootstrapRole::Responder);
    let left = a
        .owner
        .parts()
        .expect("original owner")
        .0
        .reopen_peer(left, 155)
        .expect("original sender session");
    let right = b
        .owner
        .parts()
        .expect("original owner")
        .0
        .reopen_peer(right, 155)
        .expect("original recipient session");
    assert_eq!(left.session_id(), link.session);
    assert_eq!(right.session_id(), link.session);
    (Arc::clone(left.context()), Arc::clone(right.context()))
}
fn refresh(p: &mut Endpoint, target: &VerifiedDevice) {
    p.owner.close();
    let before = disk(&p.f);
    let mut owner = open(&p.f.c);
    let image = owner.image().expect("image");
    let previous = owner
        .policy_witness_current_device(&image)
        .expect("actual predecessor");
    let anchor = owner
        .roster_refresh_anchor_client(
            p.f.c.policy.historical(),
            p.f.pin.clone(),
            Box::new(p.f.carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("original R client");
    let proposal = owner
        .prepare_witnessed_roster_refresh(
            RosterRefreshId::generate().expect("R ID"),
            p.f.c.policy.historical(),
            &p.f.c.policy,
            target,
            155,
            anchor,
        )
        .expect("original complete-account R");
    owner.close();
    let saved = disk(&p.f);
    let pending = saved.1.expect("retained original target");
    let target_bytes = pending
        .get(341..pending.len().checked_sub(32).expect("MAC"))
        .expect("target");
    assert!(
        DeviceJournal::assert_roster_target_preserves_assets(
            &JournalKey::open(&p.f.c.paths.wrapping).expect("original key"),
            &p.f.original,
            &before.0,
            target_bytes,
            proposal.scope()
        ) > 0
    );
    p.f.carrier
        .store
        .lock()
        .expect("witness")
        .prepare_roster_refresh(proposal, &previous, target, &p.f.c.policy, 155)
        .expect("exact independent R");
    let mut owner = open(&p.f.c);
    let mut anchor = owner
        .roster_refresh_anchor_client(
            p.f.c.policy.historical(),
            p.f.pin.clone(),
            Box::new(p.f.carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("original R client");
    owner
        .commit_witnessed_roster_refresh(
            &proposal,
            p.f.c.policy.historical(),
            &p.f.c.policy,
            155,
            &mut anchor,
        )
        .expect("original R applied");
    owner.close();
    assert_eq!(disk(&p.f), (target_bytes.to_vec(), None));
    let mut owner = open(&p.f.c);
    let anchor = client(&p.f, &mut owner, 155);
    p.owner = owner
        .activate(&p.f.c.policy, 155, Some(anchor))
        .expect("same original current member");
}

fn cohort(count: usize) {
    let mut a = endpoint(fixture());
    let mut peers = recipients_count(&a.f, count);
    let links = peers
        .iter_mut()
        .map(|p| connect(&mut a, p))
        .collect::<Vec<_>>();
    let contexts = links
        .iter()
        .map(|l| Arc::clone(&l.sender))
        .collect::<Vec<_>>();
    let account = peers.first().expect("account").f.original.account_id();
    let old_batch = journal(&mut a.owner)
        .next_fanout_id()
        .expect("old batch ID");
    let old = journal(&mut a.owner)
        .send_account_message(
            FanoutInput {
                id: old_batch,
                account,
                targets: &selected(&contexts, &links),
                plaintext: b"original account batch",
                associated_data: b"cohort",
            },
            150,
        )
        .expect("complete original batch");
    assert_eq!(old.len(), count);
    consume_first(&mut a, &mut peers, &links, &old);
    let initial_report = journal(&mut a.owner)
        .reconcile_fanout(old_batch, &selected(&contexts, &links))
        .expect("complete original accounting");
    assert_eq!(initial_report.members.len(), count);
    assert_eq!(
        initial_report
            .members
            .first()
            .expect("consumed member")
            .state,
        crate::FanoutMemberState::Acknowledged
    );
    assert!(initial_report
        .members
        .iter()
        .skip(1)
        .all(|m| m.state == crate::FanoutMemberState::Committed));
    let grants = grants(&peers);
    a.f.carrier.clock.store(155, Ordering::SeqCst);
    let first = grants.first().expect("primary");
    let companions = grants.iter().skip(1).collect::<Vec<_>>();
    let before = journal(&mut a.owner).test_snapshot().digest;
    assert!(
        a.owner
            .parts()
            .expect("sender")
            .0
            .admit_peer_credential_renewal(first, first.operation(), &a.f.c.policy, 155)
            .is_err(),
        "one grant cannot authorize the other changed devices"
    );
    assert_eq!(journal(&mut a.owner).test_snapshot().digest, before);
    assert!(a
        .owner
        .parts()
        .expect("sender")
        .0
        .admit_peer_account_credential_renewal(
            first,
            &[first; crate::identity::MAX_DEVICES],
            first.operation(),
            &a.f.c.policy,
            155
        )
        .is_err());
    assert_eq!(journal(&mut a.owner).test_snapshot().digest, before);
    assert!(a
        .owner
        .parts()
        .expect("sender")
        .0
        .admit_peer_account_credential_renewal(
            first,
            companions
                .get(..companions.len() - 1)
                .expect("incomplete collection"),
            first.operation(),
            &a.f.c.policy,
            155
        )
        .is_err());
    assert_eq!(journal(&mut a.owner).test_snapshot().digest, before);
    let expected = first.successor_device().roster().checkpoint();
    assert_eq!(
        a.owner
            .parts()
            .expect("sender")
            .0
            .admit_peer_account_credential_renewal(
                first,
                &companions,
                first.operation(),
                &a.f.c.policy,
                155
            )
            .expect("complete remote account adoption"),
        expected
    );
    let saved = journal(&mut a.owner).test_snapshot().digest;
    let mut reversed = companions.clone();
    reversed.reverse();
    assert_eq!(
        a.owner
            .parts()
            .expect("sender")
            .0
            .admit_peer_account_credential_renewal(
                first,
                &reversed,
                first.operation(),
                &a.f.c.policy,
                155
            )
            .expect("same semantic original readback"),
        expected
    );
    assert_eq!(journal(&mut a.owner).test_snapshot().digest, saved);
    for (i, p) in peers.iter_mut().enumerate() {
        renew(p, i, &grants);
    }
    let views = peers
        .iter_mut()
        .zip(&links)
        .map(|(p, l)| reopen(&mut a, p, l))
        .collect::<Vec<_>>();
    let current = views.iter().map(|v| Arc::clone(&v.0)).collect::<Vec<_>>();
    let before = journal(&mut a.owner).test_snapshot().digest;
    assert!(journal(&mut a.owner)
        .resume_account_message(old_batch, &selected(&current, &links), 155)
        .is_err());
    assert_eq!(journal(&mut a.owner).test_snapshot().digest, before);
    assert_eq!(
        journal(&mut a.owner)
            .fanout_status(old_batch)
            .expect("original batch retained"),
        crate::FanoutStatus::Committed
    );
    let batch = journal(&mut a.owner)
        .next_fanout_id()
        .expect("current batch");
    let sent = journal(&mut a.owner)
        .send_account_message(
            FanoutInput {
                id: batch,
                account,
                targets: &selected(&current, &links),
                plaintext: b"current complete account",
                associated_data: b"cohort",
            },
            155,
        )
        .expect("all actual renewed recipients");
    for ((p, view), item) in peers.iter_mut().zip(&views).zip(&sent) {
        assert_eq!(
            journal(&mut p.owner)
                .receive_message(&view.1, item.session, wire(item), b"cohort", 155)
                .expect("original recipient decrypts")
                .as_bytes(),
            b"current complete account"
        );
    }
    // Remove one peer without renewing any surviving credential.
    let excluded_context = current.last().expect("current removed peer context");
    let excluded_session = links.last().expect("removed original session").session;
    journal(&mut a.owner)
        .next_message_id(excluded_context, excluded_session, 155)
        .expect("same current context is authorized before removal");
    let first_peer = peers.first().expect("issuer");
    let certificates = grants
        .iter()
        .take(count - 1)
        .map(|g| {
            let d = g.successor_device();
            first_peer
                .f
                .c
                .root
                .issue_device(d.description.clone(), d.key.clone())
                .expect("same C")
        })
        .collect::<Vec<_>>();
    let entries = certificates
        .iter()
        .map(|c| first_peer.f.c.root.roster_entry(c).expect("member"))
        .collect::<Vec<_>>();
    let roster = first_peer
        .f
        .c
        .root
        .issue_roster(3, interval(), &entries)
        .expect("independent removal");
    let pin = AccountPin::new(
        account,
        first_peer.f.c.intent.root.clone(),
        roster.checkpoint(),
        a.f.c.policy.family(),
    )
    .expect("independent R3 pin");
    let targets = certificates
        .iter()
        .map(|c| {
            pin.verify_device(c, roster.as_bytes(), 155)
                .expect("unchanged current member")
        })
        .collect::<Vec<_>>();
    a.owner
        .parts()
        .expect("sender")
        .0
        .admit_peer_roster(
            targets.first().expect("target").roster(),
            &a.f.c.policy,
            155,
        )
        .expect("current remote account removal");
    for (p, t) in peers.iter_mut().zip(&targets) {
        refresh(p, t);
    }
    let mut views_after = Vec::new();
    for (p, l) in peers.iter_mut().take(count - 1).zip(&links) {
        views_after.push(reopen(&mut a, p, l));
    }
    let remaining = views_after
        .iter()
        .map(|v| Arc::clone(&v.0))
        .collect::<Vec<_>>();
    assert!(journal(&mut a.owner)
        .resume_account_message(batch, &selected(&current, &links), 155)
        .is_err());
    assert_eq!(
        journal(&mut a.owner)
            .fanout_status(batch)
            .expect("old current batch retained"),
        crate::FanoutStatus::Committed
    );
    let next = journal(&mut a.owner)
        .next_fanout_id()
        .expect("post-removal batch");
    let sent = journal(&mut a.owner)
        .send_account_message(
            FanoutInput {
                id: next,
                account,
                targets: &selected(&remaining, &links),
                plaintext: b"surviving complete account",
                associated_data: b"cohort",
            },
            155,
        )
        .expect("exact remaining cohort");
    assert_eq!(sent.len(), count - 1);
    for ((p, v), item) in peers.iter_mut().zip(&views_after).zip(&sent) {
        assert_eq!(
            journal(&mut p.owner)
                .receive_message(&v.1, item.session, wire(item), b"cohort", 155)
                .expect("surviving original session")
                .as_bytes(),
            b"surviving complete account"
        );
    }
    assert!(journal(&mut a.owner)
        .next_message_id(excluded_context, excluded_session, 155)
        .is_err());
    assert_eq!(
        journal(&mut a.owner)
            .reconcile_fanout(old_batch, &selected(&contexts, &links))
            .expect("same complete historical accounting"),
        initial_report
    );
    eprintln!("COMMON_ACCOUNT_FANOUT members={count} original_sessions={count} complete_peer_G=true survivor_R=true fixed_old_batches=true revoked_peer_refused=true");
}

#[test]
fn native_common_account_roster_three_member_fanout_and_removal() {
    cohort(3);
}
#[test]
fn native_common_account_roster_capacity_fanout_and_removal() {
    cohort(crate::identity::MAX_DEVICES);
}
