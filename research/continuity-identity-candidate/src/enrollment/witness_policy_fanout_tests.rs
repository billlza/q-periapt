// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Required-witness fanout across two independently enrolled recipient devices.
use super::*;
use crate::enrollment::tests::policy_continuation::{joint, policy, scope};
use crate::{FanoutMember, FanoutOutput, VerifiedEnrollmentRequest};

fn recipients(sender: &Fixture) -> Vec<Endpoint> {
    let mut enrolled = Vec::new();
    let mut certificates = Vec::new();
    for id in [8, 9] {
        let mut c = case_with_anchor(crate::AnchorRequirement::required(&sender.pin));
        c.root = RootSigningKey::deterministic([45; 32], [46; 32])
            .expect("same independently controlled recipient account");
        c.intent = EnrollmentIntent::new(
            c.root.public_key().expect("account key"),
            DeviceDescription::new([id; 16], 1, c.policy.family(), interval())
                .expect("different approved device"),
        );
        c.policy = policy(&c, 1, 200, 150);
        let mut owner = create(&c);
        let request = owner.request(150).expect("real durable enrollment request");
        let verified = VerifiedEnrollmentRequest::verify(&request, &c.intent, 150)
            .expect("independent possession proof");
        certificates.push(
            c.root
                .issue_enrollment(&verified, 150)
                .expect("certificate"),
        );
        enrolled.push((c, owner));
    }
    let issuer = &enrolled.first().expect("recipient account").0.root;
    let entries: Vec<_> = certificates
        .iter()
        .map(|cert| issuer.roster_entry(cert).expect("approved member"))
        .collect();
    let roster = issuer
        .issue_roster(1, interval(), &entries)
        .expect("complete two-device roster");
    let pin = AccountPin::new(
        issuer.account_id().expect("account"),
        issuer.public_key().expect("key"),
        roster.checkpoint(),
        sender.c.policy.family(),
    )
    .expect("independent account pin");
    enrolled
        .into_iter()
        .zip(certificates)
        .map(|((c, mut owner), certificate)| {
            let id = owner
                .accept(&certificate, roster.as_bytes(), &pin, &c.policy, 150)
                .expect("accept complete account membership");
            let image = owner.image().expect("accepted config");
            let original = owner
                .admitted(&image, &c.policy, 150)
                .expect("original device");
            let genesis = match owner.prepare(&c.policy, 150).expect("prepare") {
                InstallationPreparation::RequiresEnrollment(genesis) => Ok(genesis),
                InstallationPreparation::Local => Err("unexpected local protection"),
            }
            .expect("required witness fixture");
            sender
                .carrier
                .store
                .lock()
                .expect("witness")
                .enroll(&genesis, &original, &c.policy, 150)
                .expect("independent enrollment in actual witness");
            let anchor = owner
                .anchor_client(
                    &c.policy,
                    150,
                    sender.pin.clone(),
                    Box::new(sender.carrier.clone()),
                    Duration::from_secs(3),
                )
                .expect("original witness client");
            let owner = owner
                .activate(&c.policy, 150, Some(anchor))
                .expect("original active device");
            let endpoint_pin = AccountPin::new(
                original.account_id(),
                c.intent.root.clone(),
                roster.checkpoint(),
                c.policy.family(),
            )
            .expect("same independently approved account pin");
            Endpoint {
                f: Fixture {
                    _witness_dir: Arc::clone(&sender._witness_dir),
                    c,
                    pin: sender.pin.clone(),
                    carrier: sender.carrier.clone(),
                    original,
                    id,
                },
                owner,
                certificate,
                pin: endpoint_pin,
            }
        })
        .collect()
}

struct Link {
    sender: Arc<BootstrapContext>,
    receiver: Arc<BootstrapContext>,
    session: [u8; 32],
}
fn connect(a: &mut Endpoint, b: &mut Endpoint) -> Link {
    let bundle = bundle(a, b);
    let ci = Arc::new(
        bundle
            .verify(
                Arc::new(policy(&a.f.c, 1, 200, 150)),
                requirements(a, b),
                150,
            )
            .expect("initiator context"),
    );
    let cr = Arc::new(
        bundle
            .verify(
                Arc::new(policy(&b.f.c, 1, 200, 150)),
                requirements(a, b),
                150,
            )
            .expect("responder context"),
    );
    let id = InitiationId::generate().expect("original handshake identity");
    let (is, ik, _) = a.owner.parts().expect("sender");
    let (rs, rk, _) = b.owner.parts().expect("receiver");
    let (ij, ia) = is.stores().expect("sender stores");
    let (rj, ra) = rs.stores().expect("receiver stores");
    let initial = ij.initiate(Arc::clone(&ci), id, ik, 150).expect("initial");
    let reply = rj
        .respond_from_inventory(Arc::clone(&cr), &initial, rk, 150)
        .expect("reply");
    let done = ij
        .accept_reply(Arc::clone(&ci), id, &reply, 150)
        .expect("finish initiator");
    let session = done.session_id();
    rj.finish(Arc::clone(&cr), &initial, done.final_message(), 150)
        .expect("finish responder");
    ij.activate_initiator_messages(Arc::clone(&ci), id, 150)
        .expect("sender message state");
    rj.activate_responder_messages(Arc::clone(&cr), &initial, 150)
        .expect("receiver message state");
    let archive = ij
        .archive_session_closure(&ci, session)
        .expect("sender original archive");
    ia.retain(ij, &ci, session, &archive)
        .expect("retain sender archive");
    let archive = rj
        .archive_session_closure(&cr, session)
        .expect("receiver original archive");
    ra.retain(rj, &cr, session, &archive)
        .expect("retain receiver archive");
    Link {
        sender: ci,
        receiver: cr,
        session,
    }
}

fn adopt(
    a: &mut Endpoint,
    grant: &VerifiedCredentialRenewal,
    previous: &VerifiedSessionPolicy,
    prior: Option<&VerifiedPolicyContinuation>,
    target: &VerifiedSessionPolicy,
) -> VerifiedPolicyContinuation {
    a.owner.close();
    a.f.carrier.clock.store(170, Ordering::SeqCst);
    let mut expected = scope(&a.f.c, grant, a.f.id);
    expected.previous_policy = previous.checkpoint();
    expected.previous_authorization = prior.map(VerifiedPolicyContinuation::statement_digest);
    let t = joint(&a.f.c, grant, &expected, previous, target);
    let mut owner = open(&a.f.c);
    owner
        .stage_policy_continuation(grant, &t, grant.operation(), target, 170)
        .expect("stage joint renewal");
    let anchor = client(&a.f, &mut owner, 170);
    let proposal = owner
        .prepare_witnessed_policy_continuation(a.f.c.policy.historical(), target, 170, anchor)
        .expect("original sealed joint target");
    a.f.carrier
        .store
        .lock()
        .expect("witness")
        .prepare_policy_continuation(
            proposal,
            &t,
            &PolicyContinuationMaterials {
                original: a.f.c.policy.historical(),
                previous: previous.historical(),
                target,
                credential: grant,
            },
            170,
        )
        .expect("independent exact joint approval");
    let mut anchor = client(&a.f, &mut owner, 170);
    assert_eq!(
        owner
            .commit_witnessed_policy_continuation(
                &proposal,
                a.f.c.policy.historical(),
                target,
                170,
                &mut anchor,
            )
            .expect("durable completion and ACK"),
        committed(grant, &proposal)
    );
    owner.close();
    a.owner = activate(&a.f, target);
    t
}
fn continued(
    a: &mut Endpoint,
    links: &[Link],
    p: Arc<VerifiedSessionPolicy>,
) -> Vec<Arc<BootstrapContext>> {
    links
        .iter()
        .map(|link| {
            journal(&mut a.owner)
                .prepare_continued_context(
                    Arc::clone(&link.sender),
                    link.session,
                    BootstrapRole::Initiator,
                    Arc::clone(&p),
                    170,
                )
                .expect("current context for original member")
        })
        .collect()
}
fn selected<'a>(contexts: &'a [Arc<BootstrapContext>], links: &[Link]) -> Vec<FanoutTarget<'a>> {
    contexts
        .iter()
        .zip(links)
        .map(|(context, link)| FanoutTarget {
            context,
            session: link.session,
        })
        .collect()
}
fn wire(member: &FanoutMember) -> &[u8] {
    match &member.output {
        FanoutOutput::Committed(wire) => Some(wire.as_slice()),
        _ => None,
    }
    .expect("expected original committed member")
}

#[test]
fn required_witness_t2_preserves_two_member_fanout_across_closure_and_reopen() {
    let mut a = endpoint(fixture_with_policy_expiry(Some(200)));
    let mut peers = recipients(&a.f);
    assert_eq!(peers.len(), 2);
    let account = peers.first().expect("first device").f.original.account_id();
    assert!(peers
        .iter()
        .all(|peer| peer.f.original.account_id() == account));
    let links: Vec<_> = peers.iter_mut().map(|peer| connect(&mut a, peer)).collect();
    let p0 = policy(&a.f.c, 1, 200, 150);
    let p1 = Arc::new(policy(&a.f.c, 2, 250, 170));
    let g1 = grant(&a.f, &a.f.original, 2, 240);
    let t1 = adopt(&mut a, &g1, &p0, None, &p1);
    let c1 = continued(&mut a, &links, Arc::clone(&p1));
    let first = selected(&c1, &links);
    let batch = journal(&mut a.owner)
        .next_fanout_id()
        .expect("original batch identity");
    let sent = journal(&mut a.owner)
        .send_account_message(
            FanoutInput {
                id: batch,
                account,
                targets: &first,
                plaintext: b"one account operation with two real devices",
                associated_data: b"group",
            },
            170,
        )
        .expect("original complete account batch");
    assert_eq!(sent.len(), 2);
    let p2 = Arc::new(policy(&a.f.c, 3, 275, 170));
    let g2 = grant(&a.f, g1.successor_device(), 3, 260);
    let _t2 = adopt(&mut a, &g2, &p1, Some(&t1), &p2);
    let c2 = continued(&mut a, &links, Arc::clone(&p2));
    let current = selected(&c2, &links);
    let restored = journal(&mut a.owner)
        .resume_account_message(batch, &current, 170)
        .expect("same batch under actual T2 and G2");
    assert_eq!(restored.len(), 2);
    for (before, after) in sent.iter().zip(&restored) {
        assert_eq!(wire(before), wire(after));
    }
    let first_link = links.first().expect("first original member");
    let first_context = c2.first().expect("first current context");
    let report = journal(&mut a.owner)
        .begin_session_closure(first_context, first_link.session)
        .expect("explicit original delivery accounting");
    let closing = journal(&mut a.owner)
        .resume_account_message(batch, &current, 170)
        .expect("closing member and live member coexist");
    assert!(matches!(
        closing.first().expect("first member").output,
        FanoutOutput::ResolutionPending
    ));
    assert_eq!(
        wire(closing.get(1).expect("live member")),
        wire(sent.get(1).expect("original live member"))
    );
    journal(&mut a.owner)
        .acknowledge_session_closure(first_context, first_link.session, report.report)
        .expect("host accepts the original unknown outcome");
    for _ in 0..2 {
        a.owner.close();
        a.owner = activate(&a.f, &p2);
        a.f.carrier.requests.lock().expect("trace").clear();
        let result = journal(&mut a.owner)
            .resume_account_message(batch, &current, 170)
            .expect("closed member remains terminal after actual owner reopen");
        assert_eq!(result.len(), 2);
        assert!(matches!(
            result.first().expect("closed member").output,
            FanoutOutput::DeliveryUnknown
        ));
        assert_eq!(
            wire(result.get(1).expect("live member")),
            wire(sent.get(1).expect("original live member"))
        );
        assert!(a
            .f
            .carrier
            .requests
            .lock()
            .expect("fresh admission")
            .contains(&10));
    }
    let peer = peers.get_mut(1).expect("actual remaining receiver");
    peer.owner
        .parts()
        .expect("receiver")
        .0
        .admit_peer_credential_renewal(&g1, g1.operation(), &peer.f.c.policy, 170)
        .expect("receiver independently admits first peer renewal");
    peer.owner
        .parts()
        .expect("receiver")
        .0
        .admit_peer_credential_renewal(&g2, g2.operation(), &peer.f.c.policy, 170)
        .expect("receiver independently admits second peer renewal");
    let link = links.get(1).expect("remaining original session");
    let receiving = journal(&mut peer.owner)
        .prepare_reopened_context(
            Arc::clone(&link.receiver),
            link.session,
            BootstrapRole::Responder,
            170,
        )
        .expect("original receiver context with current admitted peer credential");
    assert_eq!(
        journal(&mut peer.owner)
            .receive_message(
                &receiving,
                link.session,
                wire(sent.get(1).expect("original output")),
                b"group",
                170,
            )
            .expect("actual independent receiver decrypts original bytes")
            .as_bytes(),
        b"one account operation with two real devices"
    );
    eprintln!("REQUIRED_CONTINUED_FANOUT members=2 T2=true reopened_twice=true closed_unknown=true original_live_wire=true peer_decrypted=true");
}
