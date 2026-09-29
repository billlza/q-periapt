// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn account_fanout_mixed_bootstrap_roles_use_the_correct_independent_send_chains() {
    let mut n = Network::new(4, false);
    let (_, issued, pin, runtime) = session_policy_fixture_with_budget(
        &[PrekeyQuality::ReusableBoth],
        AnchorRequirement::local_only(),
        ApplicationSendBudget::new(4).expect("budget"),
    );
    let policy = Arc::new(
        pin.verify(issued.as_bytes(), Arc::clone(&runtime), 150)
            .expect("same closed policy"),
    );
    let key = runtime.generate_key().expect("sender prekey");
    let public = key.public_key().expect("public").to_bytes();
    let (pq, classical) = public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let leaves = [
        PrekeyLeaf::new(LeafKind::SignedClassical, classical, interval()).expect("classical"),
        PrekeyLeaf::new(LeafKind::LastResortPq, pq, interval()).expect("PQ"),
    ];
    let manifest =
        n.f.local_signer
            .issue_manifest(
                &n.f.local,
                ManifestContext::new(
                    1,
                    runtime.trusted_state().digest(),
                    crate::bootstrap_suite_digest(),
                    [99; 32],
                    interval(),
                )
                .expect("context"),
                &leaves,
            )
            .expect("local prekey manifest");
    let verified =
        n.f.local
            .verify_manifest(manifest.as_bytes(), 150)
            .expect("manifest");
    let proofs: Vec<_> = (0..manifest.leaf_count())
        .map(|index| {
            let proof = manifest.proof(index).expect("proof");
            (
                verified.verify_leaf(&proof, 150).expect("leaf").kind(),
                proof,
            )
        })
        .collect();
    let proof = |kind| &proofs.iter().find(|(k, _)| *k == kind).expect("role").1;
    let selection = Arc::new(
        verified
            .select_prekeys(
                proof(LeafKind::SignedClassical),
                proof(LeafKind::LastResortPq),
                ClassicalChoice::SignedOnly,
                PqChoice::LastResort,
                150,
            )
            .expect("selection"),
    );
    let context = Arc::new(
        BootstrapContext::new(
            policy,
            Arc::clone(n.f.peers.first().expect("peer")),
            Arc::clone(&n.f.local),
            selection,
            DirectoryExpectation::from_trusted_state([99; 32]).expect("directory"),
            150,
        )
        .expect("reversed roles"),
    );
    let receiver = n.receivers.first_mut().expect("peer journal");
    let request = InitiationId::generate().expect("request");
    let initial = receiver
        .initiate(
            Arc::clone(&context),
            request,
            n.f.peer_signers.first().expect("peer signer"),
            150,
        )
        .expect("peer initiates");
    let reply = n
        .sender
        .respond(
            Arc::clone(&context),
            &initial,
            &n.f.local_signer,
            PqKeySource::from_key(&key),
            TraditionalKeySource::from_key(&key),
            150,
        )
        .expect("local responder");
    let completed = receiver
        .accept_reply(Arc::clone(&context), request, &reply, 150)
        .expect("peer final");
    let session = completed.session_id();
    n.sender
        .finish(
            Arc::clone(&context),
            &initial,
            completed.final_message(),
            150,
        )
        .expect("local finish");
    assert_eq!(
        receiver
            .activate_initiator_messages(Arc::clone(&context), request, 150)
            .expect("peer messages"),
        session
    );
    assert_eq!(
        n.sender
            .activate_responder_messages(Arc::clone(&context), &initial, 150)
            .expect("local messages"),
        session
    );
    *n.sessions.first_mut().expect("session") = session;
    *n.f.contexts.first_mut().expect("context") = context;
    assert_eq!(state(&mut n.sender, &session).role, 2);
    assert_eq!(
        state(&mut n.sender, n.sessions.get(1).expect("other session")).role,
        1
    );
    let id = n.sender.next_fanout_id().expect("ID");
    let result = n
        .send(id, b"roles are pairwise, recipients are account-wide")
        .expect("mixed-role aggregate");
    let original = wires(&result);
    n.check_delivery(&result, b"roles are pairwise, recipients are account-wide");
    n.reopen();
    assert_eq!(
        wires(
            &n.send(id, b"roles are pairwise, recipients are account-wide")
                .expect("exact replay")
        ),
        original
    );
}
