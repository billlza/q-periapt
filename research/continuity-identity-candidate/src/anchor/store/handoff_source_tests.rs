// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn codec_test_key(c: &Case) -> JournalKey {
    // Case::server is already canonical. The original TempDir spelling can
    // traverse the macOS /var alias, which private publication correctly rejects.
    let root = c
        .server
        .parent()
        .expect("canonical fixture root")
        .join("codec-target");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("private codec test directory");
    JournalKey::provision(&root.join("wrapping")).expect("independent codec test key")
}

fn capture(c: &mut Case) -> AnchorHandoffSourceState {
    let before = c.store.image().expect("original authenticated image");
    let active = c.store.active.as_ref().expect("original owner");
    let stored = encode(&active.wrapping, &active.pin, &before).expect("complete stored image");
    let state = c
        .store
        .handoff_source_state()
        .expect("complete source state");
    assert_eq!(state.pin().binding(), c.pin.binding());
    assert_eq!(state.revision(), before.revision);
    let body_length = stored.len().checked_sub(32).expect("stored authenticator");
    assert_eq!(
        state.as_bytes(),
        stored.get(..body_length).expect("complete state body")
    );
    let after = c.store.image().expect("capture is read-only");
    assert_eq!(
        (after.revision, after.digest),
        (before.revision, before.digest)
    );
    state
}

// Only the state codec is exercised here. This test MAC is not a transfer
// certificate, independent target approval or an activated target witness.
fn reseal_for_codec_test(state: &AnchorHandoffSourceState, key: &JournalKey) -> Image {
    let mut bytes = state.as_bytes().to_vec();
    let mut mac = authenticator(key).expect("different test storage key");
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    let image = decode(key, state.pin(), &bytes).expect("complete reauthenticated state");
    assert_eq!(
        image_codec::encode_body(state.pin(), &image).expect("canonical content"),
        state.as_bytes()
    );
    image
}

#[test]
fn source_state_is_read_only_stable_on_reopen_and_does_not_freeze_authority() {
    let mut c = case();
    let first = capture(&mut c);
    let repeated = capture(&mut c);
    assert_eq!(first.as_bytes(), repeated.as_bytes());
    assert_eq!(first.commitment(), repeated.commitment());
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(capture(&mut c).commitment(), first.commitment());

    let next = AnchorOperation::advance(initial(&c), [227; 32]).expect("ordinary update");
    let request = request(&c, next);
    apply_request(&mut c, &request)
        .applied_head()
        .expect("capture did not freeze source");
    let advanced = capture(&mut c);
    assert!(advanced.revision() > first.revision());
    assert_ne!(advanced.commitment(), first.commitment());
    assert_ne!(advanced.as_bytes(), first.as_bytes());
}

#[test]
fn source_state_keeps_pending_terminal_and_acknowledged_credential_work() {
    let mut c = credential_case();
    let initial_state = capture(&mut c);
    let grant = credential_grant_first(&c);
    let proposal = AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        grant.operation(),
        grant.statement_digest(),
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [229; 32]).expect("test target"),
    )
    .expect("original joint proposal");
    assert_eq!(
        c.store
            .prepare_credential_renewal(
                proposal,
                &grant,
                c.peer.responder.current_policy().expect("original policy"),
                170,
            )
            .expect("actual pending preparation"),
        AnchorCredentialRenewalState::Prepared
    );
    let pending = capture(&mut c);
    assert_ne!(pending.commitment(), initial_state.commitment());
    let key = codec_test_key(&c);
    let id = c.genesis.subject().id(&c.pin.binding());
    let restored = reseal_for_codec_test(&pending, &key);
    let entry = restored.entries.get(&id).expect("original pending subject");
    assert!(entry.renewal.is_some());
    assert_eq!(entry.head, initial(&c));

    assert_eq!(
        c.store
            .close_credential_renewal(
                proposal,
                &grant,
                c.peer.responder.current_policy().expect("original policy"),
            )
            .expect("exact terminal closure"),
        AnchorCredentialRenewalState::Closed
    );
    let closed = capture(&mut c);
    assert_ne!(pending.commitment(), closed.commitment());
    let restored = reseal_for_codec_test(&closed, &key);
    let entry = restored
        .entries
        .get(&id)
        .expect("original terminal subject");
    assert!(entry.renewal.is_some());
    assert_eq!(entry.head, initial(&c));

    let request = request(
        &c,
        AnchorOperation::acknowledge_credential_renewal(&proposal),
    );
    let wire = c
        .store
        .handle(request.as_bytes(), 181)
        .expect("historical exact acknowledgement");
    assert_eq!(
        c.pin
            .verify_reply(&request, &wire)
            .expect("signed reply")
            .credential_renewal_state(&proposal)
            .expect("exact target"),
        AnchorCredentialRenewalState::Acknowledged
    );
    let acknowledged = capture(&mut c);
    let restored = reseal_for_codec_test(&acknowledged, &key);
    let entry = restored
        .entries
        .get(&id)
        .expect("original acknowledged subject");
    assert!(entry.renewal.is_none());
    assert_eq!(entry.renewal_floor, 2);
    assert_eq!(entry.renewal_ack, Some(proposal.binding()));
    assert_ne!(closed.commitment(), acknowledged.commitment());
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(capture(&mut c).as_bytes(), acknowledged.as_bytes());
}

#[test]
fn legacy_source_state_does_not_invent_original_identity() {
    let mut c = case();
    legacy_without_original_identity(&mut c);
    let state = capture(&mut c);
    let key = codec_test_key(&c);
    let restored = reseal_for_codec_test(&state, &key);
    assert!(restored
        .entries
        .values()
        .all(|entry| entry.original_identity.is_none()));
}

#[test]
fn source_capture_reauthenticates_durable_state_and_closes_on_corruption() {
    let mut c = case();
    let _before = capture(&mut c);
    let active = c.store.active.as_ref().expect("original owner");
    let tx = transaction(&active.db).expect("test corruption transaction");
    {
        let mut table = tx.open_table(TABLE).expect("image table");
        let mut bytes = table
            .get("image")
            .expect("lookup")
            .expect("image")
            .value()
            .to_vec();
        let last = bytes.last_mut().expect("storage authenticator");
        *last ^= 1;
        table
            .insert("image", bytes.as_slice())
            .expect("corrupt only test fixture");
    }
    tx.commit().expect("fixture corruption committed");
    assert!(matches!(
        c.store.handoff_source_state(),
        Err(DurableError::Authentication)
    ));
    assert!(matches!(
        c.store.handoff_source_state(),
        Err(DurableError::Closed)
    ));
}

#[test]
fn unsigned_source_bytes_are_not_a_store_image_and_closed_owner_refuses_capture() {
    let mut c = case();
    let state = capture(&mut c);
    let active = c.store.active.as_ref().expect("original owner");
    assert!(matches!(
        decode(&active.wrapping, &active.pin, state.as_bytes()),
        Err(DurableError::Authentication)
    ));
    c.store.close();
    assert!(matches!(
        c.store.handoff_source_state(),
        Err(DurableError::Closed)
    ));
}
