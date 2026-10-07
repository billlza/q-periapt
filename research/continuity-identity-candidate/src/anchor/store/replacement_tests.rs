// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{AnchorDeviceReplacementProposal as Proposal, AnchorDeviceReplacementState as State};

fn required_case() -> Case {
    let directory = directory();
    let base = directory.path().canonicalize().expect("root");
    let server = base.join("witness");
    let client = base.join("client");
    for path in [&server, &client] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .expect("directory");
    }
    let wrapping = JournalKey::provision(&server.join("wrapping")).expect("wrapping");
    let signer = AnchorSigningKey::provision(
        &server.join("signer"),
        &wrapping,
        SigningKeyId::from_trusted_state([63; 32]).expect("id"),
    )
    .expect("signer");
    let id = AnchorIdentity::generate().expect("instance");
    fs::write(server.join("instance"), id.as_bytes()).expect("retained instance");
    let mut store =
        AnchorStore::provision(&server.join("anchor.redb"), wrapping, signer, id).expect("store");
    let pin = store.pin().expect("pin");
    let peer = crate::bootstrap::tests::fixture_with_anchor_and_budget(
        PrekeyQuality::OneTimeBoth,
        crate::AnchorRequirement::required(&pin),
        crate::ApplicationSendBudget::new(1024).expect("budget"),
    );
    let (policy, device, _) = peer.responder.inventory_inputs().expect("required policy");
    let key = JournalKey::provision(&client.join("key")).expect("key");
    let identity = crate::durable::tests::retain_new_identity(&client.join("store-id"));
    let mut journal = DeviceJournal::provision_anchored(
        &client.join("state.redb"),
        key,
        device,
        policy,
        identity,
        150,
    )
    .expect("inactive original journal");
    let genesis = journal
        .anchor_genesis(device, policy)
        .expect("actual genesis");
    store
        .enroll(&genesis, device, policy, 150)
        .expect("enrolled original");
    Case {
        store,
        pin,
        genesis,
        peer,
        _journal: journal,
        server,
        _directory: directory,
    }
}
struct Fresh {
    device: VerifiedDevice,
    signer: DeviceSigningKey,
    genesis: AnchorGenesis,
    journal: DeviceJournal,
}
fn fresh(c: &Case, generation: u64, roster_version: u64, seed: u8) -> Fresh {
    fresh_with_policy(
        c,
        c.peer.responder.current_policy().expect("policy"),
        generation,
        roster_version,
        seed,
    )
}
fn fresh_with_policy(
    c: &Case,
    policy: &VerifiedSessionPolicy,
    generation: u64,
    roster_version: u64,
    seed: u8,
) -> Fresh {
    let old = c.peer.responder.inventory_inputs().expect("original").1;
    let mut description = old.description.clone();
    description.generation = generation;
    let (device, signer) = signed_device(old, description, roster_version, seed, &[]);
    fresh_journal(c, policy, device, signer, seed)
}
fn signed_device(
    old: &VerifiedDevice,
    description: crate::DeviceDescription,
    roster_version: u64,
    seed: u8,
    others: &[crate::RosterEntry],
) -> (VerifiedDevice, DeviceSigningKey) {
    let root =
        crate::RootSigningKey::deterministic([94; 32], [95; 32]).expect("same account authority");
    let signer =
        DeviceSigningKey::deterministic([seed; 32], [seed.checked_add(1).expect("seed"); 32])
            .expect("fresh owner");
    let certificate = root
        .issue_device(description.clone(), signer.public_key().expect("public"))
        .expect("root certificate");
    let mut members = others.to_vec();
    members.push(root.roster_entry(&certificate).expect("member"));
    let roster = root
        .issue_roster(roster_version, old.roster_validity, &members)
        .expect("current roster");
    let pin = crate::AccountPin::new(
        root.account_id().expect("account"),
        root.public_key().expect("root"),
        roster.checkpoint(),
        description.family,
    )
    .expect("independent pin");
    let device = pin
        .verify_device(&certificate, roster.as_bytes(), 150)
        .expect("new verified identity");
    (device, signer)
}
fn fresh_journal(
    c: &Case,
    policy: &VerifiedSessionPolicy,
    device: VerifiedDevice,
    signer: DeviceSigningKey,
    seed: u8,
) -> Fresh {
    let generation = device.generation();
    let roster_version = device.roster().checkpoint().version();
    let path = c
        .server
        .parent()
        .expect("root")
        .join(format!("new-{generation}-{roster_version}-{seed}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("new directory");
    let key = JournalKey::provision(&path.join("key")).expect("new wrapping");
    let identity = crate::durable::tests::retain_new_identity(&path.join("store-id"));
    let mut journal = DeviceJournal::provision_anchored(
        &path.join("state.redb"),
        key,
        &device,
        policy,
        identity,
        150,
    )
    .expect("new inactive journal");
    let genesis = journal
        .anchor_genesis(&device, policy)
        .expect("actual new genesis");
    Fresh {
        device,
        signer,
        genesis,
        journal,
    }
}
fn prepare(
    c: &mut Case,
    next: &Fresh,
    subject: AnchorSubject,
    checkpoint: crate::RosterCheckpoint,
) -> Proposal {
    let policy = c.peer.responder.current_policy().expect("policy");
    c.store
        .device_replacement_proposal(
            &next.genesis,
            &next.device,
            policy,
            &[(subject, checkpoint, policy.historical())],
            150,
        )
        .expect("complete proposal")
}
fn first_proposal(c: &mut Case, next: &Fresh) -> Proposal {
    let old = c.peer.responder.inventory_inputs().expect("original").1;
    prepare(c, next, c.genesis.subject(), old.roster().checkpoint())
}
fn commit(c: &mut Case, p: &Proposal, next: &Fresh, now: u64) -> Result<State, DurableError> {
    c.store.replace_device(
        p,
        &next.genesis,
        &next.device,
        c.peer.responder.current_policy().expect("policy"),
        &p.predecessor_checkpoints()
            .map(|(subject, checkpoint)| {
                (
                    subject,
                    checkpoint,
                    c.peer
                        .responder
                        .current_policy()
                        .expect("policy")
                        .historical(),
                )
            })
            .collect::<Vec<_>>(),
        now,
    )
}
fn query(c: &mut Case, next: &Fresh) -> AnchorReply {
    let request = AnchorRequest::new(
        &c.pin,
        next.genesis.subject(),
        AnchorOperation::query(),
        &next.signer,
    )
    .expect("new query");
    let wire = c
        .store
        .handle(request.as_bytes(), 150)
        .expect("new witness authority");
    c.pin
        .verify_reply(&request, &wire)
        .expect("authenticated new reply")
}
fn assert_retired(c: &mut Case, operation: AnchorOperation) {
    let old = request(c, operation);
    assert!(matches!(
        c.store.handle(old.as_bytes(), 150),
        Err(AnchorError::Rejected(Error::Scope))
    ));
}

#[test]
fn replacement_is_one_commit_and_old_queries_and_exact_advances_stay_retired() {
    let mut c = required_case();
    let old = request(
        &c,
        AnchorOperation::advance(initial(&c), [180; 32]).expect("advance"),
    );
    let head = apply_request(&mut c, &old)
        .applied_head()
        .expect("original head");
    let next = fresh(&c, 2, 2, 140);
    assert_eq!(
        next.journal
            .identity()
            .expect("retained new journal")
            .as_bytes(),
        &next.genesis.subject().journal
    );
    let before = c.store.image().expect("original").revision;
    assert!(matches!(
        c.store.enroll(
            &next.genesis,
            &next.device,
            c.peer.responder.current_policy().expect("policy"),
            150
        ),
        Err(DurableError::Conflict)
    ));
    let p = first_proposal(&mut c, &next);
    assert_eq!(
        c.store.image().expect("proposal is read only").revision,
        before
    );
    assert_eq!(
        c.store
            .device_replacement_status(&p)
            .expect("not committed"),
        State::Unavailable
    );
    assert_eq!(
        commit(&mut c, &p, &next, 150).expect("atomic replacement"),
        State::Committed
    );
    c.store.close();
    c.store = reopen(&c.server);
    assert_eq!(
        c.store.image().expect("one transaction").revision,
        before + 1
    );
    let observation = c
        .store
        .retired_subject_observation(&p, c.genesis.subject())
        .expect("frozen history");
    assert_eq!(observation.observed_head(), head);
    assert_eq!(observation.last_command_id(), Some(old.command_id()));
    assert_eq!(
        observation.replacement_binding(),
        p.binding().expect("binding")
    );
    assert_eq!(observation.successor(), next.genesis.subject());
    for operation in [
        AnchorOperation::query(),
        old.operation,
        AnchorOperation::advance(head, [181; 32]).expect("fresh old write"),
        AnchorOperation::fence_writer(head).expect("old fence"),
    ] {
        assert_retired(&mut c, operation);
    }
    let original = c.peer.responder.inventory_inputs().expect("original").1;
    assert!(matches!(
        c.store.enroll(
            &c.genesis,
            original,
            c.peer.responder.current_policy().expect("policy"),
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        query(&mut c, &next).observed_head(),
        AnchorHead::from_trusted_state(1, 1, next.genesis.image_digest()).expect("new genesis")
    );
    assert_eq!(
        c.store
            .retired_subject_observation(&p, c.genesis.subject())
            .expect("unchanged history"),
        observation
    );
}

#[test]
fn original_replacement_retry_is_historical_after_successor_advance_expiry_and_further_replacement()
{
    let mut c = required_case();
    let next = fresh(&c, 2, 2, 142);
    let first = first_proposal(&mut c, &next);
    commit(&mut c, &first, &next, 150).expect("first replacement");
    let initial =
        AnchorHead::from_trusted_state(1, 1, next.genesis.image_digest()).expect("new genesis");
    let advance = AnchorRequest::new(
        &c.pin,
        next.genesis.subject(),
        AnchorOperation::advance(initial, [182; 32]).expect("new write"),
        &next.signer,
    )
    .expect("request");
    let wire = c
        .store
        .handle(advance.as_bytes(), 150)
        .expect("advance new journal");
    c.pin.verify_reply(&advance, &wire).expect("receipt");
    let third = fresh(&c, 3, 3, 144);
    let later = prepare(
        &mut c,
        &third,
        next.genesis.subject(),
        next.device.roster().checkpoint(),
    );
    commit(&mut c, &later, &third, 150).expect("next replacement");
    c.store.close();
    c.store = reopen(&c.server);
    let before = c.store.image().expect("two permanent decisions").digest;
    assert_eq!(
        commit(&mut c, &first, &next, 250).expect("historical original outcome"),
        State::Committed
    );
    assert_eq!(
        c.store
            .device_replacement_status(&later)
            .expect("later original outcome"),
        State::Committed
    );
    assert_eq!(c.store.image().expect("no resurrection").digest, before);
    let old = AnchorRequest::new(
        &c.pin,
        next.genesis.subject(),
        AnchorOperation::query(),
        &next.signer,
    )
    .expect("retired second generation");
    assert!(matches!(
        c.store.handle(old.as_bytes(), 150),
        Err(AnchorError::Rejected(Error::Scope))
    ));
    assert_eq!(query(&mut c, &third).outcome(), AnchorOutcome::Current);
}

#[test]
fn changed_predecessor_or_competing_target_conflicts_without_partial_admission() {
    let mut c = required_case();
    let a = fresh(&c, 2, 2, 146);
    let b = fresh(&c, 2, 2, 148);
    let stale = first_proposal(&mut c, &a);
    let advance = request(
        &c,
        AnchorOperation::advance(initial(&c), [183; 32]).expect("competing old write"),
    );
    apply_request(&mut c, &advance);
    let before = c.store.image().expect("advanced").digest;
    assert!(matches!(
        commit(&mut c, &stale, &a, 150),
        Err(DurableError::Conflict)
    ));
    assert_eq!(c.store.image().expect("no partial state").digest, before);
    let winner = first_proposal(&mut c, &a);
    let loser = first_proposal(&mut c, &b);
    commit(&mut c, &winner, &a, 150).expect("single winner");
    let before = c.store.image().expect("winner").digest;
    assert!(commit(&mut c, &loser, &b, 150).is_err());
    assert_eq!(c.store.image().expect("loser no mutation").digest, before);
    assert_eq!(
        c.store
            .device_replacement_status(&loser)
            .expect("no invented outcome"),
        State::Unavailable
    );
    assert!(commit(&mut c, &winner, &b, 150).is_err());
    assert_eq!(c.store.image().expect("wrong target retry").digest, before);
}

#[test]
fn incomplete_legacy_identity_and_reused_signing_components_are_refused() {
    let mut c = required_case();
    let next = fresh(&c, 2, 2, 150);
    let old = c.peer.responder.inventory_inputs().expect("old").1.clone();
    legacy_without_original_identity(&mut c);
    let before = c.store.image().expect("legacy").digest;
    assert!(matches!(
        c.store.device_replacement_proposal(
            &next.genesis,
            &next.device,
            c.peer.responder.current_policy().expect("policy"),
            &[(
                c.genesis.subject(),
                old.roster().checkpoint(),
                c.peer
                    .responder
                    .current_policy()
                    .expect("policy")
                    .historical()
            )],
            150
        ),
        Err(DurableError::Suspended)
    ));
    assert_eq!(c.store.image().expect("migration required").digest, before);
    c.store
        .retain_original_identity(c.genesis.subject(), &old)
        .expect("authenticated original history");
    let reused = fresh(&c, 2, 2, 96);
    assert!(matches!(
        c.store.device_replacement_proposal(
            &reused.genesis,
            &reused.device,
            c.peer.responder.current_policy().expect("policy"),
            &[(
                c.genesis.subject(),
                old.roster().checkpoint(),
                c.peer
                    .responder
                    .current_policy()
                    .expect("policy")
                    .historical()
            )],
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let p = first_proposal(&mut c, &next);
    assert!(matches!(
        commit(&mut c, &p, &next, 250),
        Err(DurableError::Protocol(Error::Validity))
    ));
    assert_eq!(
        c.store
            .device_replacement_status(&p)
            .expect("expired target not committed"),
        State::Unavailable
    );
    commit(&mut c, &p, &next, 150).expect("authorized target at current time");
}

#[test]
fn canonical_proposal_and_authenticated_retirement_corruption_are_refused() {
    let mut c = required_case();
    let next = fresh(&c, 2, 2, 152);
    let p = first_proposal(&mut c, &next);
    let bytes = p.to_bytes().expect("canonical");
    assert_eq!(bytes.len(), 674);
    assert_eq!(Proposal::from_trusted_state(&bytes).expect("restored"), p);
    for length in 0..bytes.len() {
        assert!(Proposal::from_trusted_state(bytes.get(..length).expect("prefix")).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Proposal::from_trusted_state(&extra).is_err());
    commit(&mut c, &p, &next, 150).expect("commit");
    let image = c.store.image().expect("new image");
    let active = c.store.active.as_ref().expect("active");
    let wire = encode(&active.wrapping, &active.pin, &image).expect("v11");
    assert_eq!(wire.get(..8), Some(b"QPANC011".as_slice()));
    let mut body = wire.get(..wire.len() - 32).expect("body").to_vec();
    *body.last_mut().expect("predecessor state commitment") ^= 1;
    let mut auth = authenticator(&active.wrapping).expect("test MAC");
    auth.update(&body);
    body.extend_from_slice(&auth.finalize().into_bytes());
    assert!(decode(&active.wrapping, &active.pin, &body).is_err());
}

#[test]
fn prepared_real_credential_renewal_is_frozen_and_cannot_mutate_retired_subject() {
    let mut c = required_case();
    let original = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original")
        .1
        .clone();
    let grant = credential_grant(&c, &original, 2, 240);
    let proposal = crate::AnchorCredentialRenewalProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        grant.operation(),
        grant.statement_digest(),
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [185; 32]).expect("target"),
    )
    .expect("G proposal");
    c.store
        .prepare_credential_renewal(
            proposal,
            &grant,
            c.peer.responder.current_policy().expect("policy"),
            170,
        )
        .expect("actual independently approved pending G");
    let next = fresh(&c, 2, 3, 154);
    let p = first_proposal(&mut c, &next);
    commit(&mut c, &p, &next, 170).expect("replace while original is pending");
    let saved = c.store.image().expect("retired image").digest;
    for operation in [
        AnchorOperation::commit_credential_renewal(&proposal),
        AnchorOperation::credential_renewal_status(&proposal),
        AnchorOperation::close_credential_renewal(&proposal),
        AnchorOperation::acknowledge_credential_renewal(&proposal),
    ] {
        assert_retired(&mut c, operation);
    }
    assert!(matches!(
        c.store.prepare_credential_renewal(
            proposal,
            &grant,
            c.peer.responder.current_policy().expect("policy"),
            170
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        c.store.renew_credential_authority(
            c.genesis.subject(),
            &grant,
            grant.operation(),
            c.peer.responder.current_policy().expect("policy"),
            170
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        c.store
            .image()
            .expect("all retirement denials read only")
            .digest,
        saved
    );
    let observation = c
        .store
        .retired_subject_observation(&p, c.genesis.subject())
        .expect("retained original head");
    assert_eq!(observation.observed_head(), initial(&c));
}

#[test]
fn each_sync_fault_recovers_whole_replacement_once() {
    let mut calibration = required_case();
    let next = fresh(&calibration, 2, 2, 156);
    let p = first_proposal(&mut calibration, &next);
    let (_, count) = with_fault_database(&mut calibration, false);
    count.store(0, Ordering::SeqCst);
    commit(&mut calibration, &p, &next, 150).expect("calibrate");
    let barriers = count.load(Ordering::SeqCst);
    assert!((2..=8).contains(&barriers));
    for after in [false, true] {
        for cut in 1..=barriers {
            let mut c = required_case();
            let next = fresh(&c, 2, 2, 158);
            let p = first_proposal(&mut c, &next);
            let before = c.store.image().expect("original").revision;
            let (remaining, _) = with_fault_database(&mut c, after);
            remaining.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(commit(&mut c, &p, &next, 150), after);
            assert!(c.store.active.is_none());
            c.store = reopen(&c.server);
            let image = c.store.image().expect("one coherent image");
            assert_eq!(
                image.entries.len(),
                if image.replacements.is_empty() { 1 } else { 2 }
            );
            commit(&mut c, &p, &next, 150).expect("same proposal reconciliation");
            assert_eq!(c.store.image().expect("one commit").revision, before + 1);
            assert_retired(&mut c, AnchorOperation::query());
            assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
        }
    }
    eprintln!(
        "ANCHOR_DEVICE_REPLACEMENT_SYNC barriers={barriers} before_after_faults={}",
        barriers * 2
    );
}

#[cfg(feature = "anchor-tls")]
#[test]
fn actual_mutual_tls_withholds_retired_activation_and_admits_original_new_journal() {
    use crate::anchor_tls::{AnchorTlsServer, AnchorTlsTransport, PeerBinding};
    use q_periapt_rustls::standard::{MutualTlsClient, MutualTlsServer};
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use std::{
        io,
        net::TcpListener,
        sync::{atomic::AtomicBool, Arc, Mutex},
    };
    let mut c = required_case();
    let mut next = fresh(&c, 2, 2, 160);
    let p = first_proposal(&mut c, &next);
    commit(&mut c, &p, &next, 150).expect("atomic replacement");
    let server_id = rcgen::generate_simple_self_signed(vec!["witness.test".into()])
        .expect("server TLS identity");
    let old_id =
        rcgen::generate_simple_self_signed(vec!["old.test".into()]).expect("old TLS identity");
    let new_id =
        rcgen::generate_simple_self_signed(vec!["new.test".into()]).expect("new TLS identity");
    let mut servers = rustls::RootCertStore::empty();
    servers
        .add(server_id.cert.der().clone())
        .expect("server trust");
    let mut clients = rustls::RootCertStore::empty();
    for identity in [&old_id, &new_id] {
        clients
            .add(identity.cert.der().clone())
            .expect("explicit client trust");
    }
    let configurations: Vec<_> = [&old_id, &new_id]
        .into_iter()
        .map(|identity| {
            MutualTlsClient::new(
                servers.clone(),
                vec![identity.cert.der().clone()],
                PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der()).into(),
            )
            .expect("client configuration")
        })
        .collect();
    let config = MutualTlsServer::new(
        clients,
        vec![server_id.cert.der().clone()],
        PrivatePkcs8KeyDer::from(server_id.signing_key.serialize_der()).into(),
    )
    .expect("server configuration");
    let server = AnchorTlsServer::new(
        config,
        vec![
            PeerBinding::new(old_id.cert.der().to_vec(), c.genesis.subject())
                .expect("old pinned subject"),
            PeerBinding::new(new_id.cert.der().to_vec(), next.genesis.subject())
                .expect("new pinned subject"),
        ],
    )
    .expect("witness TLS server");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    listener.set_nonblocking(true).expect("bounded listener");
    let address = listener.local_addr().expect("address");
    let done = Arc::new(AtomicBool::new(false));
    let store = Mutex::new(c.store);
    let mut configurations = configurations.into_iter();
    let old_transport = AnchorTlsTransport::new(
        address,
        ServerName::try_from("witness.test").expect("name"),
        server_id.cert.der().to_vec(),
        configurations.next().expect("old configuration"),
        crate::Cancellation::default(),
    )
    .expect("old TLS transport");
    let new_transport = AnchorTlsTransport::new(
        address,
        ServerName::try_from("witness.test").expect("name"),
        server_id.cert.der().to_vec(),
        configurations.next().expect("new configuration"),
        crate::Cancellation::default(),
    )
    .expect("new TLS transport");
    let old_client = crate::AnchorClient::new(
        c.pin.clone(),
        c.peer.signer_r,
        Box::new(old_transport),
        Duration::from_secs(5),
    )
    .expect("old signed client");
    let new_client = crate::AnchorClient::new(
        c.pin.clone(),
        next.signer,
        Box::new(new_transport),
        Duration::from_secs(5),
    )
    .expect("new signed client");
    let (policy, old, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original verified policy");
    std::thread::scope(|scope| {
        let done_server = Arc::clone(&done);
        let worker = scope.spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut outcomes = Vec::new();
            while !done_server.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline, "bounded witness server deadline");
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("accepted stream");
                        outcomes.push(server.serve(
                            stream,
                            &store,
                            Instant::now() + Duration::from_secs(5),
                            crate::Cancellation::default(),
                            &mut || Ok(150),
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok::<_, io::Error>(outcomes)
        });
        assert!(matches!(
            c._journal.activate_anchor(old, policy, old_client),
            Err(DurableError::Anchor(_))
        ));
        next.journal
            .activate_anchor(&next.device, policy, new_client)
            .expect("original replacement journal activates");
        done.store(true, Ordering::SeqCst);
        let outcomes = worker
            .join()
            .expect("server worker")
            .expect("listener accepted both requests");
        assert_eq!(outcomes.len(), 2);
        let rejected = outcomes
            .first()
            .expect("old exchange")
            .as_ref()
            .expect_err("old subject must be denied");
        assert!(matches!(
            rejected
                .get_ref()
                .and_then(|error| error.downcast_ref::<AnchorError>()),
            Some(AnchorError::Rejected(Error::Scope))
        ));
        assert!(outcomes.get(1).expect("new exchange").is_ok());
    });
    assert!(matches!(c._journal.identity(), Err(DurableError::Closed)));
    assert_eq!(
        next.journal
            .identity()
            .expect("original new owner")
            .as_bytes(),
        &next.genesis.subject().journal
    );
    eprintln!("ANCHOR_DEVICE_REPLACEMENT_TLS actual_mutual_tls=true old_certificate_scope_admitted=true old_witness_authority_refused=true old_owner_closed=true original_new_journal_activated=true");
}

#[test]
fn replacement_preserves_other_known_live_device_membership() {
    let mut c = required_case();
    let (policy, old, _) = c.peer.responder.inventory_inputs().expect("original");
    let root = crate::RootSigningKey::deterministic([94; 32], [95; 32]).expect("root");
    let mut description = old.description.clone();
    description.id = [211; 16];
    let (other, signer) = signed_device(old, description, 1, 172, &[]);
    let certificate = root
        .issue_device(other.description.clone(), signer.public_key().expect("key"))
        .expect("other certificate");
    let member = root.roster_entry(&certificate).expect("other member");
    let other = fresh_journal(&c, policy, other, signer, 172);
    c.store
        .enroll(&other.genesis, &other.device, policy, 150)
        .expect("second device");
    let next = fresh(&c, 2, 2, 174);
    let policy = c.peer.responder.current_policy().expect("policy");
    let old = c.peer.responder.inventory_inputs().expect("old").1;
    let proofs = [(
        c.genesis.subject(),
        old.roster().checkpoint(),
        policy.historical(),
    )];
    assert!(matches!(
        c.store
            .device_replacement_proposal(&next.genesis, &next.device, policy, &proofs, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let mut description = old.description.clone();
    description.generation = 2;
    let (device, signer) = signed_device(old, description, 2, 176, &[member]);
    let next = fresh_journal(&c, policy, device, signer, 176);
    let p = c
        .store
        .device_replacement_proposal(&next.genesis, &next.device, policy, &proofs, 150)
        .expect("preserves other member");
    commit(&mut c, &p, &next, 150).expect("one device replacement");
    assert_eq!(query(&mut c, &other).outcome(), AnchorOutcome::Current);
    assert_retired(&mut c, AnchorOperation::query());
    assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
}

#[test]
fn replacement_rejects_policy_fork_and_substituted_historical_proof() {
    let mut c = required_case();
    let alternate = crate::bootstrap::tests::fixture_with_anchor_and_budget(
        PrekeyQuality::OneTimeBoth,
        crate::AnchorRequirement::required(&c.pin),
        crate::ApplicationSendBudget::new(512).expect("different signed policy"),
    );
    let fork = alternate
        .responder
        .current_policy()
        .expect("authenticated fork");
    let original = c.peer.responder.current_policy().expect("original policy");
    assert_eq!(fork.checkpoint().version(), original.checkpoint().version());
    assert_ne!(fork.checkpoint(), original.checkpoint());
    let next = fresh_with_policy(&c, fork, 2, 2, 178);
    let checkpoint = c
        .peer
        .responder
        .inventory_inputs()
        .expect("old")
        .1
        .roster()
        .checkpoint();
    let proofs = [(c.genesis.subject(), checkpoint, original.historical())];
    let before = c.store.image().expect("before").digest;
    assert!(matches!(
        c.store
            .device_replacement_proposal(&next.genesis, &next.device, fork, &proofs, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    let next = fresh(&c, 2, 2, 180);
    let p = first_proposal(&mut c, &next);
    let original = c.peer.responder.current_policy().expect("original policy");
    assert!(matches!(
        c.store.replace_device(
            &p,
            &next.genesis,
            &next.device,
            original,
            &[(c.genesis.subject(), checkpoint, fork.historical())],
            150
        ),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(c.store.image().expect("no mutation").digest, before);
    commit(&mut c, &p, &next, 150).expect("authenticated exact policy");
}

#[test]
fn pending_roster_refresh_is_frozen_and_cannot_mutate_retired_subject() {
    let mut c = required_case();
    let original = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original")
        .1
        .clone();
    let (refreshed, _) = signed_device(&original, original.description.clone(), 2, 96, &[]);
    assert_eq!(storage_owner(&refreshed), storage_owner(&original));
    let policy = c.peer.responder.current_policy().expect("policy");
    let r = crate::AnchorRosterRefreshProposal::from_journal(
        c.pin.binding(),
        c.genesis.subject(),
        crate::RosterRefreshScope {
            operation: crate::RosterRefreshId::generate().expect("original operation"),
            previous: original.roster().checkpoint(),
            target: refreshed.roster().checkpoint(),
            policy: policy.checkpoint(),
            policy_authorization: None,
        },
        initial(&c),
        AnchorHead::from_trusted_state(1, 2, [187; 32]).expect("store-only target expectation"),
    )
    .expect("original R proposal");
    c.store
        .prepare_roster_refresh(r, &original, &refreshed, policy, 150)
        .expect("actual pending R");
    let next = fresh(&c, 2, 3, 182);
    let p = first_proposal(&mut c, &next);
    commit(&mut c, &p, &next, 150).expect("replacement preserves pending R");
    c.store.close();
    c.store = reopen(&c.server);
    let before = c.store.image().expect("retained R").digest;
    for operation in [
        AnchorOperation::commit_roster_refresh(&r),
        AnchorOperation::roster_refresh_status(&r),
        AnchorOperation::close_roster_refresh(&r),
        AnchorOperation::acknowledge_roster_refresh(&r),
    ] {
        assert_retired(&mut c, operation);
    }
    let policy = c.peer.responder.current_policy().expect("policy");
    assert!(matches!(
        c.store
            .prepare_roster_refresh(r, &original, &refreshed, policy, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert!(matches!(
        c.store
            .close_roster_refresh(r, &original, &refreshed, policy.historical()),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        c.store.image().expect("immutable retired state").digest,
        before
    );
    assert_eq!(
        c.store
            .retired_subject_observation(&p, c.genesis.subject())
            .expect("history")
            .observed_head(),
        initial(&c)
    );
    assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
}

#[test]
fn replacement_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_DEVICE_REPLACEMENT_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let mut store = reopen(path);
    let pin = store.pin().expect("same witness");
    let peer = crate::bootstrap::tests::fixture_with_anchor_and_budget(
        PrekeyQuality::OneTimeBoth,
        crate::AnchorRequirement::required(&pin),
        crate::ApplicationSendBudget::new(1024).expect("budget"),
    );
    let (policy, old, _) = peer
        .responder
        .inventory_inputs()
        .expect("retained original authority");
    let mut description = old.description.clone();
    description.generation = 2;
    let (next, _) = signed_device(old, description, 2, 184, &[]);
    let journal_path = path.parent().expect("root").join("new-2-2-184");
    let identity = crate::JournalIdentity::from_trusted_state(
        fs::read(journal_path.join("store-id"))
            .expect("original ID")
            .try_into()
            .expect("width"),
    )
    .expect("identity");
    let genesis = DeviceJournal::recover_anchor_genesis(
        &journal_path.join("state.redb"),
        JournalKey::open(&journal_path.join("key")).expect("same key"),
        &next,
        policy,
        identity,
    )
    .expect("actual retained encrypted journal genesis");
    let p = Proposal::from_trusted_state(
        &fs::read(path.join("replacement.bin")).expect("original proposal"),
    )
    .expect("proposal");
    let proofs: Vec<_> = p
        .predecessor_checkpoints()
        .map(|(subject, checkpoint)| (subject, checkpoint, policy.historical()))
        .collect();
    store
        .replace_device(&p, &genesis, &next, policy, &proofs, 150)
        .expect("atomic replacement");
    fs::write(path.join("returned-replacement"), b"committed").expect("return marker");
}

#[test]
fn process_loss_after_replacement_commit_recovers_exact_original_decision() {
    let mut c = required_case();
    let mut next = fresh(&c, 2, 2, 184);
    let old = request(
        &c,
        AnchorOperation::advance(initial(&c), [189; 32]).expect("prior command"),
    );
    let head = apply_request(&mut c, &old)
        .applied_head()
        .expect("prior head");
    let p = first_proposal(&mut c, &next);
    let before = c.store.image().expect("before").revision;
    fs::write(
        c.server.join("replacement.bin"),
        p.to_bytes().expect("retained original proposal"),
    )
    .expect("public proposal");
    next.journal.close();
    c.store.close();
    let log = fs::File::create_new(c.server.join("replacement-child.log")).expect("log");
    let mut child = ChildGuard(
        Process::new(std::env::current_exe().expect("binary"))
            .args([
                "--exact",
                "anchor::store::tests::replacement::replacement_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_DEVICE_REPLACEMENT_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
            .env("QPERIAPT_ANCHOR_CRASH_REVISION", (before + 1).to_string())
            .stdout(Stdio::from(log.try_clone().expect("log clone")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned child"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
            "replacement child deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.server.join("returned-replacement").exists());
    child.0.kill().expect("kill after durable commit");
    assert!(!child.0.wait().expect("reap").success());
    c.store = reopen(&c.server);
    assert_eq!(
        c.store
            .device_replacement_status(&p)
            .expect("retained decision"),
        State::Committed
    );
    assert_eq!(
        commit(&mut c, &p, &next, 250).expect("historical exact retry after expiry"),
        State::Committed
    );
    assert_eq!(c.store.image().expect("one commit").revision, before + 1);
    let history = c
        .store
        .retired_subject_observation(&p, c.genesis.subject())
        .expect("frozen original");
    assert_eq!(history.observed_head(), head);
    assert_eq!(history.last_command_id(), Some(old.command_id()));
    assert_retired(&mut c, AnchorOperation::query());
    assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
    eprintln!("ANCHOR_DEVICE_REPLACEMENT_PROCESS commit_before_return=true original_genesis_recovered=true exact_retry=true old_scope_denied=true new_current=true");
}

#[test]
fn adopted_policy_blocks_replacement_rollback_and_retired_policy_operations() {
    use crate::anchor::store::policy_renewal::tests::{policy, Case as PolicyCase};
    let mut c = PolicyCase::new();
    let approval = c.approval(&c.original, None, &c.target);
    let renewal = c.proposal(&approval, c.initial, 191);
    c.prepare(renewal, &approval)
        .expect("independent policy approval");
    c.exchange(
        &renewal,
        AnchorOperation::commit_policy_renewal(&renewal),
        170,
    );
    c.exchange(
        &renewal,
        AnchorOperation::acknowledge_policy_renewal(&renewal),
        170,
    );
    let signer = DeviceSigningKey::generate().expect("fresh owner");
    let mut description = c.device.description.clone();
    description.generation = 2;
    let certificate = c
        .account
        .issue_device(description, signer.public_key().expect("key"))
        .expect("certificate");
    let roster = c
        .account
        .issue_roster(
            2,
            Validity::new(100, 400).expect("validity"),
            &[c.account.roster_entry(&certificate).expect("member")],
        )
        .expect("roster");
    let device = crate::AccountPin::new(
        c.device.account_id(),
        c.account.public_key().expect("root"),
        roster.checkpoint(),
        c.original.family(),
    )
    .expect("independent pin")
    .verify_device(&certificate, roster.as_bytes(), 150)
    .expect("next device");
    let original = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
    let checkpoint = c.device.roster().checkpoint();
    let before = c.fingerprint();
    let current_proofs = [(c.subject, checkpoint, c.target.historical())];
    let mut accepted = None;
    for (name, target, now) in [("rollback", &original, 150), ("current", &c.target, 170)] {
        let path = c.server.join(name);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("new journal directory");
        let mut journal = DeviceJournal::provision_anchored(
            &path.join("state.redb"),
            JournalKey::provision(&path.join("key")).expect("key"),
            &device,
            target,
            crate::JournalIdentity::generate().expect("identity"),
            now,
        )
        .expect("actual genesis journal");
        let genesis = journal.anchor_genesis(&device, target).expect("genesis");
        let result =
            c.store
                .device_replacement_proposal(&genesis, &device, target, &current_proofs, now);
        if name == "rollback" {
            assert!(matches!(result, Err(DurableError::Protocol(Error::Scope))));
        } else {
            assert!(matches!(
                c.store.device_replacement_proposal(
                    &genesis,
                    &device,
                    target,
                    &[(c.subject, checkpoint, &c.original)],
                    now
                ),
                Err(DurableError::Conflict)
            ));
            accepted = Some((result.expect("current policy"), genesis, journal));
        }
    }
    assert_eq!(c.fingerprint(), before);
    let (p, genesis, _journal) = accepted.expect("approved target");
    let proofs = [(c.subject, checkpoint, c.target.historical())];
    c.store
        .replace_device(&p, &genesis, &device, &c.target, &proofs, 170)
        .expect("current policy replacement");
    c.reopen();
    let frozen = c.fingerprint();
    for op in [
        AnchorOperation::commit_policy_renewal(&renewal),
        AnchorOperation::policy_renewal_status(&renewal),
        AnchorOperation::close_policy_renewal(&renewal),
        AnchorOperation::acknowledge_policy_renewal(&renewal),
    ] {
        let request =
            AnchorRequest::new(&c.pin, c.subject, op, &c.signer).expect("old signed request");
        assert!(matches!(
            c.store.handle(request.as_bytes(), 170),
            Err(AnchorError::Rejected(Error::Scope))
        ));
    }
    assert!(matches!(
        c.prepare(renewal, &approval),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(c.fingerprint(), frozen);
    assert_eq!(
        c.store
            .retired_subject_observation(&p, c.subject)
            .expect("frozen original")
            .observed_head(),
        renewal.target_head()
    );
}

#[test]
fn retirement_receipt_is_permanent_history_across_reopen_and_successor_replacement() {
    let mut c = required_case();
    let old = request(
        &c,
        AnchorOperation::advance(initial(&c), [193; 32]).expect("old command"),
    );
    let head = apply_request(&mut c, &old)
        .applied_head()
        .expect("old head");
    let next = fresh(&c, 2, 2, 186);
    let p = first_proposal(&mut c, &next);
    assert!(matches!(
        c.store.retired_subject_receipt(&p, c.genesis.subject()),
        Err(DurableError::Absent)
    ));
    commit(&mut c, &p, &next, 150).expect("retirement committed");
    let before = c.store.image().expect("before issue").digest;
    let receipt = c
        .store
        .retired_subject_receipt(&p, c.genesis.subject())
        .expect("signed retirement");
    assert_eq!(receipt.len(), 3754);
    let observed = c
        .pin
        .verify_retired_subject(&p, c.genesis.subject(), &receipt)
        .expect("pinned historical fact");
    assert_eq!(observed.witness_binding(), c.pin.binding());
    assert_eq!(observed.observed_head(), head);
    assert_eq!(observed.last_command_id(), Some(old.command_id()));
    assert_eq!(
        observed,
        c.store
            .retired_subject_observation(&p, c.genesis.subject())
            .expect("same trusted fact")
    );
    assert_eq!(
        c.store.image().expect("issuance is read only").digest,
        before
    );
    let newest = fresh(&c, 3, 3, 188);
    let next_p = prepare(
        &mut c,
        &newest,
        next.genesis.subject(),
        next.device.roster().checkpoint(),
    );
    commit(&mut c, &next_p, &newest, 150).expect("successor also retired");
    c.store.close();
    c.store = reopen(&c.server);
    c.peer
        .responder
        .current_policy()
        .expect("original policy")
        .close();
    let before = c.store.image().expect("after future replacement").digest;
    let reissued = c
        .store
        .retired_subject_receipt(&p, c.genesis.subject())
        .expect("historical reissue needs no current policy");
    assert_eq!(
        open_envelope(&receipt).expect("first body").0,
        open_envelope(&reissued).expect("same body").0
    );
    assert_eq!(
        c.pin
            .verify_retired_subject(&p, c.genesis.subject(), &reissued)
            .expect("same permanent fact"),
        observed
    );
    assert_eq!(
        c.store.image().expect("no historical mutation").digest,
        before
    );
    assert_retired(&mut c, AnchorOperation::query());
}

#[test]
fn retirement_receipt_requires_both_signatures_exact_pin_proposal_and_subject() {
    let mut c = required_case();
    let next = fresh(&c, 2, 2, 190);
    let alternative = fresh(&c, 2, 2, 192);
    let p = first_proposal(&mut c, &next);
    let other = first_proposal(&mut c, &alternative);
    commit(&mut c, &p, &next, 150).expect("original transition");
    let wire = c
        .store
        .retired_subject_receipt(&p, c.genesis.subject())
        .expect("receipt");
    for end in 0..wire.len() {
        assert!(c
            .pin
            .verify_retired_subject(&p, c.genesis.subject(), wire.get(..end).expect("prefix"))
            .is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(c
        .pin
        .verify_retired_subject(&p, c.genesis.subject(), &trailing)
        .is_err());
    assert!(c
        .pin
        .verify_retired_subject(&other, c.genesis.subject(), &wire)
        .is_err());
    assert!(c
        .pin
        .verify_retired_subject(&p, next.genesis.subject(), &wire)
        .is_err());
    let wrong_instance = AnchorPin::new(
        AnchorIdentity::generate().expect("other instance"),
        c.pin.public_key().clone(),
    );
    assert!(wrong_instance
        .verify_retired_subject(&p, c.genesis.subject(), &wire)
        .is_err());
    let wrong_key = AnchorPin::new(
        c.pin.identity(),
        AnchorSigningKey::generate()
            .expect("other signer")
            .public_key()
            .expect("key"),
    );
    assert!(wrong_key
        .verify_retired_subject(&p, c.genesis.subject(), &wire)
        .is_err());
    for offset in [4 + 377, 4 + 377 + 3309] {
        let mut corrupted = wire.clone();
        *corrupted.get_mut(offset).expect("signature component") ^= 1;
        assert!(c
            .pin
            .verify_retired_subject(&p, c.genesis.subject(), &corrupted)
            .is_err());
    }
    let observed = c
        .pin
        .verify_retired_subject(&p, c.genesis.subject(), &wire)
        .expect("both signatures correct");
    assert_eq!(observed.observed_head(), initial(&c));
    assert_eq!(observed.last_command_id(), None);
}

#[test]
fn retirement_receipt_cannot_be_an_operating_reply_or_another_signature_purpose() {
    let mut c = required_case();
    let next = fresh(&c, 2, 2, 194);
    let p = first_proposal(&mut c, &next);
    commit(&mut c, &p, &next, 150).expect("retire original");
    let wire = c
        .store
        .retired_subject_receipt(&p, c.genesis.subject())
        .expect("retirement");
    let old_query = request(&c, AnchorOperation::query());
    assert!(c.pin.verify_reply(&old_query, &wire).is_err());
    let before = c.store.image().expect("before wrong request").digest;
    assert!(c.store.handle(&wire, 150).is_err());
    assert_eq!(c.store.image().expect("never a write").digest, before);
    let body = open_envelope(&wire).expect("body").0;
    let wrong_purpose = c
        .store
        .active
        .as_ref()
        .expect("owner")
        .signer
        .sign(Purpose::AnchorReply, body)
        .expect("explicit wrong-purpose control");
    let wrong = envelope(body, &wrong_purpose).expect("wire");
    assert!(c
        .pin
        .verify_retired_subject(&p, c.genesis.subject(), &wrong)
        .is_err());
    // Even correctly signed bytes must carry the exact retained replacement,
    // original subject, frozen state commitment and successor.
    for offset in [8 + 32, 8 + 32 + 32, 8 + 32 + 32 + 96 + 48 + 33, 377 - 1] {
        let mut altered = body.to_vec();
        *altered.get_mut(offset).expect("public field") ^= 1;
        let signature = c
            .store
            .active
            .as_ref()
            .expect("signer")
            .signer
            .sign(Purpose::AnchorRetirement, &altered)
            .expect("signed substitution control");
        let wrong = envelope(&altered, &signature).expect("wire");
        assert!(c
            .pin
            .verify_retired_subject(&p, c.genesis.subject(), &wrong)
            .is_err());
    }
    assert_eq!(query(&mut c, &next).outcome(), AnchorOutcome::Current);
}

#[test]
fn retirement_head_does_not_identify_every_retained_local_write_intent() {
    use std::{
        io,
        sync::{atomic::AtomicBool, Arc, Mutex},
    };
    struct BeforeAdvance {
        store: Arc<Mutex<AnchorStore>>,
        pin: AnchorPin,
        intercepted: Arc<AtomicBool>,
    }
    impl crate::AnchorTransport for BeforeAdvance {
        fn exchange(&mut self, wire: &[u8], _: Instant) -> io::Result<Vec<u8>> {
            let request = incoming(&self.pin, wire).map_err(io::Error::other)?;
            if matches!(request.operation.0, Command::Advance(..)) {
                self.intercepted.store(true, Ordering::SeqCst);
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "original advance not processed",
                ));
            }
            self.store
                .lock()
                .map_err(|_| io::Error::other("witness lock"))?
                .handle(wire, 150)
                .map_err(io::Error::other)
        }
    }
    fn retained_rows(path: &Path) -> (Vec<u8>, Option<Vec<u8>>) {
        let db = open_private_database(path).expect("closed original journal");
        let read = db.begin_read().expect("read");
        let table = read
            .open_table(TableDefinition::<&str, &[u8]>::new(
                "continuity_device_candidate_v21",
            ))
            .expect("existing journal table");
        let image = table
            .get("image")
            .expect("lookup")
            .expect("image")
            .value()
            .to_vec();
        let pending = table
            .get("pending")
            .expect("lookup")
            .map(|p| p.value().to_vec());
        (image, pending)
    }
    let mut c = required_case();
    let next = fresh(&c, 2, 2, 196);
    let proposal = first_proposal(&mut c, &next);
    let subject = c.genesis.subject();
    let original_head = initial(&c);
    let journal_path = c.server.parent().expect("root").join("client/state.redb");
    let key_path = c.server.parent().expect("root").join("client/key");
    let identity = c._journal.identity().expect("original ID");
    c._journal.close();
    let before = retained_rows(&journal_path);
    assert!(before.1.is_none());
    let original_journal_bytes = fs::read(&journal_path).expect("closed backup snapshot");
    let store = Arc::new(Mutex::new(c.store));
    let intercepted = Arc::new(AtomicBool::new(false));
    let client = crate::AnchorClient::new(
        c.pin.clone(),
        c.peer.signer_r,
        Box::new(BeforeAdvance {
            store: Arc::clone(&store),
            pin: c.pin.clone(),
            intercepted: Arc::clone(&intercepted),
        }),
        Duration::from_secs(5),
    )
    .expect("real signed client");
    let (policy, original, _) = c
        .peer
        .responder
        .inventory_inputs()
        .expect("original authority");
    let mut journal = DeviceJournal::open_anchored(
        &journal_path,
        JournalKey::open(&key_path).expect("same key"),
        original,
        policy,
        identity,
        client,
    )
    .expect("actual current journal");
    let devices = c.peer.initiator.devices();
    let remote_roster = devices.first().expect("initiator device").roster();
    assert_ne!(remote_roster.account_id(), original.account_id());
    let attempted = journal.install_roster(remote_roster, 150);
    assert!(
        matches!(attempted, Err(DurableError::Anchor(_))),
        "actual roster result: {attempted:?}"
    );
    assert!(intercepted.load(Ordering::SeqCst));
    assert!(matches!(journal.identity(), Err(DurableError::Closed)));
    let after = retained_rows(&journal_path);
    assert_eq!(after.0, before.0);
    assert!(
        after.1.is_some(),
        "actual original sealed write intent remains"
    );
    let observed = {
        let mut witness = store.lock().expect("trusted controller");
        let proof = [(subject, original.roster().checkpoint(), policy.historical())];
        witness
            .replace_device(&proposal, &next.genesis, &next.device, policy, &proof, 150)
            .expect("same unchanged witness predecessor");
        let wire = witness
            .retired_subject_receipt(&proposal, subject)
            .expect("actual retirement proof");
        c.pin
            .verify_retired_subject(&proposal, subject, &wire)
            .expect("permanent frozen fact")
    };
    assert_eq!(observed.observed_head(), original_head);
    assert_eq!(
        observed.observed_head().digest(),
        digest(b"Q-PERIAPT-CONTINUITY-VAULT-IMAGE-CANDIDATE/v2", &after.0)
    );
    let backup = c
        .server
        .parent()
        .expect("root")
        .join("before-intent-backup");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&backup)
        .expect("private backup directory");
    let backup_path = backup.join("state.redb");
    fs::write(&backup_path, original_journal_bytes).expect("restore exact earlier snapshot");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600)).expect("private snapshot");
    let restored = retained_rows(&backup_path);
    assert_eq!(restored.0, after.0);
    assert!(restored.1.is_none());
    eprintln!("RETIRED_LOCAL_INTENT_BOUNDARY actual_roster_write=true advance_unprocessed=true same_frozen_image=true retained_pending_differs=true retirement_receipt_is_not_complete_local_inventory=true");
}

#[path = "retired_cleanup_tests.rs"]
mod cleanup;
