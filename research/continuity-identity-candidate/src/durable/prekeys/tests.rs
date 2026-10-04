// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::{fixture, fixture_from_public, Fixture},
    durable::tests::{directory, fault_store, new_store, reopen, ChildGuard},
    tests::interval,
    InitiatorOperation,
};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(in crate::durable) struct Inventory {
    pub(in crate::durable) store: DeviceJournal,
    pub(in crate::durable) peer: Fixture,
    pub(in crate::durable) ids: [PrekeyId; 4],
    pub(in crate::durable) public: (
        [u8; q_periapt_sdk::PUBLIC_KEY_LEN],
        [u8; q_periapt_sdk::PUBLIC_KEY_LEN],
    ),
    pub(in crate::durable) path: PathBuf,
    _dir: Option<tempfile::TempDir>,
}
pub(in crate::durable) fn inventory(quality: PrekeyQuality) -> Inventory {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    inventory_at(quality, path, Some(dir))
}
pub(in crate::durable) fn inventory_at(
    quality: PrekeyQuality,
    path: PathBuf,
    dir: Option<tempfile::TempDir>,
) -> Inventory {
    let base = fixture(PrekeyQuality::OneTimeBoth);
    let mut store = new_store(&path, base.local_device());
    let ids = [1u8, 2, 3, 4].map(|i| PrekeyId::from_trusted_state([i; 32]).expect("request"));
    let kinds = [
        LeafKind::SignedClassical,
        LeafKind::OneTimeClassical,
        LeafKind::LastResortPq,
        LeafKind::OneTimePq,
    ];
    let (policy, device, _) = base.responder.inventory_inputs();
    let mut leaves = BTreeMap::new();
    for (request, kind) in ids.iter().zip(kinds) {
        let leaf = store
            .generate_prekey(policy, device, *request, kind, interval(), 150)
            .expect("durable key");
        leaves.insert(kind as u8, leaf);
    }
    let pair = |p: u8, c: u8| {
        [
            leaves.get(&p).expect("PQ").public_key(),
            leaves.get(&c).expect("classical").public_key(),
        ]
        .concat()
        .try_into()
        .expect("combined public width")
    };
    let public = (pair(3, 1), pair(4, 2));
    let mut peer = fixture_from_public(quality, Some(public));
    peer.reusable.close();
    peer.once.close(); // The inventory is the only actual prekey owner.
    Inventory {
        store,
        peer,
        ids,
        public,
        path,
        _dir: dir,
    }
}

#[test]
fn full_prekey_inventory_keeps_roster_admission_and_revocation_available() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let folder = directory();
    let path = folder.path().canonicalize().expect("private path");
    let (policy, device, _) = f.responder.inventory_inputs();
    let mut store = new_store(&path, device);
    let request = |index: usize| {
        let mut bytes = [0; 32];
        bytes
            .get_mut(24..)
            .expect("counter bytes")
            .copy_from_slice(&u64::try_from(index).expect("bounded counter").to_be_bytes());
        PrekeyId::from_trusted_state(bytes).expect("nonzero request")
    };
    // Actual owned generation and retirement leave bounded public tombstones.
    // They fit inside the image limit and still count as prekey records.
    for index in 1..MAX_PREKEY_RECORDS {
        let id = request(index);
        store
            .generate_prekey(
                policy,
                device,
                id,
                LeafKind::SignedClassical,
                interval(),
                150,
            )
            .expect("generate within prekey capacity");
        assert_eq!(
            store.retire_prekey(policy, device, id).expect("retire"),
            PrekeyStatus::Retired
        );
    }
    store
        .install_roster(f.initiator_device().roster(), 150)
        .expect("a peer roster must not consume a prekey slot");
    let last = request(MAX_PREKEY_RECORDS);
    store
        .generate_prekey(
            policy,
            device,
            last,
            LeafKind::SignedClassical,
            interval(),
            150,
        )
        .expect("the last prekey slot remains available");
    store.close();
    store = reopen(&path, device);
    assert_eq!(
        store
            .prekey_status(policy, device, last)
            .expect("last saved key"),
        PrekeyStatus::Available
    );
    assert!(matches!(
        store.generate_prekey(
            policy,
            device,
            request(MAX_PREKEY_RECORDS + 1),
            LeafKind::SignedClassical,
            interval(),
            150,
        ),
        Err(DurableError::Capacity)
    ));
    // Genuine exhaustion is refused before persistence and leaves the owner usable.
    assert_eq!(
        store
            .prekey_status(policy, device, last)
            .expect("still open"),
        PrekeyStatus::Available
    );
    let revoked = rosters::tests::update(device, 94, 2, false);
    store
        .install_roster(&revoked, 150)
        .expect("revocation at capacity");
    store.close();
    store = reopen(&path, device);
    assert_eq!(
        store
            .roster_checkpoint(device.account_id())
            .expect("durable head"),
        revoked.checkpoint()
    );
    assert!(matches!(
        store.prekey_leaf(policy, device, last, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    assert_eq!(
        store.retire_prekey(policy, device, last).expect("cleanup"),
        PrekeyStatus::Retired
    );
    for index in 1..=MAX_PREKEY_RECORDS {
        assert_eq!(
            store
                .prekey_status(policy, device, request(index))
                .expect("retained identity"),
            PrekeyStatus::Retired
        );
    }
    let image = store.image().expect("authenticated image");
    assert_eq!(image.operation_count(), 0);
    assert_eq!(image.records.len(), MAX_PREKEY_RECORDS + 2);
}

#[test]
fn installed_revocation_fences_prekey_generation_and_cached_leaf_but_allows_retirement() {
    let mut f = inventory(PrekeyQuality::OneTimeBoth);
    let (policy, device, _) = f.peer.responder.inventory_inputs();
    let request = *f.ids.first().expect("retained prekey");
    let leaf = f
        .store
        .prekey_leaf(policy, device, request, 150)
        .expect("initial leaf");
    let peer_update = rosters::tests::update(f.peer.initiator_device(), 90, 2, false);
    f.store
        .install_roster(&peer_update, 150)
        .expect("peer revocation");
    assert_eq!(
        f.store
            .prekey_leaf(policy, device, request, 150)
            .expect("unrevoked local leaf")
            .public_key(),
        leaf.public_key()
    );
    let revoked = rosters::tests::update(device, 94, 2, false);
    f.store
        .install_roster(&revoked, 150)
        .expect("local revocation");
    f.store.close();
    f.store = reopen(&f.path, device);
    assert_eq!(
        f.store
            .prekey_status(policy, device, request)
            .expect("read-only state"),
        PrekeyStatus::Available
    );
    assert!(matches!(
        f.store.prekey_leaf(policy, device, request, 150),
        Err(DurableError::Protocol(Error::Scope))
    ));
    for request in [
        request,
        PrekeyId::from_trusted_state([55; 32]).expect("new request"),
    ] {
        assert!(matches!(
            f.store.generate_prekey(
                policy,
                device,
                request,
                LeafKind::SignedClassical,
                interval(),
                150
            ),
            Err(DurableError::Protocol(Error::Scope))
        ));
    }
    assert_eq!(
        f.store
            .retire_prekey(policy, device, request)
            .expect("cleanup remains possible"),
        PrekeyStatus::Retired
    );
    f.store.close();
    f.store = reopen(&f.path, device);
    assert_eq!(
        f.store
            .prekey_status(policy, device, request)
            .expect("retirement persisted"),
        PrekeyStatus::Retired
    );
}

#[test]
fn inventory_roundtrips_every_quality_and_atomically_retires_only_selected_one_time_keys() {
    for quality in [
        PrekeyQuality::OneTimeBoth,
        PrekeyQuality::ReusableBoth,
        PrekeyQuality::SignedClassicalOneTimePq,
        PrekeyQuality::OneTimeClassicalLastResortPq,
    ] {
        let mut f = inventory(quality);
        f.store.close();
        f.store = reopen(&f.path, f.peer.local_device());
        let mut i = InitiatorOperation::start(Arc::clone(&f.peer.initiator), &f.peer.signer_i, 150)
            .expect("initial");
        let initial = i.initial_message(150).expect("wire").to_vec();
        let reply = f
            .store
            .respond_from_inventory(
                Arc::clone(&f.peer.responder),
                &initial,
                &f.peer.signer_r,
                150,
            )
            .expect("restore actual keys");
        let outcome = i.finish(&reply, 150).expect("real confirmation");
        assert_eq!(
            f.store
                .finish(
                    Arc::clone(&f.peer.responder),
                    &initial,
                    outcome.final_message(),
                    150
                )
                .expect("final"),
            outcome.pending_session().id()
        );
        let (policy, device, selection) = f.peer.responder.inventory_inputs();
        let selected = [
            selection.post_quantum().kind(),
            selection.classical().kind(),
        ];
        for (request, kind) in f.ids.iter().zip([
            LeafKind::SignedClassical,
            LeafKind::OneTimeClassical,
            LeafKind::LastResortPq,
            LeafKind::OneTimePq,
        ]) {
            let expected = if one_time(kind) && selected.contains(&kind) {
                PrekeyStatus::Consumed
            } else {
                PrekeyStatus::Available
            };
            assert_eq!(
                f.store
                    .prekey_status(policy, device, *request)
                    .expect("inventory state"),
                expected
            );
            let image = f.store.image().expect("image");
            let entry =
                Entry::decode(image.records.get(&id(*request)).expect("record")).expect("entry");
            assert_eq!(
                entry.data.len(),
                if expected == PrekeyStatus::Consumed {
                    32
                } else {
                    277
                }
            );
            if expected == PrekeyStatus::Consumed {
                assert!(matches!(
                    f.store.prekey_leaf(policy, device, *request, 150),
                    Err(DurableError::PrekeyClaimed)
                ));
            } else {
                assert_eq!(
                    f.store
                        .retire_prekey(policy, device, *request)
                        .expect("retire after completion"),
                    PrekeyStatus::Retired
                );
            }
        }
        f.peer.signer_r.close();
        f.store.close();
        f.store = reopen(&f.path, f.peer.local_device());
        assert_eq!(
            f.store
                .respond_from_inventory(
                    Arc::clone(&f.peer.responder),
                    &initial,
                    &f.peer.signer_r,
                    150
                )
                .expect("cached response without restored keys/signer"),
            reply
        );
    }
}

#[test]
fn generation_request_is_immutable_and_retirement_never_reactivates_it() {
    let mut f = inventory(PrekeyQuality::OneTimeBoth);
    let request = *f.ids.first().expect("baseline ID");
    let (policy, device, _) = f.peer.responder.inventory_inputs();
    assert!(matches!(
        f.store.generate_prekey(
            policy,
            device,
            request,
            LeafKind::LastResortPq,
            interval(),
            150
        ),
        Err(DurableError::Conflict)
    ));
    assert!(matches!(
        f.store.generate_prekey(
            policy,
            device,
            request,
            LeafKind::SignedClassical,
            Validity::new(110, 190).expect("interval"),
            150
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        f.store
            .retire_prekey(policy, device, request)
            .expect("retire"),
        PrekeyStatus::Retired
    );
    assert_eq!(
        f.store
            .retire_prekey(policy, device, request)
            .expect("repeat"),
        PrekeyStatus::Retired
    );
    assert!(matches!(
        f.store.generate_prekey(
            policy,
            device,
            request,
            LeafKind::SignedClassical,
            interval(),
            150
        ),
        Err(DurableError::KeyRetired)
    ));
    assert!(matches!(
        f.store.prekey_leaf(policy, device, request, 150),
        Err(DurableError::KeyRetired)
    ));
    f.peer.close_responder_policy();
    let (policy, device, _) = f.peer.responder.inventory_inputs();
    assert_eq!(
        f.store
            .prekey_status(policy, device, request)
            .expect("closed policy query"),
        PrekeyStatus::Retired
    );
}

#[test]
fn generation_sync_failures_reconcile_the_original_reserved_key() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let (policy, device, _) = f.responder.inventory_inputs();
    let mut states = BTreeSet::new();
    for after_sync in [false, true] {
        for cut in 1..=8 {
            let dir = directory();
            let path = dir.path().canonicalize().expect("path");
            drop(new_store(&path, device));
            let (mut store, fault, _, _) = fault_store(&path, device, after_sync);
            let request = PrekeyId::generate().expect("request");
            fault.store(cut, Ordering::SeqCst);
            assert!(matches!(
                store.generate_prekey(
                    policy,
                    device,
                    request,
                    LeafKind::OneTimePq,
                    interval(),
                    150
                ),
                Err(DurableError::CommitUncertain(_))
            ));
            let mut store = reopen(&path, device);
            let status = store.prekey_status(policy, device, request).expect("query");
            states.insert(format!("{status:?}"));
            let expected = if status != PrekeyStatus::Absent {
                let image = store.image().expect("image");
                let entry =
                    Entry::decode(image.records.get(&id(request)).expect("record")).expect("entry");
                let token = SealedOperation::from_bytes(&entry.data).expect("saved token");
                let key = store
                    .inventory_recovery_key()
                    .expect("key")
                    .generate_key(&policy.runtime, &entry.scope(&image), &token)
                    .expect("exact computation");
                Some(public_component(&key, entry.kind).expect("public"))
            } else {
                None
            };
            let leaf = store
                .generate_prekey(
                    policy,
                    device,
                    request,
                    LeafKind::OneTimePq,
                    interval(),
                    150,
                )
                .expect("resume key");
            if let Some(expected) = expected {
                assert_eq!(leaf.public_key(), expected);
            }
            assert_eq!(
                store.prekey_status(policy, device, request).expect("state"),
                PrekeyStatus::Available
            );
        }
    }
    assert!(states.contains("Reserved") && states.contains("Available"));
}

#[test]
fn response_sync_failures_keep_inventory_and_outbox_consumption_indivisible() {
    let mut measured = inventory(PrekeyQuality::OneTimeBoth);
    let initial_operation = InitiatorOperation::start(
        Arc::clone(&measured.peer.initiator),
        &measured.peer.signer_i,
        150,
    )
    .expect("initial");
    let initial = initial_operation
        .initial_message(150)
        .expect("wire")
        .to_vec();
    measured.store.close();
    let (mut measured_store, _, count, _) =
        fault_store(&measured.path, measured.peer.local_device(), false);
    measured_store
        .respond_from_inventory(
            Arc::clone(&measured.peer.responder),
            &initial,
            &measured.peer.signer_r,
            150,
        )
        .expect("count inventory response barriers");
    let syncs = count.load(Ordering::SeqCst);
    assert!((20..=64).contains(&syncs));
    for after_sync in [false, true] {
        for cut in 1..=syncs {
            let mut f = inventory(PrekeyQuality::OneTimeBoth);
            let mut i =
                InitiatorOperation::start(Arc::clone(&f.peer.initiator), &f.peer.signer_i, 150)
                    .expect("initial");
            let initial = i.initial_message(150).expect("wire").to_vec();
            f.store.close();
            let (mut store, fault, _, _) = fault_store(&f.path, f.peer.local_device(), after_sync);
            fault.store(cut, Ordering::SeqCst);
            crate::durable::tests::assert_sync_failure(
                store.respond_from_inventory(
                    Arc::clone(&f.peer.responder),
                    &initial,
                    &f.peer.signer_r,
                    150,
                ),
                after_sync,
            );
            assert!(store.active.is_none());
            let mut store = reopen(&f.path, f.peer.local_device());
            let phase = store.status(&f.peer.responder, &initial).expect("phase");
            let (policy, device, _) = f.peer.responder.inventory_inputs();
            for request in [f.ids.get(1).expect("classical"), f.ids.get(3).expect("PQ")] {
                let status = store
                    .prekey_status(policy, device, *request)
                    .expect("key phase");
                assert_eq!(
                    status,
                    if phase == DurableStatus::AwaitingFinal {
                        PrekeyStatus::Consumed
                    } else {
                        PrekeyStatus::Available
                    }
                );
                if matches!(
                    phase,
                    DurableStatus::Executing
                        | DurableStatus::ResponseKemReserved
                        | DurableStatus::ResponseSignatureReserved
                        | DurableStatus::Prepared
                ) {
                    assert!(matches!(
                        store.retire_prekey(policy, device, *request),
                        Err(DurableError::PrekeyClaimed)
                    ));
                }
            }
            let reply = store
                .respond_from_inventory(
                    Arc::clone(&f.peer.responder),
                    &initial,
                    &f.peer.signer_r,
                    150,
                )
                .expect("resume exact response");
            let outcome = i.finish(&reply, 150).expect("real reply MAC");
            assert_eq!(
                store
                    .finish(
                        Arc::clone(&f.peer.responder),
                        &initial,
                        outcome.final_message(),
                        150
                    )
                    .expect("final MAC"),
                outcome.pending_session().id()
            );
        }
    }
}

fn spawn_child(path: &Path, test: &str, phase: DurableStatus, effect: bool) -> ChildGuard {
    let log = fs::File::create(path.join("child.log")).expect("log");
    ChildGuard(
        Command::new(std::env::current_exe().expect("binary"))
            .args(["--exact", test, "--nocapture"])
            .env("QPERIAPT_PREKEY_CRASH_DIR", path)
            .env("QPERIAPT_JOURNAL_CRASH_DIR", path)
            .env(
                if effect {
                    "QPERIAPT_PREKEY_CRASH_EFFECT"
                } else {
                    "QPERIAPT_JOURNAL_CRASH_PHASE"
                },
                (phase as u8).to_string(),
            )
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("owned inventory process"),
    )
}
fn wait_for(path: &Path, marker: &str, child: &mut ChildGuard) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join(marker).exists() {
        let status = child.0.try_wait().expect("status");
        if status.is_some() {
            eprintln!(
                "child log: {}",
                fs::read_to_string(path.join("child.log")).expect("finished child log")
            );
        }
        assert!(
            status.is_none() && Instant::now() < deadline,
            "missing {marker}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn publish(path: &Path, name: &str, bytes: &[u8]) {
    let tmp = path.join(format!("{name}.tmp"));
    fs::write(&tmp, bytes).expect("owned output");
    fs::rename(tmp, path.join(name)).expect("atomic publication");
}

#[test]
fn inventory_response_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_PREKEY_CRASH_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let mut f = inventory_at(PrekeyQuality::OneTimeBoth, path.clone(), None);
    publish(&path, "peer-public", &[f.public.0, f.public.1].concat());
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("peer-initial").exists() {
        assert!(Instant::now() < deadline, "initial deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    let initial = fs::read(path.join("peer-initial")).expect("live initial");
    let reply = f
        .store
        .respond_from_inventory(
            Arc::clone(&f.peer.responder),
            &initial,
            &f.peer.signer_r,
            150,
        )
        .expect("inventory response");
    publish(&path, "returned-response", &reply);
}

#[test]
fn process_loss_recovers_original_inventory_before_authentication_and_commits_consumption() {
    for phase in [
        DurableStatus::Executing,
        DurableStatus::Prepared,
        DurableStatus::AwaitingFinal,
    ] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let mut child = spawn_child(
            &path,
            "durable::prekeys::tests::inventory_response_crash_child",
            phase,
            false,
        );
        wait_for(&path, "peer-public", &mut child);
        let public = fs::read(path.join("peer-public")).expect("enrollment");
        let (a, b) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
        let mut f = fixture_from_public(
            PrekeyQuality::OneTimeBoth,
            Some((
                a.try_into().expect("public width"),
                b.try_into().expect("public width"),
            )),
        );
        f.reusable.close();
        f.once.close(); // No original prekey owner exists in the parent process.
        if phase != DurableStatus::Executing {
            f.signer_r.close(); // Pinned output also survives loss of the signing owner.
        }
        let mut peer = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
            .expect("live peer");
        let initial = peer.initial_message(150).expect("initial").to_vec();
        publish(&path, "peer-initial", &initial);
        wait_for(&path, "ready", &mut child);
        assert!(
            !path.join("returned-response").exists(),
            "outbox escaped commit barrier"
        );
        child.0.kill().expect("kill owned process");
        assert!(!child.0.wait().expect("reap").success());
        let mut store = reopen(&path, f.local_device());
        assert_eq!(store.status(&f.responder, &initial).expect("phase"), phase);
        let (policy, device, _) = f.responder.inventory_inputs();
        for request in [2, 4].map(|n| PrekeyId::from_trusted_state([n; 32]).expect("request")) {
            assert_eq!(
                store
                    .prekey_status(policy, device, request)
                    .expect("key status"),
                if phase == DurableStatus::AwaitingFinal {
                    PrekeyStatus::Consumed
                } else {
                    PrekeyStatus::Available
                }
            );
        }
        let reply = store
            .respond_from_inventory(Arc::clone(&f.responder), &initial, &f.signer_r, 150)
            .expect("restore original inventory or exact pinned output");
        let outcome = peer
            .finish(&reply, 150)
            .expect("same live peer verifies reply MAC");
        assert_eq!(
            store
                .finish(
                    Arc::clone(&f.responder),
                    &initial,
                    outcome.final_message(),
                    150
                )
                .expect("final MAC"),
            outcome.pending_session().id()
        );
        for request in [2, 4].map(|n| PrekeyId::from_trusted_state([n; 32]).expect("request")) {
            assert_eq!(
                store
                    .prekey_status(policy, device, request)
                    .expect("consumed"),
                PrekeyStatus::Consumed
            );
        }
        assert_eq!(
            store
                .respond_from_inventory(Arc::clone(&f.responder), &initial, &f.signer_r, 150)
                .expect("exact replay"),
            reply
        );
    }
}

pub(super) fn after_generation(public: &[u8]) {
    if std::env::var_os("QPERIAPT_PREKEY_CRASH_EFFECT").is_none() {
        return;
    }
    let path = std::env::var_os("QPERIAPT_PREKEY_CRASH_DIR").expect("owned directory");
    let path = Path::new(&path);
    publish(path, "computed-public", public);
    publish(path, "ready", b"computed");
    loop {
        std::thread::park();
    }
}

#[test]
fn inventory_generation_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_PREKEY_CRASH_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let mut store = new_store(path, f.local_device());
    let (policy, device, _) = f.responder.inventory_inputs();
    let leaf = store
        .generate_prekey(
            policy,
            device,
            PrekeyId::from_trusted_state([71; 32]).expect("request"),
            LeafKind::OneTimePq,
            interval(),
            150,
        )
        .expect("generated");
    publish(path, "returned-leaf", leaf.public_key());
}

#[test]
fn generation_process_cuts_replay_exact_key_before_publication() {
    for (phase, effect) in [
        (DurableStatus::PrekeyReserved, false),
        (DurableStatus::PrekeyReserved, true),
        (DurableStatus::PrekeyAvailable, false),
    ] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let mut child = spawn_child(
            &path,
            "durable::prekeys::tests::inventory_generation_crash_child",
            phase,
            effect,
        );
        wait_for(&path, "ready", &mut child);
        assert!(
            !path.join("returned-leaf").exists(),
            "public key escaped commit barrier"
        );
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let mut store = reopen(&path, f.local_device());
        let (policy, device, _) = f.responder.inventory_inputs();
        let request = PrekeyId::from_trusted_state([71; 32]).expect("request");
        assert_eq!(
            store.prekey_status(policy, device, request).expect("phase"),
            if phase == DurableStatus::PrekeyReserved {
                PrekeyStatus::Reserved
            } else {
                PrekeyStatus::Available
            }
        );
        let leaf = store
            .generate_prekey(
                policy,
                device,
                request,
                LeafKind::OneTimePq,
                interval(),
                150,
            )
            .expect("resume same command");
        if effect {
            assert_eq!(
                leaf.public_key(),
                fs::read(path.join("computed-public")).expect("prior computation")
            );
        }
        assert_eq!(
            leaf.public_key(),
            store
                .prekey_leaf(policy, device, request, 150)
                .expect("committed leaf")
                .public_key()
        );
    }
}

#[test]
fn retirement_unknown_commit_reconciles_without_reactivating_key() {
    for after_sync in [false, true] {
        for cut in 1..=4 {
            let mut f = inventory(PrekeyQuality::OneTimeBoth);
            f.store.close();
            let (mut store, fault, _, _) = fault_store(&f.path, f.peer.local_device(), after_sync);
            let (policy, device, _) = f.peer.responder.inventory_inputs();
            let request = *f.ids.first().expect("ID");
            fault.store(cut, Ordering::SeqCst);
            assert!(matches!(
                store.retire_prekey(policy, device, request),
                Err(DurableError::CommitUncertain(_))
            ));
            assert!(matches!(
                store.prekey_status(policy, device, request),
                Err(DurableError::Closed)
            ));
            let mut store = reopen(&f.path, device);
            assert!(matches!(
                store
                    .prekey_status(policy, device, request)
                    .expect("exact status"),
                PrekeyStatus::Available | PrekeyStatus::Retired
            ));
            assert_eq!(
                store
                    .retire_prekey(policy, device, request)
                    .expect("reconcile retirement"),
                PrekeyStatus::Retired
            );
            assert!(matches!(
                store.generate_prekey(
                    policy,
                    device,
                    request,
                    LeafKind::SignedClassical,
                    interval(),
                    150
                ),
                Err(DurableError::KeyRetired)
            ));
        }
    }
}

#[test]
fn invalid_or_substituted_inventory_tokens_fail_closed_without_consumption() {
    for substitute in [false, true] {
        let mut f = inventory(PrekeyQuality::OneTimeBoth);
        let initial =
            InitiatorOperation::start(Arc::clone(&f.peer.initiator), &f.peer.signer_i, 150)
                .expect("initial")
                .initial_message(150)
                .expect("wire")
                .to_vec();
        let mut image = f.store.image().expect("image");
        let target = id(*f.ids.get(3).expect("PQ request"));
        let mut entry = Entry::decode(image.records.get(&target).expect("target")).expect("entry");
        if substitute {
            let other = Entry::decode(
                image
                    .records
                    .get(&id(*f.ids.get(1).expect("classical ID")))
                    .expect("other record"),
            )
            .expect("other entry");
            entry.data = other.data;
        } else {
            *entry.data.last_mut().expect("AEAD tag") ^= 1;
        }
        image.records.get_mut(&target).expect("target").payload = entry.encode();
        f.store
            .persist(&mut image)
            .expect("authenticated writer defect");
        assert!(matches!(
            f.store.respond_from_inventory(
                Arc::clone(&f.peer.responder),
                &initial,
                &f.peer.signer_r,
                150
            ),
            Err(DurableError::InvalidCheckpoint(Error::Runtime(
                q_periapt_sdk::Error::InvalidPrivateKey
            )))
        ));
        assert!(f.store.active.is_none());
        let mut store = reopen(&f.path, f.peer.local_device());
        assert_eq!(
            store
                .status(&f.peer.responder, &initial)
                .expect("retained work"),
            DurableStatus::Executing
        );
        let (policy, device, _) = f.peer.responder.inventory_inputs();
        assert_eq!(
            store
                .prekey_status(policy, device, *f.ids.get(3).expect("ID"))
                .expect("not consumed"),
            PrekeyStatus::Available
        );
    }
}

#[test]
fn authenticated_image_rejects_consumption_disagreement_with_outbox() {
    let mut f = inventory(PrekeyQuality::OneTimeBoth);
    let mut before = f.store.image().expect("before");
    let initial = InitiatorOperation::start(Arc::clone(&f.peer.initiator), &f.peer.signer_i, 150)
        .expect("initial")
        .initial_message(150)
        .expect("wire")
        .to_vec();
    f.store
        .respond_from_inventory(
            Arc::clone(&f.peer.responder),
            &initial,
            &f.peer.signer_r,
            150,
        )
        .expect("committed outbox");
    let mut image = f.store.image().expect("committed");
    let key = id(*f.ids.get(3).expect("PQ ID"));
    image
        .records
        .insert(key, before.records.remove(&key).expect("unconsumed key"));
    let active = f.store.active.as_ref().expect("store");
    let bytes = seal(&active.key, &image).expect("authenticated inconsistent image");
    assert!(matches!(
        unseal(&active.key, active.owner, &bytes),
        Err(DurableError::Corrupt)
    ));
}

thread_local! {
    static CLOSE_AFTER_PUBLICATION: std::cell::RefCell<Option<Arc<VerifiedSessionPolicy>>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn after_publication() {
    CLOSE_AFTER_PUBLICATION.with(|pending| {
        if let Some(policy) = pending.borrow_mut().take() {
            policy.close();
        }
    });
}
#[test]
fn policy_closed_after_publication_withholds_leaf_and_preserves_original_available_entry() {
    let f = fixture(PrekeyQuality::OneTimeBoth);
    let folder = directory();
    let path = folder.path().canonicalize().expect("path");
    let mut store = new_store(&path, f.local_device());
    let policy = f.policy_owner(crate::BootstrapRole::Responder);
    let request = PrekeyId::from_trusted_state([247; 32]).expect("request");
    CLOSE_AFTER_PUBLICATION.with(|pending| *pending.borrow_mut() = Some(Arc::clone(&policy)));
    assert!(
        store
            .generate_prekey(
                &policy,
                f.local_device(),
                request,
                LeafKind::OneTimePq,
                interval(),
                150
            )
            .is_err(),
        "a policy closed during persistence must withhold the committed leaf"
    );
    assert!(policy.check_mode(PrekeyQuality::OneTimeBoth, 150).is_err());
    assert_eq!(
        store
            .prekey_status(&policy, f.local_device(), request)
            .expect("committed fact"),
        PrekeyStatus::Available
    );
    assert!(store
        .prekey_leaf(&policy, f.local_device(), request, 150)
        .is_err());
    assert_eq!(
        store
            .retire_prekey(&policy, f.local_device(), request)
            .expect("cleanup"),
        PrekeyStatus::Retired
    );
}

#[test]
fn current_successor_replays_original_reserved_material_across_process_loss() {
    for (phase, effect) in [
        (DurableStatus::PrekeyReserved, false),
        (DurableStatus::PrekeyReserved, true),
        (DurableStatus::PrekeyAvailable, false),
    ] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let mut child = spawn_child(
            &path,
            "durable::prekeys::tests::inventory_generation_crash_child",
            phase,
            effect,
        );
        wait_for(&path, "ready", &mut child);
        assert!(!path.join("returned-leaf").exists());
        child.0.kill().expect("kill owned generator");
        assert!(!child.0.wait().expect("reap").success());
        let f = fixture(PrekeyQuality::OneTimeBoth);
        let (policy, original, _) = f.responder.inventory_inputs();
        let mut store = reopen(&path, original);
        let request = PrekeyId::from_trusted_state([71; 32]).expect("original request");
        let before = store.image().expect("original image");
        let entry_before = store
            .inventory_entry(&before, policy, request)
            .expect("original sealed material");
        let root =
            crate::RootSigningKey::deterministic([94; 32], [95; 32]).expect("original authority");
        let certificate = root
            .issue_device(original.description.clone(), original.key.clone())
            .expect("original body");
        let grant = crate::durable::rosters::tests::renewal::grant(
            &root,
            &certificate,
            original,
            300,
            2,
            [238; 32],
            policy.checkpoint().digest(),
        );
        let authority = crate::RetainedInstallationAuthority::active_installation(original, policy);
        store
            .commit_local_credential_renewal(&authority, &grant, grant.operation(), policy, 150)
            .expect("root-authorized successor");
        let after = store.image().expect("renewed image");
        let entry_after = store
            .inventory_entry(&after, policy, request)
            .expect("same original material");
        assert_eq!(before.id, after.id);
        assert_eq!(before.owner, after.owner);
        assert_eq!(entry_before.intent(), entry_after.intent());
        assert_eq!(entry_before.scope(&before), entry_after.scope(&after));
        assert_eq!(
            entry_before.data, entry_after.data,
            "renewal cannot replace retained randomness"
        );
        let current = grant.successor_device();
        assert_eq!(
            store
                .prekey_status(policy, current, request)
                .expect("original phase"),
            if phase == DurableStatus::PrekeyReserved {
                PrekeyStatus::Reserved
            } else {
                PrekeyStatus::Available
            }
        );
        let leaf = store
            .generate_prekey(
                policy,
                current,
                request,
                LeafKind::OneTimePq,
                interval(),
                150,
            )
            .expect("reconcile same original operation");
        if effect {
            assert_eq!(
                leaf.public_key(),
                fs::read(path.join("computed-public")).expect("pre-crash actual key")
            );
        }
        if phase == DurableStatus::PrekeyAvailable {
            assert_eq!(leaf.public_key(), entry_before.public);
        }
        assert_eq!(
            store
                .generate_prekey(
                    policy,
                    current,
                    request,
                    LeafKind::OneTimePq,
                    interval(),
                    150
                )
                .expect("exact retry")
                .public_key(),
            leaf.public_key()
        );
        assert_eq!(
            store
                .retire_prekey(policy, current, request)
                .expect("retire"),
            PrekeyStatus::Retired
        );
        assert!(matches!(
            store.generate_prekey(
                policy,
                current,
                request,
                LeafKind::OneTimePq,
                interval(),
                150
            ),
            Err(DurableError::KeyRetired)
        ));
    }
}
