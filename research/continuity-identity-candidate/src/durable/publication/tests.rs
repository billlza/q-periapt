// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::prekeys::tests::{inventory, Inventory};
use crate::durable::tests::reopen;
use crate::tests::interval;
use std::time::Duration;

fn plan() -> PrekeyPublicationPlan {
    PrekeyPublicationPlan::new(
        [99; 32],
        interval(),
        &[
            PrekeyPublicationKey::generate(LeafKind::SignedClassical, interval()),
            PrekeyPublicationKey::generate(LeafKind::OneTimeClassical, interval()),
            PrekeyPublicationKey::generate(LeafKind::LastResortPq, interval()),
            PrekeyPublicationKey::generate(LeafKind::OneTimePq, interval()),
        ],
    )
    .expect("complete plan")
}
fn prepare(
    f: &mut Inventory,
    id: PrekeyPublicationId,
    plan: &PrekeyPublicationPlan,
) -> PreparedPrekeyPublication {
    let (policy, device, _) = f.peer.responder.inventory_inputs().expect("owner");
    f.store
        .prepare_prekey_publication(
            PrekeyPublicationRequest {
                id,
                plan,
                policy,
                device,
                signer: &f.peer.signer_r,
            },
            PrekeyPublicationRun {
                cancel: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(30),
            },
            || Ok(150),
        )
        .expect("prepared artifact")
}

#[test]
fn publication_exact_artifact_survives_reopen_and_retirement_fences_the_epoch() {
    let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
    let image = f.store.image().expect("legacy image");
    let key = &f.store.active.as_ref().expect("open").key;
    let legacy = seal(key, &image).expect("legacy encoding");
    assert_eq!(legacy.get(..8), Some(b"QPVLT021".as_slice()));
    assert!(unseal(key, image.owner, &legacy).is_ok());
    let plan = plan();
    let id = f.store.next_prekey_publication_id().expect("next");
    assert_eq!(
        f.store.prekey_publication_status(id).expect("absent"),
        PrekeyPublicationStatus::Absent
    );
    let first = prepare(&mut f, id, &plan);
    let bytes = first.manifest().as_bytes().to_vec();
    let proofs: Vec<_> = (0..first.manifest().leaf_count())
        .map(|i| {
            first
                .manifest()
                .proof(i)
                .expect("proof")
                .encode()
                .expect("bytes")
        })
        .collect();
    let artifact = first.artifact_digest();
    let (_, device, _) = f.peer.responder.inventory_inputs().expect("owner");
    let verified = device
        .verify_manifest(&bytes, 150)
        .expect("signed artifact");
    assert_eq!(
        f.store.prekey_publication_status(id).expect("prepared"),
        PrekeyPublicationStatus::Prepared {
            intent: first.intent_digest(),
            manifest: verified.digest(),
            artifact
        }
    );
    let requests = first.inventory_requests().to_vec();
    let image = f.store.image().expect("new image");
    let key = &f.store.active.as_ref().expect("open").key;
    assert_eq!(
        seal(key, &image).expect("new encoding").get(..8),
        Some(b"QPVLT022".as_slice())
    );
    f.store.close();
    f.store = reopen(&f.path, device);
    let second = prepare(&mut f, id, &plan);
    assert_eq!(second.manifest().as_bytes(), bytes);
    assert_eq!(second.artifact_digest(), artifact);
    for (i, proof) in proofs.iter().enumerate() {
        assert_eq!(
            second
                .manifest()
                .proof(i)
                .expect("same proof")
                .encode()
                .expect("same bytes"),
            *proof
        );
    }
    assert!(matches!(
        f.store.retire_prekey_publication(id, [0; 32]),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        f.store
            .retire_prekey_publication(id, artifact)
            .expect("retired"),
        PrekeyPublicationStatus::Retired
    );
    let (policy, device, _) = f.peer.responder.inventory_inputs().expect("owner");
    // Publication cache retirement never destroys inventory or its claim history.
    for request in requests {
        assert_eq!(
            f.store
                .prekey_status(policy, device, request)
                .expect("inventory retained"),
            PrekeyStatus::Available
        );
    }
    f.store.close();
    f.store = reopen(&f.path, device);
    assert_eq!(
        f.store
            .prekey_publication_status(id)
            .expect("retired reopen"),
        PrekeyPublicationStatus::Retired
    );
    assert_ne!(f.store.next_prekey_publication_id().expect("advanced"), id);
}

#[test]
fn publication_cancellation_keeps_original_intent_and_can_abandon_fresh_reservations() {
    let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
    let plan = plan();
    let id = f.store.next_prekey_publication_id().expect("next");
    let cancel = Cancellation::default();
    let (policy, device, _) = f.peer.responder.inventory_inputs().expect("owner");
    let mut calls = 0;
    let result = f.store.prepare_prekey_publication(
        PrekeyPublicationRequest {
            id,
            plan: &plan,
            policy,
            device,
            signer: &f.peer.signer_r,
        },
        PrekeyPublicationRun {
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(30),
        },
        || {
            calls += 1;
            if calls == 2 {
                cancel.cancel();
            }
            Ok(150)
        },
    );
    assert!(matches!(result, Err(PrekeyPublicationError::Cancelled)));
    let status = f
        .store
        .prekey_publication_status(id)
        .expect("reserved original");
    let intent = match status {
        PrekeyPublicationStatus::Reserved { intent } => Some(intent),
        _ => None,
    }
    .expect("reservation missing");
    let requests = plan.requests(id).expect("original member IDs");
    f.store.close();
    f.store = reopen(&f.path, device);
    assert_eq!(
        f.store
            .abandon_prekey_publication(id, intent, policy)
            .expect("abandoned original"),
        PrekeyPublicationStatus::Retired
    );
    for request in requests {
        assert_eq!(
            f.store
                .prekey_status(policy, device, request)
                .expect("fresh key retired"),
            PrekeyStatus::Retired
        );
    }
}

#[test]
fn publication_same_id_cannot_change_intent_and_future_epoch_cannot_exhaust_counter() {
    let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
    let original = plan();
    let id = f.store.next_prekey_publication_id().expect("next");
    let _artifact = prepare(&mut f, id, &original);
    let changed = PrekeyPublicationPlan::new([100; 32], interval(), original.keys())
        .expect("other directory intent");
    let (policy, device, _) = f.peer.responder.inventory_inputs().expect("owner");
    let try_prepare = |store: &mut DeviceJournal, id, plan| {
        store.prepare_prekey_publication(
            PrekeyPublicationRequest {
                id,
                plan,
                policy,
                device,
                signer: &f.peer.signer_r,
            },
            PrekeyPublicationRun {
                cancel: &Cancellation::default(),
                deadline: Instant::now() + Duration::from_secs(30),
            },
            || Ok(150),
        )
    };
    assert!(matches!(
        try_prepare(&mut f.store, id, &changed),
        Err(PrekeyPublicationError::Durable(DurableError::Conflict))
    ));
    let future = PrekeyPublicationId::at(&f.store.image().expect("image").id, u64::MAX - 1)
        .expect("well-shaped future ID");
    assert!(matches!(
        try_prepare(&mut f.store, future, &original),
        Err(PrekeyPublicationError::Durable(DurableError::Conflict))
    ));
    assert_eq!(
        f.store
            .next_prekey_publication_id()
            .expect("unchanged next")
            .check(&f.store.image().expect("image").id)
            .expect("ordinal"),
        2
    );
}

fn invoke(
    store: &mut DeviceJournal,
    peer: &crate::bootstrap::tests::Fixture,
    id: PrekeyPublicationId,
    plan: &PrekeyPublicationPlan,
    cancel: &Cancellation,
    clock: impl FnMut() -> io::Result<u64>,
) -> Result<PreparedPrekeyPublication, PrekeyPublicationError> {
    let (policy, device, _) = peer.responder.inventory_inputs()?;
    store.prepare_prekey_publication(
        PrekeyPublicationRequest {
            id,
            plan,
            policy,
            device,
            signer: &peer.signer_r,
        },
        PrekeyPublicationRun {
            cancel,
            deadline: Instant::now() + Duration::from_secs(30),
        },
        clock,
    )
}

#[test]
fn every_publication_clock_boundary_cancellation_resumes_original_members_and_artifact() {
    let mut baseline = inventory(crate::PrekeyQuality::OneTimeBoth);
    let plan = plan();
    let id = baseline.store.next_prekey_publication_id().expect("next");
    let mut calls = 0;
    invoke(
        &mut baseline.store,
        &baseline.peer,
        id,
        &plan,
        &Cancellation::default(),
        || {
            calls += 1;
            Ok(150)
        },
    )
    .expect("baseline");
    assert!(calls >= 10);
    for cut in 1..=calls {
        let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
        let id = f.store.next_prekey_publication_id().expect("next");
        let cancel = Cancellation::default();
        let mut count = 0;
        let result = invoke(&mut f.store, &f.peer, id, &plan, &cancel, || {
            count += 1;
            if count == cut {
                cancel.cancel();
            }
            Ok(150)
        });
        assert!(
            matches!(result, Err(PrekeyPublicationError::Cancelled)),
            "cut {cut}"
        );
        let image = f.store.image().expect("image after cancellation");
        let prior = Registry::load(&image)
            .expect("registry")
            .entries
            .remove(&id.check(&image.id).expect("ordinal"));
        let retained = prior.as_ref().filter(|entry| entry.ready).map(|entry| {
            entry
                .manifest()
                .expect("retained manifest")
                .as_bytes()
                .to_vec()
        });
        let mut keys = Vec::new();
        let (policy, device, _) = f.peer.responder.inventory_inputs().expect("owner");
        for request in plan.requests(id).expect("members") {
            if f.store
                .prekey_status(policy, device, request)
                .expect("status")
                == PrekeyStatus::Available
            {
                keys.push((
                    request,
                    f.store
                        .prekey_leaf(policy, device, request, 150)
                        .expect("already committed key")
                        .public_key()
                        .to_vec(),
                ));
            }
        }
        f.store.close();
        f.store = reopen(&f.path, device);
        let result = invoke(
            &mut f.store,
            &f.peer,
            id,
            &plan,
            &Cancellation::default(),
            || Ok(150),
        )
        .expect("same operation resumes");
        if let Some(bytes) = retained {
            assert_eq!(result.manifest().as_bytes(), bytes, "cut {cut}");
        }
        for (request, bytes) in keys {
            assert_eq!(
                f.store
                    .prekey_leaf(policy, device, request, 150)
                    .expect("same member")
                    .public_key(),
                bytes,
                "cut {cut}"
            );
        }
        assert_eq!(
            f.store
                .next_prekey_publication_id()
                .expect("next")
                .check(&image.id)
                .expect("ordinal"),
            2
        );
    }
    eprintln!("publication cancellation boundaries: {calls}");
}

#[test]
fn publication_expiry_after_commit_and_closed_policy_release_no_artifact() {
    let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
    let plan = plan();
    let id = f.store.next_prekey_publication_id().expect("next");
    let retained = prepare(&mut f, id, &plan);
    let mut calls = 0;
    let result = invoke(
        &mut f.store,
        &f.peer,
        id,
        &plan,
        &Cancellation::default(),
        || {
            calls += 1;
            Ok(if calls == 1 { 150 } else { 500 })
        },
    );
    assert!(matches!(
        result,
        Err(PrekeyPublicationError::Durable(DurableError::Protocol(
            Error::Validity
        )))
    ));
    assert!(
        matches!(f.store.prekey_publication_status(id).expect("historical status"), PrekeyPublicationStatus::Prepared { artifact, .. } if artifact == retained.artifact_digest())
    );
    let (policy, _, _) = f.peer.responder.inventory_inputs().expect("owner");
    policy.close();
    assert!(matches!(
        invoke(
            &mut f.store,
            &f.peer,
            id,
            &plan,
            &Cancellation::default(),
            || Ok(150)
        ),
        Err(PrekeyPublicationError::Durable(DurableError::Protocol(
            Error::Closed
        )))
    ));
    assert_eq!(
        f.store
            .retire_prekey_publication(id, retained.artifact_digest())
            .expect("historical retirement after closure"),
        PrekeyPublicationStatus::Retired
    );
}

#[test]
fn publication_requires_a_complete_allowed_mode_and_available_reused_members() {
    let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
    let id = f.store.next_prekey_publication_id().expect("next");
    let insufficient = PrekeyPublicationPlan::new(
        [99; 32],
        interval(),
        &[
            PrekeyPublicationKey::generate(LeafKind::SignedClassical, interval()),
            PrekeyPublicationKey::generate(LeafKind::LastResortPq, interval()),
        ],
    )
    .expect("complete reusable shape");
    assert!(matches!(
        invoke(
            &mut f.store,
            &f.peer,
            id,
            &insufficient,
            &Cancellation::default(),
            || Ok(150)
        ),
        Err(PrekeyPublicationError::Durable(DurableError::Protocol(
            Error::PolicyDenied
        )))
    ));
    let original = plan();
    let mut keys = original.keys().to_vec();
    *keys.first_mut().expect("member") = PrekeyPublicationKey::reuse(
        PrekeyId::from_trusted_state([98; 32]).expect("absent ID"),
        LeafKind::SignedClassical,
        interval(),
    );
    let absent = PrekeyPublicationPlan::new([99; 32], interval(), &keys).expect("shape");
    let before = f.store.image().expect("before").revision;
    assert!(matches!(
        invoke(
            &mut f.store,
            &f.peer,
            id,
            &absent,
            &Cancellation::default(),
            || Ok(150)
        ),
        Err(PrekeyPublicationError::Durable(DurableError::Absent))
    ));
    assert_eq!(f.store.image().expect("unchanged").revision, before);
    let reused = *f.ids.first().expect("existing key");
    *keys.first_mut().expect("member") =
        PrekeyPublicationKey::reuse(reused, LeafKind::SignedClassical, interval());
    let mixed = PrekeyPublicationPlan::new([99; 32], interval(), &keys).expect("shape");
    let cancel = Cancellation::default();
    let mut count = 0;
    assert!(matches!(
        invoke(&mut f.store, &f.peer, id, &mixed, &cancel, || {
            count += 1;
            if count == 3 {
                cancel.cancel();
            }
            Ok(150)
        }),
        Err(PrekeyPublicationError::Cancelled)
    ));
    let image = f.store.image().expect("image");
    let intent = Registry::load(&image)
        .expect("registry")
        .entries
        .get(&1)
        .expect("original")
        .intent()
        .expect("intent");
    let (policy, device, _) = f.peer.responder.inventory_inputs().expect("owner");
    f.store
        .abandon_prekey_publication(id, intent, policy)
        .expect("abandon");
    assert_eq!(
        f.store
            .prekey_status(policy, device, reused)
            .expect("reused key untouched"),
        PrekeyStatus::Available
    );
    for request in mixed.requests(id).expect("members").into_iter().skip(1) {
        assert_eq!(
            f.store
                .prekey_status(policy, device, request)
                .expect("fresh key retired"),
            PrekeyStatus::Retired
        );
    }
}

#[test]
fn publication_reopen_rejects_authenticated_inventory_or_context_substitution() {
    let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
    let id = f.store.next_prekey_publication_id().expect("next");
    prepare(&mut f, id, &plan());
    for change in 0..3 {
        let mut image = f.store.image().expect("original");
        let mut registry = Registry::load(&image).expect("registry");
        let entry = registry.entries.get_mut(&1).expect("entry");
        match change {
            0 => *entry.sdk.first_mut().expect("binding") ^= 1,
            1 => {
                entry.plan.keys.first_mut().expect("member").reuse =
                    Some(*f.ids.first().expect("different key"))
            }
            _ => {
                image.records.retain(|_, r| r.kind != RecordKind::Prekey);
            }
        }
        registry
            .store(&mut image)
            .expect("encode deliberately inconsistent fixture");
        let key = &f.store.active.as_ref().expect("active").key;
        let bytes = seal(key, &image).expect("authenticate fixture");
        assert!(
            matches!(unseal(key, image.owner, &bytes), Err(DurableError::Corrupt)),
            "change {change}"
        );
    }
}

#[test]
fn every_publication_sync_failure_reconciles_original_reservation_and_signed_target() {
    use crate::durable::tests::{assert_sync_failure, fault_store};
    use std::sync::atomic::Ordering;
    let mut baseline = inventory(crate::PrekeyQuality::OneTimeBoth);
    baseline.store.close();
    let (store, _, count, _) = fault_store(&baseline.path, baseline.peer.local_device(), false);
    baseline.store = store;
    let plan = plan();
    let id = baseline.store.next_prekey_publication_id().expect("next");
    invoke(
        &mut baseline.store,
        &baseline.peer,
        id,
        &plan,
        &Cancellation::default(),
        || Ok(150),
    )
    .expect("baseline");
    let syncs = count.load(Ordering::SeqCst);
    assert!((12..=64).contains(&syncs), "{syncs}");
    for after in [false, true] {
        for cut in 1..=syncs {
            let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
            let id = f.store.next_prekey_publication_id().expect("next");
            f.store.close();
            let (store, remaining, _, _) = fault_store(&f.path, f.peer.local_device(), after);
            f.store = store;
            remaining.store(cut, Ordering::SeqCst);
            let error = invoke(
                &mut f.store,
                &f.peer,
                id,
                &plan,
                &Cancellation::default(),
                || Ok(150),
            );
            let durable = match error {
                Err(PrekeyPublicationError::Durable(error)) => Some(error),
                _ => None,
            }
            .expect("typed durable failure");
            assert_sync_failure::<()>(Err(durable), after);
            f.store.close();
            f.store = reopen(&f.path, f.peer.local_device());
            let image = f.store.image().expect("recovered image");
            let registry = Registry::load(&image).expect("recovered registry");
            let retained = registry
                .entries
                .get(&1)
                .filter(|entry| entry.ready)
                .map(|entry| entry.manifest().expect("committed").as_bytes().to_vec());
            let result = invoke(
                &mut f.store,
                &f.peer,
                id,
                &plan,
                &Cancellation::default(),
                || Ok(150),
            )
            .expect("recover exact original operation");
            if let Some(bytes) = retained {
                assert_eq!(
                    result.manifest().as_bytes(),
                    bytes,
                    "cut {cut} after {after}"
                );
            }
            assert_eq!(
                result.inventory_requests(),
                plan.requests(id).expect("same members")
            );
            assert_eq!(
                f.store
                    .next_prekey_publication_id()
                    .expect("next")
                    .check(&image.id)
                    .expect("ordinal"),
                2
            );
        }
    }
    eprintln!(
        "publication sync matrix: {syncs} boundaries, {} exact typed failures",
        syncs * 2
    );
}

#[test]
fn publication_capacity_is_atomic_reclaimable_and_does_not_take_inventory_operation_slots() {
    let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
    let original = plan();
    let keys: Vec<_> = original
        .keys()
        .iter()
        .zip(f.ids)
        .map(|(key, id)| PrekeyPublicationKey::reuse(id, key.kind(), key.validity()))
        .collect();
    let plan = PrekeyPublicationPlan::new([99; 32], interval(), &keys).expect("existing members");
    let before = f.store.image().expect("before");
    let operations = before.operation_count();
    let mut artifacts = Vec::new();
    for _ in 0..MAX_PREKEY_PUBLICATIONS {
        let id = f.store.next_prekey_publication_id().expect("next");
        artifacts.push(prepare(&mut f, id, &plan));
    }
    let image = f.store.image().expect("full publication budget");
    assert_eq!(image.operation_count(), operations);
    assert_eq!(
        image.record_count(RecordKind::Prekey),
        before.record_count(RecordKind::Prekey)
    );
    let next = f.store.next_prekey_publication_id().expect("next");
    assert!(matches!(
        invoke(
            &mut f.store,
            &f.peer,
            next,
            &plan,
            &Cancellation::default(),
            || Ok(150)
        ),
        Err(PrekeyPublicationError::Durable(DurableError::Capacity))
    ));
    assert_eq!(
        f.store.image().expect("capacity refusal").revision,
        image.revision
    );
    let (policy, device, _) = f.peer.responder.inventory_inputs().expect("owner");
    f.store
        .generate_prekey(
            policy,
            device,
            PrekeyId::from_trusted_state([90; 32]).expect("ordinary request"),
            LeafKind::OneTimePq,
            interval(),
            150,
        )
        .expect("ordinary inventory maintenance still fits");
    let first = artifacts.first().expect("original artifact");
    f.store
        .retire_prekey_publication(first.id(), first.artifact_digest())
        .expect("reclaim public history");
    prepare(&mut f, next, &plan);
    assert_eq!(
        f.store
            .prekey_publication_status(first.id())
            .expect("old floor"),
        PrekeyPublicationStatus::Retired
    );
}

#[test]
fn publication_large_plan_refuses_before_any_reservation_and_smaller_plan_remains_usable() {
    let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
    let id = f.store.next_prekey_publication_id().expect("next");
    let mut keys = plan().keys().to_vec();
    keys.extend((0..600).map(|_| PrekeyPublicationKey::generate(LeafKind::OneTimePq, interval())));
    let large =
        PrekeyPublicationPlan::new([99; 32], interval(), &keys).expect("bounded plan grammar");
    let before = f.store.image().expect("before");
    assert!(matches!(
        invoke(
            &mut f.store,
            &f.peer,
            id,
            &large,
            &Cancellation::default(),
            || Ok(150)
        ),
        Err(PrekeyPublicationError::Durable(DurableError::Capacity))
    ));
    let after = f.store.image().expect("after");
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.records.len(), after.records.len());
    assert_eq!(
        f.store.prekey_publication_status(id).expect("unallocated"),
        PrekeyPublicationStatus::Absent
    );
    prepare(&mut f, id, &plan());
}

#[test]
fn publication_process_child() {
    use std::{fs, io::Write};
    let Some(path) = std::env::var_os("QPERIAPT_PUBLICATION_CHILD_DIR") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let cut: usize = std::env::var("QPERIAPT_PUBLICATION_CHILD_CUT")
        .expect("cut")
        .parse()
        .expect("ordinal");
    let peer = crate::bootstrap::tests::fixture(crate::PrekeyQuality::OneTimeBoth);
    let mut store = reopen(&path, peer.local_device());
    let id = PrekeyPublicationId::from_trusted_state(
        fs::read(path.join("publication-id"))
            .expect("saved ID")
            .try_into()
            .expect("width"),
    )
    .expect("ID");
    let mut calls = 0;
    invoke(
        &mut store,
        &peer,
        id,
        &plan(),
        &Cancellation::default(),
        || {
            calls += 1;
            if calls == cut {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path.join("publication-cut"))?;
                file.write_all(b"original invocation suspended\n")?;
                file.sync_all()?;
                loop {
                    std::thread::park();
                }
            }
            Ok(150)
        },
    )
    .expect("child only completes if requested cut was absent");
    assert!(calls < cut, "requested cut never suspended");
}

#[test]
fn publication_process_cuts_reopen_original_epoch_members_and_committed_artifact() {
    use crate::durable::tests::ChildGuard;
    use std::{
        fs,
        process::{Command, Stdio},
    };
    let mut baseline = inventory(crate::PrekeyQuality::OneTimeBoth);
    let id = baseline.store.next_prekey_publication_id().expect("next");
    let mut calls = 0;
    invoke(
        &mut baseline.store,
        &baseline.peer,
        id,
        &plan(),
        &Cancellation::default(),
        || {
            calls += 1;
            Ok(150)
        },
    )
    .expect("baseline");
    for cut in 1..=calls {
        let mut f = inventory(crate::PrekeyQuality::OneTimeBoth);
        let id = f.store.next_prekey_publication_id().expect("next");
        fs::write(f.path.join("publication-id"), id.as_bytes()).expect("retained public identity");
        f.store.close();
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "durable::publication::tests::publication_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_PUBLICATION_CHILD_DIR", &f.path)
                .env("QPERIAPT_PUBLICATION_CHILD_CUT", cut.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("new process"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !f.path.join("publication-cut").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none(),
                "child exited before cut {cut}"
            );
            assert!(Instant::now() < deadline, "child did not reach cut {cut}");
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().expect("process loss");
        child.0.wait().expect("reap");
        f.store = reopen(&f.path, f.peer.local_device());
        let image = f.store.image().expect("recovered image");
        let registry = Registry::load(&image).expect("registry");
        let retained = registry.entries.get(&1).filter(|e| e.ready).map(|e| {
            e.manifest()
                .expect("committed envelope")
                .as_bytes()
                .to_vec()
        });
        let artifact = prepare(&mut f, id, &plan());
        if let Some(bytes) = retained {
            assert_eq!(artifact.manifest().as_bytes(), bytes, "cut {cut}");
        }
        assert_eq!(
            artifact.inventory_requests(),
            plan().requests(id).expect("same original members")
        );
    }
    eprintln!("publication process cuts: {calls}");
}
