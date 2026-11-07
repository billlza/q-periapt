use super::*;
use crate::filesystem::{
    open_private_file, publish_private_bytes, publish_private_directory,
    reclaim_private_publication, test_directory,
};
use std::{
    fs,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const VALUE: &[u8] = b"original unpublished private fixture";

fn read_intent(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
fn abandoned(parent: &Path, directory: bool) -> PathBuf {
    let attempt = if directory {
        ManagedAttempt::directory(&parent.join("formal"))
    } else {
        ManagedAttempt::file(&parent.join("formal"))
    }
    .expect("managed attempt");
    if directory {
        publish_private_bytes(&attempt.path().join("first"), VALUE).expect("first child");
        publish_private_bytes(&attempt.path().join("second"), VALUE).expect("second child");
    } else {
        let mut file = attempt.data_file().expect("payload");
        file.write_all(VALUE).expect("payload bytes");
        file.sync_all().expect("payload sync");
    }
    attempt.path().parent().expect("control").to_owned()
}
fn reclaim(path: &Path) -> PublicationCleanupOutcome {
    reclaim_private_publication(path, PublicationCleanupLimits::default())
        .expect("reclaimed original")
}

#[test]
fn zero_byte_disposal_keeps_normal_store_admission_strict() {
    if !isolated_case("filesystem::maintenance::attempt::tests::zero_byte_disposal_keeps_normal_store_admission_strict", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:zero_byte_disposal_keeps_normal_store_admission_strict") { return; }

    let temp = test_directory::directory().expect("directory");
    let parent = temp.path();
    let attempt = ManagedAttempt::file(&parent.join("formal")).expect("attempt");
    let control = attempt.path().parent().expect("control").to_owned();
    assert!(open_private_file(attempt.path(), false).is_err());
    assert!(matches!(
        reclaim_private_publication(&control, PublicationCleanupLimits::default()),
        Err(Error::Busy)
    ));
    drop(attempt);
    let expected = PublicationCleanupOutcome::Reclaimed {
        entries: 1,
        bytes: 0,
    };
    assert_eq!(reclaim(&control), expected);
    assert_eq!(reclaim(&control), expected);
    assert!(!parent.join("formal").exists());
    assert!(!control.join(PAYLOAD).exists());
    assert!(control.join(RECORD).is_file());
    assert!(control.join(LEASE).is_file());

    eprintln!("MANAGED_CASE_COMPLETE:zero_byte_disposal_keeps_normal_store_admission_strict");
}

#[test]
fn normal_file_and_tree_publication_retire_only_their_control() {
    if !isolated_case("filesystem::maintenance::attempt::tests::normal_file_and_tree_publication_retire_only_their_control", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:normal_file_and_tree_publication_retire_only_their_control") { return; }

    let temp = test_directory::directory().expect("directory");
    let parent = temp.path();
    publish_private_bytes(&parent.join("key"), VALUE).expect("key publication");
    publish_private_directory::<(), PrivatePublicationError>(&parent.join("tree"), |path| {
        publish_private_bytes(&path.join("key"), VALUE)
    })
    .expect("tree publication");
    assert_eq!(fs::read(parent.join("key")).expect("key"), VALUE);
    assert_eq!(fs::read(parent.join("tree/key")).expect("child"), VALUE);
    assert_eq!(fs::read_dir(parent).expect("root inventory").count(), 2);
    assert_eq!(
        fs::read_dir(parent.join("tree"))
            .expect("tree inventory")
            .count(),
        1
    );

    eprintln!("MANAGED_CASE_COMPLETE:normal_file_and_tree_publication_retire_only_their_control");
}

#[test]
fn published_payload_absence_is_not_cleanup_or_publication_authority() {
    if !isolated_case("filesystem::maintenance::attempt::tests::published_payload_absence_is_not_cleanup_or_publication_authority", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:published_payload_absence_is_not_cleanup_or_publication_authority") { return; }

    let temp = test_directory::directory().expect("directory");
    let parent = temp.path();
    let attempt = ManagedAttempt::file(&parent.join("formal")).expect("attempt");
    let control = attempt.path().parent().expect("control").to_owned();
    let mut file = attempt.data_file().expect("payload");
    file.write_all(VALUE).expect("write");
    file.sync_all().expect("sync");
    drop(file);
    attempt.rename().expect("rename");
    attempt.sync_publication().expect("barriers");
    drop(attempt);
    assert_eq!(reclaim(&control), PublicationCleanupOutcome::NoPayload);
    assert!(!control.join(INTENT).exists());
    assert!(!control.join(DONE).exists());
    assert_eq!(
        fs::read(parent.join("formal")).expect("formal retained"),
        VALUE
    );

    eprintln!(
        "MANAGED_CASE_COMPLETE:published_payload_absence_is_not_cleanup_or_publication_authority"
    );
}

#[test]
fn cleanup_unknown_outcomes_replay_the_original_durable_result() {
    if !isolated_case("filesystem::maintenance::attempt::tests::cleanup_unknown_outcomes_replay_the_original_durable_result", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:cleanup_unknown_outcomes_replay_the_original_durable_result") { return; }

    for cut in [
        Step::Admitted,
        Step::IntentCommitted,
        Step::EntryRemoved,
        Step::PayloadSynced,
        Step::ReceiptCommitted,
    ] {
        let temp = test_directory::directory().expect("directory");
        let control = abandoned(temp.path(), false);
        let original = fs::read(control.join(RECORD)).expect("original record");
        let result = reclaim_with(&control, PublicationCleanupLimits::default(), |step| {
            if step == cut {
                Err(io::Error::other("original injected cleanup failure"))
            } else {
                Ok(())
            }
        });
        assert!(
            matches!(result,Err(Error::Io(ref e)) if e.to_string()=="original injected cleanup failure")
        );
        let retained = read_intent(&control.join(INTENT)).expect("read original intent");
        let expected = PublicationCleanupOutcome::Reclaimed {
            entries: 1,
            bytes: u64::try_from(VALUE.len()).expect("length"),
        };
        assert_eq!(reclaim(&control), expected);
        assert_eq!(reclaim(&control), expected);
        if let Some(retained) = retained {
            assert_eq!(
                fs::read(control.join(INTENT)).expect("same intent"),
                retained
            );
        }
        assert_eq!(
            fs::read(control.join(RECORD)).expect("same record"),
            original
        );
        assert!(!temp.path().join("formal").exists());
    }

    eprintln!("MANAGED_CASE_COMPLETE:cleanup_unknown_outcomes_replay_the_original_durable_result");
}

#[test]
fn partial_tree_cleanup_preserves_original_counts_and_intent() {
    if !isolated_case("filesystem::maintenance::attempt::tests::partial_tree_cleanup_preserves_original_counts_and_intent", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:partial_tree_cleanup_preserves_original_counts_and_intent") { return; }

    let temp = test_directory::directory().expect("directory");
    let control = abandoned(temp.path(), true);
    let error = reclaim_with(&control, PublicationCleanupLimits::default(), |step| {
        if step == Step::EntryRemoved {
            Err(io::Error::other("first removal cut"))
        } else {
            Ok(())
        }
    })
    .expect_err("partial cut");
    assert!(matches!(error, Error::Io(_)));
    assert_eq!(
        fs::read_dir(control.join(PAYLOAD))
            .expect("remaining tree")
            .count(),
        1
    );
    let intent = fs::read(control.join(INTENT)).expect("original intent");
    assert_eq!(
        reclaim(&control),
        PublicationCleanupOutcome::Reclaimed {
            entries: 3,
            bytes: u64::try_from(VALUE.len() * 2).expect("length")
        }
    );
    assert_eq!(
        fs::read(control.join(INTENT)).expect("same original"),
        intent
    );

    eprintln!("MANAGED_CASE_COMPLETE:partial_tree_cleanup_preserves_original_counts_and_intent");
}

#[test]
fn complete_preflight_refuses_budget_and_live_payload_owner_before_deletion() {
    if !isolated_case(
        "filesystem::maintenance::attempt::tests::complete_preflight_refuses_budget_and_live_payload_owner_before_deletion",
        "QPERIAPT_MANAGED_BUDGET_ISOLATED", "MANAGED_BUDGET_COMPLETE") { return; }
    let temp = test_directory::directory().expect("directory");
    let control = abandoned(temp.path(), true);
    for limits in [
        PublicationCleanupLimits {
            entries: 2,
            ..Default::default()
        },
        PublicationCleanupLimits {
            bytes: 1,
            ..Default::default()
        },
        PublicationCleanupLimits {
            depth: 1,
            ..Default::default()
        },
    ] {
        let observed = reclaim_private_publication(&control, limits);
        assert!(
            matches!(observed, Err(Error::Limit)),
            "budget {limits:?}: {observed:?}"
        );
        assert!(!control.join(INTENT).exists());
        assert_eq!(
            fs::read_dir(control.join(PAYLOAD))
                .expect("retained tree")
                .count(),
            2
        );
    }
    let owner =
        tree::lock(open_private_file(&control.join("payload/second"), false).expect("child"))
            .expect("live child");
    assert!(matches!(
        reclaim_private_publication(&control, Default::default()),
        Err(Error::Busy)
    ));
    assert!(!control.join(INTENT).exists());
    assert!(control.join("payload/first").exists());
    drop(owner);
    assert!(matches!(
        reclaim(&control),
        PublicationCleanupOutcome::Reclaimed { entries: 3, .. }
    ));
    eprintln!("MANAGED_BUDGET_COMPLETE");
}

#[test]
fn incomplete_legacy_and_substituted_records_are_not_cleanup_authority() {
    if !isolated_case("filesystem::maintenance::attempt::tests::incomplete_legacy_and_substituted_records_are_not_cleanup_authority", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:incomplete_legacy_and_substituted_records_are_not_cleanup_authority") { return; }

    let temp = test_directory::directory().expect("directory");
    let parent = temp.path();
    publish_private_bytes(&parent.join(".private-publication-legacy"), VALUE)
        .expect("legacy fixture");
    assert!(matches!(
        reclaim_private_publication(
            &parent.join(".private-publication-legacy"),
            Default::default()
        ),
        Err(Error::Invalid)
    ));
    let control = abandoned(parent, false);
    let before = fs::read(control.join(PAYLOAD)).expect("payload");
    fs::write(control.join(RECORD), b"QPSTG002").expect("partial metadata");
    assert!(matches!(
        reclaim_private_publication(&control, Default::default()),
        Err(Error::Invalid)
    ));
    assert_eq!(
        fs::read(control.join(PAYLOAD)).expect("payload retained"),
        before
    );
    assert_eq!(
        fs::read(parent.join(".private-publication-legacy")).expect("legacy retained"),
        VALUE
    );

    eprintln!(
        "MANAGED_CASE_COMPLETE:incomplete_legacy_and_substituted_records_are_not_cleanup_authority"
    );
}

#[test]
fn stale_or_conflicting_cleanup_control_fields_are_not_rewritten() {
    if !isolated_case("filesystem::maintenance::attempt::tests::stale_or_conflicting_cleanup_control_fields_are_not_rewritten", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:stale_or_conflicting_cleanup_control_fields_are_not_rewritten") { return; }

    let temp = test_directory::directory().expect("directory");
    let control = abandoned(temp.path(), false);
    let garbage = b"wrong original cleanup";
    publish_private_bytes(&control.join("cleanup.intent.pending"), garbage)
        .expect("wrong pending fixture");
    assert!(reclaim_private_publication(&control, Default::default()).is_err());
    assert_eq!(
        fs::read(control.join("cleanup.intent.pending")).expect("pending retained"),
        garbage
    );
    assert_eq!(
        fs::read(control.join(PAYLOAD)).expect("payload retained"),
        VALUE
    );
    assert!(!control.join(INTENT).exists());

    eprintln!(
        "MANAGED_CASE_COMPLETE:stale_or_conflicting_cleanup_control_fields_are_not_rewritten"
    );
}

#[test]
fn invalid_cleanup_receipt_state_refuses_before_payload_removal() {
    if !isolated_case(
        "filesystem::maintenance::attempt::tests::invalid_cleanup_receipt_state_refuses_before_payload_removal",
        "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:invalid_cleanup_receipt_state_refuses_before_payload_removal") { return; }
    for case in [
        "pending-without-intent",
        "done-without-intent",
        "damaged-done",
        "pending-with-payload",
        "done-with-payload",
        "duplicate-intent",
    ] {
        let temp = test_directory::directory().expect("directory");
        let path = abandoned(temp.path(), false);
        let control = Control::open(&path).expect("original control");
        let original = Intent {
            record: control.record.digest(),
            entries: 1,
            bytes: u64::try_from(VALUE.len()).expect("length"),
        };
        if !case.ends_with("without-intent") {
            control
                .persist_field(INTENT, &original.encode())
                .expect("original intent");
        }
        let (leaf, body) = match case {
            "pending-without-intent" | "pending-with-payload" => (
                "cleanup.done.pending",
                original.receipt().get(..17).expect("prefix").to_vec(),
            ),
            "done-without-intent" | "done-with-payload" => (DONE, original.receipt()),
            "duplicate-intent" => ("cleanup.intent.pending", original.encode()),
            "damaged-done" => (DONE, b"damaged completion".to_vec()),
            _ => unreachable!("fixed cases"),
        };
        publish_private_bytes(&path.join(leaf), &body).expect("control fixture");
        drop(control);
        let result = reclaim_private_publication(&path, Default::default());
        assert!(matches!(result, Err(Error::Invalid)), "{case}: {result:?}");
        assert_eq!(
            fs::read(path.join(PAYLOAD)).expect("payload retained"),
            VALUE,
            "{case}"
        );
        assert_eq!(
            fs::read(path.join(leaf)).expect("field retained"),
            body,
            "{case}"
        );
    }
    eprintln!("MANAGED_CASE_COMPLETE:invalid_cleanup_receipt_state_refuses_before_payload_removal");
}

#[test]
fn exact_partial_control_prefix_resumes_without_changing_the_original_operation() {
    if !isolated_case("filesystem::maintenance::attempt::tests::exact_partial_control_prefix_resumes_without_changing_the_original_operation", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:exact_partial_control_prefix_resumes_without_changing_the_original_operation") { return; }

    let temp = test_directory::directory().expect("directory");
    let path = abandoned(temp.path(), false);
    let control = Control::open(&path).expect("original control");
    let original = Intent {
        record: control.record.digest(),
        entries: 1,
        bytes: u64::try_from(VALUE.len()).expect("length"),
    };
    let prefix = original.encode().get(..17).expect("prefix").to_vec();
    publish_private_bytes(&path.join("cleanup.intent.pending"), &prefix)
        .expect("retained partial field");
    drop(control);
    assert_eq!(
        reclaim(&path),
        PublicationCleanupOutcome::Reclaimed {
            entries: original.entries,
            bytes: original.bytes
        }
    );
    assert_eq!(
        fs::read(path.join(INTENT)).expect("exact intent"),
        original.encode()
    );

    let other = test_directory::directory().expect("directory");
    let path = abandoned(other.path(), false);
    let result = reclaim_with(&path, Default::default(), |step| {
        if step == Step::PayloadSynced {
            Err(io::Error::other("before receipt write"))
        } else {
            Ok(())
        }
    });
    assert!(matches!(result, Err(Error::Io(_))));
    let control = Control::open(&path).expect("original control");
    let intent_bytes = fs::read(path.join(INTENT)).expect("committed intent");
    let original = Intent::decode(&intent_bytes, &control.record).expect("original intent");
    assert!(!path.join(PAYLOAD).exists());
    publish_private_bytes(
        &path.join("cleanup.done.pending"),
        original.receipt().get(..17).expect("receipt prefix"),
    )
    .expect("partial receipt");
    drop(control);
    assert_eq!(
        reclaim(&path),
        PublicationCleanupOutcome::Reclaimed {
            entries: original.entries,
            bytes: original.bytes
        }
    );
    assert_eq!(
        fs::read(path.join(INTENT)).expect("same intent"),
        intent_bytes
    );
    assert_eq!(
        fs::read(path.join(DONE)).expect("exact receipt"),
        original.receipt()
    );

    eprintln!("MANAGED_CASE_COMPLETE:exact_partial_control_prefix_resumes_without_changing_the_original_operation");
}

#[test]
fn damaged_bookkeeping_and_valid_checksum_wrong_scope_both_refuse_cleanup() {
    if !isolated_case("filesystem::maintenance::attempt::tests::damaged_bookkeeping_and_valid_checksum_wrong_scope_both_refuse_cleanup", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:damaged_bookkeeping_and_valid_checksum_wrong_scope_both_refuse_cleanup") { return; }

    for altered_scope in [false, true] {
        let temp = test_directory::directory().expect("directory");
        let path = abandoned(temp.path(), false);
        let mut body = fs::read(path.join(RECORD)).expect("record");
        if altered_scope {
            let mut record = Record::decode(&body).expect("valid record");
            *record.parent.first_mut().expect("parent byte") ^= 1;
            body = record.encode();
        } else {
            *body.last_mut().expect("checksum byte") ^= 1;
        }
        fs::write(path.join(RECORD), body).expect("corruption fixture");
        let error = reclaim_private_publication(&path, Default::default())
            .expect_err("damaged or wrong scope");
        if altered_scope {
            assert!(matches!(error,Error::Io(ref e) if e.kind()==io::ErrorKind::InvalidData));
        } else {
            assert!(matches!(error, Error::Invalid));
        }
        assert_eq!(
            fs::read(path.join(PAYLOAD)).expect("untouched payload"),
            VALUE
        );
        assert!(!path.join(INTENT).exists());
    }

    eprintln!("MANAGED_CASE_COMPLETE:damaged_bookkeeping_and_valid_checksum_wrong_scope_both_refuse_cleanup");
}

#[test]
fn substituted_payload_is_refused_before_interacting_with_its_owner() {
    if !isolated_case("filesystem::maintenance::attempt::tests::substituted_payload_is_refused_before_interacting_with_its_owner", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:substituted_payload_is_refused_before_interacting_with_its_owner") { return; }

    let temp = test_directory::directory().expect("directory");
    let path = abandoned(temp.path(), false);
    fs::rename(path.join(PAYLOAD), temp.path().join("original")).expect("retain original");
    publish_private_bytes(&path.join(PAYLOAD), b"different owner").expect("replacement fixture");
    let owner = tree::lock(open_private_file(&path.join(PAYLOAD), false).expect("replacement"))
        .expect("different live owner");
    assert!(matches!(
        reclaim_private_publication(&path, Default::default()),
        Err(Error::Invalid)
    ));
    assert!(!path.join(INTENT).exists());
    // Keep the owner live through rejection; Windows prevents independent
    // handle reads until this test releases its own whole-file lease.
    drop(owner);
    assert_eq!(
        fs::read(path.join(PAYLOAD)).expect("replacement retained"),
        b"different owner"
    );
    assert_eq!(
        fs::read(temp.path().join("original")).expect("original retained"),
        VALUE
    );

    eprintln!(
        "MANAGED_CASE_COMPLETE:substituted_payload_is_refused_before_interacting_with_its_owner"
    );
}

#[cfg(unix)]
#[test]
fn symlink_hardlink_and_replaced_lease_never_grant_disposal() {
    if !isolated_case("filesystem::maintenance::attempt::tests::symlink_hardlink_and_replaced_lease_never_grant_disposal", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:symlink_hardlink_and_replaced_lease_never_grant_disposal") { return; }

    for case in ["symlink", "hardlink", "lease"] {
        let temp = test_directory::directory().expect("directory");
        let parent = temp.path();
        let attempt = ManagedAttempt::file(&parent.join("formal")).expect("attempt");
        let control = attempt.path().parent().expect("control").to_owned();
        let mut data = attempt.data_file().expect("payload");
        data.write_all(VALUE).expect("write");
        data.sync_all().expect("sync");
        drop(data);
        if case == "lease" {
            fs::rename(control.join(LEASE), parent.join("original-lease")).expect("move lease");
            publish_private_bytes(&control.join(LEASE), &attempt.control.record.lease_bytes())
                .expect("different unlocked lease");
            assert!(
                matches!(reclaim_private_publication(&control,Default::default()),Err(Error::Io(ref e)) if e.kind()==io::ErrorKind::InvalidData)
            );
            assert_eq!(
                fs::read(control.join(PAYLOAD)).expect("live payload"),
                VALUE
            );
        } else {
            drop(attempt);
            if case == "symlink" {
                fs::rename(control.join(PAYLOAD), parent.join("original")).expect("move");
                std::os::unix::fs::symlink(parent.join("original"), control.join(PAYLOAD))
                    .expect("symlink");
            } else {
                fs::hard_link(control.join(PAYLOAD), parent.join("alias")).expect("alias");
            }
            assert!(matches!(
                reclaim_private_publication(&control, Default::default()),
                Err(Error::Io(_))
            ));
            assert_eq!(fs::read(control.join(PAYLOAD)).expect("unchanged"), VALUE);
        }
        assert!(!control.join(INTENT).exists());
    }

    eprintln!("MANAGED_CASE_COMPLETE:symlink_hardlink_and_replaced_lease_never_grant_disposal");
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().expect("child status").is_none() {
            self.0.kill().expect("child kill");
            self.0.wait().expect("child reap");
        }
    }
}

// A quiescent-owner scenario creates its descriptors only after this exec.
// Concurrent unrelated process-spawn tests in the parent cannot retain copies
// of these new open descriptions between fork and close-on-exec. Public Busy
// results remain untouched; there is no retry or weakened assertion here.
fn isolated_case(name: &str, flag: &str, marker: &str) -> bool {
    if let Some(value) = std::env::var_os(flag) {
        assert_eq!(value, "1");
        return true;
    }
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", name, "--nocapture"])
            .env(flag, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("isolated fixture"),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("fixture status") {
            break status;
        }
        assert!(Instant::now() < deadline, "isolated fixture deadline");
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stderr = Vec::new();
    child
        .0
        .stderr
        .take()
        .expect("stderr")
        .take(1024 * 1024 + 1)
        .read_to_end(&mut stderr)
        .expect("stderr read");
    assert!(stderr.len() <= 1024 * 1024, "bounded fixture diagnostics");
    let stderr = String::from_utf8(stderr).expect("fixture diagnostic encoding");
    assert!(status.success(), "isolated fixture failed: {stderr}");
    assert_eq!(
        stderr.lines().filter(|line| *line == marker).count(),
        1,
        "selected body did not complete: {stderr}"
    );
    eprint!("{stderr}");
    false
}
#[test]
fn cleanup_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_MANAGED_CLEANUP_CHILD") else {
        return;
    };
    let path = PathBuf::from(path);
    let ready = path.parent().expect("parent").join("cleanup-ready");
    let stage = std::env::var("QPERIAPT_MANAGED_CLEANUP_STAGE").expect("cut");
    if stage == "InheritedPayload" {
        publish_private_bytes(&ready, b"ready").expect("inherited-handle readiness");
        loop {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    reclaim_with(&path, Default::default(), |step| {
        if format!("{step:?}") == stage {
            publish_private_bytes(&ready, b"ready").map_err(io::Error::other)?;
            loop {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(())
    })
    .expect("must reach selected cut");
}

#[cfg(unix)]
#[test]
fn inherited_open_description_remains_an_owner_after_parent_close() {
    if !isolated_case(
        "filesystem::maintenance::attempt::tests::inherited_open_description_remains_an_owner_after_parent_close",
        "QPERIAPT_MANAGED_INHERITED_ISOLATED", "MANAGED_INHERITED_COMPLETE") {return;}
    let temp = test_directory::directory().expect("directory");
    let path = abandoned(temp.path(), false);
    let file = open_private_file(&path.join(PAYLOAD), false).expect("payload");
    let owner = tree::lock(file.try_clone().expect("probe")).expect("original payload owner");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "filesystem::maintenance::attempt::tests::cleanup_process_child",
                "--nocapture",
            ])
            .env("QPERIAPT_MANAGED_CLEANUP_CHILD", &path)
            .env("QPERIAPT_MANAGED_CLEANUP_STAGE", "InheritedPayload")
            .stdin(Stdio::from(
                file.try_clone()
                    .expect("explicit inherited open description"),
            ))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("inherited owner"),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !temp.path().join("cleanup-ready").exists() {
        assert!(child.0.try_wait().expect("status").is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(owner);
    drop(file);
    assert!(matches!(
        reclaim_private_publication(&path, Default::default()),
        Err(Error::Busy)
    ));
    assert!(!path.join(INTENT).exists());
    assert_eq!(fs::read(path.join(PAYLOAD)).expect("unchanged"), VALUE);
    child.0.kill().expect("kill inherited owner");
    let status = child.0.wait().expect("reap");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    assert_eq!(
        reclaim(&path),
        PublicationCleanupOutcome::Reclaimed {
            entries: 1,
            bytes: u64::try_from(VALUE.len()).expect("length")
        }
    );
    eprintln!("MANAGED_INHERITED_COMPLETE");
}

#[test]
fn actual_cleanup_process_cuts_recover_original_receipts() {
    if !isolated_case("filesystem::maintenance::attempt::tests::actual_cleanup_process_cuts_recover_original_receipts", "QPERIAPT_MANAGED_CASE_ISOLATED", "MANAGED_CASE_COMPLETE:actual_cleanup_process_cuts_recover_original_receipts") { return; }

    for stage in [
        Step::IntentCommitted,
        Step::EntryRemoved,
        Step::PayloadSynced,
        Step::ReceiptCommitted,
    ] {
        let temp = test_directory::directory().expect("directory");
        let path = abandoned(temp.path(), true);
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "filesystem::maintenance::attempt::tests::cleanup_process_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_MANAGED_CLEANUP_CHILD", &path)
                .env("QPERIAPT_MANAGED_CLEANUP_STAGE", format!("{stage:?}"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("cleanup process"),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        while !temp.path().join("cleanup-ready").exists() {
            assert!(
                child.0.try_wait().expect("child status").is_none(),
                "child ended before cut"
            );
            assert!(Instant::now() < deadline, "bounded process cut");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(
            reclaim_private_publication(&path, Default::default()),
            Err(Error::Busy)
        ));
        let pid = child.0.id();
        child.0.kill().expect("kill");
        let status = child.0.wait().expect("reap");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(9));
        }
        #[cfg(windows)]
        assert!(!status.success());
        let expected = PublicationCleanupOutcome::Reclaimed {
            entries: 3,
            bytes: u64::try_from(VALUE.len() * 2).expect("length"),
        };
        assert_eq!(reclaim(&path), expected);
        assert_eq!(reclaim(&path), expected);
        eprintln!("MANAGED_CLEANUP_PROCESS cut={stage:?} pid={pid} original_receipt=true");
    }

    eprintln!("MANAGED_CASE_COMPLETE:actual_cleanup_process_cuts_recover_original_receipts");
}
