// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[test]
fn account_freeze_process_child() {
    let Some(path) = std::env::var_os("QPERIAPT_ACCOUNT_FREEZE_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let mut store = reopen(path);
    let request = AnchorAccountFreezeRequest::from_bytes(
        &fs::read(path.join("freeze-request.bin")).expect("retained original request"),
    )
    .expect("original trusted descriptor");
    store.freeze_account(&request).expect("exact freeze");
    fs::write(path.join("returned-freeze"), b"returned").expect("child return marker");
}
#[test]
fn account_freeze_process_loss_after_commit_recovers_snapshot_before_return() {
    let mut c = required_case();
    let original = freeze_request(&c, original_root(&c), 180);
    fs::write(c.server.join("freeze-request.bin"), original.to_bytes())
        .expect("retain exact original approval");
    let advance = request(
        &c,
        AnchorOperation::advance(initial(&c), [189; 32]).expect("advance after approval"),
    );
    let head = apply_request(&mut c, &advance)
        .applied_head()
        .expect("last pre-freeze head");
    let revision = c.store.image().expect("original revision").revision;
    c.store.close();
    let log =
        fs::File::create_new(c.server.join("freeze-child.log")).expect("owned bounded child log");
    let mut child = ChildGuard(Process::new(std::env::current_exe().expect("current binary"))
        .args(["--exact", "anchor::store::tests::replacement::account_root::preparation_freeze::process::account_freeze_process_child", "--nocapture"])
        .env("QPERIAPT_ACCOUNT_FREEZE_DIR", &c.server)
        .env("QPERIAPT_ANCHOR_SERVER_DIR", &c.server)
        .env("QPERIAPT_ANCHOR_CRASH_REVISION", (revision + 1).to_string())
        .stdout(Stdio::from(log.try_clone().expect("owned log descriptor")))
        .stderr(Stdio::from(log)).spawn().expect("spawn fresh witness process"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.server.join("ready").exists() {
        assert!(
            child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "freeze process reached neither durable boundary nor normal return"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.server.join("returned-freeze").exists());
    child
        .0
        .kill()
        .expect("kill owned child after commit before return");
    assert!(!child.0.wait().expect("reap owned child").success());
    c.store = reopen(&c.server);
    let frozen = c
        .store
        .account_freeze(&original)
        .expect("recover exact committed request");
    let observed = frozen.subjects().collect::<Vec<_>>();
    assert_eq!(observed.len(), 1);
    assert_eq!(
        observed
            .first()
            .expect("one original frozen subject")
            .observed_head(),
        head
    );
    assert_eq!(
        observed
            .first()
            .expect("one original frozen subject")
            .last_command_id(),
        Some(advance.command_id())
    );
    assert_eq!(
        c.store
            .freeze_account(&original)
            .expect("exact historical retry"),
        frozen
    );
    let image = c.store.image().expect("original witness image");
    assert_eq!(image.revision, revision + 1);
    assert_eq!(image.entries.len(), 1);
    assert!(image.account_replacements.is_empty());
    assert_retired(&mut c, AnchorOperation::query());
    let wire = c
        .store
        .account_freeze_receipt(&original)
        .expect("recover authenticated full snapshot");
    assert_eq!(
        c.pin
            .verify_account_freeze(&original, &wire)
            .expect("same retained approval"),
        frozen
    );
    eprintln!("ANCHOR_ACCOUNT_FREEZE_PROCESS commit_before_return=true original_request_recovered=true exact_retry=true frozen_head_preserved=true no_target_enrolled=true");
}
