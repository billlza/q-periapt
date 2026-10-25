// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::path::Path;

pub(super) fn after_commit(stage: &str) {
    target_boundary(stage, true);
}

pub(super) fn before_commit(stage: &str) {
    target_boundary(stage, false);
}

fn target_boundary(stage: &str, committed: bool) {
    let Ok(expected) = std::env::var("QPERIAPT_HANDOFF_TARGET_STAGE") else {
        return;
    };
    if stage != expected {
        return;
    }
    let path =
        std::env::var_os("QPERIAPT_HANDOFF_TARGET_DIR").expect("test-owned target directory");
    let path = Path::new(&path);
    std::fs::write(
        path.join("ready.tmp"),
        if committed {
            b"committed".as_slice()
        } else {
            b"before-commit".as_slice()
        },
    )
    .expect("test marker");
    std::fs::rename(path.join("ready.tmp"), path.join("ready")).expect("publish test marker");
    loop {
        std::thread::park();
    }
}

pub(super) fn source_boundary(kind: &str, committed: bool) {
    let stage = format!(
        "source-{kind}-{}",
        if committed { "after" } else { "before" }
    );
    if std::env::var("QPERIAPT_SOURCE_CONTROL_CUT").ok().as_deref() != Some(stage.as_str()) {
        return;
    }
    let path = std::env::var_os("QPERIAPT_SOURCE_CONTROL_DIR").expect("owned source fixture");
    let path = Path::new(&path);
    std::fs::write(
        path.join("ready.tmp"),
        if committed {
            b"committed".as_slice()
        } else {
            b"before-commit".as_slice()
        },
    )
    .expect("boundary marker");
    std::fs::rename(path.join("ready.tmp"), path.join("ready")).expect("publish boundary");
    loop {
        std::thread::park();
    }
}
