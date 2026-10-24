// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::path::Path;

pub(super) fn after_commit(stage: &str) {
    let Ok(expected) = std::env::var("QPERIAPT_HANDOFF_TARGET_STAGE") else {
        return;
    };
    if stage != expected {
        return;
    }
    let path =
        std::env::var_os("QPERIAPT_HANDOFF_TARGET_DIR").expect("test-owned target directory");
    let path = Path::new(&path);
    std::fs::write(path.join("ready.tmp"), b"committed").expect("test marker");
    std::fs::rename(path.join("ready.tmp"), path.join("ready")).expect("publish test marker");
    loop {
        std::thread::park();
    }
}
