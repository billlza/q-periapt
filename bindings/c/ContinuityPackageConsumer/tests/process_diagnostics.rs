// SPDX-License-Identifier: Apache-2.0 OR MIT
#![cfg(unix)]
#[path = "common/process_diagnostics.rs"]
mod process_diagnostics;
use std::{ffi::OsString, os::unix::process::ExitStatusExt, path::Path};

fn run(script: &str) -> std::io::Result<process_diagnostics::Captured> {
    process_diagnostics::capture(
        Path::new("/bin/sh"),
        &[OsString::from("-c"), script.into()],
        "diagnostic-contract",
    )
}
#[test]
fn normal_output_keeps_streams_and_has_no_failure_event() {
    let result = run("printf exact-output").expect("owned shell");
    assert!(result.output.status.success());
    assert_eq!(result.output.stdout, b"exact-output");
    assert!(result.output.stderr.is_empty());
    assert!(result.failure_line().is_none());
}
#[test]
fn nonzero_exit_retains_status_identity_and_stream_sizes() {
    let result = run("printf out; printf err >&2; exit 7").expect("owned failing shell");
    assert_eq!(result.output.status.code(), Some(7));
    let event = result.failure_line().expect("failure metadata");
    assert!(event.starts_with(&format!(
        "QPC_CHILD_FAILURE_V1 parent_pid={} pid=",
        std::process::id()
    )));
    assert!(event.contains(" signal=none exit=7 program_hex=7368 label=diagnostic-contract stdout_bytes=3 stderr_bytes=3"));
    assert_eq!(result.output.stdout, b"out");
    assert_eq!(result.output.stderr, b"err");
}
#[test]
fn abort_remains_signal_with_empty_stderr_and_no_exit_code() {
    // Limit only this owned child's core-file output, without changing host policy.
    let result = run("ulimit -c 0; kill -ABRT $$").expect("owned signal child");
    assert_eq!(result.output.status.signal(), Some(6));
    assert_eq!(result.output.status.code(), None);
    assert!(result.output.stderr.is_empty());
    let event = result.failure_line().expect("signal metadata");
    assert!(event.contains(" signal=6 exit=none program_hex=7368 label=diagnostic-contract stdout_bytes=0 stderr_bytes=0"));
}
#[test]
fn invalid_label_is_rejected_before_process_spawn() {
    let error =
        process_diagnostics::capture(Path::new("/no-such-diagnostic-program"), &[], "bad\nlabel")
            .err()
            .expect("invalid input");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
