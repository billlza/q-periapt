// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Regression checks for typed relay errors and success-result preservation.
use std::{io, time::Duration};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[path = "common/witness_tls_outcome.rs"]
mod outcome;
use outcome::{finish_reply, joined, RelayFailure, RelayObservation};

#[cfg(test)]
fn observed_fixture() -> RelayObservation {
    RelayObservation {
        elapsed: Duration::from_millis(32),
        native_elapsed: Some(Duration::from_millis(30)),
        request_elapsed: Some(Duration::from_millis(31)),
        reply_elapsed: Duration::from_millis(30),
        admitted: None,
    }
}

#[test]
fn relay_retains_native_failure_when_shutdown_also_fails() {
    let error = finish_reply::<()>(
        Err(io::Error::new(io::ErrorKind::TimedOut, "native sentinel").into()),
        Ok(()),
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "reply sentinel").into()),
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "shutdown sentinel",
        )),
        observed_fixture(),
    )
    .expect_err("failed native exchange must remain an error");
    let diagnostic = error.to_string();
    assert!(
        diagnostic.contains("native sentinel"),
        "native error lost: {diagnostic}"
    );
    assert!(
        diagnostic.contains("reply sentinel"),
        "reply error lost: {diagnostic}"
    );
    assert!(
        diagnostic.contains("shutdown sentinel"),
        "cleanup error lost: {diagnostic}"
    );
    let failure = error
        .downcast_ref::<RelayFailure>()
        .expect("retained stage errors");
    let primary = std::error::Error::source(failure)
        .and_then(|cause| cause.downcast_ref::<io::Error>())
        .expect("original typed cause");
    assert_eq!(primary.kind(), io::ErrorKind::TimedOut);
    assert_eq!(failure.failures.len(), 3);
    assert!(failure.observation.admitted.is_none());
}

#[test]
fn relay_returns_the_original_complete_reply_and_record() {
    let result = finish_reply(Ok(37), Ok(()), Ok(vec![17, 19]), Ok(()), observed_fixture())
        .expect("complete successful exchange");
    assert_eq!(result, (vec![17, 19], 37));
}

#[test]
fn relay_cleanup_failure_still_refuses_the_successful_native_record() {
    let error = finish_reply(
        Ok(37),
        Ok(()),
        Ok(vec![17]),
        Err(io::Error::from_raw_os_error(57)),
        observed_fixture(),
    )
    .expect_err("cleanup failure is not successful delivery");
    let failure = error
        .downcast_ref::<RelayFailure>()
        .expect("retained cleanup error");
    let original = std::error::Error::source(failure)
        .and_then(|cause| cause.downcast_ref::<io::Error>())
        .expect("original OS error");
    assert_eq!(original.raw_os_error(), Some(57));
    assert_eq!(failure.failures.len(), 1);
}

#[test]
fn relay_worker_panic_does_not_hide_other_stage_failures() {
    let (native, elapsed) = joined::<()>(
        Err(Box::new("private panic payload")),
        "TLS native server panicked",
    );
    assert!(elapsed.is_none());
    let error = finish_reply(
        native,
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "request sentinel").into()),
        Err(io::Error::new(io::ErrorKind::TimedOut, "reply sentinel").into()),
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "shutdown sentinel",
        )),
        observed_fixture(),
    )
    .expect_err("worker panic and all other failures retained");
    let diagnostic = error.to_string();
    for expected in [
        "TLS native server panicked",
        "request sentinel",
        "reply sentinel",
        "shutdown sentinel",
    ] {
        assert!(diagnostic.contains(expected));
    }
    assert!(!diagnostic.contains("private panic payload"));
    assert_eq!(
        error
            .downcast_ref::<RelayFailure>()
            .expect("combined failure")
            .failures
            .len(),
        4
    );
}
