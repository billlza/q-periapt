// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Preserve all bounded relay failures without releasing a failed native result.
use crate::Result;
use std::{io, thread, time::Duration};

pub(super) fn joined<T>(
    outcome: thread::Result<(Result<T>, Duration)>,
    panic_context: &'static str,
) -> (Result<T>, Option<Duration>) {
    match outcome {
        Ok((result, elapsed)) => (result, Some(elapsed)),
        Err(_) => (Err(panic_context.into()), None),
    }
}

#[derive(Debug)]
pub(super) struct RelayObservation {
    pub(super) elapsed: Duration,
    pub(super) native_elapsed: Option<Duration>,
    pub(super) request_elapsed: Option<Duration>,
    pub(super) reply_elapsed: Duration,
    // This marks the real server's clock callback before handle, not a commit.
    pub(super) admitted: Option<Duration>,
}

pub(super) type StageFailure = (&'static str, Box<dyn std::error::Error + Send + Sync>);

#[derive(Debug)]
pub(super) struct RelayFailure {
    pub(super) observation: RelayObservation,
    pub(super) failures: Vec<StageFailure>,
}
impl std::fmt::Display for RelayFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let observed = &self.observation;
        write!(out, "TLS relay failed elapsed_us={} native_us={:?} request_us={:?} reply_us={} admission_us={:?}",
            observed.elapsed.as_micros(), observed.native_elapsed.map(|v| v.as_micros()),
            observed.request_elapsed.map(|v| v.as_micros()), observed.reply_elapsed.as_micros(),
            observed.admitted.map(|v| v.as_micros()))?;
        for (stage, error) in &self.failures {
            write!(out, "; {stage}: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for RelayFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failures.first().map(|(_, error)| error.as_ref() as _)
    }
}

pub(super) fn finish_reply<T>(
    served: Result<T>,
    sent: Result<()>,
    received: Result<Vec<u8>>,
    stopped: io::Result<()>,
    observation: RelayObservation,
) -> Result<(Vec<u8>, T)> {
    match (served, sent, received, stopped) {
        (Ok(record), Ok(()), Ok(reply), Ok(())) => {
            if reply.is_empty() {
                return Err("TLS native reply was not retained".into());
            }
            Ok((reply, record))
        }
        (served, sent, received, stopped) => {
            let failures = [
                ("native server", served.err()),
                ("request relay", sent.err()),
                ("reply relay", received.err()),
                ("stop request reader", stopped.err().map(Into::into)),
            ]
            .into_iter()
            .filter_map(|(stage, error)| error.map(|error| (stage, error)))
            .collect();
            Err(Box::new(RelayFailure {
                observation,
                failures,
            }))
        }
    }
}
