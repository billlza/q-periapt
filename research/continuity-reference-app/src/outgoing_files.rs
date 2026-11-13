// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One bounded opaque exchange per numbered private request/response file.
use super::operator_io::{export_directory, read};
use q_periapt_continuity_identity_candidate as sdk;
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    io,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

pub(super) struct FileTransport {
    requests: PathBuf,
    responses: PathBuf,
    attempted: u16,
}
impl FileTransport {
    pub(super) fn new(
        requests: &Path,
        responses: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        export_directory(requests)?;
        export_directory(responses)?;
        if std::fs::canonicalize(requests)? == std::fs::canonicalize(responses)? {
            return Err("Request and response directories must differ".into());
        }
        Ok(Self {
            requests: requests.to_owned(),
            responses: responses.to_owned(),
            attempted: 0,
        })
    }
}
fn remaining(deadline: Instant, cancel: &sdk::Cancellation) -> io::Result<Duration> {
    if cancel.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "File exchange cancelled",
        ));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|v| !v.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "File exchange deadline"))
}
impl sdk::session_exchange::Transport for FileTransport {
    fn exchange(
        &mut self,
        request: &[u8],
        deadline: Instant,
        cancel: &sdk::Cancellation,
    ) -> io::Result<Vec<u8>> {
        remaining(deadline, cancel)?;
        if !(10..=sdk::contract::MAX_CONNECTION_FRAME_BYTES).contains(&request.len())
            || self.attempted >= 128
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.attempted += 1;
        let request_path = self.requests.join(format!("{:03}.request", self.attempted));
        let response_path = self
            .responses
            .join(format!("{:03}.response", self.attempted));
        publish_private_bytes(&request_path, request)
            .map_err(|e| io::Error::other(e.to_string()))?;
        loop {
            let wait = remaining(deadline, cancel)?;
            if response_path.try_exists()? {
                break;
            }
            thread::sleep(wait.min(Duration::from_millis(10)));
        }
        let response = read(&response_path, sdk::contract::MAX_CONNECTION_FRAME_BYTES)
            .map_err(|e| io::Error::other(e.to_string()))?;
        remaining(deadline, cancel)?;
        if response.len() < 10 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(response)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sdk::session_exchange::Transport;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> Result<FileTransport, Box<dyn std::error::Error>> {
        let root = tempfile::Builder::new()
            .prefix("qperiapt-outgoing-files-")
            .tempdir()?
            .keep()
            .canonicalize()?;
        let requests = root.join("requests");
        let responses = root.join("responses");
        for path in [&requests, &responses] {
            std::fs::create_dir(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        FileTransport::new(&requests, &responses)
    }

    #[test]
    fn pre_cancelled_or_expired_invocation_publishes_nothing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut carrier = fixture()?;
        let cancel = sdk::Cancellation::default();
        cancel.cancel();
        assert_eq!(
            carrier
                .exchange(&[1; 10], Instant::now() + Duration::from_secs(1), &cancel)
                .err()
                .ok_or("cancel was not rejected")?
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            carrier
                .exchange(&[1; 10], Instant::now(), &sdk::Cancellation::default())
                .err()
                .ok_or("expiry was not rejected")?
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(std::fs::read_dir(&carrier.requests)?.count(), 0);
        Ok(())
    }

    #[test]
    fn opaque_response_is_bounded_and_original_request_is_preserved(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut carrier = fixture()?;
        publish_private_bytes(&carrier.responses.join("001.response"), &[2; 10])?;
        assert_eq!(
            carrier.exchange(
                &[1; 10],
                Instant::now() + Duration::from_secs(1),
                &sdk::Cancellation::default()
            )?,
            vec![2; 10]
        );
        assert_eq!(
            read(&carrier.requests.join("001.request"), 32)?,
            vec![1; 10]
        );
        publish_private_bytes(
            &carrier.responses.join("002.response"),
            &[3; sdk::contract::MAX_CONNECTION_FRAME_BYTES + 1],
        )?;
        assert!(carrier
            .exchange(
                &[4; 10],
                Instant::now() + Duration::from_secs(1),
                &sdk::Cancellation::default()
            )
            .is_err());
        assert_eq!(
            read(&carrier.requests.join("001.request"), 32)?,
            vec![1; 10]
        );
        Ok(())
    }

    #[test]
    fn timeout_keeps_the_published_request_and_does_not_reset_deadline(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut carrier = fixture()?;
        let deadline = Instant::now() + Duration::from_millis(30);
        let cancel = sdk::Cancellation::default();
        assert_eq!(
            carrier
                .exchange(&[1; 10], deadline, &cancel)
                .err()
                .ok_or("absent reply did not expire")?
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            carrier
                .exchange(&[1; 10], deadline, &cancel)
                .err()
                .ok_or("deadline was reset")?
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(std::fs::read_dir(&carrier.requests)?.count(), 1);
        Ok(())
    }

    #[test]
    fn cancellation_interrupts_an_active_response_wait() -> Result<(), Box<dyn std::error::Error>> {
        let mut carrier = fixture()?;
        let request = carrier.requests.join("001.request");
        let cancel = sdk::Cancellation::default();
        let worker_cancel = cancel.clone();
        let worker = thread::spawn(move || {
            carrier.exchange(
                &[1; 10],
                Instant::now() + Duration::from_secs(5),
                &worker_cancel,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !request.try_exists()? && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        let published = request.try_exists()?;
        let start = Instant::now();
        cancel.cancel();
        let result = worker
            .join()
            .map_err(|_| io::Error::other("carrier worker panicked"))?;
        assert!(published, "actual request publication required");
        assert_eq!(
            result
                .err()
                .ok_or("cancelled wait returned a response")?
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn overlapping_or_nonempty_carrier_directories_are_refused(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let carrier = fixture()?;
        assert!(FileTransport::new(&carrier.requests, &carrier.requests).is_err());
        publish_private_bytes(&carrier.requests.join("original"), b"retained")?;
        assert!(FileTransport::new(&carrier.requests, &carrier.responses).is_err());
        assert_eq!(read(&carrier.requests.join("original"), 32)?, b"retained");
        Ok(())
    }
}
