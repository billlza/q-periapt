// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::net::Shutdown;
use std::os::{fd::OwnedFd, unix::net::UnixStream};

pub(super) struct ChildGuard(pub(super) std::process::Child);

impl ChildGuard {
    pub(super) fn wait_bounded(
        &mut self,
        deadline: Instant,
    ) -> io::Result<std::process::ExitStatus> {
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Ok(Some(_)) = self.0.try_wait() {
            return;
        }
        if let Err(e) = self.0.kill() {
            eprintln!("study child termination: {e}");
        }
        if let Err(e) = self.0.wait() {
            eprintln!("study child wait: {e}");
        }
    }
}

pub(super) fn encapsulate(
    device: &Path,
    peer: &q_periapt_sdk::PublicKey,
    context: [u8; 32],
    checkpoint: q_periapt_policy::TrustedPolicyState,
) -> std::result::Result<
    (
        q_periapt_sdk::Ciphertext,
        q_periapt_core::ZeroizingBytes<32>,
    ),
    p::DurableError,
> {
    use std::process::{Command, Stdio};
    let (mut pipe, endpoint) = UnixStream::pair()?;
    pipe.set_read_timeout(Some(Duration::from_secs(8)))?;
    pipe.set_write_timeout(Some(Duration::from_secs(8)))?;
    let dir = tempfile::tempdir()?;
    let binary = std::env::var_os("QPERIAPT_STAGE4_KEM")
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let mut child = ChildGuard(
        Command::new(binary)
            .env_clear()
            .current_dir(dir.path())
            .stdin(Stdio::from(OwnedFd::from(endpoint.try_clone()?)))
            .stdout(Stdio::from(OwnedFd::from(endpoint)))
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    for name in ["sdk-policy", "sdk-signature", "sdk-root"] {
        let data = fs::read(device.join(name))?;
        pipe.write_all(
            &u32::try_from(data.len())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
                .to_be_bytes(),
        )?;
        pipe.write_all(&data)?;
    }
    pipe.write_all(&checkpoint.encode())?;
    pipe.write_all(&peer.to_bytes())?;
    pipe.write_all(&context)?;
    pipe.shutdown(Shutdown::Write)?;
    let mut ct = [0; q_periapt_sdk::CIPHERTEXT_LEN];
    let mut secret = q_periapt_core::ZeroizingBytes::<32>::zeroed();
    pipe.read_exact(&mut ct)?;
    pipe.read_exact(secret.as_mut_bytes())?;
    if pipe.read(&mut [0])? != 0
        || !child
            .wait_bounded(Instant::now() + Duration::from_secs(4))?
            .success()
    {
        return Err(io::Error::other("isolated KEM worker failed").into());
    }
    Ok((
        q_periapt_sdk::Ciphertext::from_bytes(&ct).map_err(p::Error::from)?,
        secret,
    ))
}
