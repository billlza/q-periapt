// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public process identity survives a failed test's temporary-directory cleanup.
use std::{
    ffi::OsString,
    io,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) struct Captured {
    pub(crate) output: Output,
    pid: u32,
    parent: u32,
    program: Vec<u8>,
    label: String,
    started: SystemTime,
    ended: SystemTime,
}
fn clock(value: SystemTime) -> String {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().to_string(),
        Err(_) => "unavailable".to_owned(),
    }
}
fn status(value: Option<i32>) -> String {
    value.map_or_else(|| "none".to_owned(), |n| n.to_string())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl Captured {
    /// None means normal zero exit with empty stderr. A missing wall-clock value
    /// explicitly prevents crash-report attribution; it never changes exit status.
    pub(crate) fn failure_line(&self) -> Option<String> {
        if self.output.status.success() && self.output.stderr.is_empty() {
            return None;
        }
        Some(format!(
            "QPC_CHILD_FAILURE_V1 parent_pid={} pid={} start_ms={} end_ms={} signal={} exit={} program_hex={} label={} stdout_bytes={} stderr_bytes={}",
            self.parent, self.pid, clock(self.started), clock(self.ended),
            status(self.output.status.signal()), status(self.output.status.code()),
            hex(&self.program), self.label, self.output.stdout.len(), self.output.stderr.len(),
        ))
    }
}
pub(crate) fn capture(client: &Path, args: &[OsString], label: &str) -> io::Result<Captured> {
    if label.is_empty()
        || label.len() > 128
        || !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process diagnostic label",
        ));
    }
    let program = client
        .file_name()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing process executable name",
            )
        })?
        .as_encoded_bytes()
        .to_vec();
    if program.is_empty() || program.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process executable name",
        ));
    }
    let started = SystemTime::now();
    let child = Command::new(client)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pid = child.id();
    let output = child.wait_with_output()?;
    Ok(Captured {
        output,
        pid,
        parent: std::process::id(),
        program,
        label: label.to_owned(),
        started,
        ended: SystemTime::now(),
    })
}
