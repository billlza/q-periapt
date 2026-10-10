// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One bounded installed receiver process, shared by account and first-use workloads.
use crate::{fixture, Result};
use std::{
    ffi::OsString,
    fs,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) struct Server {
    child: fixture::OwnedChild,
    stdout: PathBuf,
    stderr: PathBuf,
    foreign: Option<(&'static str, String)>,
}
pub(crate) fn start_selected(
    client: &Path,
    language: Option<&'static str>,
    path: &Path,
    label: &str,
    args: &[OsString],
) -> Result<(Server, SocketAddr)> {
    let stdout = path.join(format!("traffic-{label}.stdout"));
    let stderr = path.join(format!("traffic-{label}.stderr"));
    let output = |path: &Path| {
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
    };
    let mut server = Server {
        child: fixture::OwnedChild(
            Command::new(client)
                .args(args)
                .stdout(Stdio::from(output(&stdout)?))
                .stderr(Stdio::from(output(&stderr)?))
                .spawn()?,
        ),
        stdout,
        stderr,
        foreign: language.map(|language| (language, label.to_owned())),
    };
    let until = Instant::now() + Duration::from_secs(25);
    loop {
        let text = fs::read_to_string(&server.stdout)?;
        if let Some((line, _)) = text.split_once('\n') {
            let port: u16 = line
                .strip_prefix("listening:")
                .ok_or("C readiness prefix")?
                .parse()?;
            if port == 0 {
                return Err("C zero listener port".into());
            }
            return Ok((server, SocketAddr::from(([127, 0, 0, 1], port))));
        }
        if let Some(status) = server.child.0.try_wait()? {
            return Err(format!(
                "{} traffic receiver {label} exited before readiness ({status}): {text}; {}",
                language.unwrap_or("C"),
                fs::read_to_string(&server.stderr)?
            )
            .into());
        }
        if Instant::now() >= until {
            return Err(format!(
                "{} traffic receiver {label} timed out before readiness: {text}; {}",
                language.unwrap_or("C"),
                fs::read_to_string(&server.stderr)?
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub(crate) fn finish(mut server: Server, expected: i32) -> Result<String> {
    let status = fixture::wait(&mut server.child)?;
    let stdout = fs::read_to_string(&server.stdout)?;
    let stderr = fs::read_to_string(&server.stderr)?;
    if status.code() != Some(expected) || !stderr.is_empty() {
        return Err(
            format!("C traffic server {status}, expected {expected}: {stdout}; {stderr}").into(),
        );
    }
    if let Some((language, label)) = &server.foreign {
        eprintln!("FOREIGN_ACCOUNT_RECEIVER language={language} label={label} exit={expected}");
    }
    Ok(stdout
        .split_once('\n')
        .ok_or("server readiness")?
        .1
        .to_owned())
}
