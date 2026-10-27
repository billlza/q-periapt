//! Native Windows key reopening: sync order, failures and real parent-ACL changes.
use crate::{
    crypto::Purpose, AnchorSigningKey, DeviceSigningKey, DurableError, JournalKey,
    PolicySigningKey, RootSigningKey, SigningKeyId,
};
use std::{
    cell::RefCell,
    fs,
    io::{self, Read, Seek},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// Only test-owned temporary directories are configured. Initial privacy is set
// before key creation; later ACL changes occur at explicit fault boundaries.
// Paths are process-local data, never interpolated into PowerShell source.
const SET_DIRECTORY_ACL: &str = r#"
$ErrorActionPreference = 'Stop'
function Write-AclPhase([string] $phase) {
    [Console]::Out.WriteLine($phase)
    [Console]::Out.Flush()
}
Write-AclPhase 'QPC_ACL_PHASE script-enter'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
Write-AclPhase 'QPC_ACL_PHASE identity-ready'
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$none = [System.Security.AccessControl.PropagationFlags]::None
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, $none, $allow)
$acl.AddAccessRule($rule)
if ($env:QPC_KEY_TEST_BROAD_ACL -eq '1') {
    $world = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($world, 'Read', $allow)))
}
Write-AclPhase 'QPC_ACL_PHASE descriptor-ready'
[System.IO.Directory]::SetAccessControl($env:QPC_KEY_TEST_DIRECTORY, $acl)
Write-AclPhase 'QPC_ACL_PHASE acl-set'
"#;

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            if child.try_wait().expect("ACL helper status").is_none() {
                child.kill().expect("stop owned ACL helper");
                child.wait().expect("reap owned ACL helper");
            }
        }
    }
}

fn set_directory_acl(path: &Path, broad: bool) {
    let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("Windows root"));
    let executable = system.join("System32/WindowsPowerShell/v1.0/powershell.exe");
    // Flushed markers distinguish script entry, identity lookup and ACL work
    // without exposing the path or SID. Keep partial output when startup stalls.
    // Temporary files avoid backpressure from an unread child pipe.
    let mut stdout = tempfile::tempfile().expect("owned ACL stdout");
    let mut stderr = tempfile::tempfile().expect("owned ACL stderr");
    let started = Instant::now();
    let mut child = ChildGuard(Some(
        Command::new(executable)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                SET_DIRECTORY_ACL,
            ])
            .env("QPC_KEY_TEST_DIRECTORY", path)
            .env("QPC_KEY_TEST_BROAD_ACL", if broad { "1" } else { "0" })
            .stdout(Stdio::from(stdout.try_clone().expect("ACL stdout handle")))
            .stderr(Stdio::from(stderr.try_clone().expect("ACL stderr handle")))
            .spawn()
            .expect("start owned ACL helper"),
    ));
    let pid = child.0.as_ref().expect("helper").id();
    let deadline = Instant::now() + Duration::from_secs(20);
    const MAX_OUTPUT: usize = 8192;
    let output_limit = u64::try_from(MAX_OUTPUT).expect("bounded ACL output limit");
    let stopped = loop {
        if stdout.metadata().expect("ACL stdout length").len() > output_limit
            || stderr.metadata().expect("ACL stderr length").len() > output_limit
        {
            break Some("output limit");
        }
        if child
            .0
            .as_mut()
            .expect("helper")
            .try_wait()
            .expect("helper status")
            .is_some()
        {
            break None;
        }
        if Instant::now() >= deadline {
            break Some("deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if stopped.is_some() {
        let running = child.0.as_mut().expect("helper");
        if running.try_wait().expect("helper stop status").is_none() {
            running.kill().expect("stop owned ACL helper");
        }
    }
    let status = child
        .0
        .take()
        .expect("owned helper")
        .wait()
        .expect("reap owned ACL helper");
    let capture = |file: &mut fs::File| {
        file.rewind().expect("ACL output position");
        let mut bytes = Vec::new();
        file.take(output_limit + 1)
            .read_to_end(&mut bytes)
            .expect("ACL bounded output");
        bytes
    };
    let stdout = capture(&mut stdout);
    let stderr = capture(&mut stderr);
    assert!(
        stopped.is_none()
            && stdout.len() <= MAX_OUTPUT
            && stderr.len() <= MAX_OUTPUT
            && status.success(),
        "ACL helper failed: stopped={stopped:?} pid={pid} elapsed={:?} status={status} stdout={:?} stderr={:?}",
        started.elapsed(),
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    let phases = std::str::from_utf8(&stdout)
        .expect("ACL helper phase encoding")
        .lines()
        .collect::<Vec<_>>();
    assert!(
        phases
            == [
                "QPC_ACL_PHASE script-enter",
                "QPC_ACL_PHASE identity-ready",
                "QPC_ACL_PHASE descriptor-ready",
                "QPC_ACL_PHASE acl-set",
            ]
            && stderr.is_empty(),
        "unexpected ACL helper output"
    );
}

pub(crate) fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("owned fixture");
    let path = dir.path().canonicalize().expect("canonical fixture");
    set_directory_acl(&path, false);
    q_periapt_host_store::filesystem::OwnedPrivateDirectory::open(&path)
        .expect("actual private-directory admission");
    dir
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Boundary {
    WrappingFile,
    WrappingDirectory,
    SigningFile,
    SigningDirectory,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Point {
    boundary: Boundary,
    after: bool,
}
#[derive(Debug)]
struct SyncFault(Point);
impl std::fmt::Display for SyncFault {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Windows key reopen sync fault {:?}", self.0)
    }
}
impl std::error::Error for SyncFault {}
struct Probe {
    seen: Vec<Point>,
    fault: Option<Point>,
    broaden: Option<std::path::PathBuf>,
}
thread_local! { static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) }; }
pub(crate) fn at_sync(boundary: Boundary, after: bool) -> Result<(), DurableError> {
    PROBE.with(|cell| {
        let mut state = cell.borrow_mut();
        let Some(probe) = state.as_mut() else {
            return Ok(());
        };
        let point = Point { boundary, after };
        probe.seen.push(point);
        if probe.fault == Some(point) {
            return Err(io::Error::other(SyncFault(point)).into());
        }
        if !after
            && matches!(
                boundary,
                Boundary::WrappingDirectory | Boundary::SigningDirectory
            )
        {
            if let Some(path) = probe.broaden.take() {
                set_directory_acl(&path, true);
            }
        }
        Ok(())
    })
}
struct ProbeGuard;
impl ProbeGuard {
    fn arm(fault: Option<Point>, broaden: Option<&Path>) -> Self {
        PROBE.with(|cell| {
            assert!(cell.borrow().is_none());
            *cell.borrow_mut() = Some(Probe {
                seen: Vec::new(),
                fault,
                broaden: broaden.map(Path::to_path_buf),
            });
        });
        Self
    }
    fn seen(&self) -> Vec<Point> {
        PROBE.with(|cell| cell.borrow().as_ref().expect("armed probe").seen.clone())
    }
}
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        PROBE.with(|cell| {
            cell.borrow_mut().take();
        });
    }
}
fn expected(file: Boundary, directory: Boundary) -> Vec<Point> {
    [file, directory]
        .into_iter()
        .flat_map(|boundary| [false, true].map(|after| Point { boundary, after }))
        .collect()
}

#[test]
fn wrapping_key_sync_the_original_file_and_parent_before_returning() {
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    drop(JournalKey::provision(&root.join("wrapping")).expect("wrapping"));
    let probe = ProbeGuard::arm(None, None);
    let wrapping = JournalKey::open(&root.join("wrapping")).expect("reopened wrapping owner");
    eprintln!(
        "WINDOWS_KEY_REOPEN_TRACE kind=wrapping owner_returned=true points={:?}",
        probe.seen()
    );
    assert_eq!(
        probe.seen(),
        expected(Boundary::WrappingFile, Boundary::WrappingDirectory)
    );
    drop(probe);
    drop(wrapping);
    eprintln!("WINDOWS_KEY_REOPEN wrapping=true file_then_parent_sync=true");
}

#[test]
fn signing_roles_sync_the_original_file_and_parent_before_returning() {
    let dir = directory();
    let root = dir.path().canonicalize().expect("path");
    let wrapping = JournalKey::provision(&root.join("wrapping")).expect("wrapping");
    macro_rules! check {
        ($owner:ident, $name:literal) => {{
            let id = SigningKeyId::generate().expect("independent ID");
            let path = root.join($name);
            let mut owner = $owner::provision(&path, &wrapping, id).expect("provision signer");
            let public = owner.public_key().expect("public");
            owner.close();
            let probe = ProbeGuard::arm(None, None);
            let restored = $owner::open(&path, &wrapping, id).expect("restored signer");
            eprintln!(
                "WINDOWS_KEY_REOPEN_TRACE kind=signing role={} owner_returned=true points={:?}",
                $name,
                probe.seen()
            );
            assert_eq!(
                probe.seen(),
                expected(Boundary::SigningFile, Boundary::SigningDirectory)
            );
            drop(probe);
            assert_eq!(restored.public_key().expect("public"), public);
            let signature = restored
                .sign(Purpose::Credential, b"native reopen")
                .expect("sign");
            public
                .verify(Purpose::Credential, b"native reopen", &signature)
                .expect("same signer");
        }};
    }
    check!(RootSigningKey, "root");
    check!(DeviceSigningKey, "device");
    check!(PolicySigningKey, "policy");
    check!(AnchorSigningKey, "anchor");
    eprintln!("WINDOWS_KEY_REOPEN signing_roles=4 file_then_parent_sync=true");
}

#[test]
fn every_reopen_sync_fault_withholds_the_owner_and_preserves_key_bytes() {
    for boundary in [
        Boundary::WrappingFile,
        Boundary::WrappingDirectory,
        Boundary::SigningFile,
        Boundary::SigningDirectory,
    ] {
        for after in [false, true] {
            let dir = directory();
            let root = dir.path().canonicalize().expect("path");
            let wrapping = JournalKey::provision(&root.join("wrapping")).expect("wrapping");
            let id = SigningKeyId::generate().expect("ID");
            let owner =
                DeviceSigningKey::provision(&root.join("device"), &wrapping, id).expect("signer");
            let public = owner.public_key().expect("public");
            drop(owner);
            let wrapping_bytes = fs::read(root.join("wrapping")).expect("wrapping bytes");
            let signer_bytes = fs::read(root.join("device")).expect("signer bytes");
            let point = Point { boundary, after };
            let probe = ProbeGuard::arm(Some(point), None);
            let result = if matches!(
                boundary,
                Boundary::WrappingFile | Boundary::WrappingDirectory
            ) {
                JournalKey::open(&root.join("wrapping")).map(drop)
            } else {
                DeviceSigningKey::open(&root.join("device"), &wrapping, id).map(drop)
            };
            assert!(
                matches!(result, Err(DurableError::Io(ref error)) if error.get_ref().and_then(|e| e.downcast_ref::<SyncFault>()).is_some_and(|fault| fault.0 == point))
            );
            let seen = probe.seen();
            assert_eq!(seen.last(), Some(&point));
            let prefix = if matches!(
                boundary,
                Boundary::WrappingFile | Boundary::WrappingDirectory
            ) {
                expected(Boundary::WrappingFile, Boundary::WrappingDirectory)
            } else {
                expected(Boundary::SigningFile, Boundary::SigningDirectory)
            };
            let position = prefix.iter().position(|p| *p == point).expect("point");
            assert_eq!(
                seen.as_slice(),
                prefix.get(..=position).expect("exact stopped prefix")
            );
            drop(probe);
            assert!(
                fs::read(root.join("wrapping")).expect("retained") == wrapping_bytes,
                "wrapping key bytes changed"
            );
            assert!(
                fs::read(root.join("device")).expect("retained") == signer_bytes,
                "signing key bytes changed"
            );
            let recovered = JournalKey::open(&root.join("wrapping")).expect("same wrapping");
            assert_eq!(
                DeviceSigningKey::open(&root.join("device"), &recovered, id)
                    .expect("same signer")
                    .public_key()
                    .expect("public"),
                public
            );
            eprintln!("WINDOWS_KEY_REOPEN_FAULT boundary={boundary:?} after={after} exact_error=true owner_returned=false bytes_preserved=true");
        }
    }
}

#[test]
fn actual_parent_acl_change_after_read_prevents_owner_release() {
    for boundary in [Boundary::WrappingDirectory, Boundary::SigningDirectory] {
        let dir = directory();
        let root = dir.path().canonicalize().expect("path");
        let wrapping = JournalKey::provision(&root.join("wrapping")).expect("wrapping");
        let id = SigningKeyId::generate().expect("ID");
        let owner =
            DeviceSigningKey::provision(&root.join("device"), &wrapping, id).expect("signer");
        let public = owner.public_key().expect("public");
        drop(owner);
        let probe = ProbeGuard::arm(None, Some(&root));
        let result = if boundary == Boundary::WrappingDirectory {
            JournalKey::open(&root.join("wrapping")).map(drop)
        } else {
            DeviceSigningKey::open(&root.join("device"), &wrapping, id).map(drop)
        };
        assert!(matches!(result, Err(DurableError::PrivateFile)));
        assert_eq!(
            probe.seen().last(),
            Some(&Point {
                boundary,
                after: false
            })
        );
        drop(probe);
        set_directory_acl(&root, false);
        let recovered = JournalKey::open(&root.join("wrapping")).expect("original wrapping");
        assert_eq!(
            DeviceSigningKey::open(&root.join("device"), &recovered, id)
                .expect("original signer")
                .public_key()
                .expect("public"),
            public
        );
        eprintln!("WINDOWS_KEY_REOPEN_ACL boundary={boundary:?} actual_acl_changed=true owner_returned=false original_recovered=true");
    }
}
