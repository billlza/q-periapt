//! Owned-child cuts and a real competing opener at the post-publication admission boundary.
use super::*;
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().expect("child status").is_none() {
            self.0.kill().expect("stop owned child");
            self.0.wait().expect("reap owned child");
        }
    }
}
fn start(c: &Case, stage: Stage, expected: &str) -> TestResult<ChildGuard> {
    let log = fs::File::create_new(c.root.join("child.log"))?;
    let child = ChildGuard(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "first_install::windows_tests::process::windows_first_use_process_child",
                "--nocapture",
            ])
            .env("QPC_FIRST_USE_CASE", &c.root)
            .env("QPC_FIRST_USE_STAGE", format!("{stage:?}"))
            .env("QPC_FIRST_USE_EXPECTED", expected)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    Ok(child)
}
fn ready(c: &Case, child: &mut ChildGuard, stage: Stage) -> TestResult<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !c.root.join("ready").exists() {
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "child failed before {stage:?}: {}",
                fs::read_to_string(c.root.join("child.log"))?
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        fs::read(c.root.join("ready"))?,
        format!("{stage:?}").as_bytes()
    );
    assert!(!c.root.join("outcome").exists());
    Ok(())
}
fn finish(c: &Case, child: &mut ChildGuard, expected: &str) -> TestResult<()> {
    publish_private_bytes(&c.root.join("resume"), b"resume original attempt")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err(format!(
                    "child failed: {}",
                    fs::read_to_string(c.root.join("child.log"))?
                )
                .into());
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err("child did not finish original admission".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fs::read(c.root.join("outcome"))?, expected.as_bytes());
    Ok(())
}

#[test]
fn windows_first_use_process_child() -> TestResult<()> {
    let Some(root) = std::env::var_os("QPC_FIRST_USE_CASE") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let input = load(&root.join("request"))?;
    let wanted = std::env::var("QPC_FIRST_USE_STAGE")?;
    let expected = std::env::var("QPC_FIRST_USE_EXPECTED")?;
    let control = root.clone();
    let guard = hook(move |stage, _| {
        if format!("{stage:?}") == wanted {
            publish_private_bytes(&control.join("ready"), wanted.as_bytes())?;
            let deadline = Instant::now() + Duration::from_secs(30);
            while !control.join("resume").exists() {
                if Instant::now() >= deadline {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "parent did not resume original attempt",
                    )));
                }
                std::thread::park_timeout(Duration::from_millis(10));
            }
        }
        Ok(())
    });
    let result = input.provision(&root.join("installation"));
    drop(guard);
    match expected.as_str() {
        "busy" => assert!(matches!(result, Err(Error::Store(StoreError::Busy)))),
        "changed" => assert!(matches!(result, Err(Error::Changed(_)))),
        "missing" => assert!(matches!(result, Err(Error::Durable(_)))),
        _ => return Err("process-cut child returned instead of being terminated".into()),
    }
    publish_private_bytes(&root.join("outcome"), expected.as_bytes())?;
    Ok(())
}

#[test]
fn windows_first_use_process_cuts_keep_complete_publication_and_original_key() -> TestResult<()> {
    for stage in [
        Stage::Prepared,
        Stage::Closed,
        Stage::Published,
        Stage::Admitted,
    ] {
        let c = Case::new()?;
        let mut child = start(&c, stage, "kill")?;
        ready(&c, &mut child, stage)?;
        let published = matches!(stage, Stage::Published | Stage::Admitted);
        assert_eq!(c.target.exists(), published);
        if stage == Stage::Admitted {
            assert!(matches!(
                c.input.reconcile(&c.target),
                Err(Error::Store(StoreError::Busy))
            ));
        }
        child.0.kill()?;
        assert!(!child.0.wait()?.success());
        if published {
            let original = fs::read(c.target.join("wrap.key"))?;
            c.input.reconcile(&c.target)?.close();
            assert!(
                fs::read(c.target.join("wrap.key"))? == original,
                "wrapping key changed"
            );
            c.assert_inputs()?;
        } else {
            assert_eq!(c.staged()?.len(), 1);
            assert!(!c.target.exists());
        }
        eprintln!("WINDOWS_FIRST_USE_PROCESS stage={stage:?} published={published} owner_returned=false original_state_preserved=true");
    }
    Ok(())
}

#[test]
fn windows_first_use_competing_admission_never_returns_stale_or_recreated_state() -> TestResult<()>
{
    for change in ["busy", "changed", "missing"] {
        let c = Case::new()?;
        let mut child = start(&c, Stage::Published, change)?;
        ready(&c, &mut child, Stage::Published)?;
        let original = fs::read(c.target.join("wrap.key"))?;
        let mut competing = c.input.sdk.open(&c.target.join("sdk.redb"))?;
        match change {
            "changed" => {
                let (policy, signature, _) = fixture::sdk_policy(2)?;
                let prior = competing.runtime()?.trusted_state();
                competing.replace_policy(prior, &policy, &signature)?;
                competing.close();
            }
            "missing" => {
                competing.close();
                fs::rename(c.target.join("wrap.key"), c.root.join("retained.key"))?;
            }
            _ => {}
        }
        finish(&c, &mut child, change)?;
        competing.close();
        match change {
            "busy" => {
                c.input.reconcile(&c.target)?.close();
            }
            "changed" => {
                assert!(matches!(
                    c.input.reconcile(&c.target),
                    Err(Error::Changed(_))
                ));
                let mut current = c.input.sdk.open(&c.target.join("sdk.redb"))?;
                assert_eq!(current.runtime()?.trusted_state().version(), 2);
                current.close();
            }
            "missing" => {
                assert!(!c.target.join("wrap.key").exists());
                assert!(
                    fs::read(c.root.join("retained.key"))? == original,
                    "retained key changed"
                );
                assert!(matches!(
                    c.input.reconcile(&c.target),
                    Err(Error::Durable(_))
                ));
            }
            _ => return Err("unknown fixture change".into()),
        }
        eprintln!("WINDOWS_FIRST_USE_CONCURRENT outcome={change} fresh_admission_refused=true original_state_preserved=true");
    }
    Ok(())
}
