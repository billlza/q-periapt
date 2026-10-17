//! Real owned-child termination around the shared directory publication barriers.
use super::*;
use std::{
    process::{Child, Command, Stdio},
    time::Instant,
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

#[test]
fn windows_directory_process_child() -> Result<()> {
    let Some(root) = std::env::var_os("QPC_DIRECTORY_CUT_ROOT") else {
        return Ok(());
    };
    let parent = PathBuf::from(root);
    let wanted = std::env::var("QPC_DIRECTORY_CUT_STAGE")?;
    publish_with(&parent.join("installation"), prepare, |stage, _| {
        if format!("{stage:?}") == wanted {
            publish_private_bytes(&parent.join("ready"), wanted.as_bytes())
                .map_err(io::Error::other)?;
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                std::thread::park_timeout(Duration::from_millis(20));
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned child was not terminated",
            ));
        }
        Ok(())
    })?;
    publish_private_bytes(&parent.join("returned"), b"unexpected return")?;
    Err("cut child returned without termination".into())
}

#[test]
fn windows_directory_process_cuts_preserve_publication_state() -> Result<()> {
    for (cut, published) in [
        (Step::Initialized, false),
        (Step::BeforeRename, false),
        (Step::Published, true),
        (Step::ParentSynced, true),
    ] {
        let temporary = directory()?;
        let root = temporary.path();
        let log = fs::File::create_new(root.join("child.log"))?;
        let label = format!("{cut:?}");
        let mut child = ChildGuard(Command::new(std::env::current_exe()?)
            .args(["--exact", "filesystem::directory_publication::windows_tests::process::windows_directory_process_child", "--nocapture"])
            .env("QPC_DIRECTORY_CUT_ROOT", root).env("QPC_DIRECTORY_CUT_STAGE", &label)
            .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
        let deadline = Instant::now() + Duration::from_secs(15);
        while !root.join("ready").exists() {
            if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
                return Err(format!(
                    "child failed before {label}: {}",
                    fs::read_to_string(root.join("child.log"))?
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read(root.join("ready"))?, label.as_bytes());
        assert!(!root.join("returned").exists());
        child.0.kill()?;
        assert!(!child.0.wait()?.success());
        let target = root.join("installation");
        assert_eq!(target.exists(), published);
        if published {
            complete(&target)?;
        } else {
            let staged: Vec<_> = fs::read_dir(root)?
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|p| {
                    p.file_name()
                        .to_string_lossy()
                        .starts_with(".private-tree-")
                })
                .collect();
            assert_eq!(staged.len(), 1);
            complete(&staged.first().ok_or("missing staging")?.path())?;
        }
        eprintln!(
            "WINDOWS_DIRECTORY_PROCESS cut={cut:?} published={published} no_returned_value=true"
        );
    }
    Ok(())
}
