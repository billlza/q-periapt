//! Windows first-use state preparation, publication and exact post-publication admission.
use super::*;
use std::{
    cell::RefCell,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Hook = Box<dyn FnMut(Stage, &Path) -> Result<()>>;
thread_local! { static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) }; }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    Prepared,
    Closed,
    Published,
    Admitted,
}
pub(super) fn at(stage: Stage, path: &Path) -> Result<()> {
    HOOK.with(|slot| match slot.borrow_mut().as_mut() {
        Some(hook) => hook(stage, path),
        None => Ok(()),
    })
}
struct HookGuard;
impl Drop for HookGuard {
    fn drop(&mut self) {
        HOOK.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn hook(callback: impl FnMut(Stage, &Path) -> Result<()> + 'static) -> HookGuard {
    HOOK.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(callback));
    });
    HookGuard
}

pub(super) mod fixture;
mod process;
use fixture::{load, Case};

#[test]
fn windows_first_use_publishes_then_admits_the_exact_original_state() -> TestResult<()> {
    let c = Case::new()?;
    let mut store = c.input.provision(&c.target)?;
    assert!(store.runtime()?.is_enabled()?);
    assert!(matches!(
        c.input.reconcile(&c.target),
        Err(Error::Store(StoreError::Busy))
    ));
    let key = fs::read(c.target.join("wrap.key"))?;
    let floor = store.runtime()?.trusted_state();
    store.close();
    let mut restored = c.input.reconcile(&c.target)?;
    assert_eq!(restored.runtime()?.trusted_state(), floor);
    restored.close();
    assert!(
        fs::read(c.target.join("wrap.key"))? == key,
        "wrapping key changed"
    );
    assert!(matches!(
        c.input.provision(&c.target),
        Err(Error::Publication(_))
    ));
    assert_eq!(fs::read_dir(&c.target)?.count(), 12);
    c.assert_inputs()?;
    Ok(())
}

#[test]
fn windows_first_use_faults_never_release_an_owner_or_recreate_state() -> TestResult<()> {
    for fault in [
        Stage::Prepared,
        Stage::Closed,
        Stage::Published,
        Stage::Admitted,
    ] {
        let c = Case::new()?;
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = fired.clone();
        let guard = hook(move |stage, _| {
            if stage == fault {
                observed.set(true);
                Err(Error::Io(io::Error::other("first-use boundary sentinel")))
            } else {
                Ok(())
            }
        });
        assert!(
            matches!(c.input.provision(&c.target), Err(Error::Io(ref error)) if error.to_string()=="first-use boundary sentinel")
        );
        assert!(fired.get());
        drop(guard);
        let published = matches!(fault, Stage::Published | Stage::Admitted);
        assert_eq!(c.target.exists(), published);
        if published {
            let key = fs::read(c.target.join("wrap.key"))?;
            c.input.reconcile(&c.target)?.close();
            assert!(
                fs::read(c.target.join("wrap.key"))? == key,
                "wrapping key changed"
            );
            c.assert_inputs()?;
        } else {
            let staged = c.staged()?;
            assert_eq!(staged.len(), 1);
            // Inspect this controlled fixture only; recovery never selects staging.
            assert_eq!(fs::read_dir(staged.first().ok_or("staging")?)?.count(), 12);
        }
        eprintln!("WINDOWS_FIRST_USE_FAULT stage={fault:?} published={published} owner_returned=false original_error=true");
    }
    Ok(())
}

#[test]
fn windows_first_use_missing_key_and_advanced_policy_are_never_repaired() -> TestResult<()> {
    let c = Case::new()?;
    c.input.provision(&c.target)?.close();
    let original = fs::read(c.target.join("wrap.key"))?;
    fs::rename(c.target.join("wrap.key"), c.root.join("retained.key"))?;
    assert!(matches!(
        c.input.reconcile(&c.target),
        Err(Error::Durable(_))
    ));
    assert!(!c.target.join("wrap.key").exists());
    assert!(
        fs::read(c.root.join("retained.key"))? == original,
        "retained key changed"
    );
    fs::rename(c.root.join("retained.key"), c.target.join("wrap.key"))?;
    let mut store = c.input.reconcile(&c.target)?;
    let (policy, signature, _) = fixture::sdk_policy(2)?;
    let previous = store.runtime()?.trusted_state();
    store.replace_policy(previous, &policy, &signature)?;
    store.close();
    assert!(matches!(
        c.input.reconcile(&c.target),
        Err(Error::Changed(_))
    ));
    let mut current = c.input.sdk.open(&c.target.join("sdk.redb"))?;
    assert_eq!(current.runtime()?.trusted_state().version(), 2);
    current.close();
    assert!(
        fs::read(c.target.join("wrap.key"))? == original,
        "wrapping key changed"
    );
    Ok(())
}

#[test]
fn windows_first_use_recoverable_trust_remains_independent_on_reopen() -> TestResult<()> {
    use q_periapt_sig::Signer;
    let mut c = Case::new()?;
    let fixed = load(&c.root.join("request"))?;
    let (key, public) = q_periapt_backends::MlDsa65::generate([61; 32]);
    let key = Zeroizing::new(key);
    let trust = PolicyRecoveryTrust::new([62; 32], &c.input.sdk.root, &public)?;
    let mut proof = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
    q_periapt_backends::MlDsa65
        .sign(
            key.as_ref(),
            &trust.enrollment_message(),
            &[63; 32],
            &mut proof,
        )
        .map_err(|error| io::Error::other(format!("recovery fixture signing: {error}")))?;
    c.input.sdk = SdkConfiguration::new_recoverable(
        &c.input.sdk.policy,
        &c.input.sdk.signature,
        &trust,
        &proof,
    )?;
    let mut store = c.input.provision(&c.target)?;
    assert!(matches!(
        c.input.reconcile(&c.target),
        Err(Error::Store(StoreError::Busy))
    ));
    store.close();
    assert_eq!(fs::read_dir(&c.target)?.count(), 14);
    assert!(matches!(
        fixed.reconcile(&c.target),
        Err(Error::Store(StoreError::RecoveryRequired))
    ));
    let wrong = PolicyRecoveryTrust::new([64; 32], &c.input.sdk.root, &public)?;
    assert!(matches!(
        PolicyStore::open_recoverable(&c.target.join("sdk.redb"), &wrong, Limits::default()),
        Err(StoreError::RootMismatch)
    ));
    c.input.reconcile(&c.target)?.close();
    c.assert_inputs()?;
    Ok(())
}
