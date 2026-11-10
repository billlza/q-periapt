use super::*;
use crate::sdk::tests::{fixture, out, span, TESTS};
use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_policy::policy_signature_message;
use q_periapt_sig::Signer;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("persistent-abi2-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private test directory")
}
fn signed(version: u32, enabled: bool) -> (Vec<u8>, Vec<u8>) {
    let policy = String::from_utf8(fixture().0.clone())
        .expect("fixture UTF-8")
        .replace("policy_version = 2", &format!("policy_version = {version}"));
    let policy = if enabled {
        policy
    } else {
        policy.replace("ML-KEM-768", "ML-KEM-1024")
    }
    .into_bytes();
    let (key, _) = MlDsa65::generate([42; 32]);
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &key,
            &policy_signature_message(&policy),
            &[0; 32],
            &mut signature,
        )
        .expect("test signature");
    (policy, signature)
}
fn options(path: &[u8], policy: &[u8], signature: &[u8]) -> QPeriaptStoreOptions {
    QPeriaptStoreOptions {
        struct_size: size_of::<QPeriaptStoreOptions>() as u32,
        extension_version: 1,
        path: span(path),
        policy: span(policy),
        signature: span(signature),
        trust_root: span(&fixture().2),
        max_live_keys: 2,
        max_in_flight: 2,
    }
}
fn local<const N: usize>(registry: &Registry<N>, path: &Path) -> (u64, Arc<PersistentRuntime>) {
    let (policy, signature, root) = fixture();
    let owner = Arc::new(
        construct(
            path.to_str().expect("test path"),
            policy,
            signature,
            root,
            sdk::Limits::default(),
            true,
        )
        .expect("provision"),
    );
    let mut slot = registry.reserve(0).expect("root slot");
    let id = slot.id();
    slot.install(Object::Persistent(Arc::clone(&owner)))
        .expect("install");
    slot.publish().expect("publish");
    (id, owner)
}

#[test]
fn actual_abi2_persistent_key_policy_and_restart_roundtrip() {
    let _serial = TESTS.lock().expect("serial SDK tests");
    let folder = directory();
    let path = folder
        .path()
        .canonicalize()
        .expect("canonical")
        .join("policy.redb");
    let path = path.to_str().expect("path").as_bytes();
    let (policy, signature, _) = fixture();
    let config = options(path, policy, signature);
    let mut runtime = 0;
    // SAFETY: all fixtures/outputs have complete independent lifetimes and sizes.
    unsafe {
        assert_eq!(
            q_periapt_sdk_runtime_provision_store(&config, &mut runtime),
            Q_PERIAPT_OK
        );
        let mut second = u64::MAX;
        assert_eq!(
            q_periapt_sdk_runtime_open_store(&config, &mut second),
            Q_PERIAPT_ERR_STORE_BUSY
        );
        assert_eq!(second, 0);
        let mut key = 0;
        assert_eq!(q_periapt_sdk_key_generate(runtime, &mut key), Q_PERIAPT_OK);
        let mut public = vec![0; sdk::PUBLIC_KEY_LEN];
        let mut ciphertext = vec![0; sdk::CIPHERTEXT_LEN];
        assert_eq!(
            q_periapt_sdk_key_public(key, out(&mut public)),
            Q_PERIAPT_OK
        );
        let (mut sender, mut receiver) = (0, 0);
        assert_eq!(
            q_periapt_sdk_encapsulate(
                runtime,
                span(&public),
                span(&[]),
                out(&mut ciphertext),
                &mut sender
            ),
            Q_PERIAPT_OK
        );
        assert_eq!(
            q_periapt_sdk_decapsulate(key, span(&ciphertext), span(&[]), &mut receiver),
            Q_PERIAPT_OK
        );
        let (mut left, mut right) = ([0; 32], [0; 32]);
        assert_eq!(
            q_periapt_sdk_secret_export(sender, out(&mut left)),
            Q_PERIAPT_OK
        );
        assert_eq!(
            q_periapt_sdk_secret_export(receiver, out(&mut right)),
            Q_PERIAPT_OK
        );
        assert_eq!(left, right);
        let (revoked, revoked_signature) = signed(3, false);
        let mut manual = u64::MAX;
        assert_eq!(
            q_periapt_sdk_runtime_prepare_update(
                runtime,
                span(&revoked),
                span(&revoked_signature),
                &mut manual
            ),
            Q_PERIAPT_ERR_STORAGE_REQUIRED
        );
        assert_eq!(manual, 0);
        let mut next = 0;
        assert_eq!(
            q_periapt_sdk_runtime_update_store(
                runtime,
                span(&revoked),
                span(&revoked_signature),
                &mut next
            ),
            Q_PERIAPT_OK
        );
        assert!(next > runtime);
        assert_eq!(q_periapt_sdk_close(runtime), Q_PERIAPT_ERR_CLOSED);
        assert_eq!(
            q_periapt_sdk_key_public(key, out(&mut public)),
            Q_PERIAPT_ERR_CLOSED
        );
        assert!(public.iter().all(|byte| *byte == 0));
        assert_eq!(
            q_periapt_sdk_secret_export(receiver, out(&mut right)),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(right, [0; 32]);
        let mut enabled = 1;
        assert_eq!(
            q_periapt_sdk_runtime_enabled(next, &mut enabled),
            Q_PERIAPT_OK
        );
        assert_eq!(enabled, 0);
        assert_eq!(q_periapt_sdk_close(next), Q_PERIAPT_OK);
        assert_eq!(
            q_periapt_sdk_runtime_open_store(&config, &mut runtime),
            Q_PERIAPT_ERR_POLICY
        );
        assert_eq!(runtime, 0);
        let (allowed, allowed_signature) = signed(4, true);
        let config = options(path, &allowed, &allowed_signature);
        assert_eq!(
            q_periapt_sdk_runtime_open_store(&config, &mut runtime),
            Q_PERIAPT_OK
        );
        assert_eq!(
            q_periapt_sdk_runtime_enabled(runtime, &mut enabled),
            Q_PERIAPT_OK
        );
        assert_eq!(enabled, 1);
        let mut state = [0; 36];
        assert_eq!(
            q_periapt_sdk_runtime_state(runtime, out(&mut state)),
            Q_PERIAPT_OK
        );
        assert_eq!(state.get(..4), Some([0, 0, 0, 4].as_slice()));
        assert_eq!(q_periapt_sdk_close(runtime), Q_PERIAPT_OK);
    }
}

#[test]
fn input_shapes_aliases_and_call_exhaustion_do_not_write_or_commit() {
    let _serial = TESTS.lock().expect("serial SDK tests");
    let folder = directory();
    let path = folder
        .path()
        .canonicalize()
        .expect("canonical")
        .join("policy.redb");
    let path_bytes = path.to_str().expect("path").as_bytes();
    let (policy, signature, _) = fixture();
    let mut config = options(path_bytes, policy, signature);
    let mut handle = u64::MAX;
    // SAFETY: valid regions; deliberately rejected aliasing precedes dereference.
    unsafe {
        config.path.len = Q_PERIAPT_STORE_MAX_PATH_BYTES + 1;
        assert_eq!(
            q_periapt_sdk_runtime_provision_store(&config, &mut handle),
            Q_PERIAPT_ERR_LENGTH
        );
        assert_eq!(handle, u64::MAX);
        assert!(!path.exists());
        config.path = span(path_bytes);
        let mut alias = [0xa5; 8];
        config.path = span(&alias);
        assert_eq!(
            q_periapt_sdk_runtime_provision_store(&config, alias.as_mut_ptr().cast()),
            Q_PERIAPT_ERR_ALIASING
        );
        assert_eq!(alias, [0xa5; 8]);
        config.path = span(path_bytes);
        assert_eq!(
            q_periapt_sdk_runtime_provision_store(&config, &mut handle),
            Q_PERIAPT_OK
        );
        let (next, signature) = signed(3, false);
        let admissions: Vec<_> = (0..Q_PERIAPT_SDK_MAX_CALLS)
            .map(|_| Admission::enter().expect("call capacity"))
            .collect();
        let mut result = u64::MAX;
        assert_eq!(
            q_periapt_sdk_runtime_update_store(handle, span(&next), span(&signature), &mut result),
            Q_PERIAPT_ERR_RESOURCE_LIMIT
        );
        assert_eq!(result, 0);
        drop(admissions);
        let mut state = [0; 36];
        assert_eq!(
            q_periapt_sdk_runtime_state(handle, out(&mut state)),
            Q_PERIAPT_OK
        );
        assert_eq!(state.get(..4), Some([0, 0, 0, 2].as_slice()));
        assert_eq!(q_periapt_sdk_close(handle), Q_PERIAPT_OK);
    }
}

#[test]
fn full_registry_reuses_root_slot_and_stale_update_cannot_close_successor() {
    let folder = directory();
    let path = folder
        .path()
        .canonicalize()
        .expect("canonical")
        .join("policy.redb");
    let registry = Arc::new(Registry::<1>::new());
    let (id, owner) = local(&registry, &path);
    assert!(matches!(
        registry.reserve(0),
        Err(Q_PERIAPT_ERR_RESOURCE_LIMIT)
    ));
    let (policy, signature) = signed(3, true);
    let mut successor = 0;
    let mut waiting = None;
    assert_eq!(
        update(&registry, id, &policy, &signature, |next| {
            successor = next;
            let registry = Arc::clone(&registry);
            let owner = Arc::clone(&owner);
            let policy = policy.clone();
            let signature = signature.clone();
            // Capture the old epoch while the first update still holds its mutex.
            waiting = Some(std::thread::spawn(move || {
                update_owned(&registry, id, &owner, &policy, &signature, |_| Ok(()))
            }));
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(
        waiting.expect("queued update").join().expect("join"),
        Err(Q_PERIAPT_ERR_CLOSED)
    );
    assert!(successor > id);
    let Object::Persistent(next) = registry.get(successor).expect("successor").0 else {
        unreachable!("persistent owner");
    };
    assert!(next.runtime.is_enabled().expect("new runtime stays open"));
    assert_eq!(next.runtime.trusted_state().version(), 3);
    assert_eq!(registry.close(id), Err(Q_PERIAPT_ERR_CLOSED));
    assert_eq!(registry.close(successor), Ok(()));
}

#[test]
fn close_after_commit_prevents_publication_but_recovers_persisted_policy() {
    let _serial = TESTS.lock().expect("serial SDK tests");
    let folder = directory();
    let path = folder
        .path()
        .canonicalize()
        .expect("canonical")
        .join("policy.redb");
    let registry = Arc::new(Registry::<1>::new());
    let (id, owner) = local(&registry, &path);
    let (policy, signature) = signed(3, false);
    let mut output = u64::MAX;
    let mut closer = None;
    // SAFETY: complete disjoint scalar output; callback is private test scheduling.
    let status = unsafe {
        execute([], [(handle_output(&mut output), 8)], || {
            update(&registry, id, &policy, &signature, |next| {
                write(handle_output(&mut output), &next.to_ne_bytes())?;
                let cloned = Arc::clone(&registry);
                closer = Some(std::thread::spawn(move || cloned.close(id)));
                let deadline = Instant::now() + Duration::from_secs(5);
                while registry.get(id).is_ok() {
                    assert!(
                        Instant::now() < deadline,
                        "close did not remove root before waiting"
                    );
                    std::thread::yield_now();
                }
                Ok(())
            })
        })
    };
    assert_eq!(status, Q_PERIAPT_ERR_STORE_COMMITTED);
    assert_eq!(output, 0);
    assert_eq!(closer.expect("closer").join().expect("join"), Ok(()));
    assert!(owner.runtime.is_enabled().is_err());
    let store = PolicyStore::open_configured(
        &path,
        &policy,
        &signature,
        &fixture().2,
        sdk::Limits::default(),
    )
    .expect("recover committed policy");
    assert_eq!(
        store.runtime().expect("runtime").trusted_state().version(),
        3
    );
    assert!(!store
        .runtime()
        .expect("runtime")
        .is_enabled()
        .expect("disabled"));
}

#[test]
fn panic_after_commit_revokes_epochs_and_clears_output_before_foreign_return() {
    let _serial = TESTS.lock().expect("serial SDK tests");
    let folder = directory();
    let path = folder
        .path()
        .canonicalize()
        .expect("canonical")
        .join("policy.redb");
    let registry = owner_registry();
    let (id, owner) = local(registry, &path);
    let (policy, signature) = signed(3, false);
    let mut output = u64::MAX;
    // SAFETY: valid scalar output. resume_unwind deliberately tests the FFI boundary.
    let status = unsafe {
        execute([], [(handle_output(&mut output), 8)], || {
            update(registry, id, &policy, &signature, |next| {
                write(handle_output(&mut output), &next.to_ne_bytes())?;
                std::panic::resume_unwind(Box::new("injected post-commit unwind"))
            })
        })
    };
    assert_eq!(status, Q_PERIAPT_ERR_PANIC);
    assert_eq!(output, 0);
    assert!(owner.runtime.is_enabled().is_err());
    let mut stale_state = [0xa5; 36];
    // SAFETY: complete writable metadata output, checked after the unwind.
    assert_eq!(
        unsafe { q_periapt_sdk_runtime_state(id, out(&mut stale_state)) },
        Q_PERIAPT_ERR_CLOSED
    );
    assert_eq!(stale_state, [0; 36]);
    assert_eq!(registry.close(id), Err(Q_PERIAPT_ERR_INTERNAL)); // poison is reported after disposal
    let store = PolicyStore::open_configured(
        &path,
        &policy,
        &signature,
        &fixture().2,
        sdk::Limits::default(),
    )
    .expect("persistent recovery");
    assert!(!store
        .runtime()
        .expect("runtime")
        .is_enabled()
        .expect("disabled"));
}
