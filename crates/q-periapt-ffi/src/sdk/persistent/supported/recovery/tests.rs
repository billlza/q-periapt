use super::*;
use crate::sdk::tests::{out, span, TESTS};
use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_policy::policy_signature_message;
use q_periapt_sig::Signer;
use std::os::unix::fs::PermissionsExt;

struct Case {
    scope: [u8; 32],
    initial: Vec<u8>,
    recovery: Vec<u8>,
    incoming: Vec<u8>,
    recovery_key: Vec<u8>,
    incoming_key: Vec<u8>,
    initial_policy: Vec<u8>,
    initial_signature: Vec<u8>,
    next_policy: Vec<u8>,
    next_signature: Vec<u8>,
    enrollment: Vec<u8>,
}
fn sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(key, message, &[0; 32], &mut signature)
        .expect("fixture signature");
    signature
}
fn policy(version: u32, enabled: bool) -> Vec<u8> {
    format!("schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [\"{}\", \"X25519\"]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n", if enabled { "ML-KEM-768" } else { "ML-KEM-1024" }).into_bytes()
}
impl Case {
    fn new() -> Self {
        // Published deterministic test material, never operational issuer keys.
        let (initial_key, initial) = MlDsa65::generate([81; 32]);
        let (recovery_key, recovery) = MlDsa65::generate([82; 32]);
        let (incoming_key, incoming) = MlDsa65::generate([83; 32]);
        let initial_policy = policy(u32::MAX, true);
        let next_policy = policy(1, false);
        let mut value = Self {
            scope: [84; 32],
            initial: initial.to_vec(),
            recovery: recovery.to_vec(),
            incoming: incoming.to_vec(),
            recovery_key: recovery_key.to_vec(),
            incoming_key: incoming_key.to_vec(),
            initial_signature: sign(&initial_key, &policy_signature_message(&initial_policy)),
            initial_policy,
            next_signature: sign(&incoming_key, &policy_signature_message(&next_policy)),
            next_policy,
            enrollment: Vec::new(),
        };
        let mut message = vec![0; Q_PERIAPT_POLICY_RECOVERY_ENROLLMENT_MESSAGE_LEN];
        // SAFETY: owned disjoint fixed-length inputs/output.
        assert_eq!(
            unsafe {
                q_periapt_sdk_policy_recovery_enrollment_message(
                    span(&value.scope),
                    span(&value.initial),
                    span(&value.recovery),
                    out(&mut message),
                )
            },
            0
        );
        let trust = value.trust();
        assert_eq!(message, trust.enrollment_message());
        value.enrollment = sign(&value.recovery_key, &message);
        value
    }
    fn trust(&self) -> PolicyRecoveryTrust {
        PolicyRecoveryTrust::new(self.scope, &self.initial, &self.recovery).expect("fixture trust")
    }
    fn options(&self, path: &[u8], creating: bool) -> QPeriaptRecoverableStoreOptions {
        QPeriaptRecoverableStoreOptions {
            struct_size: size_of::<QPeriaptRecoverableStoreOptions>() as u32,
            extension_version: 1,
            path: span(path),
            policy: span(&self.initial_policy),
            signature: span(&self.initial_signature),
            scope: span(&self.scope),
            initial_root: span(&self.initial),
            recovery_root: span(&self.recovery),
            enrollment_signature: span(if creating { &self.enrollment } else { &[] }),
            max_live_keys: 2,
            max_in_flight: 2,
        }
    }
    fn authorization(&self, request: &[u8]) -> Vec<u8> {
        let mut approval = vec![0; Q_PERIAPT_POLICY_RECOVERY_APPROVAL_MESSAGE_LEN];
        let mut possession = vec![0; Q_PERIAPT_POLICY_RECOVERY_POSSESSION_MESSAGE_LEN];
        // SAFETY: both initialized output allocations are exact and disjoint.
        assert_eq!(
            unsafe {
                q_periapt_sdk_policy_recovery_signing_messages(
                    span(request),
                    out(&mut approval),
                    out(&mut possession),
                )
            },
            0
        );
        assert_ne!(approval, possession);
        // This is the public C encoding contract, not a Rust authorization encoder.
        let mut bytes = request.to_vec();
        bytes.extend_from_slice(&sign(&self.recovery_key, &approval));
        bytes.extend_from_slice(&sign(&self.incoming_key, &possession));
        assert_eq!(bytes.len(), Q_PERIAPT_POLICY_RECOVERY_AUTHORIZATION_LEN);
        bytes
    }
}
fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("recovery-abi2-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("private test directory")
}
fn key(handle: u64) -> u64 {
    let mut result = 0;
    // SAFETY: independent writable scalar output.
    assert_eq!(
        unsafe { q_periapt_sdk_key_generate(handle, &mut result) },
        0
    );
    result
}
fn public(handle: u64) -> Vec<u8> {
    let mut bytes = vec![0; sdk::PUBLIC_KEY_LEN];
    // SAFETY: independent exact output region.
    assert_eq!(
        unsafe { q_periapt_sdk_key_public(handle, out(&mut bytes)) },
        0
    );
    bytes
}
fn state(handle: u64) -> Vec<u8> {
    let mut bytes = vec![0; 36];
    // SAFETY: independent exact output region.
    assert_eq!(
        unsafe { q_periapt_sdk_runtime_state(handle, out(&mut bytes)) },
        0
    );
    bytes
}

#[test]
fn c_recovery_on_bounded_foreign_worker() {
    const CHILD: &str = "QPERIAPT_RECOVERY_STACK_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // A stack overflow aborts rather than unwinds. Isolate it so the parent
        // reports this specific regression and retains the child's diagnostics.
        let child = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "sdk::persistent::supported::recovery::tests::c_recovery_on_bounded_foreign_worker",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("run bounded-stack regression");
        assert!(
            child.status.success(),
            "bounded recovery worker failed: {}\n{}\n{}",
            child.status,
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        return;
    }
    let _serial = TESTS.lock().expect("serial SDK tests");
    // Issuer key generation/signing is deliberately outside the foreign worker.
    // The worker verifies real signatures and performs all durable transitions.
    let case = Case::new();
    let preparation = directory();
    let preparation_path = preparation
        .path()
        .canonicalize()
        .expect("canonical")
        .join("policy.redb");
    let mut source = PolicyStore::provision_recoverable(
        &preparation_path,
        &case.initial_policy,
        &case.initial_signature,
        &case.trust(),
        &case.enrollment,
        sdk::Limits::default(),
    )
    .expect("prepare independent issuer request");
    let request = source
        .prepare_authority_recovery(
            [85; 32],
            &case.next_policy,
            &case.next_signature,
            &case.incoming,
        )
        .expect("issuer request")
        .to_bytes();
    let authorization = case.authorization(&request);
    source.close();
    let folder = directory();
    let path = folder
        .path()
        .canonicalize()
        .expect("canonical")
        .join("policy.redb");
    std::thread::Builder::new()
        .name("foreign-recovery".to_owned())
        // Smaller than the 544 KiB Swift worker on which this path overflowed.
        .stack_size(512 * 1024)
        .spawn(move || {
            let path = path.to_str().expect("UTF-8").as_bytes();
            let mut config = case.options(path, true);
            let mut initial = 0;
            let mut next = 0;
            let mut disposition = 0;
            let mut statement = vec![0; Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN];
            // SAFETY: all options/inputs and scalar/buffer outputs remain live,
            // initialized and disjoint throughout each synchronous native call.
            unsafe {
                assert_eq!(
                    q_periapt_sdk_runtime_provision_recoverable_store(&config, &mut initial),
                    0
                );
                assert_eq!(
                    q_periapt_sdk_runtime_prepare_recovery(
                        initial,
                        span(&[85; 32]),
                        span(&case.next_policy),
                        span(&case.next_signature),
                        span(&case.incoming),
                        out(&mut statement),
                    ),
                    0
                );
                assert_eq!(statement, request);
                assert_eq!(
                    q_periapt_sdk_runtime_recover_authority(
                        initial,
                        span(&authorization),
                        span(&case.next_policy),
                        span(&case.next_signature),
                        &mut next,
                        &mut disposition,
                    ),
                    0
                );
                assert_eq!(disposition, Q_PERIAPT_POLICY_RECOVERY_APPLIED);
                assert_ne!(next, 0);
                assert_eq!(q_periapt_sdk_close(next), 0);
                config.enrollment_signature = span(&[]);
                config.policy = span(&case.next_policy);
                config.signature = span(&case.next_signature);
                assert_eq!(
                    q_periapt_sdk_runtime_open_recovering_store(
                        &config,
                        span(&authorization),
                        &mut next,
                        &mut disposition,
                    ),
                    0
                );
                assert_eq!(disposition, Q_PERIAPT_POLICY_RECOVERY_ALREADY_APPLIED);
                assert_eq!(q_periapt_sdk_close(next), 0);
            }
        })
        .expect("create bounded foreign worker")
        .join()
        .expect("bounded foreign worker completed");
}

#[test]
fn c_recovery_exhaustion_roles_capacity_replays_and_real_reopen() {
    let _serial = TESTS.lock().expect("serial SDK tests");
    let case = Case::new();
    let folder = directory();
    let path = folder
        .path()
        .canonicalize()
        .expect("canonical")
        .join("policy.redb");
    let path = path.to_str().expect("UTF-8").as_bytes();
    let config = case.options(path, true);
    let mut initial = 0;
    // SAFETY: configuration, borrowed inputs and all outputs are live and disjoint.
    unsafe {
        assert_eq!(
            q_periapt_sdk_runtime_provision_recoverable_store(&config, &mut initial),
            0
        );
        assert_eq!(
            state(initial).get(..4).expect("state version"),
            &u32::MAX.to_be_bytes()
        );
        let old_key = key(initial);
        let old_public = public(old_key);
        let mut statement = vec![0; Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN];
        assert_eq!(
            q_periapt_sdk_runtime_prepare_recovery(
                initial,
                span(&[85; 32]),
                span(&case.next_policy),
                span(&case.next_signature),
                span(&case.incoming),
                out(&mut statement)
            ),
            0
        );
        let authorization = case.authorization(&statement);
        let mut swapped = statement.clone();
        let (approval, possession) = authorization
            .get(statement.len()..)
            .expect("role signatures")
            .split_at_checked(3309)
            .expect("two role signatures");
        swapped.extend_from_slice(possession);
        swapped.extend_from_slice(approval);
        let mut successor = 99;
        let mut disposition = 99;
        assert_eq!(
            q_periapt_sdk_runtime_recover_authority(
                initial,
                span(&swapped),
                span(&case.next_policy),
                span(&case.next_signature),
                &mut successor,
                &mut disposition
            ),
            Q_PERIAPT_ERR_POLICY
        );
        assert_eq!((successor, disposition), (0, 0));
        assert_eq!(public(old_key), old_public);
        // No additional handle slot is required at the durable cutover.
        let mut reservations = Vec::new();
        loop {
            match owner_registry().reserve(0) {
                Ok(slot) => reservations.push(slot),
                Err(error) => {
                    assert_eq!(error, Q_PERIAPT_ERR_RESOURCE_LIMIT);
                    break;
                }
            }
        }
        assert_eq!(
            q_periapt_sdk_runtime_recover_authority(
                initial,
                span(&authorization),
                span(&case.next_policy),
                span(&case.next_signature),
                &mut successor,
                &mut disposition
            ),
            0
        );
        assert_eq!(disposition, Q_PERIAPT_POLICY_RECOVERY_APPLIED);
        assert_ne!(successor, 0);
        assert_ne!(successor, initial);
        assert_eq!(q_periapt_sdk_close(initial), Q_PERIAPT_ERR_CLOSED);
        assert_eq!(q_periapt_sdk_close(old_key), Q_PERIAPT_ERR_CLOSED);
        drop(reservations);
        assert_eq!(
            state(successor).get(..4).expect("state version"),
            &1u32.to_be_bytes()
        );
        let mut enabled = 99;
        assert_eq!(q_periapt_sdk_runtime_enabled(successor, &mut enabled), 0);
        assert_eq!(enabled, 0);
        let mut duplicate = 99;
        assert_eq!(
            q_periapt_sdk_runtime_recover_authority(
                successor,
                span(&authorization),
                span(&case.next_policy),
                span(&case.next_signature),
                &mut duplicate,
                &mut disposition
            ),
            0
        );
        assert_eq!(
            (duplicate, disposition),
            (0, Q_PERIAPT_POLICY_RECOVERY_ALREADY_APPLIED)
        );
        // A normal update uses the newly authorized root and restores operations.
        let current_policy = policy(2, true);
        let current_signature = sign(
            &case.incoming_key,
            &policy_signature_message(&current_policy),
        );
        let mut current = 0;
        assert_eq!(
            q_periapt_sdk_runtime_update_store(
                successor,
                span(&current_policy),
                span(&current_signature),
                &mut current
            ),
            0
        );
        let current_key = key(current);
        let current_public = public(current_key);
        duplicate = 99;
        assert_eq!(
            q_periapt_sdk_runtime_recover_authority(
                current,
                span(&authorization),
                span(&case.next_policy),
                span(&case.next_signature),
                &mut duplicate,
                &mut disposition
            ),
            0
        );
        assert_eq!(
            (duplicate, disposition),
            (0, Q_PERIAPT_POLICY_RECOVERY_APPLIED_THEN_ADVANCED)
        );
        assert_eq!(public(current_key), current_public);
        let current_state = state(current);
        assert_eq!(q_periapt_sdk_close(current), 0);
        let mut reopen = case.options(path, false);
        reopen.policy = span(&case.next_policy);
        reopen.signature = span(&case.next_signature);
        assert_eq!(
            q_periapt_sdk_runtime_open_recovering_store(
                &reopen,
                span(&authorization),
                &mut current,
                &mut disposition
            ),
            0
        );
        assert_eq!(disposition, Q_PERIAPT_POLICY_RECOVERY_APPLIED_THEN_ADVANCED);
        assert_eq!(state(current), current_state);
        assert_eq!(q_periapt_sdk_close(current), 0);
        reopen.policy = span(&current_policy);
        reopen.signature = span(&current_signature);
        assert_eq!(
            q_periapt_sdk_runtime_open_recoverable_store(&reopen, &mut current),
            0
        );
        assert_eq!(state(current), current_state);
        let mut update = 99;
        assert_eq!(
            q_periapt_sdk_runtime_prepare_update(
                current,
                span(&current_policy),
                span(&current_signature),
                &mut update
            ),
            Q_PERIAPT_ERR_STORAGE_REQUIRED
        );
        assert_eq!(update, 0);
        assert_eq!(q_periapt_sdk_close(current), 0);
        // Replacing original trust does not open or re-enroll this existing file.
        let foreign_scope = [86; 32];
        reopen.scope = span(&foreign_scope);
        assert_eq!(
            q_periapt_sdk_runtime_open_recoverable_store(&reopen, &mut current),
            Q_PERIAPT_ERR_POLICY
        );
        assert_eq!(current, 0);
    }
}

#[test]
fn c_recovery_rejects_short_options_aliases_and_unenrolled_store() {
    let _serial = TESTS.lock().expect("serial SDK tests");
    let case = Case::new();
    // SAFETY: unsupported prefixes need only their documented readable words.
    unsafe {
        for prefix in [
            [4u32, 0],
            [size_of::<QPeriaptRecoverableStoreOptions>() as u32, 0],
        ] {
            let mut handle = 99;
            let mut disposition = 99;
            let config = prefix.as_ptr().cast();
            assert_eq!(
                q_periapt_sdk_runtime_provision_recoverable_store(config, &mut handle),
                Q_PERIAPT_ERR_LIMITS
            );
            assert_eq!(
                q_periapt_sdk_runtime_open_recoverable_store(config, &mut handle),
                Q_PERIAPT_ERR_LIMITS
            );
            assert_eq!(
                q_periapt_sdk_runtime_open_recovering_store(
                    config,
                    span(&[]),
                    &mut handle,
                    &mut disposition
                ),
                Q_PERIAPT_ERR_LIMITS
            );
            assert_eq!((handle, disposition), (99, 99));
        }
        let mut message = vec![0xa5; Q_PERIAPT_POLICY_RECOVERY_ENROLLMENT_MESSAGE_LEN];
        let aliased = QPeriaptInput {
            data: message.as_ptr(),
            len: 32,
        };
        assert_eq!(
            q_periapt_sdk_policy_recovery_enrollment_message(
                aliased,
                span(&case.initial),
                span(&case.recovery),
                out(&mut message)
            ),
            Q_PERIAPT_ERR_ALIASING
        );
        assert_eq!(
            message,
            vec![0xa5; Q_PERIAPT_POLICY_RECOVERY_ENROLLMENT_MESSAGE_LEN]
        );
        let folder = directory();
        let path = folder
            .path()
            .canonicalize()
            .expect("canonical")
            .join("old.redb");
        let path = path.to_str().expect("UTF-8").as_bytes();
        let config = QPeriaptStoreOptions {
            struct_size: size_of::<QPeriaptStoreOptions>() as u32,
            extension_version: 1,
            path: span(path),
            policy: span(&case.initial_policy),
            signature: span(&case.initial_signature),
            trust_root: span(&case.initial),
            max_live_keys: 2,
            max_in_flight: 2,
        };
        let mut handle = 0;
        assert_eq!(
            q_periapt_sdk_runtime_provision_store(&config, &mut handle),
            0
        );
        let mut request = vec![0xa5; Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN];
        assert_eq!(
            q_periapt_sdk_runtime_prepare_recovery(
                handle,
                span(&[85; 32]),
                span(&case.next_policy),
                span(&case.next_signature),
                span(&case.incoming),
                out(&mut request)
            ),
            Q_PERIAPT_ERR_RECOVERY_REQUIRED
        );
        assert_eq!(request, vec![0; Q_PERIAPT_POLICY_RECOVERY_REQUEST_LEN]);
        assert_eq!(
            state(handle).get(..4).expect("state version"),
            &u32::MAX.to_be_bytes()
        );
        assert_eq!(q_periapt_sdk_close(handle), 0);
        assert_eq!(
            q_periapt_sdk_runtime_open_recoverable_store(&case.options(path, false), &mut handle),
            Q_PERIAPT_ERR_RECOVERY_REQUIRED
        );
        assert_eq!(handle, 0);
    }
}

#[test]
fn committed_recovery_publication_error_and_unwind_close_before_reopen() {
    let _serial = TESTS.lock().expect("serial SDK tests");
    for unwind in [false, true] {
        let case = Case::new();
        let folder = directory();
        let path = folder
            .path()
            .canonicalize()
            .expect("canonical")
            .join("policy.redb");
        let registry = Registry::<1>::new();
        let config = Configuration {
            path: path.to_str().expect("UTF-8"),
            trust: case.trust(),
            policy: &case.initial_policy,
            signature: &case.initial_signature,
            enrollment: &case.enrollment,
            limits: sdk::Limits::default(),
        };
        let (value, _) = construct(config, RecoveryOpenMode::Provision, &[]).expect("provision");
        let owner = Arc::new(value);
        let mut slot = registry.reserve(0).expect("reserve");
        let handle = slot.id();
        slot.install(Object::Persistent(Arc::clone(&owner)))
            .expect("install");
        slot.publish().expect("publish");
        let statement = prepare(
            &registry,
            handle,
            &[85; 32],
            &case.next_policy,
            &case.next_signature,
            &case.incoming,
        )
        .expect("request");
        let authorization = case.authorization(&statement);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            recover(
                &registry,
                handle,
                &authorization,
                &case.next_policy,
                &case.next_signature,
                |_, _| {
                    if unwind {
                        std::panic::resume_unwind(Box::new("post-commit publication unwind"));
                    }
                    Err(Q_PERIAPT_ERR_INTERNAL)
                },
            )
        }));
        if unwind {
            assert!(result.is_err());
            assert_eq!(registry.close(handle), Err(Q_PERIAPT_ERR_INTERNAL));
        } else {
            assert_eq!(
                result.expect("no unwind"),
                Err(Q_PERIAPT_ERR_STORE_COMMITTED)
            );
            assert_eq!(registry.close(handle), Err(Q_PERIAPT_ERR_CLOSED));
        }
        assert_eq!(owner.runtime.is_enabled(), Err(sdk::Error::Closed));
        let config = Configuration {
            path: path.to_str().expect("UTF-8"),
            trust: case.trust(),
            policy: &case.next_policy,
            signature: &case.next_signature,
            enrollment: &[],
            limits: sdk::Limits::default(),
        };
        let (reopened, disposition) =
            construct(config, RecoveryOpenMode::Recovering, &authorization)
                .expect("reconcile original committed request");
        assert_eq!(disposition, Q_PERIAPT_POLICY_RECOVERY_ALREADY_APPLIED);
        assert_eq!(
            reopened.runtime.trusted_state().encode()[..4],
            1u32.to_be_bytes()
        );
        reopened.close().expect("close recovered");
    }
}
