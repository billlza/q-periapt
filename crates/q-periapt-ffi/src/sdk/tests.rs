use super::*;
use crate::{q_periapt_abi_version, q_periapt_decision_from_signed_policy, q_periapt_encapsulate};
use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN};
use q_periapt_policy::policy_signature_message;
use q_periapt_sig::Signer;
use std::sync::{Mutex, OnceLock};

// These tests deliberately exhaust the one process-wide admission budget.
pub(super) static TESTS: Mutex<()> = Mutex::new(());

pub(super) fn fixture() -> &'static (Vec<u8>, Vec<u8>, Vec<u8>) {
    static FIXTURE: OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let policy = b"schema_version = 1\npolicy_version = 2\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [\"ML-KEM-768\", \"X25519\"]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n".to_vec();
        let (sk, pk) = MlDsa65::generate([42; 32]);
        let mut sig = vec![0; ML_DSA_65_SIG_LEN];
        MlDsa65.sign(&sk, &policy_signature_message(&policy), &[0; 32], &mut sig).expect("fixture signing");
        (policy, sig, pk.to_vec())
    })
}
pub(super) fn span(bytes: &[u8]) -> QPeriaptInput {
    QPeriaptInput {
        data: bytes.as_ptr(),
        len: bytes.len(),
    }
}
pub(super) fn out(bytes: &mut [u8]) -> QPeriaptOutput {
    QPeriaptOutput {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
    }
}
fn options() -> QPeriaptRuntimeOptions {
    let (policy, signature, root) = fixture();
    QPeriaptRuntimeOptions {
        struct_size: size_of::<QPeriaptRuntimeOptions>() as u32,
        extension_version: 1,
        policy: span(policy),
        signature: span(signature),
        trust_root: span(root),
        previous_state: span(&[]),
        max_live_keys: 2,
        max_in_flight: 2,
    }
}

#[test]
fn constructors_reject_short_option_prefixes_before_reading_fields() {
    // Matching layout/revision still requires a complete initialized structure.
    // Unsupported layouts require only the four-byte size word; unsupported
    // revisions require only the eight-byte prefix. No later pointer is valid.
    for size_only in [0_u32, 4, u32::MAX] {
        let ptr = std::ptr::from_ref(&size_only).cast::<u8>();
        let mut output = u64::MAX;
        // SAFETY: the readable size word names an unsupported layout. The ABI
        // rejects it before reading any later bytes; output is separate/valid.
        unsafe {
            assert_eq!(
                q_periapt_sdk_runtime_new(ptr.cast(), &mut output),
                Q_PERIAPT_ERR_LIMITS
            );
            assert_eq!(
                q_periapt_sdk_runtime_provision_store(ptr.cast(), &mut output),
                Q_PERIAPT_ERR_LIMITS
            );
            assert_eq!(
                q_periapt_sdk_runtime_open_store(ptr.cast(), &mut output),
                Q_PERIAPT_ERR_LIMITS
            );
            assert_eq!(
                q_periapt_sdk_connection_client_new(0, ptr.cast(), &mut output),
                Q_PERIAPT_ERR_LIMITS
            );
            assert_eq!(
                q_periapt_sdk_connection_server_new(0, ptr.cast(), &mut output),
                Q_PERIAPT_ERR_LIMITS
            );
        }
        assert_eq!(output, u64::MAX);
    }
    let runtime_prefix = [size_of::<QPeriaptRuntimeOptions>() as u32, 0];
    let store_prefix = [size_of::<QPeriaptStoreOptions>() as u32, 0];
    let connection_prefix = [size_of::<QPeriaptConnectionOptions>() as u32, 0];
    let mut output = u64::MAX;
    // SAFETY: each prefix is readable and carries an unsupported revision.
    // No complete options value is needed or constructed on this reject path.
    unsafe {
        assert_eq!(
            q_periapt_sdk_runtime_new(runtime_prefix.as_ptr().cast(), &mut output),
            Q_PERIAPT_ERR_LIMITS
        );
        assert_eq!(
            q_periapt_sdk_runtime_provision_store(store_prefix.as_ptr().cast(), &mut output),
            Q_PERIAPT_ERR_LIMITS
        );
        assert_eq!(
            q_periapt_sdk_runtime_open_store(store_prefix.as_ptr().cast(), &mut output),
            Q_PERIAPT_ERR_LIMITS
        );
        assert_eq!(
            q_periapt_sdk_connection_client_new(0, connection_prefix.as_ptr().cast(), &mut output),
            Q_PERIAPT_ERR_LIMITS
        );
        assert_eq!(
            q_periapt_sdk_connection_server_new(0, connection_prefix.as_ptr().cast(), &mut output),
            Q_PERIAPT_ERR_LIMITS
        );
    }
    assert_eq!(output, u64::MAX);
}

pub(super) fn create() -> u64 {
    let mut handle = 0;
    // SAFETY: options and its fixture buffers are live; handle is disjoint/writable.
    assert_eq!(
        unsafe { q_periapt_sdk_runtime_new(&options(), &mut handle) },
        0
    );
    assert_ne!(handle, 0);
    handle
}
fn key(runtime: u64) -> u64 {
    let mut handle = 0;
    // SAFETY: valid separate writable handle output.
    assert_eq!(
        unsafe { q_periapt_sdk_key_generate(runtime, &mut handle) },
        0
    );
    handle
}
fn public(key: u64) -> [u8; sdk::PUBLIC_KEY_LEN] {
    let mut bytes = std::mem::MaybeUninit::<[u8; sdk::PUBLIC_KEY_LEN]>::uninit();
    // SAFETY: the entire output allocation is valid (initially uninitialized).
    assert_eq!(
        unsafe {
            q_periapt_sdk_key_public(
                key,
                QPeriaptOutput {
                    data: bytes.as_mut_ptr().cast(),
                    len: sdk::PUBLIC_KEY_LEN,
                },
            )
        },
        0
    );
    // SAFETY: successful FFI initialized all bytes.
    unsafe { bytes.assume_init() }
}
fn export(secret: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    // SAFETY: output is a live separate exact-size region.
    assert_eq!(
        unsafe { q_periapt_sdk_secret_export(secret, out(&mut bytes)) },
        0
    );
    bytes
}

fn update_policy(disabled: bool) -> (Vec<u8>, Vec<u8>) {
    let policy = String::from_utf8(fixture().0.clone())
        .expect("text")
        .replace("policy_version = 2", "policy_version = 3");
    let policy = if disabled {
        policy.replace("ML-KEM-768", "ML-KEM-1024")
    } else {
        policy
    };
    let (sk, _) = MlDsa65::generate([42; 32]);
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &sk,
            &policy_signature_message(policy.as_bytes()),
            &[0; 32],
            &mut signature,
        )
        .expect("sign");
    (policy.into_bytes(), signature)
}

#[test]
fn expert_transfer_rejects_malformed_private_material_and_erases_failed_exports() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let original = key(runtime);
    let public_key = public(original);
    let mut encoded = [0; sdk::expert::EXPANDED_KEY_LEN];
    let mut imported = 0;
    // SAFETY: every buffer is distinct, live and correctly sized except the
    // deliberately malformed span, whose length is rejected before access.
    unsafe {
        assert_eq!(
            q_periapt_sdk_expert_key_export(original, out(&mut encoded)),
            0
        );
        assert_eq!(
            q_periapt_sdk_expert_key_import(runtime, span(&encoded), &mut imported),
            0
        );
        assert_eq!(public(imported), public_key);
        assert_eq!(q_periapt_sdk_close(imported), 0);
        encoded[0] ^= 1;
        imported = 99;
        assert_eq!(
            q_periapt_sdk_expert_key_import(runtime, span(&encoded), &mut imported),
            Q_PERIAPT_ERR_INVALID_PRIVATE_KEY
        );
        assert_eq!(imported, 0);
        imported = 99;
        assert_eq!(
            q_periapt_sdk_expert_key_import(runtime, span(&encoded[..64]), &mut imported),
            Q_PERIAPT_ERR_LENGTH
        );
        assert_eq!(imported, 99); // shape failures precede any writes
        assert_eq!(q_periapt_sdk_close(runtime), 0);
        encoded.fill(0xa5);
        assert_eq!(
            q_periapt_sdk_expert_key_export(original, out(&mut encoded)),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(encoded, [0; sdk::expert::EXPANDED_KEY_LEN]);
    }
}

#[test]
fn activation_reuses_reserved_capacity_and_ignores_call_exhaustion_without_reusing_ids() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let old_key = key(runtime);
    let (policy, signature) = update_policy(true);
    let mut update = 0;
    // SAFETY: all spans and scalar outputs are valid and disjoint.
    unsafe {
        assert_eq!(
            q_periapt_sdk_runtime_prepare_update(
                runtime,
                span(&policy),
                span(&signature),
                &mut update
            ),
            0
        );
        let mut states = [0; 72];
        assert_eq!(
            q_periapt_sdk_policy_update_states(update, out(&mut states)),
            0
        );
        assert_eq!(&states[..4], &2u32.to_be_bytes());
        assert_eq!(&states[36..40], &3u32.to_be_bytes());
        let mut new_runtime = 91;
        assert_eq!(
            q_periapt_sdk_policy_update_activate(update, std::ptr::null_mut()),
            Q_PERIAPT_ERR_NULL
        );
        // Invalid output must not consume the candidate or revoke old keys.
        public(old_key);
        let reservations: Vec<_> = (3..Q_PERIAPT_SDK_MAX_HANDLES)
            .map(|_| owner_registry().reserve(0).expect("fill pending slots"))
            .collect();
        assert!(matches!(
            owner_registry().reserve(0),
            Err(Q_PERIAPT_ERR_RESOURCE_LIMIT)
        ));
        let calls: Vec<_> = (0..Q_PERIAPT_SDK_MAX_CALLS)
            .map(|_| Admission::enter().expect("fill call budget"))
            .collect();
        // Test host persistence is represented by states; no durability claim.
        assert_eq!(
            q_periapt_sdk_policy_update_activate(update, &mut new_runtime),
            0
        );
        assert_ne!(new_runtime, update);
        assert_ne!(new_runtime, runtime);
        assert_eq!(q_periapt_sdk_close(update), Q_PERIAPT_ERR_CLOSED);
        drop(calls);
        drop(reservations);
        let mut enabled = 99;
        assert_eq!(q_periapt_sdk_runtime_enabled(new_runtime, &mut enabled), 0);
        assert_eq!(enabled, 0);
        let mut handle = 99;
        assert_eq!(
            q_periapt_sdk_key_generate(new_runtime, &mut handle),
            Q_PERIAPT_ERR_POLICY
        );
        assert_eq!(handle, 0);
        assert_eq!(
            q_periapt_sdk_policy_update_activate(update, &mut handle),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(handle, 0);
        let mut bytes = [0xa5; sdk::PUBLIC_KEY_LEN];
        assert_eq!(
            q_periapt_sdk_key_public(old_key, out(&mut bytes)),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(bytes, [0; sdk::PUBLIC_KEY_LEN]);
        assert_eq!(q_periapt_sdk_close(new_runtime), 0);
    }
}

#[test]
fn activation_cleanup_failure_revokes_every_owner_and_recovers_from_next_state() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let poisoned_key = key(runtime);
    let other_key = key(runtime);
    let value = match owner_registry().get(poisoned_key).expect("key").0 {
        Object::Key(value) => Ok(value),
        _ => Err(Q_PERIAPT_ERR_CLOSED),
    }
    .expect("expected key owner");
    // A caught panic poisons this child, not the registry or the test guard.
    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _borrow = value.write().expect("unpoisoned key");
        std::panic::resume_unwind(Box::new("injected child panic before policy activation"));
    }));
    assert!(poison.is_err());
    assert!(value.is_poisoned());

    let (policy, signature) = update_policy(true);
    let mut update = 0;
    // SAFETY: all input/output allocations remain live, valid and disjoint.
    unsafe {
        assert_eq!(
            q_periapt_sdk_runtime_prepare_update(
                runtime,
                span(&policy),
                span(&signature),
                &mut update,
            ),
            0
        );
        let mut states = [0; 72];
        assert_eq!(
            q_periapt_sdk_policy_update_states(update, out(&mut states)),
            0
        );
        let successor = match owner_registry().get(update).expect("candidate").0 {
            Object::PolicyUpdate { successor, .. } => Ok(successor),
            _ => Err(Q_PERIAPT_ERR_CLOSED),
        }
        .expect("expected policy-update owner");
        // This models the host's saved CAS result; it does not test durable I/O.
        let persisted_next = &states[36..];
        let mut replacement = u64::MAX;
        assert_eq!(
            q_periapt_sdk_policy_update_activate(update, &mut replacement),
            Q_PERIAPT_ERR_INTERNAL
        );
        assert_eq!(replacement, 0);
        for handle in [runtime, poisoned_key, other_key, update, successor] {
            assert!(matches!(
                owner_registry().get(handle),
                Err(Q_PERIAPT_ERR_CLOSED)
            ));
        }
        // Cleanup continues past the poisoned child. Neither key is usable.
        for handle in [poisoned_key, other_key] {
            let mut exported = [0xa5; sdk::expert::EXPANDED_KEY_LEN];
            assert_eq!(
                q_periapt_sdk_expert_key_export(handle, out(&mut exported)),
                Q_PERIAPT_ERR_CLOSED
            );
            assert_eq!(exported, [0; sdk::expert::EXPANDED_KEY_LEN]);
        }

        let mut recovery = options();
        recovery.previous_state = span(persisted_next);
        // Reusing the old document cannot undo a committed policy floor.
        assert_eq!(
            q_periapt_sdk_runtime_new(&recovery, &mut replacement),
            Q_PERIAPT_ERR_POLICY
        );
        assert_eq!(replacement, 0);
        recovery.policy = span(&policy);
        recovery.signature = span(&signature);
        assert_eq!(q_periapt_sdk_runtime_new(&recovery, &mut replacement), 0);
        assert_ne!(replacement, successor);
        let mut recovered_state = [0; 36];
        assert_eq!(
            q_periapt_sdk_runtime_state(replacement, out(&mut recovered_state)),
            0
        );
        assert_eq!(recovered_state, persisted_next);
        let mut enabled = 99;
        assert_eq!(q_periapt_sdk_runtime_enabled(replacement, &mut enabled), 0);
        assert_eq!(enabled, 0);
        assert_eq!(q_periapt_sdk_close(replacement), 0);
    }
}

#[test]
fn closing_parent_while_activation_waits_prevents_new_runtime_publication() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let (policy, signature) = update_policy(false);
    let mut update = 0;
    // SAFETY: owned, disjoint inputs and output.
    assert_eq!(
        unsafe {
            q_periapt_sdk_runtime_prepare_update(
                runtime,
                span(&policy),
                span(&signature),
                &mut update,
            )
        },
        0
    );
    let value = match owner_registry().get(update).expect("candidate").0 {
        Object::PolicyUpdate { value, .. } => Ok(value),
        _ => Err(Q_PERIAPT_ERR_CLOSED),
    }
    .expect("candidate entry has policy-update type");
    let read = value.read().expect("hold candidate lease");
    let activate = std::thread::spawn(move || {
        let mut handle = 77;
        // SAFETY: thread-local valid output.
        let status = unsafe { q_periapt_sdk_policy_update_activate(update, &mut handle) };
        (status, handle)
    });
    let close = std::thread::spawn(move || q_periapt_sdk_close(runtime));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while owner_registry().get(runtime).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "parent must be removed before disposal waits"
        );
        std::thread::yield_now();
    }
    drop(read);
    assert_eq!(
        activate.join().expect("activation"),
        (Q_PERIAPT_ERR_CLOSED, 0)
    );
    assert_eq!(close.join().expect("close"), 0);
}

#[test]
fn purpose_key_handles_enforce_shapes_type_separation_and_runtime_revocation() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let key = key(runtime);
    let public = public(key);
    let mut ciphertext = [0; sdk::CIPHERTEXT_LEN];
    let mut secret = 0;
    // SAFETY: all inputs and outputs have live, separate storage.
    unsafe {
        assert_eq!(
            q_periapt_sdk_encapsulate(
                runtime,
                span(&public),
                span(b""),
                out(&mut ciphertext),
                &mut secret
            ),
            0
        );
        let mut derived = 0xa5a5_a5a5_a5a5_a5a5;
        assert_eq!(
            q_periapt_sdk_secret_derive(secret, 1, span(b""), span(b""), &mut derived),
            Q_PERIAPT_ERR_LENGTH
        );
        assert_eq!(derived, 0xa5a5_a5a5_a5a5_a5a5);
        let alias = QPeriaptInput {
            data: std::ptr::from_ref(&derived).cast(),
            len: 8,
        };
        assert_eq!(
            q_periapt_sdk_secret_derive(secret, 1, alias, span(b""), &mut derived),
            Q_PERIAPT_ERR_ALIASING
        );
        assert_eq!(derived, 0xa5a5_a5a5_a5a5_a5a5);
        assert_eq!(
            q_periapt_sdk_secret_derive(secret, 0, span(b"app"), span(b""), &mut derived),
            Q_PERIAPT_ERR_PURPOSE
        );
        assert_eq!(derived, 0);
        derived = 42;
        assert_eq!(
            q_periapt_sdk_secret_derive(secret, 1, span(b"\0"), span(b""), &mut derived),
            Q_PERIAPT_ERR_PURPOSE
        );
        assert_eq!(derived, 0);
        assert_eq!(
            q_periapt_sdk_secret_derive(secret, 1, span(b"app"), span(b""), &mut derived),
            0
        );
        let mut output = [0xa5; 32];
        assert_eq!(
            q_periapt_sdk_derived_key_export(derived, out(&mut output)),
            0
        );
        let mut invalid = 42;
        assert_eq!(
            q_periapt_sdk_secret_derive(derived, 1, span(b"app"), span(b""), &mut invalid),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(invalid, 0);
        assert_eq!(
            q_periapt_sdk_secret_export(derived, out(&mut output)),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(output, [0; 32]);
        assert_eq!(
            q_periapt_sdk_derived_key_export(secret, out(&mut output)),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(q_periapt_sdk_close(runtime), 0);
        assert_eq!(
            q_periapt_sdk_derived_key_export(derived, out(&mut output)),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(output, [0; 32]);
    }
}

#[test]
fn malformed_previous_state_is_a_shape_error_before_output_writes() {
    let _tests = TESTS.lock().expect("serial test guard");
    for size in [1, 4, 35, 37] {
        let bytes = vec![0; size];
        let mut options = options();
        options.previous_state = span(&bytes);
        let mut output = 0xa5a5_a5a5_a5a5_a5a5;
        // SAFETY: the malformed input is readable; output is disjoint/writable.
        assert_eq!(
            unsafe { q_periapt_sdk_runtime_new(&options, &mut output) },
            Q_PERIAPT_ERR_LENGTH
        );
        assert_eq!(output, 0xa5a5_a5a5_a5a5_a5a5);
    }
    let mut options = options();
    options.previous_state = span(&[0; 36]);
    let mut output = 42;
    // SAFETY: correct shapes with invalid state contents; failure clears output.
    assert_eq!(
        unsafe { q_periapt_sdk_runtime_new(&options, &mut output) },
        Q_PERIAPT_ERR_POLICY
    );
    assert_eq!(output, 0);
}

#[test]
fn retained_abi2_old_encapsulation_interoperates_with_owned_decapsulation() {
    let _tests = TESTS.lock().expect("serial test guard");
    assert_eq!(q_periapt_abi_version(), 2);
    assert_eq!(q_periapt_sdk_extension_version(), 1);
    let runtime = create();
    let key = key(runtime);
    let public = public(key);
    let (pq, trad) = public.split_at(1184);
    let (policy, signature, root) = fixture();
    let mut decision = [0; 40];
    let mut pq_ct = [0; 1088];
    let mut trad_ct = [0; 32];
    let mut expected = [0; 32];
    let context = b"old-client/new-owner";
    // SAFETY: all sizes, initialized input lifetimes and output disjointness
    // follow directly from independent arrays and fixed fixture buffers.
    unsafe {
        assert_eq!(
            q_periapt_decision_from_signed_policy(
                policy.as_ptr(),
                policy.len(),
                signature.as_ptr(),
                signature.len(),
                root.as_ptr(),
                root.len(),
                std::ptr::null(),
                0,
                decision.as_mut_ptr(),
                40
            ),
            0
        );
        assert_eq!(
            q_periapt_encapsulate(
                decision.as_ptr(),
                40,
                pq.as_ptr(),
                pq.len(),
                trad.as_ptr(),
                trad.len(),
                context.as_ptr(),
                context.len(),
                pq_ct.as_mut_ptr(),
                1088,
                trad_ct.as_mut_ptr(),
                32,
                expected.as_mut_ptr(),
                32
            ),
            0
        );
    }
    let ct = [pq_ct.as_slice(), trad_ct.as_slice()].concat();
    let mut secret = 0;
    // SAFETY: valid immutable inputs and separate eight-byte output.
    assert_eq!(
        unsafe { q_periapt_sdk_decapsulate(key, span(&ct), span(context), &mut secret) },
        0
    );
    assert_eq!(export(secret), expected);
    assert_eq!(q_periapt_sdk_close(runtime), 0);
    let mut zero = [0xa5; 32];
    // SAFETY: output remains valid after handle revocation.
    assert_eq!(
        unsafe { q_periapt_sdk_secret_export(secret, out(&mut zero)) },
        Q_PERIAPT_ERR_CLOSED
    );
    assert_eq!(zero, [0; 32]);
    assert_eq!(q_periapt_sdk_close(key), Q_PERIAPT_ERR_CLOSED);
}

#[test]
fn roundtrip_rejection_and_failure_outputs() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let key = key(runtime);
    let pk = public(key);
    let mut ct = [0; sdk::CIPHERTEXT_LEN];
    let mut secret = 0;
    // SAFETY: immutable public key/context, disjoint exact-sized outputs.
    assert_eq!(
        unsafe {
            q_periapt_sdk_encapsulate(runtime, span(&pk), span(b"ctx"), out(&mut ct), &mut secret)
        },
        0
    );
    let mut decoded = 0;
    // SAFETY: valid bounded immutable inputs and separate scalar output.
    assert_eq!(
        unsafe { q_periapt_sdk_decapsulate(key, span(&ct), span(b"ctx"), &mut decoded) },
        0
    );
    assert_eq!(export(secret), export(decoded));
    *ct.first_mut().expect("ciphertext byte") ^= 1;
    let mut rejected = 0;
    // SAFETY: mutation preserves the exact ciphertext framing.
    assert_eq!(
        unsafe { q_periapt_sdk_decapsulate(key, span(&ct), span(b"ctx"), &mut rejected) },
        0
    );
    assert_ne!(export(rejected), export(secret));
    ct.get_mut(1088..).expect("traditional share").fill(0);
    let mut failure = u64::MAX;
    // SAFETY: correct regions; the public share is intentionally invalid.
    assert_eq!(
        unsafe { q_periapt_sdk_decapsulate(key, span(&ct), span(b"ctx"), &mut failure) },
        Q_PERIAPT_ERR_INVALID_KEYSHARE
    );
    assert_eq!(failure, 0);
    let mut wrong_type = [0xa5; 32];
    // SAFETY: valid output; a runtime ID must not be accepted as a secret ID.
    assert_eq!(
        unsafe { q_periapt_sdk_secret_export(runtime, out(&mut wrong_type)) },
        Q_PERIAPT_ERR_CLOSED
    );
    assert_eq!(wrong_type, [0; 32]);
    assert_eq!(q_periapt_sdk_close(runtime), 0);
}

#[test]
fn bounds_aliases_and_panics_do_not_publish_success_fragments() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let key = key(runtime);
    let mut pk = public(key);
    let original = pk;
    let mut secret = u64::MAX;
    let overlap = QPeriaptOutput {
        data: pk.as_mut_ptr(),
        len: sdk::CIPHERTEXT_LEN,
    };
    // SAFETY: every region is valid; overlap must be rejected before any mutation/reference.
    assert_eq!(
        unsafe { q_periapt_sdk_encapsulate(runtime, span(&pk), span(&[]), overlap, &mut secret) },
        Q_PERIAPT_ERR_ALIASING
    );
    assert_eq!(pk, original);
    assert_eq!(secret, u64::MAX);
    let huge = QPeriaptInput {
        data: std::ptr::null(),
        len: usize::MAX,
    };
    let mut ct = [0xa5; sdk::CIPHERTEXT_LEN];
    // SAFETY: the deliberately impossible length is rejected before input access.
    assert_eq!(
        unsafe { q_periapt_sdk_encapsulate(runtime, span(&pk), huge, out(&mut ct), &mut secret) },
        Q_PERIAPT_ERR_LENGTH
    );
    assert_eq!(ct, [0xa5; sdk::CIPHERTEXT_LEN]);
    assert_eq!(secret, u64::MAX);
    let mut bytes = [0xa5; 32];
    let output = out(&mut bytes);
    // SAFETY: the private error-boundary test has valid outputs and no inputs.
    let status = unsafe {
        execute([], [(output, 32)], || {
            write(output, &[0x33; 32])?;
            std::panic::resume_unwind(Box::new("injected failure after output write"))
        })
    };
    assert_eq!(status, Q_PERIAPT_ERR_PANIC);
    assert_eq!(bytes, [0; 32]);
    assert_eq!(q_periapt_sdk_close(runtime), 0);
}

#[test]
fn global_call_budget_is_bounded_and_disposal_remains_available() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let leases: Vec<_> = (0..Q_PERIAPT_SDK_MAX_CALLS)
        .map(|_| Admission::enter().expect("admission slot"))
        .collect();
    let mut key = u64::MAX;
    // SAFETY: a valid output is cleared when the admission budget rejects work.
    assert_eq!(
        unsafe { q_periapt_sdk_key_generate(runtime, &mut key) },
        Q_PERIAPT_ERR_RESOURCE_LIMIT
    );
    assert_eq!(key, 0);
    assert_eq!(q_periapt_sdk_close(runtime), 0);
    drop(leases);
    let replacement = create();
    assert_eq!(q_periapt_sdk_close(replacement), 0);
}

#[test]
fn concurrent_call_admission_keeps_the_exact_limit_and_recovers_capacity() {
    let _tests = TESTS.lock().expect("serial test guard");
    let held: Vec<_> = (0..Q_PERIAPT_SDK_MAX_CALLS - 4)
        .map(|_| Admission::enter().expect("reserved call slot"))
        .collect();
    let start = std::sync::Barrier::new(17);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    Admission::enter()
                })
            })
            .collect();
        start.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("admission worker"))
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 4);
    assert!(results
        .iter()
        .all(|result| matches!(result, Ok(_) | Err(Q_PERIAPT_ERR_RESOURCE_LIMIT))));
    assert_eq!(
        call_count().load(Ordering::Acquire),
        Q_PERIAPT_SDK_MAX_CALLS
    );
    drop(results);
    drop(held);
    assert_eq!(call_count().load(Ordering::Acquire), 0);
    assert!(Admission::enter().is_ok());
}

#[test]
fn close_waits_for_an_admitted_key_lease_and_never_reuses_its_id() {
    let _tests = TESTS.lock().expect("serial test guard");
    let runtime = create();
    let old = key(runtime);
    let owned = match owner_registry().get(old).expect("key entry").0 {
        Object::Key(key) => Ok(key),
        _ => Err(Q_PERIAPT_ERR_CLOSED),
    }
    .expect("key entry has key type");
    let lease = owned.read().expect("active native borrow");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        started_tx.send(()).expect("start");
        done_tx.send(q_periapt_sdk_close(old)).expect("finish");
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("closer started");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while owner_registry().get(old).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "close must remove the handle before waiting"
        );
        std::thread::yield_now();
    }
    assert!(matches!(
        owner_registry().get(old),
        Err(Q_PERIAPT_ERR_CLOSED)
    ));
    assert!(matches!(
        done_rx.recv_timeout(std::time::Duration::from_millis(20)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(lease.public_key().is_ok());
    drop(lease);
    assert_eq!(
        done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("dispose after borrow"),
        0
    );
    thread.join().expect("closer join");
    let replacement = key(runtime);
    assert_ne!(old, replacement);
    let mut output = [0xa5; sdk::PUBLIC_KEY_LEN];
    // SAFETY: old ID is invalid but the complete output remains writable.
    assert_eq!(
        unsafe { q_periapt_sdk_key_public(old, out(&mut output)) },
        Q_PERIAPT_ERR_CLOSED
    );
    assert_eq!(output, [0; sdk::PUBLIC_KEY_LEN]);
    assert_eq!(q_periapt_sdk_close(runtime), 0);
}

#[test]
fn unpublished_reservations_are_bounded_and_revocation_prevents_late_publication() {
    let registry = Registry::<2>::new();
    let first = registry.reserve(0).expect("first pending");
    let second = registry.reserve(0).expect("second pending");
    assert!(matches!(
        registry.reserve(0),
        Err(Q_PERIAPT_ERR_RESOURCE_LIMIT)
    ));
    let old_id = first.id();
    drop(first);
    drop(second);
    let (policy, signature, root) = fixture();
    let owner = Arc::new(
        sdk::Runtime::from_signed_policy(policy, signature, root, None, sdk::Limits::default())
            .expect("runtime"),
    );
    let mut parent = registry.reserve(0).expect("new parent");
    assert_ne!(parent.id(), old_id);
    let parent_id = parent.id();
    parent
        .install(Object::Runtime(Arc::clone(&owner)))
        .expect("install");
    parent.publish().expect("publish");
    let mut child = registry.reserve(parent_id).expect("pending child");
    child
        .install(Object::Key(Arc::new(RwLock::new(
            owner.generate_key().expect("key"),
        ))))
        .expect("install key");
    assert_eq!(registry.close(parent_id), Ok(()));
    assert_eq!(child.publish(), Err(Q_PERIAPT_ERR_CLOSED));
    assert!(matches!(registry.get(old_id), Err(Q_PERIAPT_ERR_CLOSED)));
    assert!(registry.reserve(0).is_ok());
}
