use super::*;
use q_periapt_backends::{Sha3_256Xof, ML_DSA_65_SIG_LEN};
use q_periapt_core::{encode_policy_bound_context, policy_bound_context_len};
use q_periapt_policy::policy_signature_message;
use q_periapt_sig::Signer;
use std::sync::OnceLock;

fn fixture() -> &'static (Vec<u8>, Vec<u8>, Vec<u8>) {
    static FIXTURE: OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let policy = b"schema_version = 1\npolicy_version = 2\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [\"ML-KEM-768\", \"X25519\"]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n".to_vec();
        let (sk, pk) = MlDsa65::generate([42; 32]);
        let mut signature = vec![0; ML_DSA_65_SIG_LEN];
        MlDsa65.sign(&sk, &policy_signature_message(&policy), &[0; 32], &mut signature).expect("fixture signature");
        (policy, signature, pk.to_vec())
    })
}
fn runtime(limits: Limits) -> Runtime {
    let (policy, signature, root) = fixture();
    Runtime::from_signed_policy(policy, signature, root, None, limits).expect("verified runtime")
}
fn coins(start: u8) -> impl FnMut(&mut [u8]) -> Result<(), Error> {
    let mut value = start;
    move |out| {
        out.fill(value);
        value += 1;
        Ok(())
    }
}
fn bytes(secret: &SharedSecret) -> ZeroizingBytes<32> {
    secret.export_for_protocol().expect("open secret")
}

fn signed_update(version: u32, seed: u8, suffix: &str) -> (Vec<u8>, Vec<u8>) {
    let (policy, _, _) = fixture();
    let mut policy = String::from_utf8(policy.clone())
        .expect("policy text")
        .replace("policy_version = 2", &format!("policy_version = {version}"));
    policy.push_str(suffix);
    let (sk, _) = MlDsa65::generate([seed; 32]);
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

#[cfg(feature = "sealed-operations")]
#[test]
fn sealed_key_recovery_replays_after_owner_recreation_without_skipping_quota() {
    use expert::replay::{RecoveryKey, SealedOperation};
    let limits = Limits {
        max_live_keys: 1,
        max_in_flight: 1,
    };
    let owner = runtime(limits);
    let recovery = RecoveryKey::from_host_key(&[47; 32]).expect("host key");
    let id = [51; 32];
    let sealed = recovery.reserve_key(&owner, &id).expect("reservation");
    let key = recovery
        .generate_key(&owner, &id, &sealed)
        .expect("first computation");
    let export = expert::export_expanded(&key).expect("private comparison");
    let public = key.public_key().expect("public").to_bytes();
    assert!(matches!(
        recovery.generate_key(&owner, &id, &sealed),
        Err(Error::ResourceLimit)
    ));
    drop(key);
    drop(owner);
    drop(recovery);
    let restored = runtime(limits);
    let recovery = RecoveryKey::from_host_key(&[47; 32]).expect("restored key");
    let sealed = SealedOperation::from_bytes(sealed.as_bytes()).expect("retained ciphertext");
    let key = recovery
        .generate_key(&restored, &id, &sealed)
        .expect("identical computation");
    assert_eq!(key.public_key().expect("public").to_bytes(), public);
    assert_eq!(
        expert::export_expanded(&key)
            .expect("restored private")
            .as_bytes(),
        export.as_bytes()
    );
    let enc = restored
        .encapsulate(key.public_key().expect("public"), b"recovered")
        .expect("encap");
    let dec = key
        .decapsulate(&enc.ciphertext, b"recovered")
        .expect("decap");
    assert_eq!(bytes(&enc.secret).as_bytes(), bytes(&dec).as_bytes());
}

#[cfg(feature = "sealed-operations")]
#[test]
fn sealed_encapsulation_binds_every_input_and_preserves_exact_contextbound_result() {
    use expert::replay::{RecoveryKey, SealedOperation};
    let owner = runtime(Limits::default());
    let recovery = RecoveryKey::from_host_key(&[47; 32]).expect("host key");
    let key = owner.generate_key().expect("peer");
    let other = owner.generate_key().expect("other peer");
    let peer = key.public_key().expect("public");
    let id = [52; 32];
    let sealed = recovery
        .reserve_encapsulation(&owner, &id, peer, b"bound context")
        .expect("reservation");
    let first = recovery
        .encapsulate(&owner, &id, peer, b"bound context", &sealed)
        .expect("first");
    let reopened = SealedOperation::from_bytes(sealed.as_bytes()).expect("reopen");
    let second = recovery
        .encapsulate(&owner, &id, peer, b"bound context", &reopened)
        .expect("second");
    assert_eq!(first.ciphertext.to_bytes(), second.ciphertext.to_bytes());
    assert_eq!(
        bytes(&first.secret).as_bytes(),
        bytes(&second.secret).as_bytes()
    );
    let decoded = key
        .decapsulate(&first.ciphertext, b"bound context")
        .expect("actual peer");
    assert_eq!(bytes(&first.secret).as_bytes(), bytes(&decoded).as_bytes());
    for (scope, public, context) in [
        ([53; 32], peer, b"bound context".as_slice()),
        (
            id,
            other.public_key().expect("other"),
            b"bound context".as_slice(),
        ),
        (id, peer, b"bound context\0".as_slice()),
    ] {
        assert!(matches!(
            recovery.encapsulate(&owner, &scope, public, context, &sealed),
            Err(Error::InvalidPrivateKey)
        ));
    }
    assert!(matches!(
        recovery.generate_key(&owner, &id, &sealed),
        Err(Error::InvalidPrivateKey)
    ));
    let key_token = recovery.reserve_key(&owner, &id).expect("other kind");
    assert!(matches!(
        recovery.encapsulate(&owner, &id, peer, b"bound context", &key_token),
        Err(Error::InvalidPrivateKey)
    ));
    let independent = recovery
        .reserve_encapsulation(&owner, &[54; 32], peer, b"bound context")
        .expect("fresh operation");
    let fresh = recovery
        .encapsulate(&owner, &[54; 32], peer, b"bound context", &independent)
        .expect("fresh result");
    assert_ne!(first.ciphertext.to_bytes(), fresh.ciphertext.to_bytes());
}

#[cfg(feature = "sealed-operations")]
#[test]
fn sealed_operations_authenticate_all_bytes_and_reject_truncation_and_wrong_key() {
    use expert::replay::{RecoveryKey, SealedOperation};
    let owner = runtime(Limits::default());
    let recovery = RecoveryKey::from_host_key(&[47; 32]).expect("host key");
    let wrong = RecoveryKey::from_host_key(&[48; 32]).expect("other host key");
    let id = [55; 32];
    let sealed = recovery.reserve_key(&owner, &id).expect("reservation");
    assert_eq!(sealed.as_bytes().len(), 277);
    assert!(matches!(
        wrong.generate_key(&owner, &id, &sealed),
        Err(Error::InvalidPrivateKey)
    ));
    assert!(matches!(
        recovery.generate_key(&owner, &[56; 32], &sealed),
        Err(Error::InvalidPrivateKey)
    ));
    for offset in 0..sealed.as_bytes().len() {
        let mut changed = sealed.as_bytes().to_vec();
        *changed.get_mut(offset).expect("existing byte") ^= 1;
        if let Ok(token) = SealedOperation::from_bytes(&changed) {
            assert!(
                matches!(
                    recovery.generate_key(&owner, &id, &token),
                    Err(Error::InvalidPrivateKey)
                ),
                "offset {offset}"
            );
        }
        assert!(
            SealedOperation::from_bytes(sealed.as_bytes().get(..offset).expect("prefix")).is_err()
        );
    }
    let mut extended = sealed.as_bytes().to_vec();
    extended.push(0);
    assert!(matches!(
        SealedOperation::from_bytes(&extended),
        Err(Error::InvalidLength)
    ));
    // Refusals must not consume a live-key slot or corrupt the valid reservation.
    assert!(recovery.generate_key(&owner, &id, &sealed).is_ok());
}

#[cfg(feature = "sealed-operations")]
#[test]
fn sealed_operations_recheck_policy_revocation_and_owner_lifecycle() {
    use expert::replay::RecoveryKey;
    let owner = runtime(Limits::default());
    let mut recovery = RecoveryKey::from_host_key(&[47; 32]).expect("host key");
    let id = [57; 32];
    let sealed = recovery.reserve_key(&owner, &id).expect("reservation");
    let (updated, signature) = signed_update(3, 42, "");
    let update = owner
        .prepare_policy_update(&updated, &signature)
        .expect("verified policy");
    let newer = update
        .activate_after_persist()
        .expect("host persisted state");
    assert!(matches!(
        recovery.generate_key(&owner, &id, &sealed),
        Err(Error::Closed)
    ));
    assert!(matches!(
        recovery.generate_key(&newer, &id, &sealed),
        Err(Error::InvalidPrivateKey)
    ));
    let (revoked, signature) = signed_update(4, 42, "");
    let revoked = String::from_utf8(revoked)
        .expect("policy")
        .replace("ML-KEM-768", "ML-KEM-1024");
    let (sk, _) = MlDsa65::generate([42; 32]);
    let mut signature = signature;
    MlDsa65
        .sign(
            &sk,
            &policy_signature_message(revoked.as_bytes()),
            &[0; 32],
            &mut signature,
        )
        .expect("revocation signature");
    let disabled = newer
        .prepare_policy_update(revoked.as_bytes(), &signature)
        .expect("revocation")
        .activate_after_persist()
        .expect("persisted");
    assert!(matches!(
        recovery.reserve_key(&disabled, &id),
        Err(Error::PolicyDenied)
    ));
    let fresh_owner = runtime(Limits::default());
    assert!(matches!(
        recovery.reserve_key(&fresh_owner, &[0; 32]),
        Err(Error::InvalidLength)
    ));
    recovery.close();
    assert!(matches!(
        recovery.reserve_key(&fresh_owner, &id),
        Err(Error::Closed)
    ));
    assert!(matches!(
        recovery.generate_key(&fresh_owner, &id, &sealed),
        Err(Error::Closed)
    ));
}

#[test]
fn expert_transfer_checks_format_pairing_and_preserves_contextbound_roundtrips() {
    let owner = runtime(Limits {
        max_live_keys: 1,
        max_in_flight: 1,
    });
    let mut original = owner.generate_with(coins(7)).expect("key");
    let public = original.public_key().expect("public").to_bytes();
    let mut exported = expert::export_expanded(&original).expect("expert export");
    original.close();
    let imported = expert::import_expanded(&owner, exported.as_bytes()).expect("checked import");
    assert_eq!(imported.public_key().expect("public").to_bytes(), public);
    let enc = owner
        .encapsulate(imported.public_key().expect("public"), b"expert/context")
        .expect("encap");
    let dec = imported
        .decapsulate(&enc.ciphertext, b"expert/context")
        .expect("decap");
    assert_eq!(bytes(&enc.secret).as_bytes(), bytes(&dec).as_bytes());
    assert_eq!(
        expert::export_expanded(&imported)
            .expect("export")
            .as_bytes(),
        exported.as_bytes()
    );
    drop(imported);
    for offset in [0, 3, 4, 5, 6, 7] {
        let mut invalid = ZeroizingBytes::<{ expert::EXPANDED_KEY_LEN }>::zeroed();
        invalid.as_mut_bytes().copy_from_slice(exported.as_bytes());
        *invalid.as_mut_bytes().get_mut(offset).expect("header byte") ^= 1;
        assert!(matches!(
            expert::import_expanded(&owner, invalid.as_bytes()),
            Err(Error::InvalidPrivateKey)
        ));
    }
    for (start, length) in [(8, 1152), (8 + 1152, 2), (8 + 2336, 32)] {
        let mut invalid = ZeroizingBytes::<{ expert::EXPANDED_KEY_LEN }>::zeroed();
        invalid.as_mut_bytes().copy_from_slice(exported.as_bytes());
        invalid
            .as_mut_bytes()
            .get_mut(start..start + length)
            .expect("key region")
            .fill(0xff);
        assert!(matches!(
            expert::import_with(&owner, invalid.as_bytes(), coins(11)),
            Err(Error::InvalidPrivateKey)
        ));
        assert_eq!(owner.state.keys.load(Ordering::Acquire), 0);
    }
    assert!(matches!(
        expert::import_with(&owner, exported.as_bytes(), |_| Err(Error::Entropy)),
        Err(Error::Entropy)
    ));
    assert_eq!(owner.state.keys.load(Ordering::Acquire), 0);
    assert!(matches!(
        expert::import_expanded(&owner, &[0; 64]),
        Err(Error::InvalidLength)
    ));
    exported.close();
    assert!(exported.as_bytes().iter().all(|byte| *byte == 0));
    assert!(matches!(
        expert::import_expanded(&owner, exported.as_bytes()),
        Err(Error::InvalidPrivateKey)
    ));
    let key = owner.generate_key().expect("quota recovered");
    owner.close();
    assert!(matches!(expert::export_expanded(&key), Err(Error::Closed)));
    assert!(matches!(
        expert::import_expanded(&owner, exported.as_bytes()),
        Err(Error::Closed)
    ));
}

#[test]
fn owned_component_operations_cover_all_pairings_with_one_operation_slot() {
    use expert::{component_public_key, decapsulate_components, PqKeySource, TraditionalKeySource};
    let owner = runtime(Limits {
        max_live_keys: 2,
        max_in_flight: 1,
    });
    let first = owner.generate_with(coins(11)).expect("first owner");
    let second = owner.generate_with(coins(21)).expect("second owner");
    for (pq, traditional) in [
        (&first, &first),
        (&first, &second),
        (&second, &first),
        (&second, &second),
    ] {
        let public = component_public_key(
            &owner,
            PqKeySource::from_key(pq),
            TraditionalKeySource::from_key(traditional),
        )
        .expect("public components");
        let encapsulated = owner
            .encapsulate_with(&public, b"component-test/v1", coins(31))
            .expect("encapsulation");
        let decapsulated = decapsulate_components(
            &owner,
            PqKeySource::from_key(pq),
            TraditionalKeySource::from_key(traditional),
            &encapsulated.ciphertext,
            b"component-test/v1",
        )
        .expect("component decapsulation");
        assert_eq!(
            bytes(&encapsulated.secret).as_bytes(),
            bytes(&decapsulated).as_bytes()
        );
        assert_eq!(owner.state.keys.load(Ordering::Acquire), 2);
        assert_eq!(owner.state.operations.load(Ordering::Acquire), 0);
        let wrong_context = decapsulate_components(
            &owner,
            PqKeySource::from_key(pq),
            TraditionalKeySource::from_key(traditional),
            &encapsulated.ciphertext,
            b"component-test/v2",
        )
        .expect("different context");
        assert_ne!(
            bytes(&wrong_context).as_bytes(),
            bytes(&encapsulated.secret).as_bytes()
        );
        if !std::ptr::eq(pq, traditional) {
            let wrong_pair = pq
                .decapsulate(&encapsulated.ciphertext, b"component-test/v1")
                .expect("other pair");
            assert_ne!(
                bytes(&wrong_pair).as_bytes(),
                bytes(&encapsulated.secret).as_bytes()
            );
        }
    }
}

#[test]
fn owned_components_reject_other_runtimes_and_retain_revocation_and_implicit_rejection() {
    use expert::{component_public_key, decapsulate_components, PqKeySource, TraditionalKeySource};
    let owner = runtime(Limits::default());
    let other = runtime(Limits::default());
    let first = owner.generate_with(coins(11)).expect("first owner");
    let mut second = owner.generate_with(coins(21)).expect("second owner");
    let foreign = other
        .generate_with(coins(31))
        .expect("same-policy foreign runtime");
    assert_eq!(
        owner.policy_binding().expect("binding"),
        other.policy_binding().expect("binding")
    );
    assert!(matches!(
        component_public_key(
            &owner,
            PqKeySource::from_key(&first),
            TraditionalKeySource::from_key(&foreign)
        ),
        Err(Error::PolicyDenied)
    ));
    let public = component_public_key(
        &owner,
        PqKeySource::from_key(&first),
        TraditionalKeySource::from_key(&second),
    )
    .expect("components");
    // Both component owners agree with each other, but not with the explicit
    // runtime. Equal signed policy bytes must not join revocation authorities.
    assert!(matches!(
        component_public_key(
            &other,
            PqKeySource::from_key(&first),
            TraditionalKeySource::from_key(&second)
        ),
        Err(Error::PolicyDenied)
    ));
    let mut encapsulated = owner
        .encapsulate_with(&public, b"component-test/v1", coins(41))
        .expect("encapsulation");
    assert!(matches!(
        decapsulate_components(
            &other,
            PqKeySource::from_key(&first),
            TraditionalKeySource::from_key(&second),
            &encapsulated.ciphertext,
            b"component-test/v1"
        ),
        Err(Error::PolicyDenied)
    ));
    assert!(matches!(
        decapsulate_components(
            &owner,
            PqKeySource::from_key(&first),
            TraditionalKeySource::from_key(&foreign),
            &encapsulated.ciphertext,
            b"component-test/v1"
        ),
        Err(Error::PolicyDenied)
    ));
    *encapsulated
        .ciphertext
        .pq
        .first_mut()
        .expect("PQ ciphertext") ^= 1;
    let rejected = decapsulate_components(
        &owner,
        PqKeySource::from_key(&first),
        TraditionalKeySource::from_key(&second),
        &encapsulated.ciphertext,
        b"component-test/v1",
    )
    .expect("implicit rejection secret");
    assert_ne!(
        bytes(&rejected).as_bytes(),
        bytes(&encapsulated.secret).as_bytes()
    );
    encapsulated.ciphertext.traditional.fill(0);
    assert!(matches!(
        decapsulate_components(
            &owner,
            PqKeySource::from_key(&first),
            TraditionalKeySource::from_key(&second),
            &encapsulated.ciphertext,
            b"component-test/v1"
        ),
        Err(Error::InvalidKeyShare)
    ));
    second.close();
    assert!(matches!(
        component_public_key(
            &owner,
            PqKeySource::from_key(&first),
            TraditionalKeySource::from_key(&second)
        ),
        Err(Error::Closed)
    ));
    owner.close();
    assert!(matches!(rejected.export_for_protocol(), Err(Error::Closed)));
    assert!(matches!(
        component_public_key(
            &owner,
            PqKeySource::from_key(&first),
            TraditionalKeySource::from_key(&first)
        ),
        Err(Error::Closed)
    ));
    assert_eq!(owner.state.operations.load(Ordering::Acquire), 0);
}

#[test]
fn policy_preparation_pins_root_is_monotonic_and_abandonment_leaves_old_live() {
    let owner = runtime(Limits::default());
    for (version, seed, suffix) in [(1, 42, ""), (2, 42, ""), (2, 42, "\n"), (3, 43, "")] {
        let (policy, signature) = signed_update(version, seed, suffix);
        assert!(matches!(
            owner.prepare_policy_update(&policy, &signature),
            Err(Error::PolicyDenied)
        ));
        assert!(owner.generate_key().is_ok());
    }
    let (policy, signature) = signed_update(3, 42, "");
    let update = owner
        .prepare_policy_update(&policy, &signature)
        .expect("update");
    let (previous, next) = update.states().expect("states");
    assert_eq!(previous, owner.trusted_state());
    assert_eq!(next.version(), 3);
    drop(update);
    assert!(owner.generate_key().is_ok());
    let mut update = owner
        .prepare_policy_update(&policy, &signature)
        .expect("update");
    update.close();
    assert!(matches!(update.states(), Err(Error::Closed)));
    assert!(matches!(
        update.activate_after_persist(),
        Err(Error::Closed)
    ));
    assert!(owner.generate_key().is_ok());
}

#[test]
fn policy_activation_revokes_all_old_owners_but_not_the_replacement() {
    let owner = runtime(Limits::default());
    let key = owner.generate_key().expect("key");
    let enc = owner
        .encapsulate(key.public_key().expect("public"), b"")
        .expect("encap");
    let derived = enc
        .secret
        .derive_key(KeyPurpose::Exporter, b"app", b"")
        .expect("derived");
    let (policy3, signature3) = signed_update(3, 42, "");
    let (policy4, signature4) = signed_update(4, 42, "");
    let first = owner
        .prepare_policy_update(&policy3, &signature3)
        .expect("first");
    let other = owner
        .prepare_policy_update(&policy4, &signature4)
        .expect("other");
    // Test host CAS, only after signature verification; production storage must be durable.
    let mut stored = owner.trusted_state();
    let (expected, next) = first.states().expect("states");
    assert_eq!(stored, expected);
    stored = next;
    let replacement = first.activate_after_persist().expect("activate");
    assert_eq!(replacement.trusted_state(), stored);
    assert!(matches!(key.public_key(), Err(Error::Closed)));
    assert!(matches!(
        enc.secret.export_for_protocol(),
        Err(Error::Closed)
    ));
    assert!(matches!(derived.export_for_protocol(), Err(Error::Closed)));
    assert!(matches!(other.activate_after_persist(), Err(Error::Closed)));
    drop(owner);
    assert!(replacement.generate_key().is_ok());
    let candidate = replacement
        .prepare_policy_update(&policy4, &signature4)
        .expect("new candidate");
    replacement.close();
    assert!(matches!(
        candidate.activate_after_persist(),
        Err(Error::Closed)
    ));
}

#[test]
fn racing_policy_candidates_have_exactly_one_activation_winner() {
    let owner = runtime(Limits::default());
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for version in [3, 4] {
        let (policy, signature) = signed_update(version, 42, "");
        let candidate = owner
            .prepare_policy_update(&policy, &signature)
            .expect("candidate");
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            candidate.activate_after_persist()
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(Error::Closed)))
            .count(),
        1
    );
    assert!(matches!(owner.generate_key(), Err(Error::Closed)));
}

#[test]
fn signed_suite_revocation_can_be_persisted_recovered_and_later_reenabled() {
    let owner = runtime(Limits::default());
    let key = owner.generate_key().expect("old key");
    let (policy, _, root) = fixture();
    let revoked = String::from_utf8(policy.clone())
        .expect("text")
        .replace("policy_version = 2", "policy_version = 3")
        .replace("ML-KEM-768", "ML-KEM-1024");
    let (sk, _) = MlDsa65::generate([42; 32]);
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &sk,
            &policy_signature_message(revoked.as_bytes()),
            &[0; 32],
            &mut signature,
        )
        .expect("sign revocation");
    let update = owner
        .prepare_policy_update(revoked.as_bytes(), &signature)
        .expect("authenticated revocation must be installable");
    let (previous, persisted) = update.states().expect("states");
    assert_eq!(previous, owner.trusted_state());
    let disabled = update
        .activate_after_persist()
        .expect("activate revocation");
    assert!(matches!(key.public_key(), Err(Error::Closed)));
    let mut entropy_calls = 0;
    assert!(matches!(
        disabled.generate_with(|_| {
            entropy_calls += 1;
            Err(Error::Entropy)
        }),
        Err(Error::PolicyDenied)
    ));
    assert_eq!(entropy_calls, 0, "disabled runtime must not draw entropy");
    // Recovering from a persisted revocation must not silently restore old rights.
    let recovered = Runtime::from_signed_policy(
        revoked.as_bytes(),
        &signature,
        root,
        Some(&persisted),
        Limits::default(),
    )
    .expect("recover authenticated disabled runtime");
    assert!(!recovered.is_enabled().expect("open configuration"));
    assert!(matches!(recovered.generate_key(), Err(Error::PolicyDenied)));
    let (allowed, signature) = signed_update(4, 42, "");
    let next = recovered
        .prepare_policy_update(&allowed, &signature)
        .expect("reenable preparation")
        .activate_after_persist()
        .expect("reenable activation");
    next.generate_key().expect("new policy permits generation");
    assert!(next.is_enabled().expect("open configuration"));
}

#[test]
fn purpose_derivation_agrees_across_peers_and_revokes_with_its_runtime() {
    let runtime = runtime(Limits::default());
    let key = runtime.generate_with(coins(7)).expect("key");
    let mut result = runtime
        .encapsulate_with(key.public_key().expect("public"), b"handshake", coins(9))
        .expect("encap");
    let mut received = key
        .decapsulate(&result.ciphertext, b"handshake")
        .expect("decap");
    let mut last = None;
    for purpose in [
        KeyPurpose::InitiatorTraffic,
        KeyPurpose::ResponderTraffic,
        KeyPurpose::InitiatorConfirmation,
        KeyPurpose::ResponderConfirmation,
        KeyPurpose::Exporter,
    ] {
        let left = result
            .secret
            .derive_key(purpose, b"app/v1/aes256", b"authenticated-transcript")
            .expect("derive");
        let right = received
            .derive_key(purpose, b"app/v1/aes256", b"authenticated-transcript")
            .expect("derive");
        assert_eq!(
            left.export_for_protocol().expect("export").as_bytes(),
            right.export_for_protocol().expect("export").as_bytes()
        );
        last = Some(left);
    }
    received.close();
    assert!(matches!(
        received.derive_key(KeyPurpose::Exporter, b"app/v1", b""),
        Err(Error::Closed)
    ));
    let mut derived = last.expect("derived owner");
    result.secret.close();
    assert!(derived.export_for_protocol().is_ok());
    runtime.close();
    assert!(matches!(derived.export_for_protocol(), Err(Error::Closed)));
    assert!(matches!(
        result
            .secret
            .derive_key(KeyPurpose::Exporter, b"app/v1", b""),
        Err(Error::Closed)
    ));
    derived.close();
    derived.close();
}

#[test]
fn purpose_derivation_rejects_invalid_shapes_and_respects_the_operation_budget() {
    let runtime = runtime(Limits {
        max_live_keys: 1,
        max_in_flight: 1,
    });
    let key = runtime.generate_key().expect("key");
    let result = runtime
        .encapsulate(key.public_key().expect("public"), b"")
        .expect("encap");
    for (label, context, expected) in [
        (vec![], vec![], Error::InvalidLength),
        (vec![b'x'; 256], vec![], Error::InvalidLength),
        (vec![b'x'], vec![0; 65537], Error::InvalidLength),
        (vec![0], vec![], Error::InvalidPurpose),
        (vec![b' '], vec![], Error::InvalidPurpose),
        (vec![0xff], vec![], Error::InvalidPurpose),
    ] {
        assert!(
            matches!(result.secret.derive_key(KeyPurpose::Exporter, &label, &context), Err(e) if e == expected)
        );
    }
    assert!(result
        .secret
        .derive_key(KeyPurpose::Exporter, &[b'x'; 255], &[0; 65536])
        .is_ok());
    for value in [0, 6, u32::MAX] {
        assert_eq!(KeyPurpose::try_from(value), Err(Error::InvalidPurpose));
    }
    let lease = runtime.state.begin().expect("reserve");
    assert!(matches!(
        result.secret.derive_key(KeyPurpose::Exporter, b"app", b""),
        Err(Error::ResourceLimit)
    ));
    drop(lease);
    let mut derived = result
        .secret
        .derive_key(KeyPurpose::Exporter, b"app", b"")
        .expect("lease released");
    derived.close();
    assert!(matches!(derived.export_for_protocol(), Err(Error::Closed)));
}

#[test]
fn same_document_signed_by_another_root_does_not_share_application_keys() {
    let runtime = runtime(Limits::default());
    let (policy, _, _) = fixture();
    let (sk, root) = MlDsa65::generate([43; 32]);
    let mut signature = vec![0; ML_DSA_65_SIG_LEN];
    MlDsa65
        .sign(
            &sk,
            &policy_signature_message(policy),
            &[0; 32],
            &mut signature,
        )
        .expect("sign");
    let other = Runtime::from_signed_policy(policy, &signature, &root, None, Limits::default())
        .expect("other root");
    let key = runtime.generate_with(coins(7)).expect("key");
    let peer = key.public_key().expect("public");
    let first = runtime
        .encapsulate_with(peer, b"context", coins(9))
        .expect("encap");
    let second = other
        .encapsulate_with(peer, b"context", coins(9))
        .expect("encap");
    // The existing ContextBound protocol bytes are unchanged; the new KDF binds the root.
    assert_eq!(
        bytes(&first.secret).as_bytes(),
        bytes(&second.secret).as_bytes()
    );
    let left = first
        .secret
        .derive_key(KeyPurpose::Exporter, b"app", b"")
        .expect("derive");
    let right = second
        .secret
        .derive_key(KeyPurpose::Exporter, b"app", b"")
        .expect("derive");
    assert_ne!(
        left.export_for_protocol().expect("export").as_bytes(),
        right.export_for_protocol().expect("export").as_bytes()
    );
}

#[test]
fn verifies_signature_root_and_monotonic_state() {
    let (policy, signature, root) = fixture();
    let mut changed = policy.clone();
    changed.push(b' ');
    assert!(matches!(
        Runtime::from_signed_policy(&changed, signature, root, None, Limits::default()),
        Err(Error::PolicyDenied)
    ));
    assert!(matches!(
        Runtime::from_signed_policy(
            policy,
            signature,
            &vec![0; root.len()],
            None,
            Limits::default()
        ),
        Err(Error::PolicyDenied)
    ));
    let current = runtime(Limits::default()).trusted_state();
    assert!(Runtime::from_signed_policy(
        policy,
        signature,
        root,
        Some(&current),
        Limits::default()
    )
    .is_ok());
    for previous in [
        TrustedPolicyState::new(3, [0; 32]).expect("state"),
        TrustedPolicyState::new(2, [0; 32]).expect("state"),
    ] {
        assert!(matches!(
            Runtime::from_signed_policy(
                policy,
                signature,
                root,
                Some(&previous),
                Limits::default()
            ),
            Err(Error::PolicyDenied)
        ));
    }
    assert!(matches!(
        Runtime::from_signed_policy(&[1; 40], signature, root, None, Limits::default()),
        Err(Error::PolicyDenied)
    ));
}

#[test]
fn malformed_policy_shapes_match_foreign_sdk_length_errors() {
    let (policy, signature, root) = fixture();
    for (policy, signature, root) in [
        (Vec::new(), signature.clone(), root.clone()),
        (vec![1; 65_537], signature.clone(), root.clone()),
        (policy.clone(), Vec::new(), root.clone()),
        (policy.clone(), signature.clone(), vec![0; 1951]),
    ] {
        assert!(matches!(
            Runtime::from_signed_policy(&policy, &signature, &root, None, Limits::default()),
            Err(Error::InvalidLength)
        ));
    }
}

#[test]
fn owned_streamed_path_matches_original_serialized_staged_path() {
    let runtime = runtime(Limits::default());
    let key = runtime.generate_with(coins(7)).expect("key");
    let (old_sk, old_pk) = MlKem768::generate_zeroizing(&[7; 64]).expect("old key");
    let old_trad = X25519::public_key(&[8; 32]);
    let kem = HybridKem::<_, _, Sha3_256Xof>::new(
        &MlKem768,
        &X25519,
        Profile::ContextBound,
        DEFAULT_SUITE_ID,
        2,
    )
    .expect("old kem");
    for len in [0, 1, 135, 136, 137, 4096, MAX_APPLICATION_CONTEXT_BYTES] {
        let context = vec![0x5a; len];
        let mut wrapped = vec![0; policy_bound_context_len(len).expect("bounded")];
        encode_policy_bound_context(&runtime.trusted_state().digest(), &context, &mut wrapped)
            .expect("context");
        let result = runtime
            .encapsulate_with(key.public_key().expect("public"), &context, coins(9))
            .expect("encap");
        let mut ct_pq = [0; ML_KEM_768_CT_LEN];
        let mut ct_trad = [0; 32];
        let old_secret = kem
            .encapsulate(
                &old_pk,
                &old_trad,
                &wrapped,
                &[9; 32],
                &[10; 32],
                &mut ct_pq,
                &mut ct_trad,
            )
            .expect("old encap");
        assert_eq!(result.ciphertext.pq, ct_pq);
        assert_eq!(result.ciphertext.traditional, ct_trad);
        assert_eq!(bytes(&result.secret).as_bytes(), old_secret.as_bytes());
        let decoded = key
            .decapsulate(&result.ciphertext, &context)
            .expect("owned decap");
        assert_eq!(bytes(&decoded).as_bytes(), old_secret.as_bytes());
        let old_decoded = kem
            .decapsulate(
                q_periapt_kem::PqSecretKey::new(old_sk.as_bytes()),
                PqCiphertext::new(&ct_pq),
                q_periapt_kem::PqPublicKey::new(&old_pk),
                TradSecretKey::new(&[8; 32]),
                TradCiphertext::new(&ct_trad),
                TradPublicKey::new(&old_trad),
                &wrapped,
            )
            .expect("old decap");
        assert_eq!(bytes(&decoded).as_bytes(), old_decoded.as_bytes());
    }
}

#[test]
fn implicit_rejection_and_public_failure_semantics_are_preserved() {
    let runtime = runtime(Limits::default());
    let key = runtime.generate_key().expect("platform key");
    let result = runtime
        .encapsulate(key.public_key().expect("public"), b"test/session")
        .expect("encap");
    let mut bad = result.ciphertext.clone();
    *bad.pq.first_mut().expect("ciphertext byte") ^= 1;
    let rejected = key
        .decapsulate(&bad, b"test/session")
        .expect("implicit rejection succeeds");
    assert_ne!(
        bytes(&rejected).as_bytes(),
        bytes(&result.secret).as_bytes()
    );
    assert_eq!(
        bytes(&rejected).as_bytes(),
        bytes(&key.decapsulate(&bad, b"test/session").expect("repeat")).as_bytes()
    );
    bad.traditional.fill(0);
    assert!(matches!(
        key.decapsulate(&bad, b"test/session"),
        Err(Error::InvalidKeyShare)
    ));
    assert_ne!(
        bytes(&result.secret).as_bytes(),
        bytes(
            &key.decapsulate(&result.ciphertext, b"other")
                .expect("different binding")
        )
        .as_bytes()
    );
    let large = vec![0; MAX_APPLICATION_CONTEXT_BYTES + 1];
    assert!(matches!(
        runtime.encapsulate(key.public_key().expect("public"), &large),
        Err(Error::InvalidLength)
    ));
    assert!(matches!(
        key.decapsulate(&result.ciphertext, &large),
        Err(Error::InvalidLength)
    ));
    assert!(matches!(
        Ciphertext::from_bytes(&[0; 12]),
        Err(Error::InvalidLength)
    ));
}

#[test]
fn entropy_failure_returns_quota_and_never_publishes_a_key_or_result() {
    let runtime = runtime(Limits {
        max_live_keys: 1,
        max_in_flight: 1,
    });
    let mut calls = 0;
    let failed = runtime.generate_with(|out| {
        out.fill(0xaa);
        calls += 1;
        if calls == 2 {
            Err(Error::Entropy)
        } else {
            Ok(())
        }
    });
    assert!(matches!(failed, Err(Error::Entropy)));
    assert_eq!(runtime.state.keys.load(Ordering::Acquire), 0);
    assert_eq!(runtime.state.operations.load(Ordering::Acquire), 0);
    let key = runtime.generate_key().expect("quota recovered");
    assert!(matches!(
        runtime.encapsulate_with(key.public_key().expect("public"), b"ctx", |_| Err(
            Error::Entropy
        )),
        Err(Error::Entropy)
    ));
    assert_eq!(runtime.state.operations.load(Ordering::Acquire), 0);
}

#[test]
fn concurrent_key_admission_keeps_the_exact_limit_and_recovers_capacity() {
    let owner = runtime(Limits {
        max_live_keys: 3,
        max_in_flight: 16,
    });
    let start = std::sync::Barrier::new(17);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    owner.generate_key()
                })
            })
            .collect();
        start.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("key worker"))
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
    assert!(results
        .iter()
        .all(|result| matches!(result, Ok(_) | Err(Error::ResourceLimit))));
    assert_eq!(owner.state.keys.load(Ordering::Acquire), 3);
    drop(results);
    assert_eq!(owner.state.keys.load(Ordering::Acquire), 0);
    assert!(owner.generate_key().is_ok());
}

#[test]
fn close_drop_and_resource_bounds_are_enforced() {
    let runtime = runtime(Limits {
        max_live_keys: 1,
        max_in_flight: 1,
    });
    let mut key = runtime.generate_key().expect("key");
    assert!(matches!(runtime.generate_key(), Err(Error::ResourceLimit)));
    let result = runtime
        .encapsulate(key.public_key().expect("public"), b"ctx")
        .expect("encap");
    key.close();
    key.close();
    assert!(matches!(key.public_key(), Err(Error::Closed)));
    assert!(matches!(
        key.decapsulate(&result.ciphertext, b"ctx"),
        Err(Error::Closed)
    ));
    let other = runtime.generate_key().expect("slot reused");
    let held = runtime.state.begin().expect("admit");
    assert!(matches!(
        other.decapsulate(&result.ciphertext, b"ctx"),
        Err(Error::ResourceLimit)
    ));
    drop(held);
    let mut secret = result.secret;
    secret.close();
    secret.close();
    assert!(matches!(secret.export_for_protocol(), Err(Error::Closed)));
    drop(runtime);
    assert!(matches!(other.public_key(), Err(Error::Closed)));
    assert!(matches!(
        other.decapsulate(&result.ciphertext, b"ctx"),
        Err(Error::Closed)
    ));
}

#[test]
fn runtime_revocation_also_closes_retained_secret_exports() {
    let runtime = runtime(Limits::default());
    let key = runtime.generate_key().expect("key");
    let result = runtime
        .encapsulate(key.public_key().expect("public"), b"ctx")
        .expect("encapsulation");
    let recovered = key
        .decapsulate(&result.ciphertext, b"ctx")
        .expect("decapsulation");
    runtime.close();
    assert!(matches!(
        result.secret.export_for_protocol(),
        Err(Error::Closed)
    ));
    assert!(matches!(
        recovered.export_for_protocol(),
        Err(Error::Closed)
    ));
}

#[test]
fn close_during_admitted_operation_does_not_free_live_storage() {
    let runtime = Arc::new(runtime(Limits {
        max_live_keys: 1,
        max_in_flight: 1,
    }));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let worker_runtime = Arc::clone(&runtime);
    let worker = std::thread::spawn(move || {
        let mut first = true;
        worker_runtime.generate_with(|out| {
            if first {
                first = false;
                entered_tx.send(()).expect("entered");
                resume_rx.recv().expect("resume");
            }
            getrandom::fill(out).map_err(|_| Error::Entropy)
        })
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("worker active");
    assert!(matches!(runtime.generate_key(), Err(Error::ResourceLimit)));
    runtime.close();
    assert!(matches!(runtime.generate_key(), Err(Error::Closed)));
    resume_tx.send(()).expect("resume");
    let key = worker
        .join()
        .expect("join")
        .expect("already admitted work finishes");
    assert!(matches!(key.public_key(), Err(Error::Closed)));
    drop(key);
    assert_eq!(runtime.state.keys.load(Ordering::Acquire), 0);
    assert_eq!(runtime.state.operations.load(Ordering::Acquire), 0);
}
