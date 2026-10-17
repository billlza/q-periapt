// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    bootstrap::tests::fixture_with_signers,
    crypto::{Purpose, SigningReservation},
    durable::tests::{directory, new_store, reopen, ChildGuard},
    AnchorSigningKey, DeviceSigningKey, DurableStatus, InitiatorOperation, PolicySigningKey,
    PrekeyQuality, RootSigningKey,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

#[test]
fn all_signing_roles_reopen_exact_keys_and_cannot_cross_roles_or_identities() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let wrapping = JournalKey::provision(&path.join("wrapping")).expect("wrapping");
    let other = JournalKey::provision(&path.join("other-wrapping")).expect("other key");
    macro_rules! check {
        ($owner:ident, $role:expr, $name:literal) => {{
            let id = SigningKeyId::generate().expect("identity");
            let file = path.join($name);
            let mut owner = $owner::provision(&file, &wrapping, id).expect("provision");
            let public = owner.public_key().expect("public");
            let signature = owner
                .sign(Purpose::Credential, b"owned test message")
                .expect("sign");
            let disk = fs::read(&file).expect("ciphertext");
            assert_eq!(disk.len(), FILE_BYTES);
            assert!(!disk
                .windows(PUBLIC_KEY_BYTES)
                .any(|window| window == public.encode()));
            for role in [1, 2, 3, 4].into_iter().filter(|r| *r != $role) {
                assert!(matches!(
                    open(&file, &wrapping, id, role),
                    Err(DurableError::Conflict)
                ));
            }
            assert!(matches!(
                $owner::open(&file, &other, id),
                Err(DurableError::Authentication)
            ));
            assert!(matches!(
                $owner::open(
                    &file,
                    &wrapping,
                    SigningKeyId::generate().expect("other ID")
                ),
                Err(DurableError::Conflict)
            ));
            assert!(matches!(
                $owner::provision(&file, &wrapping, id),
                Err(DurableError::PrivateFile)
            ));
            assert_eq!(fs::read(&file).expect("unchanged"), disk);
            owner.close();
            assert!(matches!(owner.public_key(), Err(Error::Closed)));
            let restored = $owner::open(&file, &wrapping, id).expect("restore exact owner");
            assert_eq!(restored.public_key().expect("public"), public);
            public
                .verify(Purpose::Credential, b"owned test message", &signature)
                .expect("original signature");
            let new_signature = restored
                .sign(Purpose::Credential, b"after reopening")
                .expect("new signature");
            public
                .verify(Purpose::Credential, b"after reopening", &new_signature)
                .expect("new signature valid");
        }};
    }
    check!(RootSigningKey, 1, "root");
    check!(DeviceSigningKey, 2, "device");
    check!(PolicySigningKey, 3, "policy");
    check!(AnchorSigningKey, 4, "anchor");
}

#[test]
fn restored_device_owner_replays_exact_reserved_signature() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let wrapping = JournalKey::provision(&path.join("wrapping")).expect("wrapping");
    let id = SigningKeyId::generate().expect("identity");
    let file = path.join("device");
    let mut owner = DeviceSigningKey::provision(&file, &wrapping, id).expect("provision");
    let operation = [73; 32];
    let public = owner.public_key().expect("public");
    let reservation = SigningReservation::reserve(
        &public,
        &operation,
        Purpose::BootstrapResponder,
        b"fixed responder body",
    )
    .expect("reservation");
    let before = reservation
        .sign(
            &owner,
            &operation,
            Purpose::BootstrapResponder,
            b"fixed responder body",
        )
        .expect("first signature");
    owner.close();
    let owner = DeviceSigningKey::open(&file, &wrapping, id).expect("restored");
    let after = reservation
        .sign(
            &owner,
            &operation,
            Purpose::BootstrapResponder,
            b"fixed responder body",
        )
        .expect("recovered signature");
    assert_eq!(before, after);
    public
        .verify(Purpose::BootstrapResponder, b"fixed responder body", &after)
        .expect("both components verify");
    assert!(matches!(
        reservation.sign(
            &owner,
            &operation,
            Purpose::Manifest,
            b"fixed responder body"
        ),
        Err(Error::Scope)
    ));
}

#[test]
fn encrypted_owner_rejects_every_byte_change_lengths_and_inconsistent_material() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let wrapping = JournalKey::provision(&path.join("wrapping")).expect("wrapping");
    let id = SigningKeyId::generate().expect("identity");
    DeviceSigningKey::provision(&path.join("device"), &wrapping, id).expect("provision");
    let wire = fs::read(path.join("device")).expect("sealed");
    for index in 0..wire.len() {
        let mut changed = wire.clone();
        *changed.get_mut(index).expect("byte") ^= 1;
        assert!(
            unseal(&wrapping, id, 2, &changed).is_err(),
            "changed byte {index}"
        );
    }
    for length in [0, 1, HEADER - 1, HEADER, FILE_BYTES - 1] {
        assert!(unseal(&wrapping, id, 2, wire.get(..length).expect("prefix")).is_err());
    }
    let mut extended = wire;
    extended.push(0);
    assert!(unseal(&wrapping, id, 2, &extended).is_err());
    let mut seed = SigningSeed::generate().expect("seed");
    let different = SigningSeed::generate()
        .expect("other seed")
        .materialize()
        .expect("other material");
    let mismatch =
        seal(&wrapping, id, 2, &seed, &different.public).expect("authenticated writer defect");
    assert!(matches!(
        unseal(&wrapping, id, 2, &mismatch),
        Err(DurableError::InvalidCheckpoint(Error::Scope))
    ));
    seed.classic.as_mut_bytes().fill(0);
    let invalid = seal(&wrapping, id, 2, &seed, &different.public).expect("invalid scalar image");
    assert!(matches!(
        unseal(&wrapping, id, 2, &invalid),
        Err(DurableError::InvalidCheckpoint(Error::Encoding))
    ));
}

#[test]
fn missing_partial_linked_or_public_files_never_create_replacement_keys() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("path");
    let wrapping = JournalKey::provision(&path.join("wrapping")).expect("wrapping");
    let id = SigningKeyId::generate().expect("identity");
    let missing = path.join("missing");
    assert!(DeviceSigningKey::open(&missing, &wrapping, id).is_err());
    assert!(!missing.exists());
    let file = path.join("device");
    DeviceSigningKey::provision(&file, &wrapping, id).expect("provision");
    let symlink = path.join("symlink");
    std::os::unix::fs::symlink(&file, &symlink).expect("symlink fixture");
    assert!(matches!(
        DeviceSigningKey::open(&symlink, &wrapping, id),
        Err(DurableError::PrivateFile)
    ));
    let hardlink = path.join("hardlink");
    fs::hard_link(&file, &hardlink).expect("hardlink fixture");
    assert!(matches!(
        DeviceSigningKey::open(&file, &wrapping, id),
        Err(DurableError::PrivateFile)
    ));
    assert!(matches!(
        DeviceSigningKey::open(&hardlink, &wrapping, id),
        Err(DurableError::PrivateFile)
    ));
    fs::remove_file(hardlink).expect("remove owned link fixture");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("invalid mode fixture");
    assert!(matches!(
        DeviceSigningKey::open(&file, &wrapping, id),
        Err(DurableError::PrivateFile)
    ));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("restore owned fixture");
    let bytes = fs::read(&file).expect("bytes");
    for prefix in [0, HEADER, FILE_BYTES - 1] {
        fs::write(&file, bytes.get(..prefix).expect("truncation")).expect("partial fixture");
        assert!(matches!(
            DeviceSigningKey::open(&file, &wrapping, id),
            Err(DurableError::PrivateFile)
        ));
        assert!(matches!(
            DeviceSigningKey::provision(&file, &wrapping, id),
            Err(DurableError::PrivateFile)
        ));
        assert_eq!(
            fs::metadata(&file).expect("retained partial").len(),
            prefix as u64
        );
    }
}

pub(super) fn at_boundary(stage: &str, public: &PublicKey) {
    let Ok(target) = std::env::var("QPERIAPT_SIGNING_CRASH_STAGE") else {
        return;
    };
    if stage != target {
        return;
    }
    let path = std::env::var_os("QPERIAPT_SIGNING_CRASH_DIR").expect("owned directory");
    let path = Path::new(&path);
    fs::write(path.join("computed-public"), public.encode()).expect("diagnostic public bytes");
    fs::write(path.join("ready.tmp"), stage).expect("marker");
    fs::rename(path.join("ready.tmp"), path.join("ready")).expect("publish marker");
    loop {
        std::thread::park();
    }
}

#[test]
fn signing_provision_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_SIGNING_CRASH_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let wrapping = JournalKey::open(&path.join("wrapping")).expect("wrapping");
    let identity = SigningKeyId::from_trusted_state([81; 32]).expect("ID");
    let owner =
        DeviceSigningKey::provision(&path.join("device"), &wrapping, identity).expect("provision");
    fs::write(
        path.join("returned-public"),
        owner.public_key().expect("public").encode(),
    )
    .expect("return marker");
}

#[test]
fn provisioning_process_loss_never_releases_an_owner_before_file_commit() {
    for stage in ["generated", "published"] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let wrapping = JournalKey::provision(&path.join("wrapping")).expect("wrapping");
        let id = SigningKeyId::from_trusted_state([81; 32]).expect("ID");
        let log = fs::File::create(path.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "crypto::persistence::tests::signing_provision_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_SIGNING_CRASH_DIR", &path)
                .env("QPERIAPT_SIGNING_CRASH_STAGE", stage)
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned child"),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("ready").exists() {
            assert!(
                child.0.try_wait().expect("status").is_none() && Instant::now() < deadline,
                "child did not reach {stage}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !path.join("returned-public").exists(),
            "owner escaped durability barrier"
        );
        child.0.kill().expect("kill owned child");
        assert!(!child.0.wait().expect("reap").success());
        if stage == "generated" {
            assert!(matches!(
                DeviceSigningKey::open(&path.join("device"), &wrapping, id),
                Err(DurableError::PrivateFile)
            ));
            assert!(!path.join("device").exists());
            let owner = DeviceSigningKey::provision(&path.join("device"), &wrapping, id)
                .expect("explicit initial retry with independently retained ID");
            let original =
                fs::read(path.join("computed-public")).expect("unpublished diagnostic key");
            assert_ne!(owner.public_key().expect("public").encode(), original);
            let restored = DeviceSigningKey::open(&path.join("device"), &wrapping, id)
                .expect("restore published retry");
            assert_eq!(
                owner.public_key().expect("public"),
                restored.public_key().expect("public")
            );
        } else {
            let owner = DeviceSigningKey::open(&path.join("device"), &wrapping, id)
                .expect("reconcile complete file");
            assert_eq!(
                owner.public_key().expect("public").encode(),
                fs::read(path.join("computed-public")).expect("prior public")
            );
            let signature = owner
                .sign(Purpose::BootstrapResponder, b"recovered signer")
                .expect("sign");
            owner
                .public_key()
                .expect("public")
                .verify(Purpose::BootstrapResponder, b"recovered signer", &signature)
                .expect("both signatures verify");
        }
    }
}

fn open_peer_signers(path: &Path) -> (DeviceSigningKey, DeviceSigningKey) {
    let key = JournalKey::open(&path.join("wrapping")).expect("protected wrapping key");
    let load = |name, byte| {
        DeviceSigningKey::open(
            &path.join(name),
            &key,
            SigningKeyId::from_trusted_state([byte; 32]).expect("independent ID"),
        )
        .expect("protected signer")
    };
    (load("signer-i", 82), load("signer-r", 83))
}
fn publish(path: &Path, name: &str, bytes: &[u8]) {
    let tmp = path.join(format!("{name}.tmp"));
    fs::write(&tmp, bytes).expect("output");
    fs::rename(tmp, path.join(name)).expect("publish");
}
fn wait_for(path: &Path, marker: &str, child: &mut ChildGuard) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join(marker).exists() {
        let status = child.0.try_wait().expect("status");
        if status.is_some() {
            eprintln!(
                "child log: {}",
                fs::read_to_string(path.join("child.log")).expect("finished log")
            );
        }
        assert!(
            status.is_none() && Instant::now() < deadline,
            "missing {marker}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn protected_signer_response_crash_child() {
    let Some(path) = std::env::var_os("QPERIAPT_PROTECTED_RESPONSE_DIR") else {
        return;
    };
    let path = Path::new(&path);
    let f = fixture_with_signers(PrekeyQuality::OneTimeBoth, None, open_peer_signers(path));
    publish(
        path,
        "peer-public",
        &[
            f.reusable.public_key().expect("public").to_bytes(),
            f.once.public_key().expect("public").to_bytes(),
        ]
        .concat(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.join("peer-initial").exists() {
        assert!(Instant::now() < deadline, "initial deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    let initial = fs::read(path.join("peer-initial")).expect("actual initial");
    let mut store = new_store(path, f.local_device());
    let (pq, classical) = f.sources();
    let reply = store
        .respond(
            Arc::clone(&f.responder),
            &initial,
            &f.signer_r,
            pq,
            classical,
            150,
        )
        .expect("durable response");
    publish(path, "returned-response", &reply);
}

#[test]
fn process_loss_recovers_protected_signer_and_finishes_the_actual_peer_handshake() {
    for after_effect in [false, true] {
        let dir = directory();
        let path = dir.path().canonicalize().expect("path");
        let wrapping = JournalKey::provision(&path.join("wrapping")).expect("wrapping");
        for (name, byte) in [("signer-i", 82), ("signer-r", 83)] {
            drop(
                DeviceSigningKey::provision(
                    &path.join(name),
                    &wrapping,
                    SigningKeyId::from_trusted_state([byte; 32]).expect("retained identity"),
                )
                .expect("actual persistent device signer"),
            );
        }
        let log = fs::File::create(path.join("child.log")).expect("log");
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().expect("binary"))
                .args([
                    "--exact",
                    "crypto::persistence::tests::protected_signer_response_crash_child",
                    "--nocapture",
                ])
                .env("QPERIAPT_PROTECTED_RESPONSE_DIR", &path)
                .env("QPERIAPT_JOURNAL_CRASH_DIR", &path)
                .env(
                    if after_effect {
                        "QPERIAPT_RESPONSE_CRASH_EFFECT"
                    } else {
                        "QPERIAPT_JOURNAL_CRASH_PHASE"
                    },
                    (DurableStatus::ResponseSignatureReserved as u8).to_string(),
                )
                .stdout(Stdio::from(log.try_clone().expect("log clone")))
                .stderr(Stdio::from(log))
                .spawn()
                .expect("owned responder"),
        );
        wait_for(&path, "peer-public", &mut child);
        let public = fs::read(path.join("peer-public")).expect("prekey enrollment");
        let (a, b) = public.split_at(q_periapt_sdk::PUBLIC_KEY_LEN);
        let mut f = fixture_with_signers(
            PrekeyQuality::OneTimeBoth,
            Some((a.try_into().expect("width"), b.try_into().expect("width"))),
            open_peer_signers(&path),
        );
        f.reusable.close();
        f.once.close();
        f.signer_r.close(); // The parent retains no volatile responder signing material.
        let mut peer = InitiatorOperation::start(Arc::clone(&f.initiator), &f.signer_i, 150)
            .expect("actual peer");
        let initial = peer.initial_message(150).expect("initial").to_vec();
        publish(&path, "peer-initial", &initial);
        wait_for(&path, "ready", &mut child);
        assert!(
            !path.join("returned-response").exists(),
            "response escaped commit barrier"
        );
        child.0.kill().expect("kill responder");
        assert!(!child.0.wait().expect("reap").success());
        let mut store = reopen(&path, f.local_device());
        assert_eq!(
            store.status(&f.responder, &initial).expect("phase"),
            DurableStatus::ResponseSignatureReserved
        );
        assert!(matches!(
            store.resume_response(Arc::clone(&f.responder), &initial, &f.signer_r, 150),
            Err(DurableError::Protocol(Error::Closed))
        ));
        let (_, restored) = open_peer_signers(&path);
        let reply = store
            .resume_response(Arc::clone(&f.responder), &initial, &restored, 150)
            .expect("recover actual protected signer");
        if after_effect {
            assert_eq!(
                reply,
                fs::read(path.join("computed-response")).expect("pre-crash exact signature")
            );
        }
        let outcome = peer
            .finish(&reply, 150)
            .expect("actual live peer verifies recovered proof and MAC");
        assert_eq!(
            store
                .finish(
                    Arc::clone(&f.responder),
                    &initial,
                    outcome.final_message(),
                    150
                )
                .expect("final confirmation"),
            outcome.pending_session().id()
        );
    }
}
