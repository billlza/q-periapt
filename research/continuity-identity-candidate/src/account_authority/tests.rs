// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::atomic::AtomicUsize;

/// Replace only the owned test database backend; production persistence is unchanged.
pub(crate) fn fault_database(
    store: &mut AccountAuthorityStore,
    path: &Path,
    after: bool,
) -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let Active { db, key, image } = store.active.take().expect("active test registry");
    drop(db);
    let (db, remaining, count, _) = crate::durable::tests::fault_database_path(path, after);
    store.active = Some(Active { db, key, image });
    (remaining, count)
}

/// Check authenticated but semantically invalid state, not merely invalid MAC bytes.
pub(crate) fn rejects_invalid_images(store: &AccountAuthorityStore) {
    let active = store.active.as_ref().expect("active original image");
    assert_eq!(active.image.replacements.len(), 1);
    let read = |image: &Image| {
        let wire =
            codec::encode(image, &active.key, store.binding).expect("actual authenticated image");
        codec::decode(&wire, &active.key, store.binding)
            .expect("valid framing and authentication")
            .current(store.family, &store.pin)
    };
    read(&active.image).expect("original graph is valid");

    let mut image = active.image.clone();
    image
        .replacements
        .first_mut()
        .expect("original operation")
        .revision += 1;
    assert!(matches!(read(&image), Err(DurableError::Corrupt)));

    let mut image = active.image.clone();
    let duplicate = image.replacements.first().expect("operation").clone();
    image.replacements.push(duplicate);
    assert!(matches!(read(&image), Err(DurableError::Corrupt)));

    let mut image = active.image.clone();
    image.initial.clear();
    assert!(matches!(read(&image), Err(DurableError::Corrupt)));

    let mut image = active.image.clone();
    let reused = image.initial.values().next().expect("initial").clone();
    image
        .initial
        .insert(ApplicationAccountId([250; 32]), reused);
    assert!(matches!(read(&image), Err(DurableError::Corrupt)));

    let mut image = active.image.clone();
    image.replacements.clear();
    image.initial.values_mut().next().expect("initial").root = store.pin.public_key().clone();
    assert!(matches!(read(&image), Err(DurableError::Corrupt)));

    let wire = codec::encode(&active.image, &active.key, store.binding).expect("wire");
    for cut in [0, 8, 40, 75, wire.len() - 1] {
        assert!(codec::decode(
            wire.get(..cut).expect("checked prefix"),
            &active.key,
            store.binding
        )
        .is_err());
    }
    let mut tampered = wire.clone();
    *tampered.last_mut().expect("MAC byte") ^= 1;
    assert!(matches!(
        codec::decode(&tampered, &active.key, store.binding),
        Err(DurableError::Authentication)
    ));
    let mut extended = wire.clone();
    extended.push(0);
    assert!(codec::decode(&extended, &active.key, store.binding).is_err());
    let mut other_binding = store.binding;
    *other_binding.first_mut().expect("binding byte") ^= 1;
    assert!(matches!(
        codec::decode(&wire, &active.key, other_binding),
        Err(DurableError::Conflict)
    ));
}

#[test]
fn account_authority_registry_rejects_extra_multimap_tables() {
    let directory = crate::durable::tests::directory();
    let base = directory
        .path()
        .canonicalize()
        .expect("canonical private fixture");
    let path = base.join("authority.redb");
    let key_path = base.join("key");
    let identity = AccountAuthorityIdentity::generate().expect("original identity");
    let pin = AnchorPin::new(
        crate::AnchorIdentity::generate().expect("witness identity"),
        crate::AnchorSigningKey::generate()
            .expect("witness signer")
            .public_key()
            .expect("public witness key"),
    );
    let mut store = AccountAuthorityStore::provision(
        &path,
        JournalKey::provision(&key_path).expect("original key"),
        identity,
        [1; 32],
        pin.clone(),
    )
    .expect("original empty registry");
    let tx =
        transaction(&store.active.as_ref().expect("active owner").db).expect("owned fixture write");
    tx.open_multimap_table(redb::MultimapTableDefinition::<&str, &str>::new(
        "unexpected",
    ))
    .expect("additional table")
    .insert("key", "value")
    .expect("additional row");
    tx.commit().expect("persist fixture schema drift");
    store.close();
    assert!(matches!(
        AccountAuthorityStore::open(
            &path,
            JournalKey::open(&key_path).expect("same key"),
            identity,
            [1; 32],
            pin
        ),
        Err(DurableError::Corrupt)
    ));
}

/// Reject impossible preparation phases and bindings even with a valid local MAC.
pub(crate) fn rejects_preparation_images(store: &AccountAuthorityStore) {
    let active = store.active.as_ref().expect("original active registry");
    let read = |image: &Image| {
        let wire =
            codec::encode(image, &active.key, store.binding).expect("authenticated fixture image");
        assert_eq!(
            wire.get(..8).expect("complete registry header"),
            b"QPAAST02"
        );
        codec::decode(&wire, &active.key, store.binding)
            .expect("authenticated canonical framing")
            .current(store.family, &store.pin)
    };
    read(&active.image).expect("original preparation graph");
    let mut image = active.image.clone();
    let record = image
        .replacements
        .first_mut()
        .expect("original preparation");
    assert!(record.preparation.is_some());
    if record.state() == AccountAuthorityReplacementState::Preparing {
        record.decision = Decision::Committed;
        assert!(
            matches!(read(&image), Err(DurableError::Corrupt)),
            "unbound target template cannot be a committed mapping"
        );
    } else {
        let mut bytes = record.proposal.to_bytes().expect("exact frozen proposal");
        assert_eq!(bytes.get(..8).expect("complete header"), b"QPARPL02");
        *bytes.get_mut(8).expect("freeze binding byte") ^= 1;
        record.proposal = Proposal::from_trusted_state(&bytes)
            .expect("valid framing, wrong original freeze binding");
        assert!(matches!(
            read(&image),
            Err(DurableError::Protocol(Error::Scope))
        ));
    }
}

/// Hold only an explicitly selected owned child after the real database commit.
pub(super) fn after_preparation_commit(image: &Image) {
    let Some(path) = std::env::var_os("QPERIAPT_AUTHORITY_PREPARATION_DIR") else {
        return;
    };
    let Ok(selected) = std::env::var("QPERIAPT_AUTHORITY_PREPARATION_PHASE") else {
        return;
    };
    let Some(record) = image.replacements.last() else {
        return;
    };
    if record.preparation.is_none() {
        return;
    }
    let phase = match record.state() {
        AccountAuthorityReplacementState::Preparing => "prepare",
        AccountAuthorityReplacementState::Pending => "bind",
        AccountAuthorityReplacementState::Committed => "commit",
        AccountAuthorityReplacementState::Closed => "close",
    };
    if selected != phase {
        return;
    }
    std::fs::write(Path::new(&path).join("registry-committed"), phase)
        .expect("owned child commit marker");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// An adopted winner cannot erase or bypass the original terminal decision.
pub(crate) fn rejects_terminal_images(store: &AccountAuthorityStore) {
    let active = store.active.as_ref().expect("active original registry");
    let read = |image: &Image| {
        let wire = codec::encode(image, &active.key, store.binding).expect("authenticated image");
        assert_eq!(wire.get(..8).expect("header"), b"QPAAST03");
        codec::decode(&wire, &active.key, store.binding)
            .expect("authenticated framing")
            .current(store.family, &store.pin)
    };
    assert_eq!(active.image.replacements.len(), 2);
    read(&active.image).expect("actual closed then adopted history");
    let mut missing = active.image.clone();
    missing.replacements.remove(0);
    assert!(
        matches!(read(&missing), Err(DurableError::Corrupt)),
        "adoption requires an explicit previous terminal operation"
    );
    let mut pending = active.image.clone();
    pending.replacements.first_mut().expect("original").decision = Decision::Pending;
    assert!(
        matches!(read(&pending), Err(DurableError::Corrupt)),
        "unresolved original cannot be bypassed by an adoption flag"
    );
    let mut wrong = active.image.clone();
    wrong.replacements.last_mut().expect("winner").decision = Decision::Committed;
    assert!(
        matches!(read(&wrong), Err(DurableError::Corrupt)),
        "reusing a closed-only target requires the explicit adopted decision"
    );
}
