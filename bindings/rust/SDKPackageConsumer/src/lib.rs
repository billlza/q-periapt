//! External package consumer: public APIs, public TLS fixtures and fresh policy issuers.
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use q_periapt_host_store::{PolicyStore, StoreError};
    use q_periapt_rustls::connection::{self, Connection, Credentials, Endpoint, Phase};
    use q_periapt_sdk::{expert, Error, KeyPurpose, Limits, Runtime};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::Arc;

    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    const POLICY: &[u8] = include_bytes!("../fixtures/policy.toml");
    const SIGNATURE: &[u8] = include_bytes!("../fixtures/signature.bin");
    const ROOT: &[u8] = include_bytes!("../fixtures/root.bin");
    const REVOKE: &[u8] = include_bytes!("../fixtures/revoke.toml");
    const REVOKE_SIGNATURE: &[u8] = include_bytes!("../fixtures/revoke-signature.bin");
    const ENABLE: &[u8] = include_bytes!("../fixtures/enable.toml");
    const ENABLE_SIGNATURE: &[u8] = include_bytes!("../fixtures/enable-signature.bin");

    fn runtime() -> Result<Arc<Runtime>> {
        Ok(Arc::new(Runtime::from_signed_policy(
            POLICY,
            SIGNATURE,
            ROOT,
            None,
            Limits::default(),
        )?))
    }

    #[test]
    fn owned_roundtrip_derivation_transfer_and_revocation() -> Result {
        let runtime = runtime()?;
        let mut original = runtime.generate_key()?;
        let public = original.public_key()?.to_bytes();
        let mut exported = expert::export_expanded(&original)?;
        let imported = expert::import_expanded(&runtime, exported.as_bytes())?;
        exported.close();
        assert!(exported.as_bytes().iter().all(|byte| *byte == 0));
        original.close();
        assert_eq!(imported.public_key()?.to_bytes(), public);
        let context = vec![0x53; 65536];
        let encapsulated = runtime.encapsulate(imported.public_key()?, &context)?;
        let recovered = imported.decapsulate(&encapsulated.ciphertext, &context)?;
        let left = encapsulated
            .secret
            .derive_key(KeyPurpose::Exporter, b"package/v1", &context)?;
        let right = recovered.derive_key(KeyPurpose::Exporter, b"package/v1", &context)?;
        assert_eq!(
            q_periapt_core::ct_eq(
                left.export_for_protocol()?.as_bytes(),
                right.export_for_protocol()?.as_bytes()
            ),
            0xff
        );
        runtime.close();
        assert!(matches!(imported.public_key(), Err(Error::Closed)));
        assert!(matches!(left.export_for_protocol(), Err(Error::Closed)));
        Ok(())
    }

    #[test]
    fn signed_policy_failures_and_explicit_transition() -> Result {
        let mut signature = SIGNATURE.to_vec();
        signature[0] ^= 1;
        assert!(matches!(
            Runtime::from_signed_policy(POLICY, &signature, ROOT, None, Limits::default()),
            Err(Error::PolicyDenied)
        ));
        let current = runtime()?;
        let key = current.generate_key()?;
        let update = current.prepare_policy_update(REVOKE, REVOKE_SIGNATURE)?;
        let (previous, next) = update.states()?;
        assert_eq!(previous, current.trusted_state());
        // This case exercises the explicit API; durable storage is the next test.
        let disabled = update.activate_after_persist()?;
        assert_eq!(disabled.trusted_state(), next);
        assert!(!disabled.is_enabled()?);
        assert!(matches!(key.public_key(), Err(Error::Closed)));
        assert!(matches!(disabled.generate_key(), Err(Error::PolicyDenied)));
        assert!(matches!(
            Runtime::from_signed_policy(POLICY, SIGNATURE, ROOT, Some(&next), Limits::default()),
            Err(Error::PolicyDenied)
        ));
        Ok(())
    }

    // This same test runs once in a tightly selected child with a real OS file-size
    // limit. An ambient marker cannot replace the normal four-test qualification.
    const STORAGE_CHILD_ARGS: [&str; 4] = [
        "--exact",
        "tests::private_store_restart_rollback_rejection_and_reenable",
        "--nocapture",
        "--test-threads=1",
    ];
    fn limited_storage_child() -> Result<bool> {
        let Some(path) = std::env::var_os("QPERIAPT_PACKAGE_STORAGE_LIMIT_CHILD") else {
            return Ok(false);
        };
        if std::env::args().skip(1).collect::<Vec<_>>() != STORAGE_CHILD_ARGS {
            return Err("reserved storage-fault marker outside the exact child invocation".into());
        }
        let path = std::path::PathBuf::from(path);
        let outcome = PolicyStore::provision(&path, POLICY, SIGNATURE, ROOT, Limits::default());
        assert!(
            matches!(
                outcome,
                Err(StoreError::Storage(_) | StoreError::Io(_) | StoreError::CommitUncertain(_))
            ),
            "OS file-size limit did not produce an explicit storage failure"
        );
        assert!(
            !path.exists(),
            "failed initial write published a formal policy store"
        );
        let retained = unpublished_staging(&path)?;
        assert_eq!(
            retained.len(),
            1,
            "exactly this failed attempt's private staging remains"
        );
        assert!(matches!(
            PolicyStore::open_configured(&path, POLICY, SIGNATURE, ROOT, Limits::default()),
            Err(StoreError::PrivateFile)
        ));
        assert!(!path.exists(), "open must never infer first use");
        assert_eq!(unpublished_staging(&path)?, retained);
        println!("RUST_SDK_STORAGE_FAILURE_UNPUBLISHED");
        Ok(true)
    }
    // Inspection of this test-owned private directory is evidence only. The SDK
    // never uses staging names or partial contents to select a recovery candidate.
    #[derive(Debug, Eq, PartialEq)]
    struct StagingSnapshot {
        path: std::path::PathBuf,
        device: u64,
        inode: u64,
        bytes: Vec<u8>,
    }
    fn unpublished_staging(path: &std::path::Path) -> Result<Vec<StagingSnapshot>> {
        let mut snapshots = Vec::new();
        for entry in std::fs::read_dir(path.parent().ok_or("policy parent")?)? {
            let entry = entry?;
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".private-publication-")
            {
                continue;
            }
            assert!(!entry.file_type()?.is_symlink());
            let metadata = entry.metadata()?;
            assert!(metadata.is_file());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            assert!(
                metadata.len() <= 1024,
                "fixture staging exceeds OS write limit"
            );
            snapshots.push(StagingSnapshot {
                path: entry.path(),
                device: metadata.dev(),
                inode: metadata.ino(),
                bytes: std::fs::read(entry.path())?,
            });
        }
        snapshots.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(snapshots)
    }
    struct OwnedChild(Option<std::process::Child>);
    impl OwnedChild {
        fn child(&mut self) -> &mut std::process::Child {
            self.0
                .as_mut()
                .expect("owned child before output collection")
        }
        fn output(mut self) -> std::io::Result<std::process::Output> {
            self.0
                .take()
                .expect("one output collection")
                .wait_with_output()
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let Some(child) = self.0.as_mut() else {
                return;
            };
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(error) => eprintln!("storage child status: {error}"),
            }
            if let Err(error) = child.kill() {
                eprintln!("storage child cleanup: {error}");
            }
            if let Err(error) = child.wait() {
                eprintln!("storage child reap: {error}");
            }
        }
    }
    fn exercise_limited_storage(path: &std::path::Path) -> Result {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        // The ignored signal makes the kernel return EFBIG to the SDK. Both the
        // signal disposition and limit are confined to this child process.
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' XFSZ; ulimit -f 1 || exit 97; exec \"$@\"",
                "storage-fault-child",
            ])
            .arg(std::env::current_exe()?)
            .args(STORAGE_CHILD_ARGS)
            .env("QPERIAPT_PACKAGE_STORAGE_LIMIT_CHILD", path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut child = OwnedChild(Some(child));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.child().try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                return Err("limited storage child exceeded its deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let result = child.output()?;
        assert!(
            result.status.success(),
            "storage-fault child failed: {} {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout)
            .lines()
            .any(|line| line.ends_with("RUST_SDK_STORAGE_FAILURE_UNPUBLISHED")));
        let retained = unpublished_staging(path)?;
        assert_eq!(retained.len(), 1);
        assert!(!path.exists());
        // This isolated child never received an owner. The parent retains the
        // original first-use path/root/policy and has no OS write-size limit.
        let mut first = PolicyStore::provision(path, POLICY, SIGNATURE, ROOT, Limits::default())?;
        let key = first.runtime()?.generate_key()?;
        assert_eq!(key.public_key()?.to_bytes().len(), 1216);
        first.close();
        assert!(matches!(key.public_key(), Err(Error::Closed)));
        let mut resumed =
            PolicyStore::open_configured(path, POLICY, SIGNATURE, ROOT, Limits::default())?;
        assert!(resumed.runtime()?.is_enabled()?);
        resumed.close();
        assert_eq!(
            unpublished_staging(path)?,
            retained,
            "first-use retry must not choose or sweep old staging"
        );
        Ok(())
    }

    #[test]
    fn private_store_restart_rollback_rejection_and_reenable() -> Result {
        if limited_storage_child()? {
            return Ok(());
        }
        let directory = tempfile::Builder::new()
            .prefix("qperiapt-rust-consumer-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = directory.path().canonicalize()?.join("policy.redb");
        let mut store = PolicyStore::provision(&path, POLICY, SIGNATURE, ROOT, Limits::default())?;
        let old = store.runtime()?;
        let key = old.generate_key()?;
        assert!(matches!(
            old.prepare_policy_update(REVOKE, REVOKE_SIGNATURE),
            Err(Error::UpdateOwnerRequired)
        ));
        let disabled = store.replace_policy(old.trusted_state(), REVOKE, REVOKE_SIGNATURE)?;
        assert!(!disabled.is_enabled()?);
        assert!(matches!(key.public_key(), Err(Error::Closed)));
        assert!(matches!(
            disabled.prepare_policy_update(ENABLE, ENABLE_SIGNATURE),
            Err(Error::UpdateOwnerRequired)
        ));
        store.close();
        assert!(matches!(disabled.is_enabled(), Err(Error::Closed)));
        let recovered = PolicyStore::open(&path, ROOT, Limits::default())?;
        let recovered_alias = recovered.runtime()?;
        assert_eq!(recovered_alias.trusted_state(), disabled.trusted_state());
        assert!(!recovered_alias.is_enabled()?);
        assert!(matches!(
            recovered_alias.prepare_policy_update(ENABLE, ENABLE_SIGNATURE),
            Err(Error::UpdateOwnerRequired)
        ));
        drop(recovered);
        assert!(matches!(recovered_alias.is_enabled(), Err(Error::Closed)));
        assert!(matches!(
            PolicyStore::open_configured(&path, POLICY, SIGNATURE, ROOT, Limits::default()),
            Err(StoreError::Policy(Error::PolicyDenied))
        ));
        let mut reopened =
            PolicyStore::open_configured(&path, ENABLE, ENABLE_SIGNATURE, ROOT, Limits::default())?;
        let active = reopened.runtime()?;
        let key = active.generate_key()?;
        assert!(matches!(
            active.prepare_policy_update(ENABLE, ENABLE_SIGNATURE),
            Err(Error::UpdateOwnerRequired)
        ));
        assert_eq!(key.public_key()?.to_bytes().len(), 1216);
        reopened.close();
        assert!(matches!(key.public_key(), Err(Error::Closed)));
        exercise_limited_storage(&directory.path().canonicalize()?.join("limited-policy.redb"))?;
        exercise_independent_authority_recovery(
            &directory.path().canonicalize()?.join("recovery.redb"),
        )?;
        Ok(())
    }

    // Issuer tooling is deliberately outside the store. These keys come from OS
    // entropy, not a precomputed fixture; only public policies/approvals go to disk.
    struct PolicyIssuer {
        key: q_periapt_core::ZeroizingBytes<{ q_periapt_backends::ML_DSA_65_SK_LEN }>,
        public: [u8; q_periapt_backends::ML_DSA_65_VK_LEN],
    }
    impl PolicyIssuer {
        fn generate() -> Result<Self> {
            let mut seed = q_periapt_core::ZeroizingBytes::<32>::zeroed();
            getrandom::fill(seed.as_mut_bytes()).map_err(|_| Error::Entropy)?;
            let (key, public) = q_periapt_backends::MlDsa65::generate(*seed.as_bytes());
            Ok(Self {
                key: q_periapt_core::ZeroizingBytes::from_bytes(key),
                public,
            })
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            use q_periapt_sig::Signer;
            let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
            q_periapt_backends::MlDsa65
                .sign(self.key.as_bytes(), message, &[0; 32], &mut signature)
                .map_err(Error::from)?;
            Ok(signature)
        }
        fn policy(&self, version: u32, enabled: bool) -> Result<(Vec<u8>, Vec<u8>)> {
            let pq = if enabled { "ML-KEM-768" } else { "ML-KEM-1024" };
            let document = format!("schema_version = 1\npolicy_version = {version}\nmin_nist_level = 3\ndefault_profile = \"ContextBound\"\nallowed_kems = [\"{pq}\", \"X25519\"]\nallowed_sigs = [\"ML-DSA-65\"]\ndeprecated = []\n").into_bytes();
            let signature = self.sign(&q_periapt_policy::policy_signature_message(&document))?;
            Ok((document, signature))
        }
    }
    fn exercise_independent_authority_recovery(path: &std::path::Path) -> Result {
        use q_periapt_host_store::{
            PolicyRecoveryAuthorization, PolicyRecoveryOutcome, PolicyRecoveryTrust,
        };
        let initial = PolicyIssuer::generate()?;
        let offline = PolicyIssuer::generate()?;
        let incoming = PolicyIssuer::generate()?;
        let mut scope = [0; 32];
        let mut operation = [0; 32];
        getrandom::fill(&mut scope).map_err(|_| Error::Entropy)?;
        getrandom::fill(&mut operation).map_err(|_| Error::Entropy)?;
        let trust = PolicyRecoveryTrust::new(scope, &initial.public, &offline.public)?;
        let enrollment = offline.sign(&trust.enrollment_message())?;
        let (old_policy, old_signature) = initial.policy(u32::MAX, true)?;
        let mut store = PolicyStore::provision_recoverable(
            path,
            &old_policy,
            &old_signature,
            &trust,
            &enrollment,
            Limits::default(),
        )?;
        let old = store.runtime()?;
        let key = old.generate_key()?;
        let (revoked, revoked_signature) = incoming.policy(1, false)?;
        let request = store.prepare_authority_recovery(
            operation,
            &revoked,
            &revoked_signature,
            &incoming.public,
        )?;
        assert_eq!(request.trust_binding(), trust.binding());
        assert_eq!(request.replacement_root(), incoming.public);
        assert_eq!(request.states().0, old.trusted_state());
        assert_eq!(request.states().1.version(), 1);
        let possession = incoming.sign(&request.possession_message())?;
        let forged = PolicyRecoveryAuthorization::new(
            request.clone(),
            &initial.sign(&request.authorization_message())?,
            &possession,
        )?;
        assert!(matches!(
            store.recover_authority(&forged, &revoked, &revoked_signature),
            Err(StoreError::RecoveryDenied)
        ));
        assert!(old.is_enabled()?);
        let approval = offline.sign(&request.authorization_message())?;
        let authorized = PolicyRecoveryAuthorization::new(request, &approval, &possession)?;
        let retained = path.with_extension("original-authorization");
        std::fs::write(&retained, authorized.to_bytes())?;
        assert_eq!(
            store.recover_authority(&authorized, &revoked, &revoked_signature)?,
            PolicyRecoveryOutcome::Applied
        );
        assert!(matches!(key.public_key(), Err(Error::Closed)));
        assert!(!store.runtime()?.is_enabled()?);
        store.close();
        let original = PolicyRecoveryAuthorization::from_bytes(&std::fs::read(&retained)?)?;
        let (mut store, outcome) = PolicyStore::open_recovering(
            path,
            &trust,
            &original,
            &revoked,
            &revoked_signature,
            Limits::default(),
        )?;
        assert_eq!(outcome, PolicyRecoveryOutcome::AlreadyApplied);
        let (enabled, enabled_signature) = incoming.policy(2, true)?;
        let current = store.replace_policy(
            store.runtime()?.trusted_state(),
            &enabled,
            &enabled_signature,
        )?;
        assert!(current.is_enabled()?);
        assert!(matches!(
            current.prepare_policy_update(&enabled, &enabled_signature),
            Err(Error::UpdateOwnerRequired)
        ));
        assert_eq!(
            store.recover_authority(&original, &revoked, &revoked_signature)?,
            PolicyRecoveryOutcome::AppliedThenAdvanced
        );
        assert_eq!(store.runtime()?.trusted_state().version(), 2);
        store.close();
        assert!(matches!(current.is_enabled(), Err(Error::Closed)));
        Ok(())
    }

    struct Identity {
        certificate: Vec<u8>,
        private_key: Vec<u8>,
    }
    impl Identity {
        fn new(certificate: &[u8], private_key: &[u8]) -> Self {
            Self {
                certificate: certificate.to_vec(),
                private_key: private_key.to_vec(),
            }
        }
        fn credentials<'a>(&'a self, peer: &'a Self) -> Credentials<'a> {
            Credentials {
                certificate: &self.certificate,
                private_key: &self.private_key,
                peer_certificate: &peer.certificate,
            }
        }
    }
    impl Drop for Identity {
        fn drop(&mut self) {
            q_periapt_core::secure_wipe(&mut self.private_key);
        }
    }
    fn transfer(source: &mut Connection, target: &mut Connection) -> Result<bool> {
        if !source.progress()?.wants_write {
            return Ok(false);
        }
        let mut output = [0; connection::MAX_TLS_IO_BYTES];
        let count = source.drain_tls(&mut output)?;
        for mut fragment in output
            .get(..count)
            .ok_or("invalid drained extent")?
            .chunks(127)
        {
            while !fragment.is_empty() {
                let used = target.feed_tls(fragment)?;
                if used == 0 {
                    return Err("no transport progress".into());
                }
                fragment = fragment.get(used..).ok_or("invalid consumed extent")?;
            }
        }
        Ok(count != 0)
    }
    fn drive(client: &mut Connection, server: &mut Connection) -> Result {
        for _ in 0..128 {
            let left = transfer(client, server)?;
            let right = transfer(server, client)?;
            if !left && !right {
                return Ok(());
            }
        }
        Err("transport iteration budget exceeded".into())
    }
    #[test]
    fn public_reference_connection_with_mutual_identity_and_fragmented_io() -> Result {
        // Public regression keys; only TLS identity generation is precomputed.
        // The SDK still performs real fresh hybrid key exchange and authentication.
        let client_identity = Identity::new(
            include_bytes!("../fixtures/client.der"),
            include_bytes!("../fixtures/client.key.der"),
        );
        let server_identity = Identity::new(
            include_bytes!("../fixtures/server.der"),
            include_bytes!("../fixtures/server.key.der"),
        );
        let policy = runtime()?;
        let client = Endpoint::client(
            Arc::clone(&policy),
            client_identity.credentials(&server_identity),
            b"installed-rust-sdk/v1",
            connection::Limits::default(),
        )?;
        let server = Endpoint::server(
            Arc::clone(&policy),
            server_identity.credentials(&client_identity),
            b"installed-rust-sdk/v1",
            connection::Limits::default(),
        )?;
        let mut outgoing = client.connect("localhost")?;
        let mut incoming = server.accept()?;
        drive(&mut outgoing, &mut incoming)?;
        assert!(matches!(outgoing.progress()?.phase, Phase::Ready));
        assert!(matches!(incoming.progress()?.phase, Phase::Ready));
        let request = vec![0x42; 65536];
        let sequence = outgoing.send_request(&request)?;
        drive(&mut outgoing, &mut incoming)?;
        let received = incoming.take_request()?;
        assert_eq!(received.request_id(), sequence);
        assert_eq!(received.bytes(), request);
        incoming.send_response(sequence, b"installed-response")?;
        drive(&mut outgoing, &mut incoming)?;
        assert_eq!(outgoing.take_response()?.bytes(), b"installed-response");
        policy.close();
        assert!(matches!(
            outgoing.progress(),
            Err(connection::Error::Closed)
        ));
        assert!(matches!(
            incoming.progress(),
            Err(connection::Error::Closed)
        ));
        Ok(())
    }
}
