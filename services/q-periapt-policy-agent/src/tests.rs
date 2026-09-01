use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::ZeroizingBytes;
use q_periapt_migration::{
    CapabilityOfferInputV1, CapabilityOfferV1, CommittedMigrationStateV1, ComponentMode,
    EndpointKeyShareV1, EndpointRole, InitiatorFinishedV1, MigrationAuthorityKeyId,
    MigrationChainId, MigrationIdentityKeyId, MigrationNonce, MigrationProtocolId,
    MigrationResetNonce, MigrationResetV1, MigrationSecurityPosture, MigrationSessionId,
    MigrationStateDigest, MigrationStateDraftV1, MigrationStateV1, MigrationSuiteSet,
    ResponderFinishedV1, SecurityFloor, SignedCapabilityOfferV1, SignedMigrationResetV1,
    SignedMigrationStateV1, StateCertificateKind,
};
use q_periapt_policy::{
    policy_signature_message, AuthenticatedPolicy, HybridSuite, Policy, TrustedPolicyState,
};
use q_periapt_sig::Signer;

use crate::authentication::{sign_envelope, verify_envelope};
use crate::authority::{
    AuthorityErrorV2, AuthorityIntentV2, AuthorityLimitsV2, AuthorityQueryResultV2,
    AuthorityReceiptV2, AuthoritySnapshotV2, AuthorityStateV2, DeploymentConfigRevisionV2,
    OperationIdV2, StateFenceV2, StateHeadV2, StateRevisionV2, TrustedClockErrorV2, TrustedClockV2,
};
use crate::authority_protocol::{
    AuthorityKnownFailureV2, AuthorityOutcomeV2, AuthorityUnknownV2,
    DurablyRetainedAuthorityReceiptV2,
};
use crate::authority_transport::{AuthorityTransportErrorV2, InstanceAuthorityPort};
use crate::codec::{
    encode_domain, read_frame, require_domain, write_frame, DeadlineStream, Decoder, Encoder,
    MAX_FRAME_BYTES,
};
use crate::crypto::{EncapsulationCiphertexts, EncapsulationPublicKeys};
use crate::filesystem::{open_private_file, OwnedPrivateDirectory, PrivateFileError};
use crate::repository::{MigrationTrustRoots, StateRepository};
use crate::service::{
    AgentConfig, AgentError, AgentLimits, BeginDecapsulation, BeginDecapsulationResult,
    BeginEncapsulation, BeginEncapsulationResult, EndpointIdentity, InitiatorDecapsulationResult,
    InitiatorEncapsulationResult, PolicyAgent, ResponderDecapsulationResult,
    ResponderEncapsulationResult, SessionAuthorization, SignedPolicyBundle,
};
use crate::types::{
    FenceToken, OperationId, StateAdvance, StateHead, StateRevision, TransitionKind,
};
use crate::witness::{
    AuthenticatedTcpWitness, ReferenceWitnessServer, WitnessError, WitnessIntent, WitnessOutcome,
    WitnessPort, WitnessReceipt,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const POLICY: &str = "schema_version = 1\n\
    policy_version = 1\n\
    min_nist_level = 3\n\
    default_profile = \"ContextBound\"\n\
    allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
    allowed_sigs = [\"ML-DSA-65\"]\n\
    deprecated = []\n";

struct TestDirectory {
    _temporary: tempfile::TempDir,
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> TestResult<Self> {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::Builder::new()
            .prefix("q-periapt-policy-agent-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let path = temporary.path().canonicalize()?;
        Ok(Self {
            _temporary: temporary,
            path,
        })
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

/// A failed `create` must not leave the `O_CREAT|O_EXCL` leaf behind: the next
/// attempt would get `EEXIST`, and the `create = false` path rejects the
/// zero-length leftover, so one transient failure would brick provisioning
/// permanently.
///
/// Ignored by default because it manipulates the process-wide `umask`, which
/// would make any sibling test that creates a private file flaky when the suite
/// runs in parallel. Run it deliberately:
///
/// ```text
/// cargo test -p q-periapt-policy-agent -- --ignored --test-threads=1
/// ```
///
/// Verified in both directions when the unlink was added: without it this fails
/// with `failed create left .../brick.redb behind`.
#[test]
#[ignore = "manipulates the process-wide umask; run with --test-threads=1"]
fn failed_private_file_create_leaves_no_leaf_behind() -> TestResult {
    use rustix::fs::Mode;
    use rustix::process::umask;

    let directory = TestDirectory::new()?;
    let path = directory.join("brick.redb");
    // umask 0o200 strips the owner-write bit, so O_CREAT yields mode 0400 and
    // the exact-mode check rejects it after the leaf already exists.
    let previous = umask(Mode::WUSR);
    let outcome = open_private_file(&path, true);
    umask(previous);
    assert!(
        matches!(outcome, Err(PrivateFileError)),
        "expected the exact-mode check to reject a 0400 leaf"
    );
    assert!(
        !path.exists(),
        "failed create left {path:?} behind; provisioning would be bricked"
    );
    // A retry under a sane umask must now succeed.
    drop(
        open_private_file(&path, true)
            .map_err(|_| io::Error::other("retry after a cleaned-up failure must succeed"))?,
    );
    Ok(())
}

#[test]
fn private_state_file_is_opened_beneath_an_owned_descriptor_boundary() -> TestResult {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = TestDirectory::new()?;
    let valid_path = directory.join("valid.redb");
    let mut valid = open_private_file(&valid_path, true)
        .map_err(|_| io::Error::other("failed to create private test state"))?;
    valid.write_all(&[1])?;
    valid.sync_all()?;
    drop(valid);
    drop(
        open_private_file(&valid_path, false)
            .map_err(|_| io::Error::other("failed to reopen private test state"))?,
    );

    let empty_path = directory.join("empty.redb");
    drop(
        open_private_file(&empty_path, true)
            .map_err(|_| io::Error::other("failed to create empty private test state"))?,
    );
    assert!(matches!(
        open_private_file(&empty_path, false),
        Err(PrivateFileError)
    ));
    assert_eq!(fs::metadata(&empty_path)?.len(), 0);

    assert!(matches!(
        open_private_file(Path::new("relative.redb"), true),
        Err(PrivateFileError)
    ));

    let nested = directory.join("nested");
    fs::create_dir(&nested)?;
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))?;
    assert!(matches!(
        open_private_file(&nested.join("..").join("traversal.redb"), true),
        Err(PrivateFileError)
    ));

    let insecure = directory.join("insecure");
    fs::create_dir(&insecure)?;
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        open_private_file(&insecure.join("state.redb"), true),
        Err(PrivateFileError)
    ));

    let real_parent = directory.join("real-parent");
    fs::create_dir(&real_parent)?;
    fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700))?;
    let alias_parent = directory.join("alias-parent");
    symlink(&real_parent, &alias_parent)?;
    assert!(matches!(
        open_private_file(&alias_parent.join("state.redb"), true),
        Err(PrivateFileError)
    ));

    let target = directory.join("target.redb");
    let mut target_file = open_private_file(&target, true)
        .map_err(|_| io::Error::other("failed to create symlink target"))?;
    target_file.write_all(&[1])?;
    target_file.sync_all()?;
    drop(target_file);
    let alias_file = directory.join("alias.redb");
    symlink(&target, &alias_file)?;
    assert!(matches!(
        open_private_file(&alias_file, false),
        Err(PrivateFileError)
    ));

    let private_directory = OwnedPrivateDirectory::open(directory.path())
        .map_err(|_| io::Error::other("failed to pin private test directory"))?;
    assert!(private_directory.open_config_file("alias.redb", 1).is_err());

    let config_path = directory.join("config.bin");
    let mut config = open_private_file(&config_path, true)
        .map_err(|_| io::Error::other("failed to create private config"))?;
    config.write_all(&[1])?;
    config.sync_all()?;
    drop(config);
    let mut pinned_config = private_directory
        .open_config_file("config.bin", 1)
        .map_err(|_| io::Error::other("failed to open pinned private config"))?;
    let moved_config = directory.join("moved-config.bin");
    fs::rename(&config_path, &moved_config)?;
    let mut replacement = open_private_file(&config_path, true)
        .map_err(|_| io::Error::other("failed to create replacement config"))?;
    replacement.write_all(&[2])?;
    replacement.sync_all()?;
    drop(replacement);
    let mut original = [0u8; 1];
    pinned_config.read_exact(&mut original)?;
    assert_eq!(original, [1]);

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))?;
    assert!(private_directory.open_config_file("config.bin", 1).is_err());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn macos_extended_acls_are_rejected_even_when_posix_modes_remain_private() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let file_directory = TestDirectory::new()?;
    let private_directory = OwnedPrivateDirectory::open(file_directory.path())
        .map_err(|_| io::Error::other("failed to pin ACL test directory"))?;
    let state_path = file_directory.join("state.redb");
    let mut state = open_private_file(&state_path, true)
        .map_err(|_| io::Error::other("failed to create ACL test state"))?;
    state.write_all(&[1])?;
    state.sync_all()?;
    drop(state);

    install_macos_test_acl(&state_path, "everyone allow read")?;
    assert_eq!(
        fs::metadata(&state_path)?.permissions().mode() & 0o777,
        0o600
    );
    assert!(matches!(
        open_private_file(&state_path, false),
        Err(PrivateFileError)
    ));
    assert!(private_directory.open_config_file("state.redb", 1).is_err());

    let acl_directory = TestDirectory::new()?;
    install_macos_test_acl(acl_directory.path(), "everyone allow list,search")?;
    assert_eq!(
        fs::metadata(acl_directory.path())?.permissions().mode() & 0o777,
        0o700
    );
    assert!(matches!(
        OwnedPrivateDirectory::open(acl_directory.path()),
        Err(PrivateFileError)
    ));
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_macos_test_acl(path: &Path, entry: &str) -> TestResult {
    let status = Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(io::Error::other("failed to install macOS test ACL").into());
    }
    Ok(())
}

#[test]
fn authenticated_reference_witness_serializes_concurrent_cas_and_queries() -> TestResult {
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (client_sk, client_vk) = MlDsa65::generate([11u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([12u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [1u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || server.serve(listener, &server_shutdown));

    let client_a = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(client_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    assert_eq!(client_a.read_head()?, initial);

    let next_a = StateRevision::new(2, 2, [2u8; 32])?;
    let next_b = StateRevision::new(2, 2, [3u8; 32])?;
    let intent_a = WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(TransitionKind::Advance, initial.revision(), next_a)?,
        initial.fence(),
        FenceToken::generate()?,
    )?;
    let intent_b = WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(TransitionKind::Advance, initial.revision(), next_b)?,
        initial.fence(),
        FenceToken::generate()?,
    )?;
    let client_b = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(MlDsa65::generate([11u8; 32]).0),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let thread_a = thread::spawn(move || client_a.compare_and_advance(intent_a));
    let thread_b = thread::spawn(move || client_b.compare_and_advance(intent_b));
    let outcome_a = join(thread_a)??;
    let outcome_b = join(thread_b)??;
    let applied = [outcome_a, outcome_b]
        .into_iter()
        .filter(|outcome| {
            matches!(
                outcome,
                WitnessOutcome::Known(receipt)
                    if receipt.disposition() == crate::WitnessDisposition::Applied
            )
        })
        .count();
    assert_eq!(applied, 1);

    let query_client = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(MlDsa65::generate([11u8; 32]).0),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let query_a = query_client.query(intent_a.operation_id())?;
    assert!(matches!(query_a, WitnessOutcome::Known(_)));
    shutdown.store(true, Ordering::Release);
    join(server_thread)??;
    Ok(())
}

#[test]
fn authenticated_reference_witness_waits_for_a_delayed_fragmented_frame() -> TestResult {
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (client_sk, client_vk) = MlDsa65::generate([13u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([14u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [4u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || server.serve(listener, &server_shutdown));

    let result =
        (|| -> TestResult {
            let (frame, nonce) = crate::witness::test_support::framed_read_request(&client_sk)?;

            // Keep the accepted connection empty long enough for the server to enter
            // its read, then force partial reads across the length and payload.
            thread::sleep(Duration::from_millis(50));
            stream.write_all(frame.get(..2).ok_or_else(|| {
                io::Error::other("test witness frame omitted its length prefix")
            })?)?;
            stream.flush()?;
            thread::sleep(Duration::from_millis(20));
            stream.write_all(frame.get(2..7).ok_or_else(|| {
                io::Error::other("test witness frame omitted its initial payload bytes")
            })?)?;
            stream.flush()?;
            thread::sleep(Duration::from_millis(20));
            stream.write_all(
                frame
                    .get(7..)
                    .ok_or_else(|| io::Error::other("test witness frame was unexpectedly short"))?,
            )?;
            stream.flush()?;

            let response = read_frame(&mut stream)
                .map_err(|_| io::Error::other("witness response frame was unavailable"))?;
            assert_eq!(
                crate::witness::test_support::read_response_head(&response, &witness_vk, nonce)?,
                initial
            );
            Ok(())
        })();

    shutdown.store(true, Ordering::Release);
    let server_result = join(server_thread)?;
    result?;
    server_result?;
    Ok(())
}

#[test]
fn authenticated_reference_witness_evicts_a_trickling_client_at_its_deadline() -> TestResult {
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (client_sk, client_vk) = MlDsa65::generate([15u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([16u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [5u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_millis(500),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || server.serve(listener, &server_shutdown));

    let result = (|| -> TestResult {
        let mut stream = TcpStream::connect(address)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let (frame, _nonce) = crate::witness::test_support::framed_read_request(&client_sk)?;

        // Trickle one byte per 100ms without ever pausing longer: every gap
        // stays far inside the 500ms budget a per-syscall timeout would grant,
        // so only the absolute per-connection deadline can end the connection.
        // The server's hang-up surfaces as a reset on a subsequent write, so
        // the disconnect must be observed while bytes are still flowing.
        let started = Instant::now();
        let mut disconnected_after = None;
        for byte in frame.iter().take(40) {
            if stream
                .write_all(std::slice::from_ref(byte))
                .and_then(|()| stream.flush())
                .is_err()
            {
                disconnected_after = Some(started.elapsed());
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let Some(elapsed) = disconnected_after else {
            return Err(
                io::Error::other("witness held the trickled connection past its deadline").into(),
            );
        };
        // Well before the 4s the full trickle budget would take, and far
        // before the hours the complete frame would need.
        assert!(elapsed < Duration::from_secs(3));

        // The single serving slot must be free again for a well-behaved client.
        let client = AuthenticatedTcpWitness::new(
            address,
            ZeroizingBytes::from_bytes(MlDsa65::generate([15u8; 32]).0),
            witness_vk,
            Duration::from_secs(2),
        )?;
        assert_eq!(client.read_head()?, initial);
        Ok(())
    })();

    shutdown.store(true, Ordering::Release);
    let server_result = join(server_thread)?;
    result?;
    server_result?;
    Ok(())
}

#[test]
fn witness_server_survives_a_request_level_rejection() -> TestResult {
    // A caller can provoke a request-level rejection on purpose -- replaying one
    // operation id under a different intent. That must reject the request only;
    // if it terminated the listener, a single caller could destroy every
    // subsequent read and query for everyone.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (client_sk, client_vk) = MlDsa65::generate([31u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([32u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [5u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || server.serve(listener, &server_shutdown));

    let result = (|| -> TestResult {
        let client = AuthenticatedTcpWitness::new(
            address,
            ZeroizingBytes::from_bytes(client_sk),
            witness_vk,
            Duration::from_secs(2),
        )?;

        let operation = OperationId::generate()?;
        let applied = StateRevision::new(2, 2, [2u8; 32])?;
        client.compare_and_advance(WitnessIntent::new(
            operation,
            StateAdvance::new(TransitionKind::Advance, initial.revision(), applied)?,
            initial.fence(),
            FenceToken::generate()?,
        )?)?;

        // Same operation id, different intent: a request-level rejection.
        let conflicting = client.compare_and_advance(WitnessIntent::new(
            operation,
            StateAdvance::new(
                TransitionKind::Advance,
                initial.revision(),
                StateRevision::new(2, 2, [9u8; 32])?,
            )?,
            initial.fence(),
            FenceToken::generate()?,
        )?);
        // The server rejects it and produces no response, so the caller sees an
        // indeterminate outcome rather than a false success.
        assert!(
            matches!(conflicting, Ok(WitnessOutcome::Unknown) | Err(_)),
            "a conflicting replay must not be reported as applied; got {conflicting:?}"
        );

        // The listener must still be serving.
        let head = client.read_head()?;
        assert_eq!(
            head.revision(),
            applied,
            "the witness must still answer after rejecting a request"
        );
        Ok(())
    })();

    shutdown.store(true, Ordering::Release);
    let server_result = join(server_thread)?;
    result?;
    server_result?;
    Ok(())
}

#[test]
fn witness_store_rejects_an_applied_receipt_ahead_of_its_head() -> TestResult {
    // A receipt saying Applied(H0 -> H1) beside a recorded head of H0 is a store
    // that holds proof it advanced past the head it reports. That is what a tear
    // between the receipt write and the head update looks like, and what a
    // rollback of the head alone looks like. Counting rows and checking that
    // each is filed under its own operation id both pass on it, because neither
    // ever compares a receipt against the head.
    //
    // It matters because the witness would then answer read_head() with H0 while
    // already having applied H0 -> H1. A second, different advance from H0 under
    // a fresh operation id is not a replay of anything, so nothing else would
    // stop it, and the lineage the witness exists to keep single would fork.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (_client_sk, client_vk) = MlDsa65::generate([43u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([44u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [7u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    drop(server);

    // The advance the receipt claims was applied, one generation past the head
    // the store still records.
    let next = StateRevision::new(2, 2, [8u8; 32])?;
    let intent = WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(TransitionKind::Advance, initial.revision(), next)?,
        initial.fence(),
        FenceToken::generate()?,
    )?;
    crate::witness::test_support::record_applied_receipt_ahead_of_head(&database, intent)
        .map_err(|_| io::Error::other("failed to stage the torn store"))?;

    let (witness_sk_again, _) = MlDsa65::generate([44u8; 32]);
    assert!(
        ReferenceWitnessServer::open(
            &database,
            client_vk,
            ZeroizingBytes::from_bytes(witness_sk_again),
            witness_vk,
            Duration::from_secs(2),
        )
        .is_err(),
        "a store holding an applied receipt ahead of its own head must be refused"
    );
    Ok(())
}

#[test]
fn witness_store_rejects_a_semantically_damaged_database_at_open() -> TestResult {
    // redb's check_integrity proves only that its own structure is sound. A
    // recorded operation count that disagrees with the rows actually present is
    // worse than a late failure: capacity is enforced against that counter, so
    // an under-reporting store would let the explicit operation limit be
    // exceeded. It must be refused at open.
    let directory = TestDirectory::new()?;
    let database = directory.join("witness.redb");
    let (_client_sk, client_vk) = MlDsa65::generate([41u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([42u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [5u8; 32])?,
        FenceToken::generate()?,
    );
    let server = ReferenceWitnessServer::provision(
        &database,
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?;
    drop(server);

    crate::witness::test_support::desynchronize_operation_count(&database)
        .map_err(|_| io::Error::other("failed to stage the damaged store"))?;

    assert!(
        ReferenceWitnessServer::open(
            &database,
            client_vk,
            ZeroizingBytes::from_bytes(MlDsa65::generate([42u8; 32]).0),
            MlDsa65::generate([42u8; 32]).1,
            Duration::from_secs(2),
        )
        .is_err(),
        "a store whose operation count disagrees with its rows must be refused"
    );
    let _ = witness_vk;
    Ok(())
}

#[test]
fn witness_rejects_one_key_pair_serving_both_directions() -> TestResult {
    // Requests are verified under the client key and responses are signed under
    // the witness key. If those are one key pair, whoever may send requests can
    // also forge responses and the asymmetry the protocol depends on is gone.
    // The authority transport refuses the equivalent by requiring distinct
    // endpoint identities; the witness must refuse it too.
    let directory = TestDirectory::new()?;
    let (shared_sk, shared_vk) = MlDsa65::generate([51u8; 32]);
    let initial = StateHead::new(
        StateRevision::new(1, 1, [5u8; 32])?,
        FenceToken::generate()?,
    );
    assert!(
        ReferenceWitnessServer::provision(
            &directory.join("shared.redb"),
            initial,
            shared_vk,
            ZeroizingBytes::from_bytes(shared_sk),
            shared_vk,
            Duration::from_secs(2),
        )
        .is_err(),
        "one key pair must not carry both protocol directions"
    );

    // The distinct-key configuration the deployment actually uses still works.
    let (client_sk, client_vk) = MlDsa65::generate([52u8; 32]);
    let (witness_sk, witness_vk) = MlDsa65::generate([53u8; 32]);
    drop(ReferenceWitnessServer::provision(
        &directory.join("distinct.redb"),
        initial,
        client_vk,
        ZeroizingBytes::from_bytes(witness_sk),
        witness_vk,
        Duration::from_secs(2),
    )?);
    let _ = client_sk;
    Ok(())
}

#[test]
fn cas_with_an_unverifiable_response_is_indeterminate_not_a_failure() -> TestResult {
    // The request has already gone out, so the witness may have committed the
    // advance and only the answer was lost or tampered with. Reporting a
    // definite failure would invite the caller to retry or roll back against a
    // state that actually moved.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let (_witness_sk, witness_vk) = MlDsa65::generate([61u8; 32]);

    let hostile = thread::spawn(move || -> TestResult {
        let (mut stream, _peer) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        // Consume the request, then answer with a well-framed but unverifiable
        // envelope: signed by nobody the client trusts.
        let mut scratch = [0u8; 4096];
        let _ = stream.read(&mut scratch);
        let junk = [0x5Au8; 64];
        let mut framed = Vec::new();
        framed.extend_from_slice(&(junk.len() as u32).to_be_bytes());
        framed.extend_from_slice(&junk);
        let _ = stream.write_all(&framed);
        let _ = stream.flush();
        Ok(())
    });

    let client = AuthenticatedTcpWitness::new(
        address,
        ZeroizingBytes::from_bytes(MlDsa65::generate([62u8; 32]).0),
        witness_vk,
        Duration::from_secs(2),
    )?;
    let outcome = client.compare_and_advance(WitnessIntent::new(
        OperationId::generate()?,
        StateAdvance::new(
            TransitionKind::Advance,
            StateRevision::new(1, 1, [5u8; 32])?,
            StateRevision::new(2, 2, [2u8; 32])?,
        )?,
        FenceToken::generate()?,
        FenceToken::generate()?,
    )?);

    assert!(
        matches!(outcome, Ok(WitnessOutcome::Unknown)),
        "an unverifiable response to a state-changing request must be indeterminate; got {outcome:?}"
    );
    let _ = hostile.join();
    Ok(())
}

fn join<T>(handle: thread::JoinHandle<T>) -> TestResult<T> {
    handle
        .join()
        .map_err(|_| io::Error::other("test worker panicked").into())
}

struct FailingWriteTransport {
    input: Cursor<Vec<u8>>,
}

impl Read for FailingWriteTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}

impl Write for FailingWriteTransport {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "intentional response write failure",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "intentional response flush failure",
        ))
    }
}

impl DeadlineStream for FailingWriteTransport {
    fn set_read_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

struct CaptureTransport {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for CaptureTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}

impl Write for CaptureTransport {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for CaptureTransport {
    fn set_read_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

/// Records the write timeout the framing layer asks for, so a test can see
/// which budget the response was actually given.
struct WriteBudgetTransport {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    write_timeout: std::cell::Cell<Option<Duration>>,
}

impl Read for WriteBudgetTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.input.read(output)
    }
}

impl Write for WriteBudgetTransport {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for WriteBudgetTransport {
    fn set_read_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.write_timeout.set(timeout);
        Ok(())
    }
}

/// Yields one buffered byte per read after a short pause, mimicking a client
/// that stays inside any per-syscall timeout while never completing a frame.
struct TricklingTransport {
    input: Cursor<Vec<u8>>,
    step: Duration,
    output: Vec<u8>,
}

impl Read for TricklingTransport {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        thread::sleep(self.step);
        let mut byte = [0u8; 1];
        if self.input.read(&mut byte)? == 0 {
            return Ok(0);
        }
        let Some(first) = output.first_mut() else {
            return Ok(0);
        };
        *first = byte[0];
        Ok(1)
    }
}

impl Write for TricklingTransport {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DeadlineStream for TricklingTransport {
    fn set_read_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_deadline_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

fn framed_accept_initiator_request(
    signing_key: &[u8],
    nonce: [u8; 32],
    handle: crate::PendingSessionHandle,
    finished: InitiatorFinishedV1,
) -> TestResult<Vec<u8>> {
    let mut body = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut body, b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC domain encoding failed: {error:?}")))?;
    body.fixed(&nonce)
        .and_then(|()| body.byte(4))
        .and_then(|()| body.fixed(handle.as_bytes()))
        .and_then(|()| body.fixed(finished.as_bytes()))
        .map_err(|error| io::Error::other(format!("IPC request encoding failed: {error:?}")))?;
    let envelope = sign_envelope(&body.finish(), signing_key)
        .map_err(|error| io::Error::other(format!("IPC request signing failed: {error:?}")))?;
    let mut framed = Vec::new();
    write_frame(&mut framed, &envelope)
        .map_err(|error| io::Error::other(format!("IPC framing failed: {error:?}")))?;
    Ok(framed)
}

fn decode_responder_acceptance_response(
    framed: &[u8],
    verification_key: &[u8],
    expected_nonce: [u8; 32],
) -> TestResult<([u8; 32], [u8; 32])> {
    let envelope = read_frame(&mut Cursor::new(framed))
        .map_err(|error| io::Error::other(format!("IPC response framing failed: {error:?}")))?;
    let body = verify_envelope(&envelope, verification_key)
        .map_err(|error| io::Error::other(format!("IPC response signature failed: {error:?}")))?;
    let mut decoder = Decoder::new(body);
    require_domain(&mut decoder, b"Q-PERIAPT-POLICY-AGENT-IPC-RESPONSE/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC response domain failed: {error:?}")))?;
    let nonce: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC response nonce failed: {error:?}")))?;
    assert_eq!(nonce, expected_nonce);
    let _: [u8; 32] = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC response digest failed: {error:?}")))?;
    let status = decoder
        .byte()
        .map_err(|error| io::Error::other(format!("IPC response status failed: {error:?}")))?;
    assert_eq!(status, 0);
    let tag = decoder
        .byte()
        .map_err(|error| io::Error::other(format!("IPC response tag failed: {error:?}")))?;
    assert_eq!(tag, 7);
    let key_handle = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC key handle failed: {error:?}")))?;
    let responder_finished = decoder
        .array()
        .map_err(|error| io::Error::other(format!("IPC Finished failed: {error:?}")))?;
    decoder
        .finish()
        .map_err(|error| io::Error::other(format!("IPC trailing bytes: {error:?}")))?;
    Ok((key_handle, responder_finished))
}

#[derive(Clone)]
struct MemoryWitness {
    state: Arc<Mutex<MemoryWitnessState>>,
    unknown_after_apply: Arc<AtomicBool>,
}

struct MemoryWitnessState {
    head: StateHead,
    operations: HashMap<OperationId, WitnessReceipt>,
}

impl MemoryWitness {
    fn new(head: StateHead) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryWitnessState {
                head,
                operations: HashMap::new(),
            })),
            unknown_after_apply: Arc::new(AtomicBool::new(false)),
        }
    }

    fn make_next_unknown(&self) {
        self.unknown_after_apply.store(true, Ordering::Release);
    }

    fn replace_head(&self, head: StateHead) -> Result<(), WitnessError> {
        self.state
            .lock()
            .map_err(|_| WitnessError::Persistence)?
            .head = head;
        Ok(())
    }
}

impl WitnessPort for MemoryWitness {
    fn read_head(&self) -> Result<StateHead, WitnessError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| WitnessError::Persistence)?
            .head)
    }

    fn compare_and_advance(&self, intent: WitnessIntent) -> Result<WitnessOutcome, WitnessError> {
        let mut state = self.state.lock().map_err(|_| WitnessError::Persistence)?;
        if let Some(receipt) = state.operations.get(&intent.operation_id()).copied() {
            if receipt.intent() != Some(intent) {
                return Err(WitnessError::InvalidIntent);
            }
            return Ok(WitnessOutcome::Known(Box::new(receipt)));
        }
        let receipt = if state.head == intent.expected() {
            state.head = intent.next();
            WitnessReceipt::applied(intent)
        } else {
            WitnessReceipt::conflict(intent, state.head)
        };
        state.operations.insert(intent.operation_id(), receipt);
        if self.unknown_after_apply.swap(false, Ordering::AcqRel) {
            Ok(WitnessOutcome::Unknown)
        } else {
            Ok(WitnessOutcome::Known(Box::new(receipt)))
        }
    }

    fn query(&self, operation_id: OperationId) -> Result<WitnessOutcome, WitnessError> {
        let state = self.state.lock().map_err(|_| WitnessError::Persistence)?;
        Ok(WitnessOutcome::Known(Box::new(
            state
                .operations
                .get(&operation_id)
                .copied()
                .unwrap_or_else(|| WitnessReceipt::not_applied(state.head)),
        )))
    }
}

const MEMORY_AUTHORITY_LEASE_TTL_MILLIS: u64 = 10_000;
const MEMORY_AUTHORITY_EPOCH_MILLIS: u64 = 1_000_000;

struct FixedClock(u64);

impl TrustedClockV2 for FixedClock {
    fn now_millis(&self) -> Result<u64, TrustedClockErrorV2> {
        Ok(self.0)
    }
}

/// In-process instance-lease authority sharing one Stage 1 state per deployment.
///
/// Cloning shares the same authority, so two agents built over one clone pair
/// model a recovery clone or concurrent second instance against one deployment.
#[derive(Clone)]
struct MemoryAuthority {
    state: Arc<Mutex<MemoryAuthorityState>>,
}

struct MemoryAuthorityState {
    authority: AuthorityStateV2,
    config: DeploymentConfigRevisionV2,
    now_millis: u64,
    unknown_after_apply: bool,
    advance_before_snapshot: u64,
    snapshot_delay: Duration,
}

fn map_memory_authority_failure(error: AuthorityErrorV2) -> AuthorityKnownFailureV2 {
    match error {
        AuthorityErrorV2::ClockUnavailable => AuthorityKnownFailureV2::ClockUnavailable,
        AuthorityErrorV2::OperationConflict => AuthorityKnownFailureV2::OperationConflict,
        AuthorityErrorV2::AuthorityVersionMismatch => {
            AuthorityKnownFailureV2::AuthorityVersionMismatch
        }
        AuthorityErrorV2::AuthorityVersionExhausted => {
            AuthorityKnownFailureV2::AuthorityVersionExhausted
        }
        AuthorityErrorV2::ReceiptCapacityExceeded => {
            AuthorityKnownFailureV2::ReceiptCapacityExceeded
        }
        _ => AuthorityKnownFailureV2::AllocationFailed,
    }
}

impl MemoryAuthority {
    fn new() -> TestResult<Self> {
        let head = StateHeadV2::new(
            StateRevisionV2::new(1, [41u8; 32], 1, [43u8; 32])?,
            StateFenceV2::from_bytes([44u8; 32])?,
        );
        let config = DeploymentConfigRevisionV2::new(1, [45u8; 32])?;
        let authority = AuthorityStateV2::provision(
            head,
            config,
            AuthorityLimitsV2::new(64, 16, 16, MEMORY_AUTHORITY_LEASE_TTL_MILLIS)?,
            &FixedClock(MEMORY_AUTHORITY_EPOCH_MILLIS),
        )?;
        Ok(Self {
            state: Arc::new(Mutex::new(MemoryAuthorityState {
                authority,
                config,
                now_millis: MEMORY_AUTHORITY_EPOCH_MILLIS,
                unknown_after_apply: false,
                advance_before_snapshot: 0,
                snapshot_delay: Duration::ZERO,
            })),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryAuthorityState> {
        self.state.lock().expect("memory authority poisoned")
    }

    fn advance_clock(&self, delta_millis: u64) {
        let mut state = self.lock();
        state.now_millis += delta_millis;
    }

    /// Advance the authority clock once, just before the next snapshot is
    /// computed, so the snapshot reports a lease with almost no life left.
    ///
    /// This is the real sequence, not a contrived one: the renew succeeds and
    /// then time passes before the agent learns the expiry. Advancing the clock
    /// up front cannot reproduce it, because the renew itself resets the expiry
    /// to `now + ttl`.
    fn advance_clock_before_next_snapshot(&self, delta_millis: u64) {
        self.lock().advance_before_snapshot = delta_millis;
    }

    /// Make the next snapshot take real time, the way a network round trip
    /// does. The coverage anchor is captured before the request is sent, so a
    /// slow snapshot spends the budget it is being asked to report -- which is
    /// the conservative behaviour the anchor exists to produce.
    fn delay_next_snapshot(&self, delay: Duration) {
        self.lock().snapshot_delay = delay;
    }

    fn expire_active_lease(&self) {
        self.advance_clock(MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1);
    }

    fn make_next_unknown(&self) {
        self.lock().unknown_after_apply = true;
    }

    fn lease_call(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        let mut state = self.lock();
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.apply(&clock, intent) {
            Ok(receipt) => {
                if state.unknown_after_apply {
                    state.unknown_after_apply = false;
                    AuthorityOutcomeV2::Unknown(AuthorityUnknownV2::ResponseUnavailable)
                } else {
                    AuthorityOutcomeV2::Known(receipt)
                }
            }
            Err(error) => AuthorityOutcomeV2::KnownFailure(map_memory_authority_failure(error)),
        })
    }
}

impl InstanceAuthorityPort for MemoryAuthority {
    fn wire_config(&self) -> DeploymentConfigRevisionV2 {
        self.lock().config
    }

    fn snapshot(
        &self,
    ) -> Result<AuthorityOutcomeV2<AuthoritySnapshotV2>, AuthorityTransportErrorV2> {
        let mut state = self.lock();
        let pending = core::mem::take(&mut state.advance_before_snapshot);
        state.now_millis = state.now_millis.saturating_add(pending);
        let delay = core::mem::take(&mut state.snapshot_delay);
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.snapshot(&clock) {
            Ok(snapshot) => AuthorityOutcomeV2::Known(snapshot),
            Err(error) => AuthorityOutcomeV2::KnownFailure(map_memory_authority_failure(error)),
        })
    }

    fn acquire(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_call(intent)
    }

    fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_call(intent)
    }

    fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityReceiptV2>, AuthorityTransportErrorV2> {
        self.lease_call(intent)
    }

    fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV2<AuthorityQueryResultV2>, AuthorityTransportErrorV2> {
        let mut state = self.lock();
        if let Some(receipt) = state.authority.receipt(operation_id) {
            return Ok(AuthorityOutcomeV2::Known(AuthorityQueryResultV2::Found(
                Box::new(receipt),
            )));
        }
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.snapshot(&clock) {
            Ok(snapshot) => AuthorityOutcomeV2::Known(AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: snapshot.authority_version(),
            }),
            Err(error) => AuthorityOutcomeV2::KnownFailure(map_memory_authority_failure(error)),
        })
    }

    fn acknowledge(
        &self,
        retained: &DurablyRetainedAuthorityReceiptV2,
    ) -> Result<
        AuthorityOutcomeV2<crate::authority::ReceiptAckDispositionV2>,
        AuthorityTransportErrorV2,
    > {
        let mut state = self.lock();
        Ok(
            match state.authority.acknowledge_receipt(retained.locator()) {
                Ok(disposition) => AuthorityOutcomeV2::Known(disposition),
                Err(_) => AuthorityOutcomeV2::KnownFailure(
                    AuthorityKnownFailureV2::ReceiptAcknowledgementMismatch,
                ),
            },
        )
    }
}

struct PolicyMaterial {
    bundle: SignedPolicyBundle,
    authenticated: AuthenticatedPolicy,
}

fn policy_material(seed: u8) -> TestResult<PolicyMaterial> {
    policy_material_from_text(seed, POLICY)
}

fn policy_material_from_text(seed: u8, document: &str) -> TestResult<PolicyMaterial> {
    let (signing_key, verification_key) = MlDsa65::generate([seed; 32]);
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let written = MlDsa65
        .sign(
            &signing_key,
            &policy_signature_message(document.as_bytes()),
            &[0u8; 32],
            &mut signature,
        )
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    if written != ML_DSA_65_SIG_LEN {
        return Err(io::Error::other("unexpected policy signature length").into());
    }
    let authenticated =
        Policy::load_signed(&MlDsa65, &verification_key, document.as_bytes(), &signature)
            .map_err(|error| io::Error::other(error.to_string()))?;
    let bundle = SignedPolicyBundle::new(
        document.as_bytes().to_vec(),
        signature.to_vec(),
        verification_key,
    )?;
    Ok(PolicyMaterial {
        bundle,
        authenticated,
    })
}

#[test]
fn constructors_reject_collapsed_identity_domains_and_zero_timeouts() -> TestResult {
    let (_, shared_vk) = MlDsa65::generate([90u8; 32]);
    assert_eq!(
        MigrationTrustRoots::new(
            MigrationAuthorityKeyId::from_bytes([1u8; 32]),
            shared_vk,
            MigrationAuthorityKeyId::from_bytes([1u8; 32]),
            shared_vk,
        ),
        Err(crate::RepositoryError::UnprovisionedAuthority)
    );

    let policy = policy_material(20)?;
    let config = AgentConfig::new(
        AgentLimits::new(2, 2, Duration::from_secs(1))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([2u8; 32]), shared_vk)?,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([3u8; 32]), shared_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle,
    );
    assert!(matches!(config, Err(AgentError::InvalidConfiguration)));

    let (client_sk, _) = MlDsa65::generate([91u8; 32]);
    assert_eq!(
        AuthenticatedTcpWitness::new(
            "127.0.0.1:9".parse()?,
            ZeroizingBytes::from_bytes(client_sk),
            shared_vk,
            Duration::ZERO,
        )
        .err(),
        Some(WitnessError::InvalidConfiguration)
    );
    assert_eq!(
        AuthenticatedTcpWitness::new(
            "127.0.0.1:9".parse()?,
            ZeroizingBytes::zeroed(),
            shared_vk,
            Duration::from_secs(1),
        )
        .err(),
        Some(WitnessError::InvalidConfiguration)
    );
    assert_eq!(
        AuthenticatedTcpWitness::new(
            "127.0.0.1:9".parse()?,
            ZeroizingBytes::from_bytes(client_sk),
            [0u8; ML_DSA_65_VK_LEN],
            Duration::from_secs(1),
        )
        .err(),
        Some(WitnessError::InvalidConfiguration)
    );
    let directory = TestDirectory::new()?;
    let (server_sk, server_vk) = MlDsa65::generate([92u8; 32]);
    let head = StateHead::new(
        StateRevision::new(1, 1, [1u8; 32])?,
        FenceToken::generate()?,
    );
    assert_eq!(
        ReferenceWitnessServer::provision(
            &directory.join("witness.redb"),
            head,
            shared_vk,
            ZeroizingBytes::from_bytes(server_sk),
            server_vk,
            Duration::ZERO,
        )
        .err(),
        Some(WitnessError::InvalidConfiguration)
    );
    Ok(())
}

struct MigrationMaterial {
    roots: MigrationTrustRoots,
    authority_signing_key: Vec<u8>,
    recovery_signing_key: Vec<u8>,
    genesis: Vec<u8>,
}

fn migration_material(policy: &AuthenticatedPolicy) -> TestResult<MigrationMaterial> {
    let (authority_sk, authority_vk) = MlDsa65::generate([21u8; 32]);
    let (recovery_sk, recovery_vk) = MlDsa65::generate([22u8; 32]);
    let authority_id = MigrationAuthorityKeyId::from_bytes([31u8; 32]);
    let recovery_id = MigrationAuthorityKeyId::from_bytes([32u8; 32]);
    let state = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 1,
        chain_id: MigrationChainId::from_bytes([41u8; 32]),
        protocol_id: MigrationProtocolId::from_bytes([42u8; 16]),
        epoch: 1,
        previous_state_digest: MigrationStateDigest::from_bytes([0u8; 32]),
        authority_key_id: authority_id,
        execution_policy_state: policy.trusted_state(),
        posture: MigrationSecurityPosture::new(
            SecurityFloor::Level3,
            ComponentMode::HybridRequired,
        ),
        allowed_suites: MigrationSuiteSet::from_suites(&[HybridSuite::MlKem768X25519])?,
    })?;
    let mut signature_output = [0u8; ML_DSA_65_SIG_LEN];
    let certificate = SignedMigrationStateV1::sign(
        StateCertificateKind::Genesis,
        state,
        &MlDsa65,
        &authority_sk,
        &[0u8; 32],
        &mut signature_output,
    )?;
    Ok(MigrationMaterial {
        roots: MigrationTrustRoots::new(authority_id, authority_vk, recovery_id, recovery_vk)?,
        authority_signing_key: authority_sk.to_vec(),
        recovery_signing_key: recovery_sk.to_vec(),
        genesis: certificate.encode()?,
    })
}

struct AgentPair {
    initiator: PolicyAgent<MemoryWitness, MemoryAuthority>,
    responder: PolicyAgent<MemoryWitness, MemoryAuthority>,
    witness: MemoryWitness,
    initiator_authority: MemoryAuthority,
    committed: CommittedMigrationStateV1,
    migration: MigrationMaterial,
    initiator_config: AgentConfig,
    endpoint_policy_bundle: SignedPolicyBundle,
    initiator_repository_path: PathBuf,
    old_snapshot_path: PathBuf,
    initiator_authorization: SessionAuthorization,
    responder_authorization: SessionAuthorization,
    /// A second, independently identified session, for tests that need two
    /// live sessions on one agent.
    second_initiator_authorization: SessionAuthorization,
    second_responder_authorization: SessionAuthorization,
    initiator_public_keys: EncapsulationPublicKeys,
    responder_public_keys: EncapsulationPublicKeys,
}

fn agent_pair(directory: &TestDirectory, session_byte: u8) -> TestResult<AgentPair> {
    agent_pair_with_session_ttl(directory, session_byte, Duration::from_secs(60))
}

fn agent_pair_with_session_ttl(
    directory: &TestDirectory,
    session_byte: u8,
    session_ttl: Duration,
) -> TestResult<AgentPair> {
    use std::os::unix::fs::PermissionsExt;

    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let initiator_repository_path = directory.join("initiator.redb");
    let responder_repository_path = directory.join("responder.redb");
    let old_snapshot_path = directory.join("old-snapshot.redb");
    let (initial_repository, head) = StateRepository::provision_new(
        &initiator_repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let committed = initial_repository.committed_state();
    drop(initial_repository);
    for destination in [&responder_repository_path, &old_snapshot_path] {
        fs::copy(&initiator_repository_path, destination)?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    }
    let initiator_repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let responder_repository =
        StateRepository::open_existing(&responder_repository_path, migration.roots.clone())?;
    let witness = MemoryWitness::new(head);
    let (initiator_identity_sk, initiator_identity_vk) = MlDsa65::generate([51u8; 32]);
    let (responder_identity_sk, responder_identity_vk) = MlDsa65::generate([52u8; 32]);
    let initiator_identity_id = MigrationIdentityKeyId::from_bytes([61u8; 32]);
    let responder_identity_id = MigrationIdentityKeyId::from_bytes([62u8; 32]);
    let limits = AgentLimits::new(16, 16, session_ttl)?;
    let initiator_config = AgentConfig::new(
        limits,
        EndpointRole::Initiator,
        EndpointIdentity::new(initiator_identity_id, initiator_identity_vk)?,
        EndpointIdentity::new(responder_identity_id, responder_identity_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle.clone(),
    )?;
    let responder_config = AgentConfig::new(
        limits,
        EndpointRole::Responder,
        EndpointIdentity::new(responder_identity_id, responder_identity_vk)?,
        EndpointIdentity::new(initiator_identity_id, initiator_identity_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle.clone(),
    )?;
    let initiator_authority = MemoryAuthority::new()?;
    let responder_authority = MemoryAuthority::new()?;
    let initiator = PolicyAgent::new(
        initiator_repository,
        witness.clone(),
        initiator_authority.clone(),
        initiator_config.clone(),
    )?;
    let responder = PolicyAgent::new(
        responder_repository,
        witness.clone(),
        responder_authority.clone(),
        responder_config,
    )?;
    let initiator_public_keys = initiator.public_keys()?;
    let responder_public_keys = responder.public_keys()?;
    let session_id = MigrationSessionId::from_bytes([session_byte; 32]);
    let initiator_offer = signed_offer(SignedOfferInput {
        role: EndpointRole::Initiator,
        sender_identity: initiator_identity_id,
        receiver_identity: responder_identity_id,
        nonce: MigrationNonce::from_bytes([71u8.wrapping_add(session_byte); 32]),
        session_id,
        policy: &policy.authenticated,
        committed,
        keys: &initiator_public_keys,
        signing_key: &initiator_identity_sk,
    })?;
    let responder_offer = signed_offer(SignedOfferInput {
        role: EndpointRole::Responder,
        sender_identity: responder_identity_id,
        receiver_identity: initiator_identity_id,
        nonce: MigrationNonce::from_bytes([81u8.wrapping_add(session_byte); 32]),
        session_id,
        policy: &policy.authenticated,
        committed,
        keys: &responder_public_keys,
        signing_key: &responder_identity_sk,
    })?;
    let second_session_id = MigrationSessionId::from_bytes([session_byte.wrapping_add(128); 32]);
    let second_initiator_offer = signed_offer(SignedOfferInput {
        role: EndpointRole::Initiator,
        sender_identity: initiator_identity_id,
        receiver_identity: responder_identity_id,
        nonce: MigrationNonce::from_bytes([91u8.wrapping_add(session_byte); 32]),
        session_id: second_session_id,
        policy: &policy.authenticated,
        committed,
        keys: &initiator_public_keys,
        signing_key: &initiator_identity_sk,
    })?;
    let second_responder_offer = signed_offer(SignedOfferInput {
        role: EndpointRole::Responder,
        sender_identity: responder_identity_id,
        receiver_identity: initiator_identity_id,
        nonce: MigrationNonce::from_bytes([101u8.wrapping_add(session_byte); 32]),
        session_id: second_session_id,
        policy: &policy.authenticated,
        committed,
        keys: &responder_public_keys,
        signing_key: &responder_identity_sk,
    })?;
    Ok(AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        committed,
        migration,
        initiator_config,
        endpoint_policy_bundle: policy.bundle,
        initiator_repository_path,
        old_snapshot_path,
        initiator_authorization: SessionAuthorization::new(
            initiator_offer.clone(),
            responder_offer.clone(),
        )?,
        responder_authorization: SessionAuthorization::new(responder_offer, initiator_offer)?,
        second_initiator_authorization: SessionAuthorization::new(
            second_initiator_offer.clone(),
            second_responder_offer.clone(),
        )?,
        second_responder_authorization: SessionAuthorization::new(
            second_responder_offer,
            second_initiator_offer,
        )?,
        initiator_public_keys,
        responder_public_keys,
    })
}

struct SignedOfferInput<'a> {
    role: EndpointRole,
    sender_identity: MigrationIdentityKeyId,
    receiver_identity: MigrationIdentityKeyId,
    nonce: MigrationNonce,
    session_id: MigrationSessionId,
    policy: &'a AuthenticatedPolicy,
    committed: CommittedMigrationStateV1,
    keys: &'a EncapsulationPublicKeys,
    signing_key: &'a [u8],
}

fn signed_offer(input: SignedOfferInput<'_>) -> TestResult<Vec<u8>> {
    let SignedOfferInput {
        role,
        sender_identity,
        receiver_identity,
        nonce,
        session_id,
        policy,
        committed,
        keys,
        signing_key,
    } = input;
    let key_share = EndpointKeyShareV1::new(keys.pq(), keys.traditional())?;
    let offer = CapabilityOfferV1::from_authenticated_state(CapabilityOfferInputV1 {
        protocol_id: committed.state().protocol_id(),
        session_id,
        sender_role: role,
        sender_identity,
        receiver_identity,
        sender_nonce: nonce,
        sender_policy: policy,
        committed_state: committed,
        offered_suites: MigrationSuiteSet::from_suites(&[HybridSuite::MlKem768X25519])?,
        sender_key_share: &key_share,
    })?;
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let signed =
        SignedCapabilityOfferV1::sign(offer, &MlDsa65, signing_key, &[0u8; 32], &mut signature)?;
    Ok(signed.encode()?)
}

fn initiator_encapsulation(
    result: BeginEncapsulationResult,
) -> TestResult<InitiatorEncapsulationResult> {
    match result {
        BeginEncapsulationResult::Initiator(result) => Ok(result),
        BeginEncapsulationResult::Responder(_) => {
            Err(io::Error::other("initiator returned responder begin state").into())
        }
    }
}

fn responder_encapsulation(
    result: BeginEncapsulationResult,
) -> TestResult<ResponderEncapsulationResult> {
    match result {
        BeginEncapsulationResult::Responder(result) => Ok(result),
        BeginEncapsulationResult::Initiator(_) => {
            Err(io::Error::other("responder returned initiator begin state").into())
        }
    }
}

fn initiator_decapsulation(
    result: BeginDecapsulationResult,
) -> TestResult<InitiatorDecapsulationResult> {
    match result {
        BeginDecapsulationResult::Initiator(result) => Ok(result),
        BeginDecapsulationResult::Responder(_) => {
            Err(io::Error::other("initiator returned responder begin state").into())
        }
    }
}

fn responder_decapsulation(
    result: BeginDecapsulationResult,
) -> TestResult<ResponderDecapsulationResult> {
    match result {
        BeginDecapsulationResult::Responder(result) => Ok(result),
        BeginDecapsulationResult::Initiator(_) => {
            Err(io::Error::other("responder returned initiator begin state").into())
        }
    }
}

#[test]
fn a_coverage_lapse_at_acceptance_releases_the_durable_reservation() -> TestResult {
    // By the acceptance point the session has already left the in-memory map
    // and its confirmation is consumed, but its durable reservation is still
    // held. Refusing there without releasing it would orphan the row --
    // `erase_pending` can no longer find the handle and `fence_out` iterates the
    // map -- permanently burning one of the bounded SESSION_TABLE slots, and
    // surviving restart. That would make this fix worse than the gap it closes.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 63)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let accepted = pair
        .responder
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;

    // Lapse the coverage for the initiator's acceptance specifically.
    pair.initiator_authority
        .advance_clock_before_next_snapshot(MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 1);
    pair.initiator_authority
        .delay_next_snapshot(Duration::from_millis(20));
    assert_eq!(
        pair.initiator
            .accept_responder_finished(encapsulated.handle, accepted.responder_finished)
            .err(),
        Some(AgentError::InstanceLeaseCoverageElapsed)
    );

    // The durable row is gone: cancelling it again must fail, because there is
    // nothing left to cancel. If the reservation had leaked this would succeed.
    assert!(
        pair.initiator
            .desynchronize_session_for_test(encapsulated.handle)
            .is_err(),
        "the durable reservation was orphaned instead of released"
    );
    assert_eq!(pair.initiator.pending_session_count(), 0);
    Ok(())
}

#[test]
fn a_lease_that_lapsed_without_a_successor_is_recovered_not_fenced() -> TestResult {
    // An authority unreachable for longer than the lease TTL used to brick the
    // agent permanently: the first successful renew after reconnect returned
    // LeaseExpired, which was treated as supersession and fenced the instance
    // for the life of the process. A fifteen-second restart of the authority is
    // more than the ten-second minimum TTL, so this happened unattended and to
    // every agent at once.
    //
    // LeaseExpired says the lease had run out, not that anyone took it. Here
    // nobody did.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 67)?;
    pair.initiator_authority.expire_active_lease();

    // The guarded operation drives the renew, which is rejected as expired and
    // recovers by re-acquiring at this instance's own generation.
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    assert!(!encapsulated
        .initiator_finished
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0));

    // Still usable, and holding the session it just created.
    assert_eq!(pair.initiator.pending_session_count(), 1);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn an_operation_that_outlives_its_proven_lease_coverage_retains_nothing() -> TestResult {
    // The lease is checked on the way in, but a witness round trip, two
    // signature verifications and a KEM operation all run before a secret first
    // becomes retained. The renew receipt carries no expiry, so the agent takes
    // one snapshot to learn how long it can prove it still holds the lease, and
    // refuses to retain anything past that point.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 61)?;

    // The renew applies, and then the authority's clock jumps to one
    // millisecond before the new expiry. That is the shape of the real race:
    // the renew succeeded, and time passed before the agent learned the expiry.
    pair.initiator_authority
        .advance_clock_before_next_snapshot(MEMORY_AUTHORITY_LEASE_TTL_MILLIS - 1);
    // Spend that last millisecond inside the snapshot, so the coverage has
    // provably lapsed by the time the operation checks it. Without this the
    // test would be racing the real work between the snapshot and the check --
    // key generation, the witness round trip, the contract's signature
    // verifications -- and would start passing for the wrong reason, or fail
    // outright, once a release build brings that work under a millisecond.
    pair.initiator_authority
        .delay_next_snapshot(Duration::from_millis(20));

    let outcome = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization,
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(
        outcome.err(),
        Some(AgentError::InstanceLeaseCoverageElapsed),
        "an operation past its proven coverage must not return a handle"
    );

    // Nothing was retained. A coverage lapse is not a fence: it is a local
    // deadline running out, which is no evidence that a successor exists, so
    // the agent stays usable rather than being permanently retired.
    assert_eq!(pair.initiator.pending_session_count(), 0);
    assert_eq!(pair.initiator.confirmed_key_count(), 0);
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn fencing_out_erases_every_key_even_when_a_durable_cancel_fails() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 41)?;

    // Carry one session through to a confirmed application key.
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    pair.responder
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    assert_eq!(pair.responder.confirmed_key_count(), 1);

    // And leave a second session pending, so the sweep has something to fail on
    // before it reaches the retained key.
    let second =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.second_initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    let second_pending = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.second_responder_authorization, second.ciphertexts),
    )?)?;
    assert_eq!(pair.responder.pending_session_count(), 1);

    // Make that session's durable cancellation fail the way a diverged store
    // would: its row is gone, but the session is still held in memory.
    pair.responder
        .desynchronize_session_for_test(second_pending.handle)?;

    // Fencing out happens when another instance holds the lease, so this
    // process must not be left holding key material. The durable failure is
    // still reported, but it must not be reported instead of erasing.
    assert!(pair.responder.fence_out_for_test().is_err());
    assert_eq!(pair.responder.pending_session_count(), 0);
    assert_eq!(
        pair.responder.confirmed_key_count(),
        0,
        "a failed durable cancel left accepted application keys in memory"
    );
    Ok(())
}

#[test]
fn an_idle_agent_erases_expired_session_secrets_without_being_asked() -> TestResult {
    let directory = TestDirectory::new()?;
    // Short enough that the session is past its deadline almost immediately, so
    // the test observes the expiry rather than waiting out a realistic TTL.
    let pair = agent_pair_with_session_ttl(&directory, 9, Duration::from_millis(1))?;
    initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?)?;
    assert_eq!(pair.initiator.pending_session_count(), 1);

    thread::sleep(Duration::from_millis(20));

    // The deadline has passed and the session is still here. That is the whole
    // problem: every purge so far has been a side effect of some request, so an
    // agent nobody is talking to holds its expired key material indefinitely.
    assert_eq!(pair.initiator.pending_session_count(), 1);

    // This is what the serving loop calls when its accept wait times out.
    pair.initiator.expire_idle_sessions();
    assert_eq!(pair.initiator.pending_session_count(), 0);

    // The sweep releases the durable reservation too, so the freed capacity is
    // real and not just a forgotten map entry.
    assert!(pair.initiator.public_keys().is_ok());
    Ok(())
}

#[test]
fn mutual_confirmation_releases_only_handles_and_replay_tombstone_survives_restart() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 1)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated =
        responder_decapsulation(pair.responder.begin_decapsulation(BeginDecapsulation::new(
            pair.responder_authorization.clone(),
            encapsulated.ciphertexts.clone(),
        ))?)?;

    assert_eq!(
        pair.initiator
            .accept_initiator_finished(encapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::UnexpectedFlight)
    );
    assert_eq!(
        pair.responder.accept_responder_finished(
            decapsulated.handle,
            ResponderFinishedV1::from_bytes([9u8; 32]),
        ),
        Err(AgentError::UnexpectedFlight)
    );

    let responder_acceptance = pair
        .responder
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,)?,
        responder_acceptance
    );
    assert_eq!(
        pair.responder.accept_initiator_finished(
            decapsulated.handle,
            InitiatorFinishedV1::from_bytes([0u8; 32]),
        ),
        Err(AgentError::ConflictingAcceptanceReplay)
    );
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,)?,
        responder_acceptance
    );
    let initiator_key = pair
        .initiator
        .accept_responder_finished(encapsulated.handle, responder_acceptance.responder_finished)?;
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            responder_acceptance.responder_finished,
        )?,
        initiator_key
    );
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            ResponderFinishedV1::from_bytes([0u8; 32]),
        ),
        Err(AgentError::ConflictingAcceptanceReplay)
    );
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            responder_acceptance.responder_finished,
        )?,
        initiator_key
    );
    pair.initiator.destroy_key(initiator_key)?;
    pair.responder
        .destroy_key(responder_acceptance.key_handle)?;
    let replay = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ));
    assert_eq!(replay, Err(AgentError::AuthorizationRejected));

    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        initiator_authorization,
        responder_public_keys,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();
    let reopened_repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    let reopened = PolicyAgent::new(
        reopened_repository,
        witness,
        initiator_authority,
        initiator_config,
    )?;
    let replay_after_restart = reopened.begin_encapsulation(BeginEncapsulation::new(
        initiator_authorization,
        responder_public_keys,
    ));
    assert_eq!(replay_after_restart, Err(AgentError::AuthorizationRejected));
    Ok(())
}

#[test]
fn protocol_role_not_kem_direction_controls_finished_order() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 12)?;
    let encapsulated = responder_encapsulation(pair.responder.begin_encapsulation(
        BeginEncapsulation::new(pair.responder_authorization, pair.initiator_public_keys),
    )?)?;
    let decapsulated = initiator_decapsulation(pair.initiator.begin_decapsulation(
        BeginDecapsulation::new(pair.initiator_authorization, encapsulated.ciphertexts),
    )?)?;

    let responder_acceptance = pair
        .responder
        .accept_initiator_finished(encapsulated.handle, decapsulated.initiator_finished)?;
    let initiator_key = pair
        .initiator
        .accept_responder_finished(decapsulated.handle, responder_acceptance.responder_finished)?;
    pair.initiator.destroy_key(initiator_key)?;
    pair.responder
        .destroy_key(responder_acceptance.key_handle)?;
    Ok(())
}

#[test]
fn concurrent_exact_responder_acceptance_returns_one_stable_result() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 15)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let responder = Arc::new(pair.responder);
    let barrier = Arc::new(Barrier::new(3));

    let first_agent = Arc::clone(&responder);
    let first_barrier = Arc::clone(&barrier);
    let first_finished = encapsulated.initiator_finished;
    let first = thread::spawn(move || {
        first_barrier.wait();
        first_agent.accept_initiator_finished(decapsulated.handle, first_finished)
    });
    let second_agent = Arc::clone(&responder);
    let second_barrier = Arc::clone(&barrier);
    let second_finished = encapsulated.initiator_finished;
    let second = thread::spawn(move || {
        second_barrier.wait();
        second_agent.accept_initiator_finished(decapsulated.handle, second_finished)
    });
    barrier.wait();
    let first_result = join(first)??;
    let second_result = join(second)??;
    assert_eq!(first_result, second_result);
    responder.destroy_key(first_result.key_handle)?;
    assert_eq!(
        responder.destroy_key(first_result.key_handle),
        Err(AgentError::UnknownHandle)
    );
    Ok(())
}

#[test]
fn ipc_rejects_a_response_key_clients_could_not_verify() -> TestResult {
    // A perfectly valid signing key that simply is not the one clients pinned.
    // It signs, and it is a different pair from the request direction, so every
    // other startup check passes. Only comparing a signature against the pinned
    // response key catches it -- and without that the daemon starts, commits
    // state, and only then emits responses every client rejects.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 27)?;
    let (_, client_verification_key) = MlDsa65::generate([95u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([96u8; 32]);
    let (_, unrelated_verification_key) = MlDsa65::generate([99u8; 32]);
    assert!(
        crate::ipc::UnixIpcServer::new_for_test(
            pair.responder,
            client_verification_key,
            ZeroizingBytes::from_bytes(server_signing_key),
            unrelated_verification_key,
        )
        .is_err(),
        "a signing key that does not match the pinned response key must be refused"
    );

    // The matching pair is still accepted, so the check is not simply refusing
    // everything.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 28)?;
    let (server_signing_key_again, _) = MlDsa65::generate([96u8; 32]);
    assert!(crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key_again),
        server_verification_key,
    )
    .is_ok());
    Ok(())
}

#[test]
fn ipc_rejects_one_key_pair_serving_both_directions() -> TestResult {
    // The IPC server verifies requests under the client key and signs responses
    // under its own. One key pair for both directions would let any client
    // authorized to send requests forge responses.
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 23)?;
    let (shared_sk, shared_vk) = MlDsa65::generate([93u8; 32]);
    assert!(
        crate::ipc::UnixIpcServer::new_for_test(
            pair.responder,
            shared_vk,
            ZeroizingBytes::from_bytes(shared_sk),
            shared_vk,
        )
        .is_err(),
        "one key pair must not carry both IPC directions"
    );
    Ok(())
}

#[test]
fn a_busy_listener_does_not_starve_the_session_sweep() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair_with_session_ttl(&directory, 53, Duration::from_millis(1))?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys.clone(),
        ))?)?;
    responder_decapsulation(pair.responder.begin_decapsulation(BeginDecapsulation::new(
        pair.responder_authorization,
        encapsulated.ciphertexts,
    ))?)?;
    assert_eq!(pair.responder.pending_session_count(), 1);

    let (_, client_verification_key) = MlDsa65::generate([97u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([98u8; 32]);
    let server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let socket_path = directory.join("busy.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    let shutdown = AtomicBool::new(false);

    thread::scope(|scope| -> TestResult {
        let serving = scope.spawn(|| {
            let mut server = server;
            let outcome = server.serve_for_test(listener, &shutdown);
            (server, outcome)
        });

        // Keep the listener continuously readable for longer than one
        // maintenance interval. Each connection is dropped without sending a
        // request, which is the cheapest way a client can hold the loop's
        // attention -- and exactly what an unauthenticated peer can do.
        let hammering = Instant::now();
        while hammering.elapsed() < Duration::from_millis(1_400) {
            if let Ok(connection) = std::os::unix::net::UnixStream::connect(&socket_path) {
                drop(connection);
            }
        }
        shutdown.store(true, Ordering::Release);
        // Unblock the final wait so the loop observes the flag promptly.
        let _ = std::os::unix::net::UnixStream::connect(&socket_path);
        let (returned, outcome) = serving
            .join()
            .map_err(|_| io::Error::other("serving thread panicked"))?;
        outcome?;

        // The session expired 1.4s ago. Tying the sweep to an idle wait would
        // leave it here forever, because the wait never timed out.
        assert_eq!(
            returned.agent_for_test().pending_session_count(),
            0,
            "a continuously busy listener starved the session sweep"
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn the_serving_loop_answers_over_a_real_socket_and_stops_on_shutdown() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 31)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([95u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([96u8; 32]);
    let server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let socket_path = directory.join("serve.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_thread = thread::spawn(move || {
        let mut server = server;
        server.serve_for_test(listener, &server_shutdown)
    });

    // The only test that drives the accept path itself: the non-blocking
    // listener, the poll readiness report, and putting the accepted stream back
    // into blocking mode so the handler's SO_RCVTIMEO deadlines behave. An
    // accepted socket inherits non-blocking mode on the BSDs but not on Linux,
    // so this covers a difference the unit tests cannot see.
    let nonce = [26u8; 32];
    let mut client = std::os::unix::net::UnixStream::connect(&socket_path)?;
    client.write_all(&framed_accept_initiator_request(
        &client_signing_key,
        nonce,
        decapsulated.handle,
        encapsulated.initiator_finished,
    )?)?;
    // The server serves one request per connection and then drops the stream,
    // so the read ends when it closes.
    let mut response = Vec::new();
    client.read_to_end(&mut response)?;
    let (key_handle, responder_finished) =
        decode_responder_acceptance_response(&response, &server_verification_key, nonce)?;
    assert!(!key_handle.iter().all(|byte| *byte == 0));
    assert!(!responder_finished.iter().all(|byte| *byte == 0));

    // The loop reads the flag once per accept wait, so it stops within one
    // maintenance interval rather than needing a connection to wake it.
    shutdown.store(true, Ordering::Release);
    server_thread
        .join()
        .map_err(|_| io::Error::other("serving thread panicked"))??;
    Ok(())
}

#[test]
fn the_response_write_budget_does_not_come_out_of_the_request_deadline() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 23)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([93u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([94u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let mut transport = WriteBudgetTransport {
        input: Cursor::new(framed_accept_initiator_request(
            &client_signing_key,
            [24u8; 32],
            decapsulated.handle,
            encapsulated.initiator_finished,
        )?),
        output: Vec::new(),
        write_timeout: std::cell::Cell::new(None),
    };
    // A request deadline with almost nothing left on it, standing in for an
    // operation whose execution consumed the budget. A real advance does this
    // routinely: the witness and authority timeouts together outlast a single
    // IPC timeout.
    let read_deadline = Instant::now()
        .checked_add(Duration::from_millis(50))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    server.handle_io_with_deadline_for_test(&mut transport, read_deadline)?;

    // The response was written on a fresh budget, not on the sliver left of the
    // request's. Sharing the deadline would have failed the write outright and
    // left the client unable to learn the outcome of a committed operation.
    let granted = transport
        .write_timeout
        .get()
        .ok_or_else(|| io::Error::other("no write timeout was set"))?;
    assert!(
        granted > Duration::from_millis(50),
        "response write budget {granted:?} came out of the request deadline"
    );
    assert!(!transport.output.is_empty());
    Ok(())
}

#[test]
fn ipc_write_failure_can_recover_exact_acceptance_with_a_new_nonce() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 17)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([91u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([92u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    let first_nonce = [21u8; 32];
    let first_request = framed_accept_initiator_request(
        &client_signing_key,
        first_nonce,
        decapsulated.handle,
        encapsulated.initiator_finished,
    )?;
    let mut failed_write = FailingWriteTransport {
        input: Cursor::new(first_request.clone()),
    };
    assert_eq!(
        server.handle_io_for_test(&mut failed_write),
        Err(crate::ipc::IpcError::Unavailable)
    );
    assert_eq!(
        server.agent_for_test().acceptance_counts_for_test()?,
        (1, 1)
    );

    let mut replayed_nonce = CaptureTransport {
        input: Cursor::new(first_request),
        output: Vec::new(),
    };
    assert_eq!(
        server.handle_io_for_test(&mut replayed_nonce),
        Err(crate::ipc::IpcError::AuthenticationFailed)
    );
    assert!(replayed_nonce.output.is_empty());

    let cached = server
        .agent_for_test()
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    let retry_nonce = [22u8; 32];
    let mut retried = CaptureTransport {
        input: Cursor::new(framed_accept_initiator_request(
            &client_signing_key,
            retry_nonce,
            decapsulated.handle,
            encapsulated.initiator_finished,
        )?),
        output: Vec::new(),
    };
    server.handle_io_for_test(&mut retried)?;
    let (key_handle, responder_finished) = decode_responder_acceptance_response(
        &retried.output,
        &server_verification_key,
        retry_nonce,
    )?;
    assert_eq!(key_handle, *cached.key_handle.as_bytes());
    assert_eq!(responder_finished, *cached.responder_finished.as_bytes());
    assert_eq!(
        server.agent_for_test().acceptance_counts_for_test()?,
        (1, 1)
    );
    server.agent_for_test().destroy_key(cached.key_handle)?;
    assert_eq!(
        server.agent_for_test().acceptance_counts_for_test()?,
        (0, 0)
    );
    Ok(())
}

#[test]
fn ipc_absolute_deadline_evicts_a_pre_auth_trickle_client() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 19)?;
    let (_, client_verification_key) = MlDsa65::generate([93u8; 32]);
    let (server_signing_key, server_verification_key) = MlDsa65::generate([94u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
        server_verification_key,
    )?;

    // A maximum-length frame trickled one byte per 20ms would take minutes;
    // the absolute deadline must fail the connection at ~200ms instead.
    let mut frame = u32::try_from(MAX_FRAME_BYTES)
        .map_err(|_| io::Error::other("IPC frame length does not fit"))?
        .to_be_bytes()
        .to_vec();
    frame.resize(frame.len().saturating_add(512), 0);
    let mut trickle = TricklingTransport {
        input: Cursor::new(frame),
        step: Duration::from_millis(20),
        output: Vec::new(),
    };
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_millis(200))
        .ok_or_else(|| io::Error::other("test deadline overflowed"))?;
    let result = server.handle_io_with_deadline_for_test(&mut trickle, deadline);
    let elapsed = started.elapsed();
    assert_eq!(result, Err(crate::ipc::IpcError::InvalidMessage));
    assert!(elapsed >= Duration::from_millis(200));
    assert!(elapsed < Duration::from_secs(10));
    assert!(trickle.output.is_empty());
    Ok(())
}

#[test]
fn abi2_secret_mismatch_rejects_finished_and_terminally_erases_session() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 2)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let mut damaged_pq = *encapsulated.ciphertexts.pq();
    if let Some(first) = damaged_pq.first_mut() {
        *first ^= 1;
    }
    let damaged =
        EncapsulationCiphertexts::from_slices(&damaged_pq, encapsulated.ciphertexts.traditional())?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, damaged),
    )?)?;
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::FinishedRejected)
    );
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::UnknownHandle)
    );
    pair.initiator.cancel(encapsulated.handle)?;
    assert_eq!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization,
            pair.responder_public_keys,
        )),
        Err(AgentError::AuthorizationRejected)
    );
    Ok(())
}

#[test]
fn durable_release_failure_never_returns_responder_finished_or_retained_handle() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 13)?;
    let encapsulated = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let decapsulated = responder_decapsulation(pair.responder.begin_decapsulation(
        BeginDecapsulation::new(pair.responder_authorization, encapsulated.ciphertexts),
    )?)?;

    pair.responder
        .remove_durable_reservation_for_test(decapsulated.handle)?;
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::InternalPoisoned)
    );
    Ok(())
}

#[test]
fn durable_cancel_failure_poisoning_prevents_further_service() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 18)?;
    let pending = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    pair.initiator
        .remove_durable_reservation_for_test(pending.handle)?;
    assert_eq!(
        pair.initiator.cancel(pending.handle),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(
        pair.initiator.public_keys(),
        Err(AgentError::InternalPoisoned)
    );
    Ok(())
}

#[test]
fn stale_witness_is_rejected_before_finished_verification_and_consumes_session() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 14)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated =
        responder_decapsulation(pair.responder.begin_decapsulation(BeginDecapsulation::new(
            pair.responder_authorization,
            encapsulated.ciphertexts.clone(),
        ))?)?;
    pair.witness.replace_head(StateHead::new(
        StateRevision::new(2, 2, [14u8; 32])?,
        FenceToken::generate()?,
    ))?;

    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::StaleSession)
    );
    assert_eq!(
        pair.responder
            .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished,),
        Err(AgentError::UnknownHandle)
    );
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            ResponderFinishedV1::from_bytes([0u8; 32]),
        ),
        Err(AgentError::StaleSession)
    );
    assert_eq!(
        pair.initiator.accept_responder_finished(
            encapsulated.handle,
            ResponderFinishedV1::from_bytes([0u8; 32]),
        ),
        Err(AgentError::UnknownHandle)
    );
    Ok(())
}

#[test]
fn restart_rejects_secretless_pending_handle_but_preserves_capability_tombstone() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 16)?;
    let pending =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        initiator_authorization,
        responder_public_keys,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();

    let repository = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    assert_eq!(repository.restart_rejections(), 1);
    let reopened = PolicyAgent::new(repository, witness, initiator_authority, initiator_config)?;
    assert_eq!(
        reopened
            .accept_responder_finished(pending.handle, ResponderFinishedV1::from_bytes([0u8; 32]),),
        Err(AgentError::UnknownHandle)
    );
    assert_eq!(
        reopened.begin_encapsulation(BeginEncapsulation::new(
            initiator_authorization,
            responder_public_keys,
        )),
        Err(AgentError::AuthorizationRejected)
    );
    Ok(())
}

fn signed_advance(
    current: MigrationStateV1,
    migration: &MigrationMaterial,
    posture: MigrationSecurityPosture,
    allowed_suites: MigrationSuiteSet,
) -> TestResult<(MigrationStateV1, Vec<u8>)> {
    signed_advance_with_execution(
        current,
        migration,
        current.execution_policy_state(),
        posture,
        allowed_suites,
    )
}

fn signed_advance_with_execution(
    current: MigrationStateV1,
    migration: &MigrationMaterial,
    execution_policy_state: TrustedPolicyState,
    posture: MigrationSecurityPosture,
    allowed_suites: MigrationSuiteSet,
) -> TestResult<(MigrationStateV1, Vec<u8>)> {
    let next = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: current
            .global_generation()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("generation overflow"))?,
        chain_id: current.chain_id(),
        protocol_id: current.protocol_id(),
        epoch: current
            .epoch()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("epoch overflow"))?,
        previous_state_digest: current.digest()?,
        authority_key_id: current.authority_key_id(),
        execution_policy_state,
        posture,
        allowed_suites,
    })?;
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let certificate = SignedMigrationStateV1::sign(
        StateCertificateKind::Advance,
        next,
        &MlDsa65,
        &migration.authority_signing_key,
        &[0u8; 32],
        &mut signature,
    )?;
    Ok((next, certificate.encode()?))
}

#[test]
fn floor_five_advance_is_rejected_before_durable_intent_or_witness_cas() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 8)?;
    let initial_state = pair.committed.state();
    let initial_head = pair.witness.read_head()?;
    let (_, floor_five_certificate) = signed_advance(
        initial_state,
        &pair.migration,
        MigrationSecurityPosture::new(SecurityFloor::Level5, ComponentMode::HybridRequired),
        MigrationSuiteSet::from_suites(&[HybridSuite::MlKem1024X25519])?,
    )?;

    assert_eq!(
        pair.initiator.apply_advance(&floor_five_certificate),
        Err(AgentError::Repository(
            crate::RepositoryError::InvalidCertificate
        ))
    );
    assert_eq!(pair.witness.read_head()?, initial_head);

    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();

    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    assert_eq!(repository.pending_intent(), None);
    assert_eq!(repository.head()?, initial_head);
    assert_eq!(repository.committed_state().state(), initial_state);

    let (floor_three_state, floor_three_certificate) = signed_advance(
        initial_state,
        &migration,
        initial_state.posture(),
        initial_state.allowed_suites(),
    )?;
    let agent = PolicyAgent::new(
        repository,
        witness.clone(),
        initiator_authority,
        initiator_config,
    )?;
    agent.apply_advance(&floor_three_certificate)?;
    drop(agent);

    let transitioned = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    assert_eq!(transitioned.pending_intent(), None);
    assert_eq!(transitioned.committed_state().state(), floor_three_state);
    assert_eq!(transitioned.head()?, witness.read_head()?);
    assert_ne!(transitioned.head()?, initial_head);
    Ok(())
}

#[test]
fn unknown_transition_reconciles_same_operation_and_stales_old_session() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 3)?;
    let pending = initiator_encapsulation(pair.initiator.begin_encapsulation(
        BeginEncapsulation::new(pair.initiator_authorization, pair.responder_public_keys),
    )?)?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.witness.make_next_unknown();
    assert_eq!(
        pair.initiator.apply_advance(&certificate),
        Err(AgentError::TransitionIndeterminate)
    );
    assert_eq!(
        pair.initiator
            .accept_responder_finished(pending.handle, ResponderFinishedV1::from_bytes([0u8; 32]),),
        Err(AgentError::TransitionPending)
    );
    pair.initiator.reconcile_transition()?;
    assert_eq!(
        pair.initiator
            .accept_responder_finished(pending.handle, ResponderFinishedV1::from_bytes([0u8; 32]),),
        Err(AgentError::UnknownHandle)
    );

    let old_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    // A fresh deployment authority isolates this assertion to the witness
    // rollback check; the shared-authority clone case is covered by the
    // dedicated instance-lease fencing tests.
    let rolled_back = PolicyAgent::new(
        old_repository,
        pair.witness,
        MemoryAuthority::new()?,
        pair.initiator_config,
    );
    assert!(matches!(rolled_back, Err(AgentError::RollbackOrFork)));
    Ok(())
}

#[test]
fn valid_incompatible_state_commits_without_executor_and_later_state_recovers() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 4)?;
    let (incompatible_state, incompatible_certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        MigrationSuiteSet::from_suites(&[HybridSuite::MlKem1024X25519])?,
    )?;
    pair.initiator.apply_advance(&incompatible_certificate)?;
    assert_eq!(
        pair.initiator.public_keys(),
        Err(AgentError::ExecutionUnavailable)
    );

    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();
    let repository =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let restarted = PolicyAgent::new(repository, witness, initiator_authority, initiator_config)?;
    assert_eq!(
        restarted.public_keys(),
        Err(AgentError::ExecutionUnavailable)
    );
    let (_, recovery_certificate) = signed_advance(
        incompatible_state,
        &migration,
        incompatible_state.posture(),
        MigrationSuiteSet::from_suites(&[HybridSuite::MlKem768X25519])?,
    )?;
    restarted.apply_advance(&recovery_certificate)?;
    assert!(restarted.public_keys().is_ok());
    Ok(())
}

#[test]
fn execution_policy_identity_can_advance_while_old_bundle_remains_blocked() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 6)?;
    let policy_v2_text = POLICY.replace("policy_version = 1", "policy_version = 2");
    let policy_v2 = policy_material_from_text(23, &policy_v2_text)?;
    let (_, certificate) = signed_advance_with_execution(
        pair.committed.state(),
        &pair.migration,
        policy_v2.authenticated.trusted_state(),
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.initiator.apply_advance(&certificate)?;
    assert_eq!(
        pair.initiator.public_keys(),
        Err(AgentError::ExecutionUnavailable)
    );

    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_repository_path,
        endpoint_policy_bundle,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();
    let repository = StateRepository::open_existing(&initiator_repository_path, migration.roots)?;
    let (_, initiator_vk) = MlDsa65::generate([51u8; 32]);
    let (_, responder_vk) = MlDsa65::generate([52u8; 32]);
    let updated_config = AgentConfig::new(
        AgentLimits::new(16, 16, Duration::from_secs(60))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([61u8; 32]), initiator_vk)?,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([62u8; 32]), responder_vk)?,
        policy_v2.bundle,
        endpoint_policy_bundle.clone(),
        endpoint_policy_bundle,
    )?;
    let restarted = PolicyAgent::new(repository, witness, initiator_authority, updated_config)?;
    assert!(restarted.public_keys().is_ok());
    Ok(())
}

#[test]
fn reset_cannot_rotate_to_an_unprovisioned_migration_authority() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 5)?;
    let current = pair.committed;
    let next = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: 2,
        chain_id: MigrationChainId::from_bytes([99u8; 32]),
        protocol_id: current.state().protocol_id(),
        epoch: 1,
        previous_state_digest: current.revision().digest(),
        authority_key_id: MigrationAuthorityKeyId::from_bytes([100u8; 32]),
        execution_policy_state: current.state().execution_policy_state(),
        posture: current.state().posture(),
        allowed_suites: current.state().allowed_suites(),
    })?;
    let reset = MigrationResetV1::new(
        current.revision(),
        next,
        MigrationResetNonce::from_bytes([101u8; 32]),
        MigrationAuthorityKeyId::from_bytes([32u8; 32]),
    );
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let signed = SignedMigrationResetV1::sign(
        reset,
        &MlDsa65,
        &pair.migration.recovery_signing_key,
        &[0u8; 32],
        &mut signature,
    )?;
    assert_eq!(
        pair.initiator.apply_reset(&signed.encode()?),
        Err(AgentError::Repository(
            crate::RepositoryError::UnprovisionedAuthority
        ))
    );
    assert_eq!(pair.witness.read_head()?, pair.committed_head()?);
    Ok(())
}

impl AgentPair {
    fn committed_head(&self) -> TestResult<StateHead> {
        let repository =
            StateRepository::open_existing(&self.old_snapshot_path, self.migration.roots.clone())?;
        repository.head().map_err(Into::into)
    }
}

#[test]
fn redb_lock_rejects_a_second_agent_repository_open() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let path = directory.join("repository.redb");
    let (repository, _) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    assert!(matches!(
        StateRepository::open_existing(&path, migration.roots),
        Err(crate::RepositoryError::CorruptStore)
    ));
    drop(repository);
    Ok(())
}

#[test]
fn abrupt_process_exit_after_durable_intent_reopens_and_reconciles_exact_operation() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let repository_path = directory.join("repository.redb");
    let certificate_path = directory.join("advance.cert");
    let (repository, head) = StateRepository::provision_new(
        &repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let current = repository.committed_state();
    drop(repository);
    let (_, certificate) = signed_advance(
        current.state(),
        &migration,
        current.state().posture(),
        current.state().allowed_suites(),
    )?;
    fs::write(&certificate_path, &certificate)?;
    fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o600))?;
    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("tests::crash_after_durable_intent_child")
        .current_dir(directory.path())
        .env("Q_PERIAPT_TEST_CRASH_INTENT", "1")
        .status()?;
    assert_eq!(status.code(), Some(86));

    let reopened = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
    let operation = reopened
        .pending_intent()
        .ok_or_else(|| io::Error::other("crash lost durable transition intent"))?
        .operation_id();
    let witness = MemoryWitness::new(head);
    let (_, local_vk) = MlDsa65::generate([51u8; 32]);
    let (_, peer_vk) = MlDsa65::generate([52u8; 32]);
    let config = AgentConfig::new(
        AgentLimits::new(8, 8, Duration::from_secs(30))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([61u8; 32]), local_vk)?,
        EndpointIdentity::new(MigrationIdentityKeyId::from_bytes([62u8; 32]), peer_vk)?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle,
    )?;
    let agent = PolicyAgent::new(reopened, witness.clone(), MemoryAuthority::new()?, config)?;
    agent.reconcile_transition()?;
    assert!(matches!(
        witness.query(operation)?,
        WitnessOutcome::Known(receipt) if receipt.disposition() == crate::WitnessDisposition::Applied
    ));
    Ok(())
}

#[test]
fn crash_after_durable_intent_child() -> TestResult {
    if std::env::var_os("Q_PERIAPT_TEST_CRASH_INTENT").is_none() {
        return Ok(());
    }
    let directory_path = std::env::current_dir()?;
    let repository_path = directory_path.join("repository.redb");
    let directory = OwnedPrivateDirectory::open(&directory_path)
        .map_err(|_| io::Error::other("crash test directory is not private"))?;
    let (_, authority_vk) = MlDsa65::generate([21u8; 32]);
    let (_, recovery_vk) = MlDsa65::generate([22u8; 32]);
    let roots = MigrationTrustRoots::new(
        MigrationAuthorityKeyId::from_bytes([31u8; 32]),
        authority_vk,
        MigrationAuthorityKeyId::from_bytes([32u8; 32]),
        recovery_vk,
    )?;
    let mut repository = StateRepository::open_existing(&repository_path, roots)?;
    let mut certificate_file = directory
        .open_config_file(
            "advance.cert",
            q_periapt_migration::MAX_MIGRATION_SIGNATURE_BYTES
                + q_periapt_migration::MAX_MIGRATION_RESET_BODY_BYTES
                + 16,
        )
        .map_err(|_| io::Error::other("crash certificate is not private"))?;
    let mut certificate = Vec::new();
    certificate_file.read_to_end(&mut certificate)?;
    repository.prepare_advance(&certificate)?;
    std::process::exit(86);
}

#[test]
fn second_instance_on_same_authority_is_fenced_at_construction() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 33)?;
    // No transition has happened, so the snapshot copy equals the live state
    // and only the instance lease separates the clone from the live holder.
    let clone_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let clone = PolicyAgent::new(
        clone_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    );
    assert!(matches!(clone, Err(AgentError::InstanceFenced)));
    // The live holder keeps its lease-guarded operations.
    let _live = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?;
    Ok(())
}

#[test]
fn expired_lease_successor_fences_out_live_instance_and_erases_secrets() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 34)?;
    let encapsulated =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let decapsulated =
        responder_decapsulation(pair.responder.begin_decapsulation(BeginDecapsulation::new(
            pair.responder_authorization.clone(),
            encapsulated.ciphertexts.clone(),
        ))?)?;
    let responder_acceptance = pair
        .responder
        .accept_initiator_finished(decapsulated.handle, encapsulated.initiator_finished)?;
    pair.initiator
        .accept_responder_finished(encapsulated.handle, responder_acceptance.responder_finished)?;
    assert_eq!(pair.initiator.acceptance_counts_for_test()?, (1, 1));

    // The holder's lease reaches witness-clock expiry; a successor clone
    // acquires the next generation over the identical migration state.
    pair.initiator_authority.expire_active_lease();
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let successor = PolicyAgent::new(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;

    // The superseded instance is fenced on its next guarded operation and
    // erases every in-process pending and accepted secret first.
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceFenced)
    ));
    assert_eq!(pair.initiator.acceptance_counts_for_test()?, (0, 0));
    // Fencing is permanent for this instance, even after the successor stops.
    successor.release_instance_lease()?;
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceFenced)
    ));
    Ok(())
}

#[test]
fn released_lease_is_idempotent_and_hands_over_without_ttl_wait() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 35)?;
    pair.initiator.release_instance_lease()?;
    pair.initiator.release_instance_lease()?;
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceFenced)
    ));
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let successor = PolicyAgent::new(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;
    successor.release_instance_lease()?;
    Ok(())
}

#[test]
fn lost_lease_responses_reconcile_by_exact_operation_query() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 36)?;
    // Advance the trusted clock so the next renewal strictly extends and is
    // Applied rather than short-circuited as not-extended.
    pair.initiator_authority.advance_clock(1_000);
    pair.initiator_authority.make_next_unknown();
    let _encapsulated = pair.initiator.begin_encapsulation(BeginEncapsulation::new(
        pair.initiator_authorization.clone(),
        pair.responder_public_keys.clone(),
    ))?;

    // A lost acquire response is likewise reconciled by the successor itself.
    pair.initiator.release_instance_lease()?;
    pair.initiator_authority.make_next_unknown();
    let successor_repository =
        StateRepository::open_existing(&pair.old_snapshot_path, pair.migration.roots.clone())?;
    let successor = PolicyAgent::new(
        successor_repository,
        pair.witness.clone(),
        pair.initiator_authority.clone(),
        pair.initiator_config.clone(),
    )?;
    successor.release_instance_lease()?;
    Ok(())
}

#[test]
fn concurrent_instances_race_to_exactly_one_lease() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 38)?;
    let AgentPair {
        initiator,
        responder,
        witness,
        initiator_authority,
        migration,
        initiator_config,
        initiator_repository_path,
        old_snapshot_path,
        ..
    } = pair;
    drop(initiator);
    drop(responder);
    initiator_authority.expire_active_lease();
    let repository_a =
        StateRepository::open_existing(&initiator_repository_path, migration.roots.clone())?;
    let repository_b = StateRepository::open_existing(&old_snapshot_path, migration.roots)?;
    let barrier = Arc::new(Barrier::new(2));
    let spawn_instance = |repository: StateRepository| {
        let witness = witness.clone();
        let authority = initiator_authority.clone();
        let config = initiator_config.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            PolicyAgent::new(repository, witness, authority, config).map(drop)
        })
    };
    let first = spawn_instance(repository_a);
    let second = spawn_instance(repository_b);
    let outcomes = [
        first.join().map_err(|_| io::Error::other("join failed"))?,
        second.join().map_err(|_| io::Error::other("join failed"))?,
    ];
    let acquired = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    let fenced = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Err(AgentError::InstanceFenced)))
        .count();
    assert_eq!((acquired, fenced), (1, 1));
    Ok(())
}
