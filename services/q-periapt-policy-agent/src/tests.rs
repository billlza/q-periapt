use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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
use redb::{Database, Durability, TableDefinition, TableHandle};

use crate::authentication::{sign_envelope, verify_envelope};
use crate::authority::{
    AuthorityDispositionV2, AuthorityEpochV2, AuthorityErrorV2, AuthorityIntentV2,
    AuthorityLimitsV2, AuthorityMutationV2, AuthorityQueryResultV2, AuthorityReceiptV2,
    AuthoritySnapshotV2, AuthorityStateV2, DeploymentConfigRevisionV2, InstanceFenceV2,
    OperationIdV2, ProcessInstanceIdV2, ReceiptAckDispositionV2, StateFenceV2, StateHeadV2,
    StateRevisionV2, TrustedClockErrorV2, TrustedClockV2,
};
use crate::authority_journal::DurableAuthorityOperation;
use crate::authority_protocol::{
    AuthorityClientIdV3, AuthorityKnownFailureV3, AuthorityOutcomeV3, AuthorityServerIdV3,
    AuthorityUnknownV3, AuthorityWireIdentityV3, DurablyRetainedAuthorityReceiptV3,
};
use crate::authority_store::AuthorityStoreV2;
use crate::authority_transport::{
    AuthenticatedTcpAuthorityV3, AuthorityServerProvisionV3, AuthorityTransportErrorV3,
    AuthorityTransportLimitsV3, InstanceAuthorityPort, ReferenceAuthorityServerV3,
};
use crate::codec::{
    encode_domain, read_frame, require_domain, write_frame, DeadlineStream, Decoder, Encoder,
    MAX_FRAME_BYTES,
};
use crate::crypto::{EncapsulationCiphertexts, EncapsulationPublicKeys};
use crate::filesystem::{open_private_file, OwnedPrivateDirectory, PrivateFileError};
use crate::repository::{MigrationTrustRoots, RepositoryError, StateRepository};
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
fn fixed_private_socket_is_bound_beneath_the_process_directory_capability() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new()?;
    let service_directory = directory.join("service");
    fs::create_dir(&service_directory)?;
    fs::set_permissions(&service_directory, fs::Permissions::from_mode(0o700))?;
    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("tests::private_socket_bind_child")
        .current_dir(directory.path())
        .env("Q_PERIAPT_TEST_SOCKET_BIND", "1")
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
fn private_socket_bind_child() -> TestResult {
    if std::env::var_os("Q_PERIAPT_TEST_SOCKET_BIND").is_none() {
        return Ok(());
    }
    let launch_directory = std::env::current_dir()?;
    let directory_path = launch_directory.join("service");
    let launch = OwnedPrivateDirectory::open(&launch_directory)
        .map_err(|_| io::Error::other("socket launch directory is not private"))?;
    let directory = OwnedPrivateDirectory::open(&directory_path)
        .map_err(|_| io::Error::other("socket test directory is not private"))?;
    let listener = crate::ipc::bind_private_socket(&directory)?;
    assert_eq!(std::env::current_dir()?, directory_path);
    assert!(directory.socket_is_protected(std::ffi::OsStr::new("agent.sock")));
    assert!(launch
        .require_absent(std::ffi::OsStr::new("agent.sock"))
        .is_ok());
    assert!(matches!(
        crate::ipc::bind_private_socket(&directory),
        Err(crate::ipc::IpcError::InsecureSocket)
    ));
    drop(listener);
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

fn join<T>(handle: thread::JoinHandle<T>) -> TestResult<T> {
    handle
        .join()
        .map_err(|_| io::Error::other("test worker panicked").into())
}

type RunningWitness = (
    SocketAddr,
    Arc<AtomicBool>,
    thread::JoinHandle<Result<(), WitnessError>>,
);

fn spawn_reference_witness(server: ReferenceWitnessServer) -> TestResult<RunningWitness> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let handle = thread::spawn(move || server.serve(listener, &server_shutdown));
    Ok((address, shutdown, handle))
}

type RunningAuthority = (
    SocketAddr,
    Arc<AtomicBool>,
    thread::JoinHandle<Result<(), crate::authority_transport::AuthorityServerErrorV3>>,
);

fn spawn_reference_authority(
    mut server: ReferenceAuthorityServerV3,
) -> TestResult<RunningAuthority> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let handle = thread::spawn(move || server.serve(listener, &server_shutdown));
    Ok((address, shutdown, handle))
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

fn framed_advance_request(
    signing_key: &[u8],
    nonce: [u8; 32],
    certificate: &[u8],
) -> TestResult<Vec<u8>> {
    let mut body = Encoder::new(MAX_FRAME_BYTES);
    encode_domain(&mut body, b"Q-PERIAPT-POLICY-AGENT-IPC-REQUEST/v2", 2)
        .map_err(|error| io::Error::other(format!("IPC domain encoding failed: {error:?}")))?;
    body.fixed(&nonce)
        .and_then(|()| body.byte(8))
        .and_then(|()| body.lp16(certificate))
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
    identity: AuthorityWireIdentityV3,
    now_millis: u64,
    unknown_after_apply: bool,
    unknown_advance_responses: usize,
    unknown_ack_responses: usize,
    unknown_query_responses: usize,
    next_absent_version: Option<u64>,
    expire_before_next_advance: bool,
    fail_next_identity_advance: bool,
}

fn map_memory_authority_failure(error: AuthorityErrorV2) -> AuthorityKnownFailureV3 {
    match error {
        AuthorityErrorV2::ClockUnavailable => AuthorityKnownFailureV3::ClockUnavailable,
        AuthorityErrorV2::OperationConflict => AuthorityKnownFailureV3::OperationConflict,
        AuthorityErrorV2::AuthorityVersionMismatch => {
            AuthorityKnownFailureV3::AuthorityVersionMismatch
        }
        AuthorityErrorV2::AuthorityVersionExhausted => {
            AuthorityKnownFailureV3::AuthorityVersionExhausted
        }
        AuthorityErrorV2::ReceiptCapacityExceeded => {
            AuthorityKnownFailureV3::ReceiptCapacityExceeded
        }
        _ => AuthorityKnownFailureV3::AllocationFailed,
    }
}

impl MemoryAuthority {
    fn with_head(head: StateHeadV2) -> TestResult<Self> {
        let config = DeploymentConfigRevisionV2::new(1, [45u8; 32])?;
        let authority = AuthorityStateV2::provision(
            head,
            config,
            AuthorityLimitsV2::new(64, 16, 16, MEMORY_AUTHORITY_LEASE_TTL_MILLIS)?,
            &FixedClock(MEMORY_AUTHORITY_EPOCH_MILLIS),
        )?;
        let identity = AuthorityWireIdentityV3::new(
            AuthorityClientIdV3::from_bytes([71u8; 32])?,
            AuthorityServerIdV3::from_bytes([72u8; 32])?,
            AuthorityEpochV2::from_bytes([73u8; 32])?,
            head,
            config,
        )?;
        Ok(Self {
            state: Arc::new(Mutex::new(MemoryAuthorityState {
                authority,
                identity,
                now_millis: MEMORY_AUTHORITY_EPOCH_MILLIS,
                unknown_after_apply: false,
                unknown_advance_responses: 0,
                unknown_ack_responses: 0,
                unknown_query_responses: 0,
                next_absent_version: None,
                expire_before_next_advance: false,
                fail_next_identity_advance: false,
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

    fn expire_active_lease(&self) {
        self.advance_clock(MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1);
    }

    fn make_next_unknown(&self) {
        self.lock().unknown_after_apply = true;
    }

    fn lose_next_advance_responses(&self, count: usize) {
        self.lock().unknown_advance_responses = count;
    }

    fn lose_next_ack_responses(&self, count: usize) {
        self.lock().unknown_ack_responses = count;
    }

    fn lose_next_query_responses(&self, count: usize) {
        self.lock().unknown_query_responses = count;
    }

    fn authority_version(&self) -> TestResult<u64> {
        let mut state = self.lock();
        let clock = FixedClock(state.now_millis);
        Ok(state.authority.snapshot(&clock)?.authority_version())
    }

    fn report_next_absent_version(&self, authority_version: u64) {
        self.lock().next_absent_version = Some(authority_version);
    }

    fn expire_before_next_advance(&self) {
        self.lock().expire_before_next_advance = true;
    }

    fn fail_next_identity_advance(&self) {
        self.lock().fail_next_identity_advance = true;
    }

    fn acquire_for_transition_recovery(
        &self,
        instance_id: ProcessInstanceIdV2,
    ) -> TestResult<InstanceFenceV2> {
        let mut state = self.lock();
        let clock = FixedClock(state.now_millis);
        let snapshot = state.authority.snapshot(&clock)?;
        let intent = AuthorityIntentV2::new(
            OperationIdV2::new(snapshot.authority_version(), [0xD0; 32])?,
            snapshot.authority_version(),
            state.identity.config(),
            AuthorityMutationV2::AcquireLease {
                expected_lease_generation: snapshot.lease_generation(),
                instance_id,
            },
        )?;
        let receipt = state.authority.apply(&clock, intent)?;
        if receipt.disposition() != AuthorityDispositionV2::Applied {
            return Err(io::Error::other("test transition lease was not acquired").into());
        }
        state.authority.acknowledge_receipt(receipt.locator())?;
        Ok(InstanceFenceV2::new(1, instance_id)?)
    }

    fn lease_call(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV3<AuthorityReceiptV2>, AuthorityTransportErrorV3> {
        let mut state = self.lock();
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.apply(&clock, intent) {
            Ok(receipt) => {
                if state.unknown_after_apply {
                    state.unknown_after_apply = false;
                    AuthorityOutcomeV3::Unknown(AuthorityUnknownV3::ResponseUnavailable)
                } else {
                    AuthorityOutcomeV3::Known(receipt)
                }
            }
            Err(error) => AuthorityOutcomeV3::KnownFailure(map_memory_authority_failure(error)),
        })
    }
}

fn authority_head_for(
    committed: CommittedMigrationStateV1,
    local_head: StateHead,
) -> TestResult<StateHeadV2> {
    let revision = committed.revision();
    if revision.global_generation() != local_head.revision().global_generation()
        || revision.epoch() != local_head.revision().epoch()
        || revision.digest().as_bytes() != local_head.revision().digest()
    {
        return Err(io::Error::other("test migration head projection mismatch").into());
    }
    Ok(StateHeadV2::new(
        StateRevisionV2::new(
            revision.global_generation(),
            *committed.state().chain_id().as_bytes(),
            revision.epoch(),
            *revision.digest().as_bytes(),
        )?,
        StateFenceV2::from_bytes(*local_head.fence().as_bytes())?,
    ))
}

fn encode_authority_head_file(head: StateHeadV2) -> [u8; 112] {
    let mut bytes = [0u8; 112];
    let revision = head.revision();
    bytes[0..8].copy_from_slice(&revision.global_generation().to_be_bytes());
    bytes[8..40].copy_from_slice(revision.chain_id());
    bytes[40..48].copy_from_slice(&revision.epoch().to_be_bytes());
    bytes[48..80].copy_from_slice(revision.digest());
    bytes[80..112].copy_from_slice(head.fence().as_bytes());
    bytes
}

fn encode_authority_config_file(config: DeploymentConfigRevisionV2) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[0..8].copy_from_slice(&config.generation().to_be_bytes());
    bytes[8..40].copy_from_slice(config.digest());
    bytes
}

fn write_private_config(path: &Path, bytes: &[u8]) -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

impl InstanceAuthorityPort for MemoryAuthority {
    fn wire_identity(&self) -> Result<AuthorityWireIdentityV3, AuthorityTransportErrorV3> {
        Ok(self.lock().identity)
    }

    fn advance_wire_identity(
        &self,
        expected: AuthorityWireIdentityV3,
        next: AuthorityWireIdentityV3,
    ) -> Result<(), AuthorityTransportErrorV3> {
        let mut state = self.lock();
        if state.fail_next_identity_advance {
            state.fail_next_identity_advance = false;
            return Err(AuthorityTransportErrorV3::InvalidConfiguration);
        }
        let clock = FixedClock(state.now_millis);
        let snapshot = state
            .authority
            .snapshot(&clock)
            .map_err(|_| AuthorityTransportErrorV3::InvalidConfiguration)?;
        if state.identity != expected
            || snapshot.state_head() != next.state_head()
            || expected.client_id() != next.client_id()
            || expected.server_id() != next.server_id()
            || expected.authority_epoch() != next.authority_epoch()
            || expected.config() != next.config()
        {
            return Err(AuthorityTransportErrorV3::InvalidConfiguration);
        }
        state.identity = next;
        Ok(())
    }

    fn snapshot(
        &self,
    ) -> Result<AuthorityOutcomeV3<AuthoritySnapshotV2>, AuthorityTransportErrorV3> {
        let mut state = self.lock();
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.snapshot(&clock) {
            Ok(snapshot) => AuthorityOutcomeV3::Known(snapshot),
            Err(error) => AuthorityOutcomeV3::KnownFailure(map_memory_authority_failure(error)),
        })
    }

    fn acquire(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV3<AuthorityReceiptV2>, AuthorityTransportErrorV3> {
        self.lease_call(intent)
    }

    fn renew(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV3<AuthorityReceiptV2>, AuthorityTransportErrorV3> {
        self.lease_call(intent)
    }

    fn release(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV3<AuthorityReceiptV2>, AuthorityTransportErrorV3> {
        self.lease_call(intent)
    }

    fn advance_state(
        &self,
        intent: AuthorityIntentV2,
    ) -> Result<AuthorityOutcomeV3<AuthorityReceiptV2>, AuthorityTransportErrorV3> {
        let force_unknown = {
            let mut state = self.lock();
            if state.expire_before_next_advance {
                state.expire_before_next_advance = false;
                state.now_millis = state
                    .now_millis
                    .saturating_add(MEMORY_AUTHORITY_LEASE_TTL_MILLIS + 1);
            }
            if state.unknown_advance_responses > 0 {
                state.unknown_advance_responses -= 1;
                true
            } else {
                false
            }
        };
        let outcome = self.lease_call(intent)?;
        if force_unknown {
            Ok(AuthorityOutcomeV3::Unknown(
                AuthorityUnknownV3::ResponseUnavailable,
            ))
        } else {
            Ok(outcome)
        }
    }

    fn query(
        &self,
        operation_id: OperationIdV2,
    ) -> Result<AuthorityOutcomeV3<AuthorityQueryResultV2>, AuthorityTransportErrorV3> {
        let mut state = self.lock();
        if state.unknown_query_responses > 0 {
            state.unknown_query_responses -= 1;
            return Ok(AuthorityOutcomeV3::Unknown(
                AuthorityUnknownV3::ResponseUnavailable,
            ));
        }
        if let Some(authority_version) = state.next_absent_version.take() {
            return Ok(AuthorityOutcomeV3::Known(
                AuthorityQueryResultV2::AbsentAtVersion { authority_version },
            ));
        }
        if let Some(receipt) = state.authority.receipt(operation_id) {
            return Ok(AuthorityOutcomeV3::Known(AuthorityQueryResultV2::Found(
                Box::new(receipt),
            )));
        }
        let clock = FixedClock(state.now_millis);
        Ok(match state.authority.snapshot(&clock) {
            Ok(snapshot) => AuthorityOutcomeV3::Known(AuthorityQueryResultV2::AbsentAtVersion {
                authority_version: snapshot.authority_version(),
            }),
            Err(error) => AuthorityOutcomeV3::KnownFailure(map_memory_authority_failure(error)),
        })
    }

    fn acknowledge(
        &self,
        retained: &DurablyRetainedAuthorityReceiptV3,
    ) -> Result<
        AuthorityOutcomeV3<crate::authority::ReceiptAckDispositionV2>,
        AuthorityTransportErrorV3,
    > {
        let mut state = self.lock();
        let outcome = match state.authority.acknowledge_receipt(retained.locator()) {
            Ok(disposition) => AuthorityOutcomeV3::Known(disposition),
            Err(_) => AuthorityOutcomeV3::KnownFailure(
                AuthorityKnownFailureV3::ReceiptAcknowledgementMismatch,
            ),
        };
        if state.unknown_ack_responses > 0 {
            state.unknown_ack_responses -= 1;
            Ok(AuthorityOutcomeV3::Unknown(
                AuthorityUnknownV3::ResponseUnavailable,
            ))
        } else {
            Ok(outcome)
        }
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
    let (server_sk, _) = MlDsa65::generate([92u8; 32]);
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
    initiator_public_keys: EncapsulationPublicKeys,
    responder_public_keys: EncapsulationPublicKeys,
}

fn agent_pair(directory: &TestDirectory, session_byte: u8) -> TestResult<AgentPair> {
    use std::os::unix::fs::PermissionsExt;

    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let initiator_repository_path = directory.join("initiator.redb");
    let responder_repository_path = directory.join("responder.redb");
    let old_snapshot_path = directory.join("old-snapshot.redb");
    let (mut initial_repository, head) = StateRepository::provision_new(
        &initiator_repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let committed = initial_repository.committed_state();
    let authority_head = authority_head_for(committed, head)?;
    let initiator_authority = MemoryAuthority::with_head(authority_head)?;
    let responder_authority = MemoryAuthority::with_head(authority_head)?;
    initial_repository.provision_authority_binding(initiator_authority.wire_identity()?)?;
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
    let limits = AgentLimits::new(16, 16, Duration::from_secs(60))?;
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
    let (server_signing_key, _) = MlDsa65::generate([94u8; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.responder,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
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
    let old_authority =
        MemoryAuthority::with_head(old_repository.authority_identity()?.state_head())?;
    // A fresh deployment authority isolates this assertion to the witness
    // rollback check; the shared-authority clone case is covered by the
    // dedicated instance-lease fencing tests.
    let rolled_back = PolicyAgent::new(
        old_repository,
        pair.witness,
        old_authority,
        pair.initiator_config,
    );
    assert!(matches!(rolled_back, Err(AgentError::RollbackOrFork)));
    Ok(())
}

#[test]
fn graceful_release_never_reconciles_an_advance_state_journal_slot() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 49)?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.initiator_authority.lose_next_advance_responses(32);
    pair.initiator_authority.lose_next_query_responses(32);
    assert_eq!(
        pair.initiator.apply_advance(&certificate),
        Err(AgentError::TransitionIndeterminate)
    );
    assert_eq!(
        pair.initiator.release_instance_lease(),
        Err(AgentError::TransitionPending)
    );

    pair.initiator_authority.lose_next_query_responses(0);
    pair.initiator.reconcile_transition()?;
    pair.initiator.release_instance_lease()?;
    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    drop(pair.initiator);
    let repository = StateRepository::open_existing(&repository_path, roots)?;
    assert_eq!(repository.pending_intent(), None);
    assert_eq!(repository.head()?, pair.witness.read_head()?);
    Ok(())
}

#[test]
fn transition_replaces_only_the_exact_lease_expiry_rejection() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 43)?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.initiator_authority.expire_before_next_advance();
    pair.initiator.apply_advance(&certificate)?;
    let expected_witness_head = pair.witness.read_head()?;
    let expected_authority_head = match pair.initiator_authority.snapshot()? {
        AuthorityOutcomeV3::Known(snapshot) => snapshot.state_head(),
        other => return Err(format!("expected authority snapshot, got {other:?}").into()),
    };
    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    drop(pair.initiator);
    let repository = StateRepository::open_existing(&repository_path, roots)?;
    assert_eq!(repository.pending_intent(), None);
    assert_eq!(repository.head()?, expected_witness_head);
    assert_eq!(
        repository.authority_identity()?.state_head(),
        expected_authority_head
    );
    Ok(())
}

#[test]
fn replacement_lease_prepared_and_resolved_crash_cuts_recover_exactly() -> TestResult {
    for (seed, commits_until_fault, resolved_cut) in [(46, 7, false), (47, 8, true)] {
        let directory = TestDirectory::new()?;
        let pair = agent_pair(&directory, seed)?;
        let (_, certificate) = signed_advance(
            pair.committed.state(),
            &pair.migration,
            pair.committed.state().posture(),
            pair.committed.state().allowed_suites(),
        )?;
        pair.initiator_authority.expire_before_next_advance();
        pair.initiator
            .fail_after_authority_journal_commits_for_test(commits_until_fault)?;
        assert_eq!(
            pair.initiator.apply_advance(&certificate),
            Err(AgentError::InternalPoisoned)
        );

        let repository_path = pair.initiator_repository_path.clone();
        let roots = pair.migration.roots.clone();
        let witness = pair.witness.clone();
        let authority = pair.initiator_authority.clone();
        let config = pair.initiator_config.clone();
        drop(pair.initiator);

        let repository = StateRepository::open_existing(&repository_path, roots.clone())?;
        let identity = repository.authority_identity()?;
        let durable = repository
            .durable_lease_operation(identity)?
            .ok_or_else(|| io::Error::other("replacement lease cut was not durable"))?;
        match durable {
            DurableAuthorityOperation::Prepared(intent) if !resolved_cut => {
                assert!(matches!(
                    intent.mutation(),
                    AuthorityMutationV2::AcquireLease { .. }
                ));
            }
            DurableAuthorityOperation::Resolved(receipt) if resolved_cut => {
                assert!(matches!(
                    receipt.intent().mutation(),
                    AuthorityMutationV2::AcquireLease { .. }
                ));
            }
            other => {
                return Err(format!("unexpected replacement lease crash cut: {other:?}").into());
            }
        }

        let restarted = match PolicyAgent::new(
            repository,
            witness.clone(),
            authority.clone(),
            config.clone(),
        ) {
            Ok(agent) if !resolved_cut => agent,
            Err(AgentError::InstanceFenced) if resolved_cut => {
                authority.expire_active_lease();
                let repository = StateRepository::open_existing(&repository_path, roots.clone())?;
                PolicyAgent::new(
                    repository,
                    witness.clone(),
                    authority.clone(),
                    config.clone(),
                )?
            }
            Ok(_) => {
                return Err(io::Error::other(
                    "resolved replacement lease was reused across process restart",
                )
                .into());
            }
            Err(error) => {
                return Err(format!("replacement lease recovery failed: {error:?}").into());
            }
        };
        restarted.release_instance_lease()?;
        drop(restarted);

        let repository = StateRepository::open_existing(&repository_path, roots)?;
        assert_eq!(repository.pending_intent(), None);
        assert_eq!(repository.head()?, witness.read_head()?);
        assert_eq!(
            repository.durable_lease_operation(repository.authority_identity()?)?,
            None
        );
    }
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
fn repository_v1_to_v3_migration_is_explicit_idempotent_and_has_no_open_fallback() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let path = directory.join("repository-migration.redb");
    let (repository, head) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    let authority =
        MemoryAuthority::with_head(authority_head_for(repository.committed_state(), head)?)?;
    let identity = authority.wire_identity()?;
    drop(repository);

    let file = open_private_file(&path, false)
        .map_err(|_| io::Error::other("legacy fixture path is not private"))?;
    let database = Database::builder().create_file(file)?;
    let mut transaction = database.begin_write()?;
    transaction.set_durability(Durability::Immediate);
    transaction.set_two_phase_commit(true);
    for table in [
        TableDefinition::<&str, &[u8]>::new("agent_authority_binding_v3"),
        TableDefinition::<&str, &[u8]>::new("agent_authority_active_v3"),
        TableDefinition::<&str, &[u8]>::new("agent_authority_checkpoint_v3"),
    ] {
        assert!(transaction.delete_table(table)?);
    }
    {
        let mut meta =
            transaction.open_table(TableDefinition::<&str, &[u8]>::new("agent_meta_v1"))?;
        meta.insert("schema", [0u8, 1].as_slice())?;
    }
    transaction.commit()?;
    drop(database);

    assert!(matches!(
        StateRepository::open_existing(&path, migration.roots.clone()),
        Err(RepositoryError::CorruptStore)
    ));
    StateRepository::migrate_v1_to_v3(&path, migration.roots.clone(), identity)?;
    StateRepository::migrate_v1_to_v3(&path, migration.roots.clone(), identity)?;
    let reopened = StateRepository::open_existing(&path, migration.roots)?;
    drop(reopened);
    Ok(())
}

#[test]
fn interrupted_fresh_v3_provisioning_has_an_exact_idempotent_finalize_path() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let path = directory.join("repository-unbound-v3.redb");
    let (repository, head) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    let authority =
        MemoryAuthority::with_head(authority_head_for(repository.committed_state(), head)?)?;
    let identity = authority.wire_identity()?;
    drop(repository);

    assert!(matches!(
        StateRepository::open_existing(&path, migration.roots.clone()),
        Err(RepositoryError::AuthorityBindingMismatch)
    ));
    StateRepository::finalize_unbound_v3_binding(&path, migration.roots.clone(), identity)?;
    StateRepository::finalize_unbound_v3_binding(&path, migration.roots.clone(), identity)?;
    let repository = StateRepository::open_existing(&path, migration.roots)?;
    assert_eq!(repository.authority_identity()?, identity);
    Ok(())
}

#[test]
fn v1_to_v3_migration_validates_sessions_before_any_schema_commit() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let path = directory.join("repository-migration-corrupt-session.redb");
    let (repository, head) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    let authority =
        MemoryAuthority::with_head(authority_head_for(repository.committed_state(), head)?)?;
    let identity = authority.wire_identity()?;
    drop(repository);

    let file = open_private_file(&path, false)
        .map_err(|_| io::Error::other("legacy fixture path is not private"))?;
    let database = Database::builder().create_file(file)?;
    let mut transaction = database.begin_write()?;
    transaction.set_durability(Durability::Immediate);
    transaction.set_two_phase_commit(true);
    for table in [
        TableDefinition::<&str, &[u8]>::new("agent_authority_binding_v3"),
        TableDefinition::<&str, &[u8]>::new("agent_authority_active_v3"),
        TableDefinition::<&str, &[u8]>::new("agent_authority_checkpoint_v3"),
    ] {
        assert!(transaction.delete_table(table)?);
    }
    {
        let mut meta =
            transaction.open_table(TableDefinition::<&str, &[u8]>::new("agent_meta_v1"))?;
        meta.insert("schema", [0u8, 1].as_slice())?;
        let mut sessions = transaction.open_table(TableDefinition::<&[u8], &[u8]>::new(
            "agent_session_reservations_v1",
        ))?;
        sessions.insert([1u8].as_slice(), [2u8].as_slice())?;
    }
    transaction.commit()?;
    drop(database);

    assert_eq!(
        StateRepository::migrate_v1_to_v3(&path, migration.roots, identity),
        Err(RepositoryError::CorruptStore)
    );
    let database =
        Database::builder().create_file(open_private_file(&path, false).map_err(|_| {
            io::Error::other("legacy fixture path is not private after rejected migration")
        })?)?;
    let read = database.begin_read()?;
    let meta = read.open_table(TableDefinition::<&str, &[u8]>::new("agent_meta_v1"))?;
    assert_eq!(
        meta.get("schema")?.map(|value| value.value().to_vec()),
        Some(vec![0, 1])
    );
    let table_names: Vec<_> = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect();
    assert!(!table_names
        .iter()
        .any(|name| name.starts_with("agent_authority_")));
    Ok(())
}

#[test]
fn executable_v3_migration_binds_the_actual_pristine_authority_epoch() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let repository_path = directory.join("repository-executable-migration.redb");
    let authority_path = directory.join("authority-executable-migration.redb");
    let config_path = directory.join("migration-config");
    fs::create_dir(&config_path)?;
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o700))?;

    let (repository, local_head) = StateRepository::provision_new(
        &repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let authority_head = authority_head_for(repository.committed_state(), local_head)?;
    let authority_config = DeploymentConfigRevisionV2::new(1, [0x45; 32])?;
    drop(repository);
    let authority_store = AuthorityStoreV2::provision(
        &authority_path,
        authority_head,
        authority_config,
        AuthorityLimitsV2::new(32, 8, 8, MEMORY_AUTHORITY_LEASE_TTL_MILLIS)?,
    )?;
    let actual_epoch = authority_store.authority_epoch();
    drop(authority_store);

    let file = open_private_file(&repository_path, false)
        .map_err(|_| io::Error::other("legacy fixture path is not private"))?;
    let database = Database::builder().create_file(file)?;
    let mut transaction = database.begin_write()?;
    transaction.set_durability(Durability::Immediate);
    transaction.set_two_phase_commit(true);
    for table in [
        TableDefinition::<&str, &[u8]>::new("agent_authority_binding_v3"),
        TableDefinition::<&str, &[u8]>::new("agent_authority_active_v3"),
        TableDefinition::<&str, &[u8]>::new("agent_authority_checkpoint_v3"),
    ] {
        assert!(transaction.delete_table(table)?);
    }
    {
        let mut meta =
            transaction.open_table(TableDefinition::<&str, &[u8]>::new("agent_meta_v1"))?;
        meta.insert("schema", [0u8, 1].as_slice())?;
    }
    transaction.commit()?;
    drop(database);

    let (_, migration_authority_vk) = MlDsa65::generate([21u8; 32]);
    let (_, recovery_authority_vk) = MlDsa65::generate([22u8; 32]);
    write_private_config(&config_path.join("migration-authority-id.bin"), &[31u8; 32])?;
    write_private_config(
        &config_path.join("migration-authority-vk.bin"),
        &migration_authority_vk,
    )?;
    write_private_config(&config_path.join("recovery-authority-id.bin"), &[32u8; 32])?;
    write_private_config(
        &config_path.join("recovery-authority-vk.bin"),
        &recovery_authority_vk,
    )?;
    write_private_config(&config_path.join("authority-client-id.bin"), &[71u8; 32])?;
    write_private_config(&config_path.join("authority-server-id.bin"), &[72u8; 32])?;
    write_private_config(
        &config_path.join("authority-state-head.bin"),
        &encode_authority_head_file(authority_head),
    )?;
    write_private_config(
        &config_path.join("authority-config.bin"),
        &encode_authority_config_file(authority_config),
    )?;
    write_private_config(&config_path.join("authority-epoch.bin"), &[0xEE; 32])?;

    let migration_arguments = || {
        vec![
            std::ffi::OsString::from("q-periapt-policy-agent"),
            std::ffi::OsString::from("migrate-agent-repository-v1-to-v3"),
            repository_path.clone().into_os_string(),
            authority_path.clone().into_os_string(),
            config_path.clone().into_os_string(),
        ]
    };
    assert_eq!(
        crate::ipc::run_from_arguments(migration_arguments()),
        Err(crate::ipc::IpcError::InvalidConfiguration)
    );
    assert!(!StateRepository::has_v3_storage_schema(&repository_path)?);

    write_private_config(
        &config_path.join("authority-epoch.bin"),
        actual_epoch.as_bytes(),
    )?;
    crate::ipc::run_from_arguments(migration_arguments())?;
    let migrated = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
    let identity = migrated.authority_identity()?;
    assert_eq!(identity.authority_epoch(), actual_epoch);
    assert_eq!(identity.state_head(), authority_head);
    drop(migrated);

    let mut used_authority = AuthorityStoreV2::open(&authority_path)?;
    let acquire = AuthorityIntentV2::new(
        OperationIdV2::new(1, [0xA7; 32])?,
        1,
        authority_config,
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([0xA8; 32])?,
        },
    )?;
    assert_eq!(
        used_authority.apply(acquire)?.disposition(),
        AuthorityDispositionV2::Applied
    );
    drop(used_authority);
    crate::ipc::run_from_arguments(migration_arguments())?;
    Ok(())
}

#[test]
fn real_tcp_authority_witness_and_repository_survive_advance_reset_and_restart() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let repository_path = directory.join("coordinator-agent.redb");
    let witness_path = directory.join("coordinator-witness.redb");
    let authority_path = directory.join("coordinator-authority.redb");
    let (mut repository, initial_head) = StateRepository::provision_new(
        &repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let initial_committed = repository.committed_state();
    let authority_head = authority_head_for(initial_committed, initial_head)?;
    let authority_config = DeploymentConfigRevisionV2::new(1, [0xC1; 32])?;

    let (_, witness_client_vk) = MlDsa65::generate([0xC2; 32]);
    let (witness_server_sk, witness_server_vk) = MlDsa65::generate([0xC3; 32]);
    let witness_server = ReferenceWitnessServer::provision(
        &witness_path,
        initial_head,
        witness_client_vk,
        ZeroizingBytes::from_bytes(witness_server_sk),
        Duration::from_secs(2),
    )?;
    let (_, authority_client_vk) = MlDsa65::generate([0xC4; 32]);
    let (authority_server_sk, authority_server_vk) = MlDsa65::generate([0xC5; 32]);
    let authority_server = ReferenceAuthorityServerV3::provision(
        &authority_path,
        AuthorityServerProvisionV3::new(
            AuthorityClientIdV3::from_bytes([0xC6; 32])?,
            AuthorityServerIdV3::from_bytes([0xC7; 32])?,
            authority_head,
            authority_config,
            AuthorityLimitsV2::new(64, 16, 16, MEMORY_AUTHORITY_LEASE_TTL_MILLIS)?,
        )?,
        authority_client_vk,
        ZeroizingBytes::from_bytes(authority_server_sk),
        AuthorityTransportLimitsV3::new(Duration::from_secs(2), Duration::from_secs(60), 64)?,
    )?;
    let bootstrap_identity = authority_server.identity();
    repository.provision_authority_binding(bootstrap_identity)?;

    let (_, local_identity_vk) = MlDsa65::generate([0xC8; 32]);
    let (_, peer_identity_vk) = MlDsa65::generate([0xC9; 32]);
    let config = AgentConfig::new(
        AgentLimits::new(16, 16, Duration::from_secs(60))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(
            MigrationIdentityKeyId::from_bytes([0xCA; 32]),
            local_identity_vk,
        )?,
        EndpointIdentity::new(
            MigrationIdentityKeyId::from_bytes([0xCB; 32]),
            peer_identity_vk,
        )?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle.clone(),
    )?;
    let (advanced_state, advance_certificate) = signed_advance(
        initial_committed.state(),
        &migration,
        initial_committed.state().posture(),
        initial_committed.state().allowed_suites(),
    )?;

    let (witness_address, witness_shutdown, witness_handle) =
        spawn_reference_witness(witness_server)?;
    let (authority_address, authority_shutdown, authority_handle) =
        spawn_reference_authority(authority_server)?;
    let first_phase = (|| -> TestResult {
        let (witness_client_sk, _) = MlDsa65::generate([0xC2; 32]);
        let witness = AuthenticatedTcpWitness::new(
            witness_address,
            ZeroizingBytes::from_bytes(witness_client_sk),
            witness_server_vk,
            Duration::from_secs(2),
        )?;
        let (authority_client_sk, _) = MlDsa65::generate([0xC4; 32]);
        let authority = AuthenticatedTcpAuthorityV3::new(
            authority_address,
            bootstrap_identity,
            ZeroizingBytes::from_bytes(authority_client_sk),
            authority_server_vk,
            Duration::from_secs(2),
        )?;
        let agent = PolicyAgent::new(repository, witness, authority, config.clone())?;
        agent.apply_advance(&advance_certificate)?;
        agent.release_instance_lease()?;
        Ok(())
    })();
    authority_shutdown.store(true, Ordering::Release);
    witness_shutdown.store(true, Ordering::Release);
    let authority_result = join(authority_handle)?;
    let witness_result = join(witness_handle)?;
    first_phase?;
    authority_result?;
    witness_result?;

    let repository = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
    let advanced_committed = repository.committed_state();
    let advanced_identity = repository.authority_identity()?;
    assert_eq!(advanced_committed.state(), advanced_state);
    drop(repository);

    let (_, witness_client_vk) = MlDsa65::generate([0xC2; 32]);
    let (witness_server_sk, witness_server_vk) = MlDsa65::generate([0xC3; 32]);
    let witness_server = ReferenceWitnessServer::open(
        &witness_path,
        witness_client_vk,
        ZeroizingBytes::from_bytes(witness_server_sk),
        Duration::from_secs(2),
    )?;
    let (_, authority_client_vk) = MlDsa65::generate([0xC4; 32]);
    let (authority_server_sk, authority_server_vk) = MlDsa65::generate([0xC5; 32]);
    let authority_server = ReferenceAuthorityServerV3::open(
        &authority_path,
        bootstrap_identity,
        authority_client_vk,
        ZeroizingBytes::from_bytes(authority_server_sk),
        AuthorityTransportLimitsV3::new(Duration::from_secs(2), Duration::from_secs(60), 64)?,
    )?;
    assert_eq!(authority_server.identity(), advanced_identity);

    let reset_state = MigrationStateV1::new(MigrationStateDraftV1 {
        global_generation: advanced_committed.state().global_generation() + 1,
        chain_id: MigrationChainId::from_bytes([0xCC; 32]),
        protocol_id: advanced_committed.state().protocol_id(),
        epoch: 1,
        previous_state_digest: advanced_committed.revision().digest(),
        authority_key_id: MigrationAuthorityKeyId::from_bytes([31u8; 32]),
        execution_policy_state: advanced_committed.state().execution_policy_state(),
        posture: advanced_committed.state().posture(),
        allowed_suites: advanced_committed.state().allowed_suites(),
    })?;
    let reset = MigrationResetV1::new(
        advanced_committed.revision(),
        reset_state,
        MigrationResetNonce::from_bytes([0xCD; 32]),
        MigrationAuthorityKeyId::from_bytes([32u8; 32]),
    );
    let mut reset_signature = [0u8; ML_DSA_65_SIG_LEN];
    let reset_certificate = SignedMigrationResetV1::sign(
        reset,
        &MlDsa65,
        &migration.recovery_signing_key,
        &[0u8; 32],
        &mut reset_signature,
    )?
    .encode()?;

    let (witness_address, witness_shutdown, witness_handle) =
        spawn_reference_witness(witness_server)?;
    let (authority_address, authority_shutdown, authority_handle) =
        spawn_reference_authority(authority_server)?;
    let second_phase = (|| -> TestResult {
        let (witness_client_sk, _) = MlDsa65::generate([0xC2; 32]);
        let witness = AuthenticatedTcpWitness::new(
            witness_address,
            ZeroizingBytes::from_bytes(witness_client_sk),
            witness_server_vk,
            Duration::from_secs(2),
        )?;
        let (authority_client_sk, _) = MlDsa65::generate([0xC4; 32]);
        let authority = AuthenticatedTcpAuthorityV3::new(
            authority_address,
            advanced_identity,
            ZeroizingBytes::from_bytes(authority_client_sk),
            authority_server_vk,
            Duration::from_secs(2),
        )?;
        let repository = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
        let agent = PolicyAgent::new(repository, witness, authority, config)?;
        assert!(agent.public_keys().is_ok());
        agent.apply_reset(&reset_certificate)?;
        agent.release_instance_lease()?;
        drop(agent);

        let repository = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
        let final_head = repository.head()?;
        let final_identity = repository.authority_identity()?;
        assert_eq!(repository.committed_state().state(), reset_state);
        drop(repository);
        let (witness_client_sk, _) = MlDsa65::generate([0xC2; 32]);
        let witness = AuthenticatedTcpWitness::new(
            witness_address,
            ZeroizingBytes::from_bytes(witness_client_sk),
            witness_server_vk,
            Duration::from_secs(2),
        )?;
        assert_eq!(witness.read_head()?, final_head);
        let (authority_client_sk, _) = MlDsa65::generate([0xC4; 32]);
        let authority = AuthenticatedTcpAuthorityV3::new(
            authority_address,
            final_identity,
            ZeroizingBytes::from_bytes(authority_client_sk),
            authority_server_vk,
            Duration::from_secs(2),
        )?;
        match authority.snapshot()? {
            AuthorityOutcomeV3::Known(snapshot) => {
                assert_eq!(snapshot.state_head(), final_identity.state_head());
                assert_eq!(snapshot.active_lease(), None);
            }
            other => return Err(format!("expected final authority snapshot, got {other:?}").into()),
        }
        Ok(())
    })();
    authority_shutdown.store(true, Ordering::Release);
    witness_shutdown.store(true, Ordering::Release);
    let authority_result = join(authority_handle)?;
    let witness_result = join(witness_handle)?;
    second_phase?;
    authority_result?;
    witness_result?;
    Ok(())
}

#[test]
fn real_tcp_restart_reconciles_authority_commit_after_lost_advance_response() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let repository_path = directory.join("lost-response-agent.redb");
    let witness_path = directory.join("lost-response-witness.redb");
    let authority_path = directory.join("lost-response-authority.redb");
    let (mut repository, initial_head) = StateRepository::provision_new(
        &repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let committed = repository.committed_state();
    let authority_head = authority_head_for(committed, initial_head)?;
    let authority_config = DeploymentConfigRevisionV2::new(1, [0xD1; 32])?;

    let (_, witness_client_vk) = MlDsa65::generate([0xD2; 32]);
    let (witness_server_sk, witness_server_vk) = MlDsa65::generate([0xD3; 32]);
    let witness_server = ReferenceWitnessServer::provision(
        &witness_path,
        initial_head,
        witness_client_vk,
        ZeroizingBytes::from_bytes(witness_server_sk),
        Duration::from_secs(1),
    )?;
    let (_, authority_client_vk) = MlDsa65::generate([0xD4; 32]);
    let (authority_server_sk, authority_server_vk) = MlDsa65::generate([0xD5; 32]);
    let mut authority_server = ReferenceAuthorityServerV3::provision(
        &authority_path,
        AuthorityServerProvisionV3::new(
            AuthorityClientIdV3::from_bytes([0xD6; 32])?,
            AuthorityServerIdV3::from_bytes([0xD7; 32])?,
            authority_head,
            authority_config,
            AuthorityLimitsV2::new(32, 8, 8, MEMORY_AUTHORITY_LEASE_TTL_MILLIS)?,
        )?,
        authority_client_vk,
        ZeroizingBytes::from_bytes(authority_server_sk),
        AuthorityTransportLimitsV3::new(Duration::from_secs(1), Duration::from_secs(60), 64)?,
    )?;
    authority_server.stop_after_next_advance_without_response_for_test();
    let bootstrap_identity = authority_server.identity();
    repository.provision_authority_binding(bootstrap_identity)?;

    let (_, local_identity_vk) = MlDsa65::generate([0xD8; 32]);
    let (_, peer_identity_vk) = MlDsa65::generate([0xD9; 32]);
    let config = AgentConfig::new(
        AgentLimits::new(8, 8, Duration::from_secs(30))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(
            MigrationIdentityKeyId::from_bytes([0xDA; 32]),
            local_identity_vk,
        )?,
        EndpointIdentity::new(
            MigrationIdentityKeyId::from_bytes([0xDB; 32]),
            peer_identity_vk,
        )?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle,
    )?;
    let (_, certificate) = signed_advance(
        committed.state(),
        &migration,
        committed.state().posture(),
        committed.state().allowed_suites(),
    )?;

    let (witness_address, witness_shutdown, witness_handle) =
        spawn_reference_witness(witness_server)?;
    let (authority_address, _, authority_handle) = spawn_reference_authority(authority_server)?;
    let (witness_client_sk, _) = MlDsa65::generate([0xD2; 32]);
    let witness = AuthenticatedTcpWitness::new(
        witness_address,
        ZeroizingBytes::from_bytes(witness_client_sk),
        witness_server_vk,
        Duration::from_secs(1),
    )?;
    let (authority_client_sk, _) = MlDsa65::generate([0xD4; 32]);
    let authority = AuthenticatedTcpAuthorityV3::new(
        authority_address,
        bootstrap_identity,
        ZeroizingBytes::from_bytes(authority_client_sk),
        authority_server_vk,
        Duration::from_secs(1),
    )?;
    let agent = PolicyAgent::new(repository, witness, authority, config.clone())?;
    assert_eq!(
        agent.apply_advance(&certificate),
        Err(AgentError::TransitionIndeterminate)
    );
    drop(agent);
    join(authority_handle)??;
    witness_shutdown.store(true, Ordering::Release);
    join(witness_handle)??;

    let repository = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
    let old_identity = repository.authority_identity()?;
    assert!(repository.coordinated_transition().is_some());
    assert_eq!(repository.head()?, initial_head);
    drop(repository);

    let (_, witness_client_vk) = MlDsa65::generate([0xD2; 32]);
    let (witness_server_sk, witness_server_vk) = MlDsa65::generate([0xD3; 32]);
    let witness_server = ReferenceWitnessServer::open(
        &witness_path,
        witness_client_vk,
        ZeroizingBytes::from_bytes(witness_server_sk),
        Duration::from_secs(1),
    )?;
    let (_, authority_client_vk) = MlDsa65::generate([0xD4; 32]);
    let (authority_server_sk, authority_server_vk) = MlDsa65::generate([0xD5; 32]);
    let authority_server = ReferenceAuthorityServerV3::open(
        &authority_path,
        bootstrap_identity,
        authority_client_vk,
        ZeroizingBytes::from_bytes(authority_server_sk),
        AuthorityTransportLimitsV3::new(Duration::from_secs(1), Duration::from_secs(60), 64)?,
    )?;
    assert_ne!(
        authority_server.identity().state_head(),
        old_identity.state_head()
    );
    let (witness_address, witness_shutdown, witness_handle) =
        spawn_reference_witness(witness_server)?;
    let (authority_address, authority_shutdown, authority_handle) =
        spawn_reference_authority(authority_server)?;
    let second_phase = (|| -> TestResult {
        let (witness_client_sk, _) = MlDsa65::generate([0xD2; 32]);
        let witness = AuthenticatedTcpWitness::new(
            witness_address,
            ZeroizingBytes::from_bytes(witness_client_sk),
            witness_server_vk,
            Duration::from_secs(1),
        )?;
        let (authority_client_sk, _) = MlDsa65::generate([0xD4; 32]);
        let authority = AuthenticatedTcpAuthorityV3::new(
            authority_address,
            old_identity,
            ZeroizingBytes::from_bytes(authority_client_sk),
            authority_server_vk,
            Duration::from_secs(1),
        )?;
        let repository = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
        let recovered = PolicyAgent::new(repository, witness, authority, config)?;
        assert!(recovered.public_keys().is_ok());
        recovered.release_instance_lease()?;
        drop(recovered);

        let repository = StateRepository::open_existing(&repository_path, migration.roots.clone())?;
        assert_eq!(repository.pending_intent(), None);
        let final_head = repository.head()?;
        let final_identity = repository.authority_identity()?;
        drop(repository);
        let (witness_client_sk, _) = MlDsa65::generate([0xD2; 32]);
        let witness = AuthenticatedTcpWitness::new(
            witness_address,
            ZeroizingBytes::from_bytes(witness_client_sk),
            witness_server_vk,
            Duration::from_secs(1),
        )?;
        assert_eq!(witness.read_head()?, final_head);
        let (authority_client_sk, _) = MlDsa65::generate([0xD4; 32]);
        let authority = AuthenticatedTcpAuthorityV3::new(
            authority_address,
            final_identity,
            ZeroizingBytes::from_bytes(authority_client_sk),
            authority_server_vk,
            Duration::from_secs(1),
        )?;
        match authority.snapshot()? {
            AuthorityOutcomeV3::Known(snapshot) => {
                assert_eq!(snapshot.state_head(), final_identity.state_head());
            }
            other => {
                return Err(
                    format!("expected reconciled authority snapshot, got {other:?}").into(),
                );
            }
        }
        Ok(())
    })();
    authority_shutdown.store(true, Ordering::Release);
    witness_shutdown.store(true, Ordering::Release);
    let authority_result = join(authority_handle)?;
    let witness_result = join(witness_handle)?;
    second_phase?;
    authority_result?;
    witness_result?;
    Ok(())
}

#[test]
fn authority_journal_commit_uncertainty_reopens_at_resolve_and_ack_cuts() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let path = directory.join("repository-lease-uncertain.redb");
    let (mut repository, head) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    let authority =
        MemoryAuthority::with_head(authority_head_for(repository.committed_state(), head)?)?;
    let identity = authority.wire_identity()?;
    repository.provision_authority_binding(identity)?;
    let snapshot = match authority.snapshot()? {
        AuthorityOutcomeV3::Known(snapshot) => snapshot,
        other => return Err(format!("expected authority snapshot, got {other:?}").into()),
    };
    let intent = AuthorityIntentV2::new(
        OperationIdV2::new(snapshot.authority_version(), [93u8; 32])?,
        snapshot.authority_version(),
        identity.config(),
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: snapshot.lease_generation(),
            instance_id: ProcessInstanceIdV2::from_bytes([94u8; 32])?,
        },
    )?;
    let receipt = AuthorityReceiptV2::restore(
        intent,
        AuthorityDispositionV2::Applied,
        intent.expected_authority_version() + 1,
    )
    .map_err(|_| io::Error::other("lease receipt fixture is invalid"))?;
    repository.prepare_lease_operation(identity, intent)?;
    repository.fail_after_next_authority_journal_commit_for_test();
    assert_eq!(
        repository.resolve_lease_operation(identity, intent, receipt),
        Err(RepositoryError::CommitUncertain)
    );
    assert_eq!(
        repository.durable_lease_operation(identity),
        Err(RepositoryError::RepositoryPoisoned)
    );
    drop(repository);

    let mut repository = StateRepository::open_existing(&path, migration.roots.clone())?;
    assert_eq!(
        repository.durable_lease_operation(identity)?,
        Some(DurableAuthorityOperation::Resolved(receipt))
    );
    let retained = DurablyRetainedAuthorityReceiptV3::after_repository_commit(receipt)?;
    repository.fail_after_next_authority_journal_commit_for_test();
    assert_eq!(
        repository.complete_lease_acknowledgement(
            identity,
            retained,
            ReceiptAckDispositionV2::AlreadyAbsent,
        ),
        Err(RepositoryError::CommitUncertain)
    );
    assert_eq!(
        repository.durable_lease_operation(identity),
        Err(RepositoryError::RepositoryPoisoned)
    );
    drop(repository);

    let repository = StateRepository::open_existing(&path, migration.roots)?;
    assert_eq!(repository.durable_lease_operation(identity)?, None);
    Ok(())
}

#[test]
fn abrupt_process_exit_after_lease_prepare_reopens_exact_slot() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let path = directory.join("repository-lease-crash.redb");
    let (mut repository, head) =
        StateRepository::provision_new(&path, &migration.genesis, migration.roots.clone())?;
    let authority =
        MemoryAuthority::with_head(authority_head_for(repository.committed_state(), head)?)?;
    repository.provision_authority_binding(authority.wire_identity()?)?;
    drop(repository);

    let status = Command::new(std::env::current_exe()?)
        .arg("--exact")
        .arg("tests::lease_prepare_crash_child")
        .current_dir(directory.path())
        .env("Q_PERIAPT_TEST_LEASE_PREPARE_CRASH", "1")
        .status()?;
    assert_eq!(status.code(), Some(87));

    let identity = authority.wire_identity()?;
    let snapshot = match authority.snapshot()? {
        AuthorityOutcomeV3::Known(snapshot) => snapshot,
        other => return Err(format!("expected authority snapshot, got {other:?}").into()),
    };
    let intent = AuthorityIntentV2::new(
        OperationIdV2::new(snapshot.authority_version(), [97u8; 32])?,
        snapshot.authority_version(),
        identity.config(),
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: snapshot.lease_generation(),
            instance_id: ProcessInstanceIdV2::from_bytes([98u8; 32])?,
        },
    )?;
    let mut repository = StateRepository::open_existing(&path, migration.roots)?;
    assert_eq!(
        repository.durable_lease_operation(identity)?,
        Some(DurableAuthorityOperation::Prepared(intent))
    );
    repository.cancel_prepared_lease_operation(identity, intent)?;
    Ok(())
}

#[test]
fn lease_prepare_crash_child() -> TestResult {
    if std::env::var_os("Q_PERIAPT_TEST_LEASE_PREPARE_CRASH").is_none() {
        return Ok(());
    }
    let path = std::env::current_dir()?.join("repository-lease-crash.redb");
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let mut repository = StateRepository::open_existing(&path, migration.roots)?;
    let identity = repository.authority_identity()?;
    let intent = AuthorityIntentV2::new(
        OperationIdV2::new(1, [97u8; 32])?,
        1,
        identity.config(),
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: 0,
            instance_id: ProcessInstanceIdV2::from_bytes([98u8; 32])?,
        },
    )?;
    repository.prepare_lease_operation(identity, intent)?;
    std::process::exit(87);
}

#[test]
fn abrupt_process_exit_after_durable_intent_reopens_and_reconciles_exact_operation() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let repository_path = directory.join("repository.redb");
    let certificate_path = directory.join("advance.cert");
    let (mut repository, head) = StateRepository::provision_new(
        &repository_path,
        &migration.genesis,
        migration.roots.clone(),
    )?;
    let current = repository.committed_state();
    let authority = MemoryAuthority::with_head(authority_head_for(current, head)?)?;
    repository.provision_authority_binding(authority.wire_identity()?)?;
    let recovery_instance = ProcessInstanceIdV2::from_bytes([0xD1; 32])?;
    assert_eq!(
        authority.acquire_for_transition_recovery(recovery_instance)?,
        InstanceFenceV2::new(1, recovery_instance)?
    );
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
    let _agent = PolicyAgent::new(reopened, witness.clone(), authority, config)?;
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
    repository.prepare_advance(
        &certificate,
        2,
        InstanceFenceV2::new(1, ProcessInstanceIdV2::from_bytes([0xD1; 32])?)?,
    )?;
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
fn reopen_reconciles_server_commit_after_client_prepared_state() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 39)?;
    pair.initiator.release_instance_lease()?;
    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    let witness = pair.witness.clone();
    let authority = pair.initiator_authority.clone();
    let config = pair.initiator_config.clone();
    drop(pair.initiator);

    let mut repository = StateRepository::open_existing(&repository_path, roots.clone())?;
    let identity = authority.wire_identity()?;
    repository.provision_authority_binding(identity)?;
    let snapshot = match authority.snapshot()? {
        AuthorityOutcomeV3::Known(snapshot) => snapshot,
        other => return Err(format!("expected authority snapshot, got {other:?}").into()),
    };
    let instance_id = ProcessInstanceIdV2::from_bytes([91u8; 32])?;
    let intent = AuthorityIntentV2::new(
        OperationIdV2::new(snapshot.authority_version(), [92u8; 32])?,
        snapshot.authority_version(),
        identity.config(),
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: snapshot.lease_generation(),
            instance_id,
        },
    )?;
    repository.prepare_lease_operation(identity, intent)?;
    authority.make_next_unknown();
    assert!(matches!(
        authority.acquire(intent)?,
        AuthorityOutcomeV3::Unknown(AuthorityUnknownV3::ResponseUnavailable)
    ));
    drop(repository);

    let repository = StateRepository::open_existing(&repository_path, roots.clone())?;
    assert!(matches!(
        PolicyAgent::new(
            repository,
            witness.clone(),
            authority.clone(),
            config.clone()
        ),
        Err(AgentError::InstanceFenced)
    ));
    authority.expire_active_lease();
    let repository = StateRepository::open_existing(&repository_path, roots)?;
    let reopened = PolicyAgent::new(repository, witness, authority, config)?;
    reopened.release_instance_lease()?;
    Ok(())
}

#[test]
fn recovery_rejects_a_regressed_absence_version_and_preserves_prepared_state() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 41)?;
    pair.initiator.release_instance_lease()?;
    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    let witness = pair.witness.clone();
    let authority = pair.initiator_authority.clone();
    let config = pair.initiator_config.clone();
    drop(pair.initiator);

    let mut repository = StateRepository::open_existing(&repository_path, roots.clone())?;
    let identity = authority.wire_identity()?;
    repository.provision_authority_binding(identity)?;
    let snapshot = match authority.snapshot()? {
        AuthorityOutcomeV3::Known(snapshot) => snapshot,
        other => return Err(format!("expected authority snapshot, got {other:?}").into()),
    };
    let intent = AuthorityIntentV2::new(
        OperationIdV2::new(snapshot.authority_version(), [95u8; 32])?,
        snapshot.authority_version(),
        identity.config(),
        AuthorityMutationV2::AcquireLease {
            expected_lease_generation: snapshot.lease_generation(),
            instance_id: ProcessInstanceIdV2::from_bytes([96u8; 32])?,
        },
    )?;
    repository.prepare_lease_operation(identity, intent)?;
    drop(repository);
    authority.report_next_absent_version(
        intent
            .expected_authority_version()
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("authority version cannot regress below one"))?,
    );

    let repository = StateRepository::open_existing(&repository_path, roots.clone())?;
    assert!(matches!(
        PolicyAgent::new(repository, witness, authority.clone(), config),
        Err(AgentError::InstanceLeaseUnavailable)
    ));
    let mut repository = StateRepository::open_existing(&repository_path, roots)?;
    assert_eq!(
        repository.durable_lease_operation(identity)?,
        Some(DurableAuthorityOperation::Prepared(intent))
    );
    repository.cancel_prepared_lease_operation(identity, intent)?;
    Ok(())
}

#[test]
fn reopen_terminalizes_resolved_receipt_after_lost_ack_responses() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 40)?;
    pair.initiator_authority.advance_clock(1_000);
    pair.initiator_authority.lose_next_ack_responses(2);
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InstanceLeaseIndeterminate)
    ));

    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    let witness = pair.witness.clone();
    let authority = pair.initiator_authority.clone();
    let config = pair.initiator_config.clone();
    drop(pair.initiator);
    let repository = StateRepository::open_existing(&repository_path, roots.clone())?;
    assert!(matches!(
        PolicyAgent::new(
            repository,
            witness.clone(),
            authority.clone(),
            config.clone()
        ),
        Err(AgentError::InstanceFenced)
    ));
    authority.expire_active_lease();
    let repository = StateRepository::open_existing(&repository_path, roots)?;
    let reopened = PolicyAgent::new(repository, witness, authority, config)?;
    reopened.release_instance_lease()?;
    Ok(())
}

#[test]
fn uncertain_pre_dispatch_journal_commit_poisoning_reopens_without_dispatch() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 37)?;
    let before = pair.initiator_authority.authority_version()?;
    pair.initiator
        .fail_after_next_authority_journal_commit_for_test()?;
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InternalPoisoned)
    ));
    assert_eq!(pair.initiator_authority.authority_version()?, before);
    assert!(matches!(
        pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        )),
        Err(AgentError::InternalPoisoned)
    ));

    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    let witness = pair.witness.clone();
    let authority = pair.initiator_authority.clone();
    let config = pair.initiator_config.clone();
    drop(pair.initiator);
    authority.expire_active_lease();
    let repository = StateRepository::open_existing(&repository_path, roots)?;
    let reopened = PolicyAgent::new(repository, witness, authority, config)?;
    reopened.release_instance_lease()?;
    Ok(())
}

#[test]
fn uncertain_transition_prepare_fatalizes_and_reopens_the_exact_pending_cut() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 50)?;
    let _pending =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.initiator
        .fail_after_authority_journal_commits_for_test(4)?;
    assert_eq!(
        pair.initiator.apply_advance(&certificate),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(pair.initiator.fatal_state_for_test()?, (true, 0, 0, true));

    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    let witness = pair.witness.clone();
    let authority = pair.initiator_authority.clone();
    let config = pair.initiator_config.clone();
    drop(pair.initiator);

    let repository = StateRepository::open_existing(&repository_path, roots.clone())?;
    let transition = repository
        .coordinated_transition()
        .ok_or_else(|| io::Error::other("uncertain T1 did not retain the transition"))?;
    assert_eq!(
        repository.durable_lease_operation(repository.authority_identity()?)?,
        Some(DurableAuthorityOperation::Prepared(
            transition.authority_intent()
        ))
    );
    let restarted = PolicyAgent::new(repository, witness.clone(), authority, config)?;
    restarted.release_instance_lease()?;
    drop(restarted);
    let repository = StateRepository::open_existing(&repository_path, roots)?;
    assert_eq!(repository.pending_intent(), None);
    assert_eq!(repository.head()?, witness.read_head()?);
    Ok(())
}

#[test]
fn ipc_fatal_poison_erases_runtime_secrets_and_releases_repository_lock() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 44)?;
    let _pending =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    pair.initiator
        .fail_after_next_authority_journal_commit_for_test()?;
    let (client_signing_key, client_verification_key) = MlDsa65::generate([0xB1; 32]);
    let (server_signing_key, _) = MlDsa65::generate([0xB2; 32]);
    let mut server = crate::ipc::UnixIpcServer::new_for_test(
        pair.initiator,
        client_verification_key,
        ZeroizingBytes::from_bytes(server_signing_key),
    )?;
    let mut transport = CaptureTransport {
        input: Cursor::new(framed_advance_request(
            &client_signing_key,
            [0xB3; 32],
            &certificate,
        )?),
        output: Vec::new(),
    };
    assert_eq!(
        server.handle_io_for_test(&mut transport),
        Err(crate::ipc::IpcError::AgentFatal)
    );
    assert!(transport.output.is_empty());
    assert_eq!(
        server.agent_for_test().fatal_state_for_test()?,
        (true, 0, 0, true)
    );
    assert!(matches!(
        StateRepository::open_existing(&repository_path, roots.clone()),
        Err(RepositoryError::CorruptStore)
    ));
    drop(server);
    let reopened = StateRepository::open_existing(&repository_path, roots)?;
    assert_eq!(reopened.restart_rejections(), 1);
    Ok(())
}

#[test]
fn post_commit_wire_identity_failure_fatalizes_and_erases_runtime_secrets() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 48)?;
    let _pending =
        initiator_encapsulation(pair.initiator.begin_encapsulation(BeginEncapsulation::new(
            pair.initiator_authorization.clone(),
            pair.responder_public_keys.clone(),
        ))?)?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    let witness = pair.witness.clone();
    let authority = pair.initiator_authority.clone();
    authority.fail_next_identity_advance();

    assert_eq!(
        pair.initiator.apply_advance(&certificate),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(pair.initiator.fatal_state_for_test()?, (true, 0, 0, true));
    assert!(matches!(
        pair.initiator.public_keys(),
        Err(AgentError::InternalPoisoned)
    ));
    drop(pair.initiator);

    let repository = StateRepository::open_existing(&repository_path, roots)?;
    assert_eq!(repository.pending_intent(), None);
    assert_eq!(repository.head()?, witness.read_head()?);
    let durable_identity = repository.authority_identity()?;
    assert_ne!(authority.wire_identity()?, durable_identity);
    match authority.snapshot()? {
        AuthorityOutcomeV3::Known(snapshot) => {
            assert_eq!(snapshot.state_head(), durable_identity.state_head());
        }
        other => {
            return Err(format!("expected committed authority snapshot, got {other:?}").into())
        }
    }
    Ok(())
}

#[test]
fn uncertain_local_transition_commit_reopens_at_the_committed_three_domain_head() -> TestResult {
    let directory = TestDirectory::new()?;
    let pair = agent_pair(&directory, 45)?;
    let (_, certificate) = signed_advance(
        pair.committed.state(),
        &pair.migration,
        pair.committed.state().posture(),
        pair.committed.state().allowed_suites(),
    )?;
    pair.initiator
        .fail_after_authority_journal_commits_for_test(7)?;
    assert_eq!(
        pair.initiator.apply_advance(&certificate),
        Err(AgentError::InternalPoisoned)
    );
    assert_eq!(pair.initiator.fatal_state_for_test()?, (true, 0, 0, true));
    let repository_path = pair.initiator_repository_path.clone();
    let roots = pair.migration.roots.clone();
    let witness = pair.witness.clone();
    let authority = pair.initiator_authority.clone();
    let config = pair.initiator_config.clone();
    drop(pair.initiator);

    let repository = StateRepository::open_existing(&repository_path, roots.clone())?;
    assert_eq!(repository.pending_intent(), None);
    assert_eq!(repository.head()?, witness.read_head()?);
    let durable_identity = repository.authority_identity()?;
    match authority.snapshot()? {
        AuthorityOutcomeV3::Known(snapshot) => {
            assert_eq!(snapshot.state_head(), durable_identity.state_head());
            assert_eq!(snapshot.active_lease(), None);
        }
        other => return Err(format!("expected authority snapshot, got {other:?}").into()),
    }
    let stale_process_identity = authority.wire_identity()?;
    authority.advance_wire_identity(stale_process_identity, durable_identity)?;
    let restarted = PolicyAgent::new(repository, witness, authority, config)?;
    assert!(restarted.public_keys().is_ok());
    restarted.release_instance_lease()?;
    Ok(())
}

#[test]
fn startup_rejects_unjournaled_authority_head_advance_before_any_new_mutation() -> TestResult {
    let directory = TestDirectory::new()?;
    let policy = policy_material(20)?;
    let migration = migration_material(&policy.authenticated)?;
    let repository_path = directory.join("startup-authority-mismatch.redb");
    let (mut repository, local_head) =
        StateRepository::provision_new(&repository_path, &migration.genesis, migration.roots)?;
    let authority_head = authority_head_for(repository.committed_state(), local_head)?;
    let authority = MemoryAuthority::with_head(authority_head)?;
    let old_identity = authority.wire_identity()?;
    repository.provision_authority_binding(old_identity)?;
    let fence =
        authority.acquire_for_transition_recovery(ProcessInstanceIdV2::from_bytes([0xE1; 32])?)?;
    let next_head = StateHeadV2::new(
        StateRevisionV2::new(2, *authority_head.revision().chain_id(), 2, [0xE2; 32])?,
        StateFenceV2::from_bytes([0xE3; 32])?,
    );
    let intent = AuthorityIntentV2::new(
        OperationIdV2::new(2, [0xE4; 32])?,
        2,
        old_identity.config(),
        AuthorityMutationV2::AdvanceState {
            fence,
            advance: crate::authority::StateAdvanceV2::new(
                crate::authority::StateTransitionKindV2::Advance,
                authority_head,
                next_head,
            )?,
        },
    )?;
    assert!(matches!(
        authority.advance_state(intent)?,
        AuthorityOutcomeV3::Known(receipt)
            if receipt.disposition() == AuthorityDispositionV2::Applied
    ));
    let version_before = authority.authority_version()?;
    let (_, local_identity_vk) = MlDsa65::generate([0xE5; 32]);
    let (_, peer_identity_vk) = MlDsa65::generate([0xE6; 32]);
    let config = AgentConfig::new(
        AgentLimits::new(8, 8, Duration::from_secs(30))?,
        EndpointRole::Initiator,
        EndpointIdentity::new(
            MigrationIdentityKeyId::from_bytes([0xE7; 32]),
            local_identity_vk,
        )?,
        EndpointIdentity::new(
            MigrationIdentityKeyId::from_bytes([0xE8; 32]),
            peer_identity_vk,
        )?,
        policy.bundle.clone(),
        policy.bundle.clone(),
        policy.bundle,
    )?;
    assert!(matches!(
        PolicyAgent::new(
            repository,
            MemoryWitness::new(local_head),
            authority.clone(),
            config
        ),
        Err(AgentError::RollbackOrFork)
    ));
    assert_eq!(authority.authority_version()?, version_before);
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
