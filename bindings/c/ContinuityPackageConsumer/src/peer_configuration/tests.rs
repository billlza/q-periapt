use super::*;
use crate::native_fixture as fixture;
use std::{fs, path::Path};
type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn diagnostic() -> ErrorRecord {
    ErrorRecord {
        code: 0,
        length: 0,
        truncated: 0,
        message: [0; 512],
    }
}
fn finish(handle: u64, error: &mut ErrorRecord) -> i32 {
    // SAFETY: exclusive live diagnostic, with no overlapping input buffers.
    unsafe { opening::qpc_owner_v1_finish_open(handle, error) }
}
fn close(handle: u64, error: &mut ErrorRecord) -> i32 {
    // SAFETY: exclusive live diagnostic, with no overlapping input buffers.
    unsafe { qpc_owner_v1_close(handle, error) }
}
fn cancel(handle: u64, error: &mut ErrorRecord) -> i32 {
    // SAFETY: exclusive live diagnostic, with no overlapping input buffers.
    unsafe { qpc_owner_v1_cancel(handle, error) }
}
fn checked(code: i32, error: &ErrorRecord) -> TestResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "native status {code}: {}",
            String::from_utf8_lossy(&error.message)
        )
        .into())
    }
}
struct Account {
    root: Vec<u8>,
    account: [u8; 32],
    family: [u8; 32],
    version: u64,
    digest: [u8; 32],
    device: [u8; 16],
    generation: u64,
}
impl Account {
    fn load(path: &Path, prefix: &str) -> TestResult<Self> {
        Ok(Self {
            root: fixture::read(path, &format!("{prefix}-root"), p::PUBLIC_KEY_BYTES)?,
            account: fixture::array(path, &format!("{prefix}-account"))?,
            family: fixture::array(path, "family")?,
            version: u64::from_be_bytes(fixture::array(path, &format!("{prefix}-roster-version"))?),
            digest: fixture::array(path, &format!("{prefix}-roster-digest"))?,
            device: fixture::array(path, &format!("{prefix}-device"))?,
            generation: u64::from_be_bytes(fixture::array(path, &format!("{prefix}-generation"))?),
        })
    }
    fn input(&self) -> ExpectedDeviceInput {
        ExpectedDeviceInput {
            account: enrollment::Pin {
                account: self.account,
                root: self.root.as_ptr(),
                root_length: self.root.len(),
                family: self.family,
                checkpoint: enrollment::Checkpoint {
                    version: self.version,
                    digest: self.digest,
                },
            },
            device: self.device,
            generation: self.generation,
        }
    }
}
struct Materials {
    initiator: Account,
    responder: Account,
    directory: [u8; 32],
    bundle: Vec<u8>,
    certificate: Vec<u8>,
    name: Vec<u8>,
}
fn blob(value: &[u8]) -> Blob {
    Blob {
        data: value.as_ptr(),
        length: value.len(),
    }
}
impl Materials {
    fn load(path: &Path) -> TestResult<Self> {
        Ok(Self {
            initiator: Account::load(path, "initiator")?,
            responder: Account::load(path, "responder")?,
            directory: fixture::array(path, "directory")?,
            bundle: fixture::read(path, "bootstrap.bundle", p::MAX_BOOTSTRAP_BUNDLE_BYTES)?,
            certificate: fixture::read(path, "tls-peer", 8192)?,
            name: fixture::read(path, "tls-peer-name", 128)?,
        })
    }
    fn input(&self) -> TestResult<Input> {
        Ok(Input {
            header: Header {
                struct_size: u32::try_from(std::mem::size_of::<Input>())?,
                version: 1,
            },
            quality: 1,
            role: 1,
            initiator: self.initiator.input(),
            responder: self.responder.input(),
            directory: self.directory,
            bundle: blob(&self.bundle),
            tls_peer: blob(&self.certificate),
            tls_name: blob(&self.name),
        })
    }
}
fn parent(path: &Path) -> TestResult<u64> {
    let path = path.to_str().ok_or("UTF-8 parent")?.as_bytes();
    let options = opening::Options {
        kind: 3,
        quality: 0,
        carrier: 0,
        witness: std::ptr::null(),
    };
    let mut handle = 0;
    let mut error = diagnostic();
    // SAFETY: exact live independent immutable inputs and writable outputs.
    unsafe {
        checked(
            opening::qpc_owner_v1_prepare_open(
                path.as_ptr(),
                path.len(),
                &options,
                &mut handle,
                &mut error,
            ),
            &error,
        )?;
    }
    checked(finish(handle, &mut error), &error)?;
    Ok(handle)
}
fn remove_peer_files(path: &Path) -> TestResult<()> {
    for prefix in ["initiator", "responder"] {
        for leaf in [
            "root",
            "account",
            "roster-version",
            "roster-digest",
            "device",
            "generation",
        ] {
            fs::remove_file(path.join(format!("{prefix}-{leaf}")))?;
        }
    }
    for name in ["bootstrap.bundle", "directory", "tls-peer", "tls-peer-name"] {
        fs::remove_file(path.join(name))?;
    }
    Ok(())
}

#[test]
fn configured_peer_header_and_input_refusals_precede_parent_lookup() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let short = 4u32;
    let mut output = 99;
    let mut error = diagnostic();
    unsafe {
        assert_eq!(
            qpc_peer_v1_prepare_configured(
                0,
                std::ptr::from_ref(&short).cast(),
                &mut output,
                &mut error
            ),
            1
        );
        assert_eq!(output, 0);
        output = 99;
        assert_eq!(
            qpc_peer_v1_prepare_configured_reopen(
                0,
                std::ptr::from_ref(&short).cast(),
                std::ptr::null(),
                &mut output,
                &mut error
            ),
            1
        );
        assert_eq!(output, 0);
    }
    let fixture = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let values = Materials::load(&fixture.initiator)?;
    let mut input = values.input()?;
    input.header.version = 2;
    unsafe {
        assert_eq!(
            qpc_peer_v1_prepare_configured(0, &input, &mut output, &mut error),
            1
        );
    }
    input.header.version = 1;
    input.quality = 0;
    unsafe {
        assert_eq!(
            qpc_peer_v1_prepare_configured(0, &input, &mut output, &mut error),
            1
        );
    }
    input.quality = 1;
    input.role = 0;
    unsafe {
        assert_eq!(
            qpc_peer_v1_prepare_configured(0, &input, &mut output, &mut error),
            1
        );
    }
    input.role = 1;
    input.bundle.length = p::MAX_BOOTSTRAP_BUNDLE_BYTES + 1;
    unsafe {
        assert_eq!(
            qpc_peer_v1_prepare_configured(0, &input, &mut output, &mut error),
            1
        );
    }
    input.bundle = blob(&values.bundle);
    unsafe {
        assert_eq!(
            qpc_peer_v1_prepare_configured_reopen(
                0,
                &input,
                [0; 32].as_ptr(),
                &mut output,
                &mut error
            ),
            1
        );
        assert_eq!(output, 0);
    }
    assert!(TABLE.lock().map_err(|_| "table")?.slots.is_empty());
    Ok(())
}

#[test]
fn configured_peer_copies_inputs_without_peer_files_and_parent_close_releases_leases(
) -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let fixture = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let mut values = Materials::load(&fixture.initiator)?;
    let parent = parent(&fixture.initiator)?;
    let input = values.input()?;
    let mut error = diagnostic();
    let mut peer = 0;
    unsafe {
        checked(
            qpc_peer_v1_prepare_configured(parent, &input, &mut peer, &mut error),
            &error,
        )?;
    }
    values.initiator.root.fill(0);
    values.responder.root.fill(0);
    values.bundle.fill(0);
    values.certificate.fill(0);
    values.name.fill(0);
    remove_peer_files(&fixture.initiator)?;
    checked(finish(peer, &mut error), &error)?;
    // A real context exists under this parent; no request buffer or peer path survived.
    with_entry(peer, Instant::now() + invocation::TIMEOUT, |slot, _| {
        let value = match slot.as_ref() {
            Some(Owned::Peer(peer)) => peer,
            _ => return Err(Failure::argument()),
        };
        assert!(value.belongs_to(&device::parent(
            parent,
            Instant::now() + invocation::TIMEOUT
        )?));
        Ok(())
    })
    .map_err(|e| format!("peer context: {}", e.message))?;
    checked(close(parent, &mut error), &error)?;
    let mut id = [0; 32];
    unsafe {
        assert_eq!(
            qpc_owner_v1_next_message(peer, [3; 32].as_ptr(), &mut id, &mut error),
            2
        );
    }
    // Explicit parent close releases its actual store even while the child is retained.
    let reopened = self::parent(&fixture.initiator)?;
    checked(close(reopened, &mut error), &error)?;
    checked(close(peer, &mut error), &error)?;
    assert!(TABLE.lock().map_err(|_| "table")?.slots.is_empty());
    Ok(())
}

#[test]
fn configured_peer_scope_failures_cancel_and_quota_preserve_original_parent() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry")?;
    let fixture = fixture::setup(fixture::enrollment::SetupKind::Installed)?;
    let values = Materials::load(&fixture.initiator)?;
    let parent = parent(&fixture.initiator)?;
    let mut error = diagnostic();
    for wrong in 0..8 {
        let mut input = values.input()?;
        match wrong {
            0 => input.initiator.device = [200; 16],
            1 => input.directory = [201; 32],
            2 => input.role = 2,
            3 => input.responder.account.checkpoint.version += 1,
            4 => input.responder.generation += 1,
            5 => {
                input.initiator.account.family = [203; 32];
                input.responder.account.family = [203; 32];
            }
            6 => input.tls_peer = blob(b"malformed certificate"),
            _ => input.tls_name = blob(b"invalid name with spaces"),
        }
        let mut peer = 0;
        unsafe {
            checked(
                qpc_peer_v1_prepare_configured(parent, &input, &mut peer, &mut error),
                &error,
            )?;
        }
        let expected = match wrong {
            0 | 1 | 4 | 5 => 103,
            2 => 211,
            3 => 105,
            6 => 309,
            _ => 0,
        };
        assert_eq!(finish(peer, &mut error), expected, "case {wrong}");
        assert_eq!(error.code, expected);
        if wrong == 7 {
            // The shared TLS engine validates the DNS name at connection time,
            // after admitting its DER configuration. Exercise that boundary.
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
            let address = listener.local_addr()?.to_string();
            let mut session = [99; 32];
            let mut exchanges = 99;
            unsafe {
                assert_eq!(
                    qpc_owner_v1_establish(
                        peer,
                        address.as_ptr(),
                        address.len(),
                        [211; 32].as_ptr(),
                        &mut session,
                        &mut exchanges,
                        &mut error,
                    ),
                    309,
                );
            }
            assert_eq!(session, [0; 32]);
            assert_eq!(exchanges, 0);
            // Failure need not mean no durable initiation was reserved. This
            // assertion only denies a successful session/traffic result.
        }
        checked(close(peer, &mut error), &error)?;
    }
    let input = values.input()?;
    let mut pending = Vec::new();
    for _ in 0..MAX_OWNERS - 1 {
        let mut peer = 0;
        unsafe {
            checked(
                qpc_peer_v1_prepare_configured(parent, &input, &mut peer, &mut error),
                &error,
            )?;
        }
        pending.push(peer);
    }
    let mut overflow = 99;
    unsafe {
        assert_eq!(
            qpc_peer_v1_prepare_configured(parent, &input, &mut overflow, &mut error),
            4
        );
    }
    assert_eq!(overflow, 0);
    for peer in pending {
        checked(cancel(peer, &mut error), &error)?;
        assert_eq!(finish(peer, &mut error), 302);
        checked(close(peer, &mut error), &error)?;
    }
    let mut peer = 0;
    unsafe {
        checked(
            qpc_peer_v1_prepare_configured(parent, &input, &mut peer, &mut error),
            &error,
        )?;
    }
    checked(finish(peer, &mut error), &error)?;
    checked(close(peer, &mut error), &error)?;
    checked(close(parent, &mut error), &error)?;
    assert!(TABLE.lock().map_err(|_| "table")?.slots.is_empty());
    Ok(())
}
