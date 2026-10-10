// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn native<T>(result: Result<T>) -> TestResult<T> {
    result.map_err(|error| format!("foreign error {}: {}", error.code, error.message).into())
}
fn diagnostic() -> ErrorRecord {
    ErrorRecord {
        code: 0,
        length: 0,
        truncated: 0,
        message: [0; 512],
    }
}
fn checked(code: i32, error: &ErrorRecord) -> TestResult<()> {
    if code == 0 {
        return Ok(());
    }
    let message = error
        .message
        .get(..usize::try_from(error.length)?)
        .ok_or("diagnostic length")?;
    Err(format!("foreign error {code}: {}", String::from_utf8_lossy(message)).into())
}
struct Handle(u64);
impl Handle {
    fn close(&mut self) -> TestResult<()> {
        let mut error = diagnostic();
        // SAFETY: exclusive diagnostic and this test's original idle handle.
        checked(unsafe { qpc_owner_v1_close(self.0, &mut error) }, &error)?;
        self.0 = 0;
        Ok(())
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            let mut error = diagnostic();
            // SAFETY: test-owned idle handle; no concurrent call outlives the guard.
            assert_eq!(unsafe { qpc_owner_v1_close(self.0, &mut error) }, 0);
        }
    }
}
struct Registry {
    handle: Handle,
    _dir: tempfile::TempDir,
    path: PathBuf,
    _public: Vec<u8>,
    options: Options,
}
fn directory() -> TestResult<tempfile::TempDir> {
    Ok(tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?)
}
impl Registry {
    fn new() -> TestResult<Self> {
        let dir = directory()?;
        let path = dir.path().canonicalize()?;
        let wire = path.to_str().ok_or("path")?.as_bytes();
        let witness = p::AnchorSigningKey::generate()?;
        let public = witness.public_key()?.encode();
        let options = Options {
            struct_size: u32::try_from(std::mem::size_of::<Options>())?,
            identity: *p::AccountAuthorityIdentity::generate()?.as_bytes(),
            family: [229; 32],
            witness: *p::AnchorIdentity::generate()?.as_bytes(),
            public_key: public.as_ptr(),
            public_key_length: public.len(),
        };
        let mut error = diagnostic();
        let mut handle = Handle(0);
        // SAFETY: caller buffers live through each synchronous invocation and do not overlap.
        unsafe {
            checked(
                qpc_authority_v1_provision_wrapping_key(wire.as_ptr(), wire.len(), &mut error),
                &error,
            )?;
            checked(
                qpc_authority_v1_prepare_create(
                    wire.as_ptr(),
                    wire.len(),
                    &options,
                    &mut handle.0,
                    &mut error,
                ),
                &error,
            )?;
            assert!(
                !path.join(STORE).exists(),
                "preparation performs no storage I/O"
            );
            checked(
                opening::qpc_owner_v1_finish_open(handle.0, &mut error),
                &error,
            )?;
        }
        Ok(Self {
            handle,
            _dir: dir,
            path,
            _public: public,
            options,
        })
    }
    fn reopen(&mut self) -> TestResult<()> {
        let wire = self.path.to_str().ok_or("path")?.as_bytes();
        let mut error = diagnostic();
        // SAFETY: retained independent original options and exclusive outputs.
        unsafe {
            checked(
                qpc_authority_v1_prepare_open(
                    wire.as_ptr(),
                    wire.len(),
                    &self.options,
                    &mut self.handle.0,
                    &mut error,
                ),
                &error,
            )?;
            checked(
                opening::qpc_owner_v1_finish_open(self.handle.0, &mut error),
                &error,
            )
        }
    }
    fn associate(&self, export: Option<&Path>) -> TestResult<(Checkpoint, Vec<u8>, p::Validity)> {
        let root = p::RootSigningKey::generate()?;
        let signer = p::DeviceSigningKey::generate()?;
        let now = owner::now()?;
        let validity = p::Validity::new(
            now.checked_sub(1).ok_or("clock")?,
            now.checked_add(1800).ok_or("clock")?,
        )?;
        let certificate = root.issue_device(
            p::DeviceDescription::new([31; 16], 1, self.options.family, validity)?,
            signer.public_key()?,
        )?;
        let roster = root.issue_roster(1, validity, &[root.roster_entry(&certificate)?])?;
        let public = root.public_key()?.encode();
        let pin = enrollment::Pin {
            account: root.account_id()?,
            root: public.as_ptr(),
            root_length: public.len(),
            family: self.options.family,
            checkpoint: enrollment::Checkpoint {
                version: roster.checkpoint().version(),
                digest: roster.checkpoint().digest(),
            },
        };
        let association = Association {
            struct_size: u32::try_from(std::mem::size_of::<Association>())?,
            application: [232; 32],
            pin: &pin,
            certificate: certificate.as_ptr(),
            certificate_length: certificate.len(),
            roster: roster.as_bytes().as_ptr(),
            roster_length: roster.as_bytes().len(),
        };
        let mut checkpoint = Checkpoint {
            application: [0; 32],
            revision: 0,
            account: [0; 32],
        };
        let mut error = diagnostic();
        if let Some(path) = export {
            OwnedPrivateDirectory::open(path)?;
            let fields = [
                (
                    "registry-id",
                    p::AccountAuthorityIdentity::generate()?.as_bytes().to_vec(),
                ),
                ("family", self.options.family.to_vec()),
                ("witness-id", self.options.witness.to_vec()),
                ("witness-public", self._public.clone()),
                ("application", association.application.to_vec()),
                ("account", pin.account.to_vec()),
                ("root-public", public.clone()),
                ("certificate", certificate.clone()),
                ("roster", roster.as_bytes().to_vec()),
                (
                    "roster-version",
                    roster.checkpoint().version().to_be_bytes().to_vec(),
                ),
                ("roster-digest", roster.checkpoint().digest().to_vec()),
                ("valid-from", validity.from().to_be_bytes().to_vec()),
                ("valid-until", validity.until().to_be_bytes().to_vec()),
            ];
            for (name, bytes) in fields {
                crate::native_fixture::store(path, name, &bytes)?;
            }
        }
        // SAFETY: actual signed public inputs and separate caller-owned output.
        unsafe {
            checked(
                qpc_authority_v1_associate(
                    self.handle.0,
                    &association,
                    &mut checkpoint,
                    &mut error,
                ),
                &error,
            )?;
        }
        assert_eq!(checkpoint.application, association.application);
        assert_eq!(checkpoint.revision, 1);
        assert_eq!(checkpoint.account, root.account_id()?);
        Ok((checkpoint, public, validity))
    }
}

#[test]
fn authority_registry_reopens_exact_mapping_and_cancel_does_not_replace_close() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry lock")?;
    let mut registry = Registry::new()?;
    let export = std::env::var_os("QPC_AUTHORITY_FIXTURE").map(PathBuf::from);
    let (checkpoint, _, _) = registry.associate(export.as_deref())?;
    let selection = native(Selection::read(
        registry.handle.0,
        &checkpoint,
        Instant::now() + std::time::Duration::from_secs(10),
    ))?;
    let mut error = diagnostic();
    let mut observed = checkpoint;
    // SAFETY: original handle and distinct live input/output buffers.
    unsafe {
        checked(qpc_owner_v1_cancel(registry.handle.0, &mut error), &error)?;
        assert_eq!(
            qpc_authority_v1_checkpoint(
                registry.handle.0,
                checkpoint.application.as_ptr(),
                &mut observed,
                &mut error
            ),
            302
        );
    }
    native(selection.admit())?;
    registry.handle.close()?;
    assert_eq!(
        selection
            .admit()
            .err()
            .ok_or("closed selection admitted")?
            .code,
        202
    );
    registry.reopen()?;
    // SAFETY: original application selector and exclusive output.
    unsafe {
        checked(
            qpc_authority_v1_checkpoint(
                registry.handle.0,
                checkpoint.application.as_ptr(),
                &mut observed,
                &mut error,
            ),
            &error,
        )?;
    }
    assert_eq!(observed, checkpoint);
    assert_eq!(
        selection.admit().err().ok_or("old reader revived")?.code,
        202
    );
    native(
        native(Selection::read(
            registry.handle.0,
            &checkpoint,
            Instant::now() + std::time::Duration::from_secs(10),
        ))?
        .admit(),
    )?;
    registry.handle.close()?;
    Ok(())
}

#[test]
fn authority_registry_short_options_are_refused_before_full_structure_read() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry lock")?;
    #[repr(C, align(16))]
    struct Short(u32);
    let header = Short(4);
    let path = b"/nonexistent-owned-registry-fixture";
    let mut handle = 91;
    let mut error = diagnostic();
    // SAFETY: only the aligned size header is readable; the API must reject it before body access.
    unsafe {
        assert_eq!(
            qpc_authority_v1_prepare_create(
                path.as_ptr(),
                path.len(),
                (&header as *const Short).cast(),
                &mut handle,
                &mut error
            ),
            1
        );
        assert_eq!(handle, 0);
        assert_eq!(
            qpc_authority_v1_prepare_owner(
                path.as_ptr(),
                path.len(),
                (&header as *const Short).cast(),
                &mut handle,
                &mut error
            ),
            1
        );
        assert_eq!(handle, 0);
        let mut checkpoint = Checkpoint {
            application: [0; 32],
            revision: 0,
            account: [0; 32],
        };
        assert_eq!(
            qpc_authority_v1_associate(
                0,
                (&header as *const Short).cast(),
                &mut checkpoint,
                &mut error
            ),
            1
        );
        assert_eq!(
            qpc_authority_v1_prepare_enrollment(
                path.as_ptr(),
                path.len(),
                (&header as *const Short).cast(),
                &mut handle,
                &mut error
            ),
            1
        );
        assert_eq!(handle, 0);
    }
    Ok(())
}

#[test]
fn authority_registry_parent_close_rejects_pending_enrollment_before_file_creation(
) -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry lock")?;
    let mut registry = Registry::new()?;
    let (checkpoint, root, validity) = registry.associate(None)?;
    let dir = directory()?;
    let path = dir.path().canonicalize()?;
    let wire = path.to_str().ok_or("path")?.as_bytes();
    let intent = enrollment::Intent {
        root: root.as_ptr(),
        root_length: root.len(),
        device: [31; 16],
        generation: 1,
        family: registry.options.family,
        valid_from: validity.from(),
        valid_until: validity.until(),
    };
    let address = b"127.0.0.1:9";
    let witness = witness::Options {
        address: address.as_ptr(),
        address_length: address.len(),
        timeout_ms: 1000,
    };
    let opening = opening::Options {
        kind: 3,
        quality: 0,
        carrier: 1,
        witness: &witness,
    };
    let options = EnrollmentOptions {
        struct_size: u32::try_from(std::mem::size_of::<EnrollmentOptions>())?,
        create: 1,
        registry: registry.handle.0,
        checkpoint,
        intent: &intent,
        options: &opening,
    };
    let mut error = diagnostic();
    let mut child = Handle(0);
    // SAFETY: immutable original registry/enrollment descriptors and separate output.
    unsafe {
        checked(
            qpc_authority_v1_prepare_enrollment(
                wire.as_ptr(),
                wire.len(),
                &options,
                &mut child.0,
                &mut error,
            ),
            &error,
        )?;
    }
    registry.handle.close()?;
    // Deliberately no wrapping key: Closed must win before any enrollment filesystem attempt.
    unsafe {
        assert_eq!(opening::qpc_owner_v1_finish_open(child.0, &mut error), 202);
    }
    assert_eq!(fs::read_dir(&path)?.count(), 0);
    child.close()?;
    Ok(())
}

#[test]
fn authority_registry_parent_close_blocks_all_existing_owner_routes_before_io() -> TestResult<()> {
    let _serial = TEST_REGISTRY.lock().map_err(|_| "registry lock")?;
    let mut registry = Registry::new()?;
    let (checkpoint, _, _) = registry.associate(None)?;
    let directory = directory()?;
    let path = directory.path().canonicalize()?;
    let wire = path.to_str().ok_or("path")?.as_bytes();
    let address = b"127.0.0.1:9";
    let witness = witness::Options {
        address: address.as_ptr(),
        address_length: address.len(),
        timeout_ms: 1000,
    };
    let session = [73; 32];
    let mut children = Vec::new();
    let mut error = diagnostic();
    for (kind, quality, reopen) in [(3, 0, 0), (1, 1, 0), (1, 1, 1)] {
        let options = opening::Options {
            kind,
            quality,
            carrier: 1,
            witness: &witness,
        };
        let selected = OpenOptions {
            struct_size: u32::try_from(std::mem::size_of::<OpenOptions>())?,
            reopen,
            registry: registry.handle.0,
            checkpoint,
            options: &options,
            session: if reopen == 1 {
                session.as_ptr()
            } else {
                std::ptr::null()
            },
        };
        let mut child = Handle(0);
        // SAFETY: copied input descriptors are immutable and all outputs are disjoint.
        unsafe {
            checked(
                qpc_authority_v1_prepare_owner(
                    wire.as_ptr(),
                    wire.len(),
                    &selected,
                    &mut child.0,
                    &mut error,
                ),
                &error,
            )?;
        }
        children.push(child);
    }
    registry.handle.close()?;
    for child in &mut children {
        // SAFETY: original test-owned pending handle and exclusive diagnostic.
        unsafe {
            assert_eq!(opening::qpc_owner_v1_finish_open(child.0, &mut error), 202);
        }
        child.close()?;
    }
    assert_eq!(fs::read_dir(&path)?.count(), 0);
    Ok(())
}
