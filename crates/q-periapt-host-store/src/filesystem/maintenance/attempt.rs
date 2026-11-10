use super::{
    record::{self, Intent, Kind, Record, INTENT_BYTES, LEASE_BYTES, RECORD_BYTES},
    tree, PublicationCleanupLimits, PublicationCleanupOutcome,
    PublicationMaintenanceError as Error,
};
use crate::filesystem::{
    open_private_parent, publication_ops as ops, LockedFileBackend, OwnedPrivateDirectory,
    PrivatePublicationError,
};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const PAYLOAD: &str = "payload";
const LEASE: &str = "lease";
const RECORD: &str = "record";
const INTENT: &str = "cleanup.intent";
const DONE: &str = "cleanup.done";
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "managed publication scope or record differs",
    )
}
fn as_io(error: Error) -> io::Error {
    match error {
        Error::Io(e) => e,
        Error::Busy => io::Error::new(io::ErrorKind::WouldBlock, error),
        other => io::Error::other(other),
    }
}
fn read(file: &File, maximum: usize) -> io::Result<Vec<u8>> {
    ops::file_identity(file)?;
    let length = usize::try_from(file.metadata()?.len()).map_err(|_| invalid())?;
    if length > maximum {
        return Err(invalid());
    }
    let mut probe = file.try_clone()?;
    probe.seek(SeekFrom::Start(0))?;
    let mut body = Vec::with_capacity(length);
    probe
        .take(
            u64::try_from(maximum)
                .map_err(|_| invalid())?
                .checked_add(1)
                .ok_or_else(invalid)?,
        )
        .read_to_end(&mut body)?;
    if body.len() != length
        || file.metadata()?.len() != u64::try_from(length).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(body)
}
fn optional(
    parent: &OwnedPrivateDirectory,
    name: &str,
    maximum: usize,
) -> io::Result<Option<Vec<u8>>> {
    match ops::open_file(parent, OsStr::new(name)) {
        Ok(file) => {
            let body = read(&file, maximum)?;
            ops::same_plain_file(parent, OsStr::new(name), &file)?;
            Ok(Some(body))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

struct Control {
    parent: OwnedPrivateDirectory,
    directory: OwnedPrivateDirectory,
    name: OsString,
    record: Record,
    record_file: File,
    lease_probe: File,
    _lease: LockedFileBackend,
}
impl Control {
    fn open(path: &Path) -> Result<Self, Error> {
        let (parent, name) = open_private_parent(path).map_err(|_| Error::Invalid)?;
        let name = name.to_owned();
        let nonce = record::nonce(&name)?;
        let directory = ops::open_directory(&parent, &name)?;
        let lease_probe = ops::open_file(&directory, OsStr::new(LEASE))?;
        let lease = tree::lock(lease_probe.try_clone()?)?;
        let record_file = ops::open_file(&directory, OsStr::new(RECORD))?;
        let record = Record::decode(&read(&record_file, RECORD_BYTES)?)?;
        if record.nonce != nonce {
            return Err(Error::Invalid);
        }
        let control = Self {
            parent,
            directory,
            name,
            record,
            record_file,
            lease_probe,
            _lease: lease,
        };
        control.validate()?;
        control.inventory(true)?;
        Ok(control)
    }
    fn validate(&self) -> io::Result<()> {
        ops::same_directory(&self.parent, &self.name, &self.directory)?;
        if ops::directory_identity(&self.parent)? != self.record.parent
            || ops::directory_identity(&self.directory)? != self.record.control
            || ops::file_identity(&self.lease_probe)? != self.record.lease
        {
            return Err(invalid());
        }
        ops::same_plain_file(&self.directory, OsStr::new(LEASE), &self.lease_probe)?;
        ops::same_plain_file(&self.directory, OsStr::new(RECORD), &self.record_file)?;
        if read(&self.lease_probe, LEASE_BYTES)? != self.record.lease_bytes()
            || read(&self.record_file, RECORD_BYTES)? != self.record.encode()
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn inventory(&self, maintenance: bool) -> io::Result<()> {
        let names = ops::directory_entries(&self.directory, 8)?;
        if names.len() > 7
            || names.iter().any(|n| {
                n != LEASE
                    && n != RECORD
                    && n != PAYLOAD
                    && !(maintenance
                        && [
                            INTENT,
                            DONE,
                            "cleanup.intent.pending",
                            "cleanup.done.pending",
                        ]
                        .iter()
                        .any(|s| n.as_os_str() == OsStr::new(s)))
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Control-field recovery is authorized by the original v2 record and lease.
    /// A pending field may only be an exact prefix of its original canonical
    /// bytes. It is never truncated, reset or accepted as a completed field.
    fn persist_field(&self, name: &str, body: &[u8]) -> io::Result<()> {
        self.validate()?;
        self.inventory(true)?;
        if let Some(existing) = optional(&self.directory, name, body.len())? {
            if existing != body {
                return Err(invalid());
            }
            ops::sync_directory(&self.directory)?;
            return Ok(());
        }
        let pending = OsString::from(format!("{name}.pending"));
        let mut file = match ops::open_file(&self.directory, &pending) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ops::clone_file(&ops::create_file(&self.directory, &pending)?)?
            }
            Err(error) => return Err(error),
        };
        let prefix = read(&file, body.len())?;
        if !body.starts_with(&prefix) {
            return Err(invalid());
        }
        file.seek(SeekFrom::Start(
            u64::try_from(prefix.len()).map_err(|_| invalid())?,
        ))?;
        file.write_all(body.get(prefix.len()..).ok_or_else(invalid)?)?;
        file.sync_all()?;
        if read(&file, body.len())? != body {
            return Err(invalid());
        }
        ops::rename_plain_file_to(
            &self.directory,
            &pending,
            &self.directory,
            OsStr::new(name),
            &file,
        )?;
        ops::same_plain_file(&self.directory, OsStr::new(name), &file)?;
        ops::sync_directory(&self.directory)?;
        self.validate()
    }
}

enum Payload {
    File(ops::Descriptor),
    Directory(OwnedPrivateDirectory),
}
pub(in crate::filesystem) struct ManagedAttempt {
    control: Control,
    payload: Payload,
    destination: OsString,
    path: PathBuf,
}
impl ManagedAttempt {
    pub(in crate::filesystem) fn file(path: &Path) -> Result<Self, PrivatePublicationError> {
        Self::new(path, Kind::File)
    }
    pub(in crate::filesystem) fn directory(path: &Path) -> Result<Self, PrivatePublicationError> {
        Self::new(path, Kind::Directory)
    }
    fn new(path: &Path, kind: Kind) -> Result<Self, PrivatePublicationError> {
        let (parent, destination) = open_private_parent(path).map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private publication parent admission failed",
            )
        })?;
        ops::require_absent(&parent, destination)?;
        let destination = destination.to_owned();
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let name = record::name(nonce);
        if destination == name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication destination collides with its control name",
            )
            .into());
        }
        let build = (|| -> io::Result<Self> {
            let directory = ops::create_directory(&parent, &name)?;
            let mut lease_probe =
                ops::clone_file(&ops::create_file(&directory, OsStr::new(LEASE))?)?;
            let lease = tree::lock(lease_probe.try_clone()?).map_err(as_io)?;
            lease_probe.write_all(&record::lease_bytes(nonce))?;
            lease_probe.sync_all()?;
            let (payload, payload_identity) = match kind {
                Kind::File => {
                    let file = ops::create_file(&directory, OsStr::new(PAYLOAD))?;
                    let identity = ops::file_identity(&ops::clone_file(&file)?)?;
                    (Payload::File(file), identity)
                }
                Kind::Directory => {
                    let dir = ops::create_directory(&directory, OsStr::new(PAYLOAD))?;
                    let identity = ops::directory_identity(&dir)?;
                    (Payload::Directory(dir), identity)
                }
            };
            let record = Record {
                kind,
                nonce,
                parent: ops::directory_identity(&parent)?,
                control: ops::directory_identity(&directory)?,
                lease: ops::file_identity(&lease_probe)?,
                payload: payload_identity,
                destination: record::destination(&destination),
            };
            let mut record_file =
                ops::clone_file(&ops::create_file(&directory, OsStr::new(RECORD))?)?;
            record_file.write_all(&record.encode())?;
            record_file.sync_all()?;
            ops::sync_directory(&directory)?;
            ops::sync_directory(&parent)?;
            let payload_path = path.parent().ok_or_else(invalid)?.join(&name).join(PAYLOAD);
            let control = Control {
                parent,
                directory,
                name: name.clone(),
                record,
                record_file,
                lease_probe,
                _lease: lease,
            };
            let attempt = Self {
                control,
                payload,
                destination,
                path: payload_path,
            };
            attempt.validate_unpublished()?;
            Ok(attempt)
        })();
        build.map_err(|error| PrivatePublicationError::staged(error, name))
    }
    pub(in crate::filesystem) fn correlation_name(&self) -> &OsStr {
        &self.control.name
    }
    pub(in crate::filesystem) fn source(&self) -> &OwnedPrivateDirectory {
        &self.control.directory
    }
    pub(in crate::filesystem) fn target_parent(&self) -> &OwnedPrivateDirectory {
        &self.control.parent
    }
    pub(in crate::filesystem) fn path(&self) -> &Path {
        &self.path
    }
    pub(in crate::filesystem) fn data_file(&self) -> io::Result<File> {
        match &self.payload {
            Payload::File(file) => ops::clone_file(file),
            _ => Err(invalid()),
        }
    }
    pub(in crate::filesystem) fn data_directory(&self) -> io::Result<&OwnedPrivateDirectory> {
        match &self.payload {
            Payload::Directory(dir) => Ok(dir),
            _ => Err(invalid()),
        }
    }
    pub(in crate::filesystem) fn validate_unpublished(&self) -> io::Result<()> {
        self.control.validate()?;
        self.control.inventory(false)?;
        match &self.payload {
            Payload::File(file) => ops::same_file(self.source(), OsStr::new(PAYLOAD), file),
            Payload::Directory(dir) => ops::same_directory(self.source(), OsStr::new(PAYLOAD), dir),
        }
    }
    pub(in crate::filesystem) fn rename(&self) -> io::Result<()> {
        self.validate_unpublished()?;
        match &self.payload {
            Payload::File(file) => ops::rename_file_to(
                self.source(),
                OsStr::new(PAYLOAD),
                &self.control.parent,
                &self.destination,
                file,
            ),
            Payload::Directory(dir) => ops::rename_directory_to(
                self.source(),
                OsStr::new(PAYLOAD),
                &self.control.parent,
                &self.destination,
                dir,
            ),
        }
    }
    pub(in crate::filesystem) fn same_target(&self) -> io::Result<()> {
        match &self.payload {
            Payload::File(file) => ops::same_file(&self.control.parent, &self.destination, file),
            Payload::Directory(dir) => {
                ops::same_directory(&self.control.parent, &self.destination, dir)
            }
        }
    }
    pub(in crate::filesystem) fn sync_publication(&self) -> io::Result<()> {
        self.control.validate()?;
        self.same_target()?;
        ops::sync_directory(&self.control.parent)?;
        ops::sync_directory(self.source())
    }
    pub(in crate::filesystem) fn finish(&self) -> io::Result<()> {
        self.control.validate()?;
        self.control.inventory(false)?;
        self.same_target()?;
        ops::require_absent(self.source(), OsStr::new(PAYLOAD))?;
        // Only this original attempt's control fields are retired. Its independent
        // lease remains held until the control name is gone and the parent synced.
        ops::remove_file(self.source(), OsStr::new(RECORD), &self.control.record_file)?;
        ops::remove_file(self.source(), OsStr::new(LEASE), &self.control.lease_probe)?;
        ops::sync_directory(self.source())?;
        ops::remove_directory(&self.control.parent, &self.control.name, self.source())?;
        ops::sync_directory(&self.control.parent)?;
        self.same_target()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    Admitted,
    IntentCommitted,
    EntryRemoved,
    PayloadSynced,
    ReceiptCommitted,
}
pub(super) fn reclaim(
    path: &Path,
    limits: PublicationCleanupLimits,
) -> Result<PublicationCleanupOutcome, Error> {
    reclaim_with(path, limits, |_| Ok(()))
}
fn reclaim_with(
    path: &Path,
    limits: PublicationCleanupLimits,
    mut hook: impl FnMut(Step) -> io::Result<()>,
) -> Result<PublicationCleanupOutcome, Error> {
    let control = Control::open(path)?;
    let intent = optional(&control.directory, INTENT, INTENT_BYTES)?
        .map(|body| Intent::decode(&body, &control.record))
        .transpose()?;
    let done = optional(&control.directory, DONE, 40)?;
    let pending_intent = optional(&control.directory, "cleanup.intent.pending", INTENT_BYTES)?;
    let pending_done = optional(&control.directory, "cleanup.done.pending", 40)?;
    // Each field has one non-replacing pending -> committed transition. A
    // duplicate or out-of-order field is not a crash state of this protocol.
    if (intent.is_some() && pending_intent.is_some())
        || (done.is_some() && pending_done.is_some())
        || ((done.is_some() || pending_done.is_some()) && intent.is_none())
    {
        return Err(Error::Invalid);
    }
    if let Some(original) = intent {
        let receipt = original.receipt();
        if done.as_ref().is_some_and(|bytes| *bytes != receipt)
            || pending_done
                .as_ref()
                .is_some_and(|bytes| !receipt.starts_with(bytes))
        {
            return Err(Error::Invalid);
        }
    }
    let mut used = tree::Usage::default();
    let plan = match control.record.kind {
        Kind::File => match ops::open_file(&control.directory, OsStr::new(PAYLOAD)) {
            Ok(file) => {
                if ops::file_identity(&file)? != control.record.payload {
                    return Err(Error::Invalid);
                }
                Some(tree::file(file, control.record.parent, limits, &mut used)?)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        },
        Kind::Directory => match ops::open_directory(&control.directory, OsStr::new(PAYLOAD)) {
            Ok(dir) => {
                if ops::directory_identity(&dir)? != control.record.payload {
                    return Err(Error::Invalid);
                }
                Some(tree::directory(
                    dir,
                    control.record.parent,
                    limits,
                    1,
                    &mut used,
                )?)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        },
    };
    if let Some(plan) = &plan {
        if plan.identity()? != control.record.payload {
            return Err(Error::Invalid);
        }
    }
    // Receipt writing starts only after the entire payload removal was synced.
    if (plan.is_some() && (done.is_some() || pending_done.is_some()))
        || (plan.is_none() && intent.is_none() && pending_intent.is_some())
    {
        return Err(Error::Invalid);
    }
    control.validate()?;
    control.inventory(true)?;
    hook(Step::Admitted)?;
    if let Some(done) = done {
        let original = intent.ok_or(Error::Invalid)?;
        if done != original.receipt() {
            return Err(Error::Invalid);
        }
        ops::sync_directory(&control.directory)?;
        return Ok(PublicationCleanupOutcome::Reclaimed {
            entries: original.entries,
            bytes: original.bytes,
        });
    }
    let original = match intent {
        Some(value) => {
            if used.entries > value.entries || used.bytes > value.bytes {
                return Err(Error::Invalid);
            }
            value
        }
        None if plan.is_none() => {
            ops::sync_directory(&control.directory)?;
            return Ok(PublicationCleanupOutcome::NoPayload);
        }
        None => {
            let value = Intent {
                record: control.record.digest(),
                entries: used.entries,
                bytes: used.bytes,
            };
            control.persist_field(INTENT, &value.encode())?;
            value
        }
    };
    hook(Step::IntentCommitted)?;
    if let Some(plan) = &plan {
        plan.remove(&control.directory, OsStr::new(PAYLOAD), &mut || {
            hook(Step::EntryRemoved)
        })?;
    }
    ops::sync_directory(&control.directory)?;
    hook(Step::PayloadSynced)?;
    control.persist_field(DONE, &original.receipt())?;
    hook(Step::ReceiptCommitted)?;
    control.validate()?;
    Ok(PublicationCleanupOutcome::Reclaimed {
        entries: original.entries,
        bytes: original.bytes,
    })
}

#[cfg(test)]
mod tests;
