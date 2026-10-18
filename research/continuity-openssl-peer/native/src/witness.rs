// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual persistent witness and explicit test control plane, never peer enrollment.
use crate::{fixture::Fixture, Result, NOW};
use q_periapt_continuity_identity_candidate::{
    AnchorClient, AnchorGenesis, AnchorIdentity, AnchorPin, AnchorSigningKey, AnchorStore,
    AnchorSubject, AnchorTransport, BootstrapRole, DeviceSigningKey, DurableError, JournalKey,
    SigningKeyId,
};
use std::{
    fs, io,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub(super) struct Witness {
    store: Mutex<Option<AnchorStore>>,
    pub pin: AnchorPin,
    path: PathBuf,
    witness_key: SigningKeyId,
    device_key: SigningKeyId,
    now: AtomicU64,
}

impl Witness {
    pub fn create(public: &Path) -> Result<Arc<Self>> {
        let path = tempfile::Builder::new()
            .prefix("qperiapt-independent-witness-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?
            .keep()
            .canonicalize()?;
        if path.starts_with(public.canonicalize()?.parent().ok_or("artifact boundary")?) {
            return Err("witness private state inside public output".into());
        }
        let wrapping = JournalKey::provision(&path.join("key"))?;
        let witness_key = SigningKeyId::generate()?;
        let device_key = SigningKeyId::generate()?;
        let identity = AnchorIdentity::generate()?;
        for (name, bytes) in [
            ("witness-id", identity.as_bytes()),
            ("witness-key-id", witness_key.as_bytes()),
            ("device-key-id", device_key.as_bytes()),
        ] {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        fs::File::open(&path)?.sync_all()?;
        let signer =
            AnchorSigningKey::provision(&path.join("witness-signer"), &wrapping, witness_key)?;
        let store = AnchorStore::provision(&path.join("witness.redb"), wrapping, signer, identity)?;
        let pin = store.pin()?;
        fs::write(public.join("pin-witness-id"), identity.as_bytes())?;
        fs::write(public.join("pin-witness-key"), pin.public_key().encode())?;
        fs::write(
            public.join("private-witness-path"),
            path.as_os_str().as_encoded_bytes(),
        )?;
        Ok(Arc::new(Self {
            store: Mutex::new(Some(store)),
            pin,
            path,
            witness_key,
            device_key,
            now: AtomicU64::new(NOW),
        }))
    }

    pub fn provision_device(&self) -> Result<DeviceSigningKey> {
        Ok(DeviceSigningKey::provision(
            &self.path.join("device-signer"),
            &JournalKey::open(&self.path.join("key"))?,
            self.device_key,
        )?)
    }

    pub fn client(self: &Arc<Self>) -> std::result::Result<AnchorClient, DurableError> {
        let signer = DeviceSigningKey::open(
            &self.path.join("device-signer"),
            &JournalKey::open(&self.path.join("key"))?,
            self.device_key,
        )?;
        Ok(AnchorClient::new(
            self.pin.clone(),
            signer,
            Box::new(Carrier(Arc::clone(self))),
            Duration::from_secs(10),
        )?)
    }

    pub fn enroll(
        &self,
        genesis: &AnchorGenesis,
        fixture: &Fixture,
        role: BootstrapRole,
    ) -> Result<()> {
        self.store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .enroll(
                genesis,
                fixture.context.device(role),
                fixture.context.current_policy()?,
                self.now.load(Ordering::SeqCst),
            )?;
        Ok(())
    }

    pub fn exchange(&self, wire: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .store
            .lock()
            .map_err(|_| "witness lock poisoned")?
            .as_mut()
            .ok_or("closed witness")?
            .handle(wire, self.now.load(Ordering::SeqCst))?)
    }

    pub fn command(&self, fixture: &Fixture, command: u8, payload: &[u8]) -> Result<Vec<u8>> {
        match command {
            30 if payload.len() == 128 => {
                let genesis = AnchorGenesis::from_trusted_state(
                    AnchorSubject::from_trusted_state(&payload[..96])?,
                    payload[96..].try_into()?,
                )?;
                self.enroll(&genesis, fixture, BootstrapRole::Initiator)?;
                Ok(b"enrolled".to_vec())
            }
            31 => self.exchange(payload),
            32 if payload.is_empty() => {
                let mut store = self.store.lock().map_err(|_| "witness lock poisoned")?;
                store.take().ok_or("closed witness")?.close();
                let wrapping = JournalKey::open(&self.path.join("key"))?;
                let signer = AnchorSigningKey::open(
                    &self.path.join("witness-signer"),
                    &wrapping,
                    self.witness_key,
                )?;
                *store = Some(AnchorStore::open(
                    &self.path.join("witness.redb"),
                    wrapping,
                    signer,
                    self.pin.identity(),
                )?);
                Ok(b"witness reopened".to_vec())
            }
            33 if payload.len() == 8 => {
                self.now
                    .store(u64::from_be_bytes(payload.try_into()?), Ordering::SeqCst);
                Ok(b"witness clock set".to_vec())
            }
            _ => Err("witness test command shape".into()),
        }
    }
}

struct Carrier(Arc<Witness>);
impl AnchorTransport for Carrier {
    fn exchange(&mut self, wire: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let reply = self
            .0
            .exchange(wire)
            .map_err(|e| io::Error::other(e.to_string()))?;
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(reply)
    }
}
