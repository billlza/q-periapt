// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_host_store::filesystem::{open_private_database, provision_private_database};
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition, TableHandle};
use std::path::PathBuf;

const CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("continuity_witness_host_v1");
const MAX_CONFIG: usize = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    identity: [u8; 32],
    signing_id: [u8; 32],
    phase: Phase,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "phase", deny_unknown_fields)]
enum Phase {
    Wrapping,
    Signing,
    Store { pin: Pin },
    Ready { pin: Pin },
}
struct Paths {
    wrapping: PathBuf,
    signer: PathBuf,
    store: PathBuf,
}

/// This lease serializes local initialization and control-plane operations.
/// Losing a reply never authorizes a fresh identity, key or empty witness.
pub struct Witness {
    database: Database,
    path: PathBuf,
    identity: [u8; 32],
    failed: bool,
}
impl Witness {
    /// Persist the original host identity and signing ID before creating keys.
    /// `identity` must be retained independently before first use.
    pub fn provision(path: &Path, identity: [u8; 32]) -> Result<Self> {
        sdk::AnchorIdentity::from_trusted_state(identity)?;
        let config = Config {
            schema: 1,
            identity,
            signing_id: *sdk::SigningKeyId::generate()?.as_bytes(),
            phase: Phase::Wrapping,
        };
        let database = provision_private_database(path, |db| -> Result<()> { save(db, &config) })?;
        Ok(Self {
            database,
            path: path.into(),
            identity,
            failed: false,
        })
    }

    /// Open only the existing configuration; this creates no dependent state.
    pub fn open(path: &Path, identity: [u8; 32]) -> Result<Self> {
        let owner = Self {
            database: open_private_database(path)?,
            path: path.into(),
            identity,
            failed: false,
        };
        owner.config()?;
        Ok(owner)
    }

    fn config(&self) -> Result<Config> {
        if self.failed {
            return Err("Witness host is closed after failure; reopen original state".into());
        }
        let tx = self.database.begin_read()?;
        let names: Vec<_> = tx
            .list_tables()?
            .map(|table| table.name().to_owned())
            .collect();
        if names != [CONFIG.name()] || tx.list_multimap_tables()?.next().is_some() {
            return Err("Witness host table schema differs".into());
        }
        let table = tx.open_table(CONFIG)?;
        if table.len()? != 1 {
            return Err("Witness host configuration inventory differs".into());
        }
        let raw = table
            .get("state")?
            .ok_or("Witness host configuration missing")?;
        if raw.value().is_empty() || raw.value().len() > MAX_CONFIG {
            return Err("Witness host configuration size differs".into());
        }
        let config: Config = serde_json::from_slice(raw.value())?;
        if config.schema != 1 || config.identity != self.identity {
            return Err("Witness host identity or schema differs".into());
        }
        sdk::AnchorIdentity::from_trusted_state(config.identity)?;
        sdk::SigningKeyId::from_trusted_state(config.signing_id)?;
        if let Phase::Store { pin } | Phase::Ready { pin } = &config.phase {
            if pin.identity != config.identity {
                return Err("Witness key belongs to another identity".into());
            }
            pin.as_sdk()?;
        }
        Ok(config)
    }
    fn paths(&self, config: &Config) -> Result<Paths> {
        let parent = self.path.parent().ok_or("Witness host parent missing")?;
        let stem = URL_SAFE_NO_PAD.encode(config.signing_id);
        Ok(Paths {
            wrapping: parent.join(format!("witness-{stem}.wrap")),
            signer: parent.join(format!("witness-{stem}.signer")),
            store: parent.join(format!("witness-{stem}.redb")),
        })
    }
    fn signer(
        &self,
        config: &Config,
        paths: &Paths,
    ) -> Result<(sdk::JournalKey, sdk::AnchorSigningKey)> {
        let wrapping = sdk::JournalKey::open(&paths.wrapping)?;
        let signer = sdk::AnchorSigningKey::open(
            &paths.signer,
            &wrapping,
            sdk::SigningKeyId::from_trusted_state(config.signing_id)?,
        )?;
        if let Phase::Store { pin } | Phase::Ready { pin } = &config.phase {
            if signer.public_key()?.encode() != pin.key {
                return Err("Original witness signing key differs".into());
            }
        }
        Ok((wrapping, signer))
    }
    fn original_store(&self, config: &Config) -> Result<sdk::AnchorStore> {
        if !matches!(config.phase, Phase::Ready { .. }) {
            return Err("Witness host preparation is incomplete".into());
        }
        let paths = self.paths(config)?;
        let (wrapping, signer) = self.signer(config, &paths)?;
        Ok(sdk::AnchorStore::open(
            &paths.store,
            wrapping,
            signer,
            sdk::AnchorIdentity::from_trusted_state(self.identity)?,
        )?)
    }

    /// Reconcile the original preparation only. Once Ready, missing files fail;
    /// neither this command nor ordinary network traffic regenerates them.
    pub fn prepare(&mut self) -> Result<Pin> {
        let result = self.prepare_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn prepare_inner(&mut self) -> Result<Pin> {
        let mut config = self.config()?;
        let paths = self.paths(&config)?;
        if matches!(config.phase, Phase::Wrapping) {
            if exists(&paths.signer)? || exists(&paths.store)? {
                return Err("Witness dependent state precedes wrapping admission".into());
            }
            drop(if exists(&paths.wrapping)? {
                sdk::JournalKey::open(&paths.wrapping)?
            } else {
                sdk::JournalKey::provision(&paths.wrapping)?
            });
            #[cfg(test)]
            boundary("witness-wrapping-published")?;
            config.phase = Phase::Signing;
            save(&self.database, &config)?;
            #[cfg(test)]
            boundary("witness-signing-prepared")?;
        }
        if matches!(config.phase, Phase::Signing) {
            if exists(&paths.store)? {
                return Err("Witness store precedes signing admission".into());
            }
            let wrapping = sdk::JournalKey::open(&paths.wrapping)?;
            let id = sdk::SigningKeyId::from_trusted_state(config.signing_id)?;
            let signer = if exists(&paths.signer)? {
                sdk::AnchorSigningKey::open(&paths.signer, &wrapping, id)?
            } else {
                sdk::AnchorSigningKey::provision(&paths.signer, &wrapping, id)?
            };
            let pin = Pin {
                identity: self.identity,
                key: signer.public_key()?.encode(),
            };
            #[cfg(test)]
            boundary("witness-signer-published")?;
            config.phase = Phase::Store { pin };
            save(&self.database, &config)?;
            #[cfg(test)]
            boundary("witness-store-prepared")?;
        }
        if let Phase::Store { pin } = &config.phase {
            let (wrapping, signer) = self.signer(&config, &paths)?;
            let identity = sdk::AnchorIdentity::from_trusted_state(self.identity)?;
            drop(if exists(&paths.store)? {
                sdk::AnchorStore::open(&paths.store, wrapping, signer, identity)?
            } else {
                sdk::AnchorStore::provision(&paths.store, wrapping, signer, identity)?
            });
            #[cfg(test)]
            boundary("witness-store-published")?;
            config.phase = Phase::Ready { pin: pin.clone() };
            save(&self.database, &config)?;
            #[cfg(test)]
            boundary("witness-ready-committed")?;
        }
        self.pin()
    }
    /// Return only public metadata after authenticating all original files.
    pub fn pin(&self) -> Result<Pin> {
        let config = self.config()?;
        drop(self.original_store(&config)?);
        match config.phase {
            Phase::Ready { pin } => Ok(pin),
            _ => Err("Witness host preparation is incomplete".into()),
        }
    }
    /// Explicit trusted local approval, never reachable from the network handler.
    pub fn enroll(
        &mut self,
        trust: &EnrollmentTrust,
        request: &EnrollmentRequest,
        now: u64,
    ) -> Result<()> {
        let config = self.config()?;
        let mut store = self.original_store(&config)?;
        trust.enroll(&mut store, request, now)
    }
    /// Prepare an exact expectation. Retain it before committing; this reserves nothing.
    pub fn prepare_device_replacement(
        &mut self,
        trust: &DeviceReplacementTrust,
        request: &EnrollmentRequest,
        now: u64,
    ) -> Result<DeviceReplacementDecision> {
        let config = self.config()?;
        replacement::prepare(&mut self.original_store(&config)?, trust, request, now)
    }
    /// Commit only under live successor authority. After an uncertain error, query
    /// the same decision; expired trust can still use the historical status API.
    pub fn commit_device_replacement(
        &mut self,
        trust: &DeviceReplacementTrust,
        request: &EnrollmentRequest,
        decision: &DeviceReplacementDecision,
        now: u64,
    ) -> Result<DeviceReplacementOutcome> {
        let config = self.config()?;
        replacement::commit(
            &mut self.original_store(&config)?,
            trust,
            request,
            decision,
            now,
        )
    }
    /// Observe the exact original outcome without a current-authority claim.
    pub fn device_replacement_status(
        &mut self,
        decision: &DeviceReplacementDecision,
    ) -> Result<DeviceReplacementOutcome> {
        let config = self.config()?;
        replacement::status(&mut self.original_store(&config)?, decision)
    }
    /// Independently approve the exact original roster/head target; no Commit.
    pub fn prepare_roster_refresh(
        &mut self,
        trust: &RosterRefreshTrust,
        request: &crate::roster_refresh::Request,
        now: u64,
    ) -> Result<crate::roster_refresh::Outcome> {
        let config = self.config()?;
        roster_refresh::prepare(&mut self.original_store(&config)?, trust, request, now)
    }
    /// Close only the independently approved original target, including after expiry.
    /// An already applied target remains Applied; this grants no traffic permission.
    pub fn close_roster_refresh(
        &mut self,
        trust: &RosterRefreshTrust,
        request: &crate::roster_refresh::Request,
    ) -> Result<crate::roster_refresh::Outcome> {
        let config = self.config()?;
        roster_refresh::close(&mut self.original_store(&config)?, trust, request)
    }
    /// Independently prepare the exact two-root P approval and sealed target.
    pub fn prepare_policy_renewal(
        &mut self,
        trust: &PolicyRenewalTrust,
        preparation: &crate::policy_renewal::witness::Preparation,
        now: u64,
    ) -> Result<crate::policy_renewal::witness::Outcome> {
        let config = self.config()?;
        policy_renewal::prepare(&mut self.original_store(&config)?, trust, preparation, now)
    }
    /// Close original signed policy history, including after target expiry.
    pub fn close_policy_renewal(
        &mut self,
        trust: &PolicyRenewalTrust,
        preparation: &crate::policy_renewal::witness::Preparation,
    ) -> Result<crate::policy_renewal::witness::Outcome> {
        let config = self.config()?;
        policy_renewal::close(&mut self.original_store(&config)?, trust, preparation)
    }
    /// Open the exact original store for one signed request. An unknown commit
    /// remains an error; the caller may later reconcile that original request.
    pub fn handle(
        &mut self,
        request: &[u8],
        run: &sdk::session_exchange::Run<'_>,
        now: u64,
    ) -> Result<Vec<u8>> {
        run.check()?;
        if request.len() != 3674 {
            return Err("Witness request frame size differs".into());
        }
        let config = self.config()?;
        let mut store = self.original_store(&config)?;
        run.check()?;
        let response = store.handle(request, now)?;
        run.check()?;
        Ok(response)
    }
}
fn save(database: &Database, config: &Config) -> Result<()> {
    let bytes = serde_json::to_vec(config)?;
    if bytes.len() > MAX_CONFIG {
        return Err("Witness host configuration exceeds bound".into());
    }
    let mut tx = database.begin_write()?;
    tx.set_durability(redb::Durability::Immediate)?;
    tx.set_two_phase_commit(true);
    tx.open_table(CONFIG)?.insert("state", bytes.as_slice())?;
    tx.commit()?;
    Ok(())
}
