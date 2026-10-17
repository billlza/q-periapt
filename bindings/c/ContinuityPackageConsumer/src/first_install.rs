// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Explicit host-trusted configuration and retained SDK policy ownership.
use q_periapt_continuity_identity_candidate as p;
use q_periapt_host_store::{
    filesystem::{
        publish_private_bytes, publish_private_directory, OwnedPrivateDirectory, PrivateFileError,
        PrivatePublicationError,
    },
    PolicyRecoveryTrust, PolicyStore, StoreError,
};
use q_periapt_policy::MAX_SIGNED_POLICY_BYTES;
use q_periapt_sdk::{Limits, Runtime};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    fmt,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Error {
    Input(&'static str),
    Changed(&'static str),
    Sdk(q_periapt_sdk::Error),
    Protocol(p::Error),
    Durable(p::DurableError),
    Store(StoreError),
    File(PrivateFileError),
    Publication(PrivatePublicationError),
    Tls(q_periapt_rustls::standard::ConfigurationError),
    Io(io::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Input(_) => "invalid first-install input",
            Self::Changed(_) => "original first-install configuration differs",
            Self::Sdk(_) => "SDK policy validation failed",
            Self::Protocol(_) => "protocol policy validation failed",
            Self::Durable(_) => "installation key admission failed",
            Self::Store(_) => "SDK policy store admission failed",
            Self::File(_) => "private configuration admission failed",
            Self::Publication(_) => "configuration publication failed; reconcile original inputs",
            Self::Tls(_) => "local TLS identity validation failed",
            Self::Io(_) => "configuration I/O failed",
        })
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sdk(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Durable(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::File(e) => Some(e),
            Self::Publication(e) => Some(e),
            Self::Tls(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Input(_) | Self::Changed(_) => None,
        }
    }
}
impl From<PrivatePublicationError> for Error {
    fn from(value: PrivatePublicationError) -> Self {
        Self::Publication(value)
    }
}
type Result<T> = std::result::Result<T, Error>;

enum SdkAuthority {
    Fixed(Vec<u8>),
    Recoverable(Box<PolicyRecoveryTrust>),
}

/// Original host-supplied SDK trust. This is never reconstructed from store
/// contents or inferred by finding a recovery file in the installation.
pub struct SdkTrust(SdkAuthority);
impl SdkTrust {
    pub fn fixed(root: &[u8]) -> Result<Self> {
        if root.len() != 1952 {
            return Err(Error::Input("SDK root length"));
        }
        Ok(Self(SdkAuthority::Fixed(root.into())))
    }
    pub fn recoverable(trust: &PolicyRecoveryTrust) -> Self {
        Self(SdkAuthority::Recoverable(Box::new(trust.clone())))
    }
    fn open(&self, path: &Path) -> std::result::Result<PolicyStore, StoreError> {
        match &self.0 {
            SdkAuthority::Fixed(root) => PolicyStore::open(path, root, Limits::default()),
            SdkAuthority::Recoverable(trust) => {
                PolicyStore::open_recoverable(path, trust, Limits::default())
            }
        }
    }
}

struct RecoveryConfiguration {
    trust: Box<PolicyRecoveryTrust>,
    enrollment: Vec<u8>,
    binding: [u8; 32],
}

/// Independent SDK authority and its exact initial signed policy. Recovery
/// trust is an explicit host input; configuration files never select that mode.
pub struct SdkConfiguration {
    policy: Vec<u8>,
    signature: Vec<u8>,
    root: Vec<u8>,
    recovery: Option<RecoveryConfiguration>,
}
impl SdkConfiguration {
    pub(crate) fn with_trust(
        policy: &[u8],
        signature: &[u8],
        trust: SdkTrust,
        enrollment: &[u8],
    ) -> Result<Self> {
        match trust.0 {
            SdkAuthority::Fixed(root) if enrollment.is_empty() => {
                Self::new(policy, signature, &root)
            }
            SdkAuthority::Fixed(_) => {
                Err(Error::Input("fixed authority has no recovery enrollment"))
            }
            SdkAuthority::Recoverable(trust) => {
                Self::new_recoverable(policy, signature, &trust, enrollment)
            }
        }
    }
    pub fn new(policy: &[u8], signature: &[u8], root: &[u8]) -> Result<Self> {
        if !(1..=MAX_SIGNED_POLICY_BYTES).contains(&policy.len())
            || signature.len() != 3309
            || root.len() != 1952
        {
            return Err(Error::Input("SDK policy lengths"));
        }
        Ok(Self {
            policy: policy.into(),
            signature: signature.into(),
            root: root.into(),
            recovery: None,
        })
    }

    /// Explicit recoverable first use. Retain the original trust independently
    /// across restarts; neither an incoming policy nor on-disk metadata supplies it.
    pub fn new_recoverable(
        policy: &[u8],
        signature: &[u8],
        trust: &PolicyRecoveryTrust,
        enrollment: &[u8],
    ) -> Result<Self> {
        let mut value = Self::new(policy, signature, trust.initial_root())?;
        if enrollment.len() != 3309 {
            return Err(Error::Input("recovery enrollment length"));
        }
        value.recovery = Some(RecoveryConfiguration {
            trust: Box::new(trust.clone()),
            enrollment: enrollment.to_vec(),
            binding: trust.binding(),
        });
        Ok(value)
    }

    fn provision(&self, path: &Path) -> std::result::Result<PolicyStore, StoreError> {
        match &self.recovery {
            Some(recovery) => PolicyStore::provision_recoverable(
                path,
                &self.policy,
                &self.signature,
                &recovery.trust,
                &recovery.enrollment,
                Limits::default(),
            ),
            None => PolicyStore::provision(
                path,
                &self.policy,
                &self.signature,
                &self.root,
                Limits::default(),
            ),
        }
    }

    fn open(&self, path: &Path) -> std::result::Result<PolicyStore, StoreError> {
        match &self.recovery {
            Some(recovery) => {
                PolicyStore::open_recoverable(path, &recovery.trust, Limits::default())
            }
            None => PolicyStore::open(path, &self.root, Limits::default()),
        }
    }
}

/// Independently obtained policy family/root/checkpoint, never derived from the signed response.
pub struct ProtocolConfiguration {
    family: [u8; 32],
    root: Vec<u8>,
    version: [u8; 8],
    digest: [u8; 32],
    policy: Vec<u8>,
}
impl ProtocolConfiguration {
    pub fn new(
        family: [u8; 32],
        root: &[u8],
        checkpoint: p::PolicyCheckpoint,
        policy: &[u8],
    ) -> Result<Self> {
        if root.len() != p::PUBLIC_KEY_BYTES || !(1..=8192).contains(&policy.len()) {
            return Err(Error::Input("protocol policy lengths"));
        }
        Ok(Self {
            family,
            root: root.into(),
            version: checkpoint.version().to_be_bytes(),
            digest: checkpoint.digest(),
            policy: policy.into(),
        })
    }

    fn pin(&self) -> Result<p::PolicyPin> {
        p::PolicyPin::new(
            self.family,
            p::PublicKey::decode(&self.root).map_err(Error::Protocol)?,
            p::PolicyCheckpoint::from_trusted_state(u64::from_be_bytes(self.version), self.digest)
                .map_err(Error::Protocol)?,
        )
        .map_err(Error::Protocol)
    }
    fn historical(&self) -> Result<p::HistoricalSessionPolicy> {
        self.pin()?
            .verify_historical(&self.policy)
            .map_err(Error::Protocol)
    }
}

/// Reopen existing SDK state under original host trust, with independently
/// pinned protocol metadata. No initial policy/root or recovery proof is replayed
/// as a desired update. Historical metadata grants no operational permission.
pub struct OpenConfiguration {
    sdk: SdkTrust,
    protocol: ProtocolConfiguration,
}
impl OpenConfiguration {
    pub fn new(sdk: SdkTrust, protocol: ProtocolConfiguration) -> Self {
        Self { sdk, protocol }
    }
    pub(crate) fn open(self, path: &Path) -> Result<SuppliedPolicy> {
        self.protocol.historical()?;
        OwnedPrivateDirectory::open(path).map_err(Error::File)?;
        let store = self
            .sdk
            .open(&path.join("sdk.redb"))
            .map_err(Error::Store)?;
        p::JournalKey::open(&path.join("wrap.key")).map_err(Error::Durable)?;
        Ok(SuppliedPolicy {
            store: Some(store),
            protocol: self.protocol,
        })
    }
}

/// Retains the one original SDK lease until the existing registration owner
/// needs live policy authority. Historical recovery never borrows a runtime.
pub(crate) struct SuppliedPolicy {
    store: Option<PolicyStore>,
    protocol: ProtocolConfiguration,
}
impl SuppliedPolicy {
    pub(crate) fn family(&self) -> [u8; 32] {
        self.protocol.family
    }
    pub(crate) fn historical(&self) -> Result<p::HistoricalSessionPolicy> {
        self.protocol.historical()
    }
    pub(crate) fn take_current(
        &mut self,
        cancel: &crate::Cancellation,
        deadline: std::time::Instant,
    ) -> crate::Result<(PolicyStore, std::sync::Arc<p::VerifiedSessionPolicy>)> {
        crate::opening::check(cancel, deadline)?;
        let store = self.store.as_ref().ok_or_else(|| crate::failure(2))?;
        let policy = self.protocol.pin()?.verify(
            &self.protocol.policy,
            store.runtime()?,
            crate::owner::now().map_err(crate::Failure::configuration)?,
        )?;
        crate::opening::check(cancel, deadline)?;
        // No fallible work follows moving the lease into the live authority.
        let store = self.store.take().ok_or_else(|| crate::failure(2))?;
        Ok((store, std::sync::Arc::new(policy)))
    }
}

/// Caller-supplied local identity. No peer trust, account authorization or network is inferred.
pub struct TlsConfiguration {
    certificate: Vec<u8>,
    key: Zeroizing<Vec<u8>>,
}
impl TlsConfiguration {
    pub fn new(certificate: &[u8], key: &[u8]) -> Result<Self> {
        if !(1..=8192).contains(&certificate.len()) || !(1..=8192).contains(&key.len()) {
            return Err(Error::Input("TLS identity lengths"));
        }
        Ok(Self {
            certificate: certificate.into(),
            key: Zeroizing::new(key.into()),
        })
    }
}

/// Immutable initialization inputs, with distinct creation and original-input reconciliation.
/// Preparing configuration creates no device identity and grants no Continuity authority.
/// Current time, SDK eligibility, credential/roster and peer trust are rechecked by enrollment
/// and connection admission. In particular, authenticated expired/future policy can be stored
/// here but cannot authorize an operation merely because this preparation succeeded.
pub struct FirstInstallConfiguration {
    sdk: SdkConfiguration,
    protocol: ProtocolConfiguration,
    tls: TlsConfiguration,
}
impl FirstInstallConfiguration {
    pub fn new(
        sdk: SdkConfiguration,
        protocol: ProtocolConfiguration,
        tls: TlsConfiguration,
    ) -> Self {
        Self { sdk, protocol, tls }
    }

    fn validate(&self) -> Result<[u8; 68]> {
        if let Some(recovery) = &self.sdk.recovery {
            recovery
                .trust
                .verify_enrollment(&recovery.enrollment)
                .map_err(Error::Store)?;
        }
        let runtime = Runtime::from_signed_policy(
            &self.sdk.policy,
            &self.sdk.signature,
            &self.sdk.root,
            None,
            Limits::default(),
        )
        .map_err(Error::Sdk)?;
        // This is a signature-checked configuration snapshot, not a live policy owner.
        let historical = self.protocol.historical()?;
        if historical.sdk_binding() != runtime.policy_binding().map_err(Error::Sdk)? {
            return Err(Error::Protocol(p::Error::Scope));
        }
        let key = PrivateKeyDer::try_from(self.tls.key.as_slice())
            .map_err(|_| Error::Input("private key DER"))?
            .clone_key();
        q_periapt_rustls::standard::validate_local_identity(
            vec![CertificateDer::from(self.tls.certificate.clone())],
            key,
        )
        .map_err(Error::Tls)?;
        let state = runtime.policy_binding().map_err(Error::Sdk)?;
        runtime.close();
        Ok(state)
    }

    fn fields(&self) -> Vec<(&'static str, &[u8])> {
        let mut fields: Vec<(&'static str, &[u8])> = vec![
            ("sdk-policy", &self.sdk.policy),
            ("sdk-signature", &self.sdk.signature),
            ("sdk-root", &self.sdk.root),
            ("family", &self.protocol.family),
            ("policy-root", &self.protocol.root),
            ("policy-version", &self.protocol.version),
            ("policy-digest", &self.protocol.digest),
            ("protocol-policy", &self.protocol.policy),
            ("tls-cert", &self.tls.certificate),
            ("tls-key", &self.tls.key),
        ];
        if let Some(recovery) = &self.sdk.recovery {
            // These compare the exact original inputs during reconciliation.
            // Neither file is parsed to obtain trust or choose authority mode.
            fields.push(("sdk-recovery-binding", &recovery.binding));
            fields.push(("sdk-recovery-enrollment", &recovery.enrollment));
        }
        fields
    }

    /// Explicit first use. The final directory must not already exist, even if empty.
    /// Any publication error may have committed a complete tree. Reconcile; never overwrite.
    pub fn provision(&self, target: &Path) -> Result<PolicyStore> {
        let expected = self.validate()?;
        publish_private_directory(target, |staging| {
            for (name, bytes) in self.fields() {
                publish_private_bytes(&staging.join(name), bytes)?;
            }
            // The same atomic first publication prepares the wrapping key needed
            // by original enrollment. It is never regenerated by reconciliation.
            p::JournalKey::provision(&staging.join("wrap.key")).map_err(Error::Durable)?;
            let store = self
                .sdk
                .provision(&staging.join("sdk.redb"))
                .map_err(Error::Store)?;
            if store
                .runtime()
                .map_err(Error::Store)?
                .policy_binding()
                .map_err(Error::Sdk)?
                != expected
            {
                return Err(Error::Changed("initial SDK authority and policy"));
            }
            // Keep the original database lease through directory publication;
            // an output-publication failure drops this unreleased owner.
            Ok::<_, Error>(store)
        })
    }

    /// Check an uncertain first creation against the independently retained original inputs.
    /// This never creates missing children or advances an unexpected SDK floor. Configuration
    /// that later changed must use its explicit current lifecycle path, not this initializer.
    pub fn reconcile(&self, target: &Path) -> Result<PolicyStore> {
        let expected = self.validate()?;
        let directory = OwnedPrivateDirectory::open(target).map_err(Error::File)?;
        // Hold the database lease while comparing configuration, just as operational
        // admission does. Cooperating lifecycle writers must own the same lease.
        // open_configured could persist a requested higher policy; open only the
        // committed image here and require its exact original floor.
        let store = self
            .sdk
            .open(&target.join("sdk.redb"))
            .map_err(Error::Store)?;
        if store
            .runtime()
            .map_err(Error::Store)?
            .policy_binding()
            .map_err(Error::Sdk)?
            != expected
        {
            return Err(Error::Changed("SDK authority or policy differs"));
        }
        if let Some(recovery) = &self.sdk.recovery {
            store
                .verify_initial_recovery(&recovery.trust, &recovery.enrollment)
                .map_err(Error::Store)?;
        }
        p::JournalKey::open(&target.join("wrap.key")).map_err(Error::Durable)?;
        for (name, bytes) in self.fields() {
            let file = directory
                .open_config_file(name, bytes.len())
                .map_err(Error::File)?;
            let mut stored = Zeroizing::new(Vec::with_capacity(bytes.len()));
            file.take(bytes.len() as u64 + 1)
                .read_to_end(&mut stored)
                .map_err(Error::Io)?;
            if stored.as_slice() != bytes {
                return Err(Error::Changed(name));
            }
        }
        Ok(store)
    }

    pub(crate) fn prepare(self, target: &Path, create: bool) -> Result<SuppliedPolicy> {
        let store = if create {
            self.provision(target)?
        } else {
            self.reconcile(target)?
        };
        Ok(SuppliedPolicy {
            store: Some(store),
            protocol: self.protocol,
        })
    }
}

#[cfg(test)]
mod tests;
