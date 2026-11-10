// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::{store::*, *};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

impl AuthorityStore {
    /// Resume only the original root preparation. Ready never regenerates a key.
    pub fn prepare(&mut self) -> Result<Authority, Error> {
        self.action(|owner| {
            let mut config = owner.config()?;
            let (wrap_path, signer_path) = owner.paths(&config)?;
            if matches!(config.phase, Phase::Wrapping {}) {
                if exists(&signer_path)? {
                    return Err(Error::Conflict("SDK signer precedes wrapping admission"));
                }
                let wrapping = if exists(&wrap_path)? {
                    native::JournalKey::open(&wrap_path)
                } else {
                    native::JournalKey::provision(&wrap_path)
                }
                .map_err(|e| Error::issuer_key("prepare SDK wrapping key", e))?;
                drop(wrapping);
                #[cfg(test)]
                boundary("sdk-wrapping-published", b"wrapping")?;
                config.phase = Phase::Signing {};
                let tx = transaction(&owner.db)?;
                put_config(&tx, &config)?;
                tx.commit().map_err(fail)?;
                #[cfg(test)]
                boundary("sdk-signing-prepared", b"signing")?;
            }
            if matches!(config.phase, Phase::Signing {}) {
                let wrapping = native::JournalKey::open(&wrap_path)
                    .map_err(|e| Error::issuer_key("reopen SDK wrapping key", e))?;
                let identity =
                    native::SigningKeyId::from_trusted_state(config.signing_id).map_err(fail)?;
                let signer = if exists(&signer_path)? {
                    native::SdkPolicySigningKey::open(&signer_path, &wrapping, identity)
                } else {
                    native::SdkPolicySigningKey::provision(&signer_path, &wrapping, identity)
                }
                .map_err(|e| Error::issuer_key("prepare original SDK signer", e))?;
                let root = signer.public_key().map_err(fail)?.to_vec();
                config.phase = Phase::Ready { root: root.clone() };
                #[cfg(test)]
                boundary("sdk-signer-published", &root)?;
                let tx = transaction(&owner.db)?;
                put_config(&tx, &config)?;
                tx.commit().map_err(fail)?;
                #[cfg(test)]
                boundary("sdk-ready-committed", &root)?;
            }
            owner.open_signer(&config)?;
            owner.authority()
        })
    }
    /// Public root and allocated version inventory; this does not establish consumer trust.
    pub fn authority(&self) -> Result<Authority, Error> {
        let config = self.config()?;
        let Phase::Ready { root } = config.phase else {
            return Err(Error::Conflict("Original SDK signer is not ready"));
        };
        Ok(Authority {
            identity: config.identity,
            root,
            allocated_version: config.version,
            pending: match config.cursor {
                Cursor::Idle {} => None,
                Cursor::Pending { operation } => Some(operation),
            },
        })
    }
    pub(super) fn paths(&self, config: &Config) -> Result<(PathBuf, PathBuf), Error> {
        let parent = self.path.parent().ok_or(Error::Internal)?;
        let stem = URL_SAFE_NO_PAD.encode(config.signing_id);
        Ok((
            parent.join(format!("sdk-{stem}.wrap")),
            parent.join(format!("sdk-{stem}.signer")),
        ))
    }
    pub(super) fn open_signer(
        &self,
        config: &Config,
    ) -> Result<native::SdkPolicySigningKey, Error> {
        let Phase::Ready { root } = &config.phase else {
            return Err(Error::Conflict("Original SDK signer is not ready"));
        };
        let (wrap_path, signer_path) = self.paths(config)?;
        let wrapping = native::JournalKey::open(&wrap_path)
            .map_err(|e| Error::issuer_key("open original SDK wrapping key", e))?;
        let signer = native::SdkPolicySigningKey::open(
            &signer_path,
            &wrapping,
            native::SigningKeyId::from_trusted_state(config.signing_id).map_err(fail)?,
        )
        .map_err(|e| Error::issuer_key("open original SDK signer", e))?;
        if signer.public_key().map_err(fail)?.as_slice() != root {
            return Err(Error::IssuerUnavailable);
        }
        Ok(signer)
    }
}
fn exists(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::issuer_key("inspect original SDK key", e)),
    }
}
