// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::{store::*, *};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

impl Publisher {
    /// Complete only the original prepared signing owner. Ready never regenerates keys.
    pub fn prepare(&mut self) -> Result<Authority, Error> {
        self.action(|owner| {
            let mut config = owner.config()?;
            let (wrap_path, signer_path) = owner.paths(&config)?;
            if matches!(config.signer, SignerPhase::Wrapping {}) {
                if exists(&signer_path)? {
                    return Err(Error::Conflict("Policy signer precedes wrapping admission"));
                }
                let wrapping = if exists(&wrap_path)? {
                    sdk::JournalKey::open(&wrap_path)
                } else {
                    sdk::JournalKey::provision(&wrap_path)
                }
                .map_err(|e| Error::issuer_key("prepare policy wrapping key", e))?;
                drop(wrapping);
                #[cfg(test)]
                boundary("policy-wrapping-published", b"wrapping")?;
                config.signer = SignerPhase::Signing {};
                let tx = transaction(&owner.db)?;
                put_config(&tx, &config)?;
                tx.commit().map_err(fail)?;
                #[cfg(test)]
                boundary("policy-signing-prepared", b"signing")?;
            }
            if matches!(config.signer, SignerPhase::Signing {}) {
                let wrapping = sdk::JournalKey::open(&wrap_path)
                    .map_err(|e| Error::issuer_key("reopen policy wrapping key", e))?;
                let identity =
                    sdk::SigningKeyId::from_trusted_state(config.signing_id).map_err(fail)?;
                let signer = if exists(&signer_path)? {
                    sdk::PolicySigningKey::open(&signer_path, &wrapping, identity)
                } else {
                    sdk::PolicySigningKey::provision(&signer_path, &wrapping, identity)
                }
                .map_err(|e| Error::issuer_key("prepare original policy signer", e))?;
                let public = signer.public_key().map_err(fail)?.encode();
                if public.get(..1952) == Some(config.sdk.root.as_slice()) {
                    return Err(Error::Conflict(
                        "SDK and protocol policy roots must be distinct",
                    ));
                }
                config.signer = SignerPhase::Ready {
                    public: public.clone(),
                    family: signer.policy_family().map_err(fail)?,
                };
                #[cfg(test)]
                boundary("policy-signer-published", &public)?;
                let tx = transaction(&owner.db)?;
                put_config(&tx, &config)?;
                tx.commit().map_err(fail)?;
                #[cfg(test)]
                boundary("policy-ready-committed", &public)?;
            }
            owner.open_signer(&config)?;
            owner.authority()
        })
    }
    /// Public authority from the same original controlled signer and SDK configuration.
    pub fn authority(&self) -> Result<Authority, Error> {
        let config = self.config()?;
        let SignerPhase::Ready { public, family } = config.signer else {
            return Err(Error::Conflict(
                "Original policy signing owner is not ready",
            ));
        };
        sdk::PublicKey::decode(&public).map_err(fail)?;
        Ok(Authority {
            publisher: config.publisher,
            family,
            policy_root: public,
            sdk_root: config.sdk.root,
            sdk_state: config.sdk.state,
        })
    }
    pub(super) fn paths(&self, config: &Config) -> Result<(PathBuf, PathBuf), Error> {
        let parent = self.path.parent().ok_or(Error::Internal)?;
        let stem = URL_SAFE_NO_PAD.encode(config.signing_id);
        Ok((
            parent.join(format!("policy-{stem}.wrap")),
            parent.join(format!("policy-{stem}.signer")),
        ))
    }
    pub(super) fn open_signer(&self, config: &Config) -> Result<sdk::PolicySigningKey, Error> {
        let SignerPhase::Ready { public, family } = &config.signer else {
            return Err(Error::Conflict(
                "Original policy signing owner is not ready",
            ));
        };
        let (wrap_path, signer_path) = self.paths(config)?;
        let wrapping = sdk::JournalKey::open(&wrap_path)
            .map_err(|e| Error::issuer_key("open original policy wrapping key", e))?;
        let signer = sdk::PolicySigningKey::open(
            &signer_path,
            &wrapping,
            sdk::SigningKeyId::from_trusted_state(config.signing_id).map_err(fail)?,
        )
        .map_err(|e| Error::issuer_key("open original policy signer", e))?;
        if signer.public_key().map_err(fail)?.encode() != *public
            || signer.policy_family().map_err(fail)? != *family
        {
            return Err(Error::IssuerUnavailable);
        }
        Ok(signer)
    }
}
fn exists(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::issuer_key("inspect original policy key", e)),
    }
}
