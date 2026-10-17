// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared independent recovery enrollment inputs for foreign consumers.
use crate::Result;
use q_periapt_host_store::{filesystem::publish_private_bytes, PolicyRecoveryTrust};
use q_periapt_sig::Signer;
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub(crate) fn install_recovery(source: &Path) -> Result<()> {
    let (key, public) = q_periapt_backends::MlDsa65::generate([101; 32]);
    let key = Zeroizing::new(key);
    let scope = [102; 32];
    let trust = PolicyRecoveryTrust::new(scope, &fs::read(source.join("sdk-root"))?, &public)?;
    let mut proof = vec![0; 3309];
    q_periapt_backends::MlDsa65
        .sign(
            key.as_ref(),
            &trust.enrollment_message(),
            &[103; 32],
            &mut proof,
        )
        .map_err(|e| format!("test recovery proof: {e:?}"))?;
    publish_private_bytes(&source.join("recovery-scope"), &scope)?;
    publish_private_bytes(&source.join("recovery-root"), &public)?;
    publish_private_bytes(&source.join("recovery-enrollment"), &proof)?;
    Ok(())
}
