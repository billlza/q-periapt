// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::sdk_inputs::SdkInput;
use q_periapt_sdk::{Limits, Runtime};
use q_periapt_sig::Signer;
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn sdk_input() -> Result<SdkInput, Box<dyn std::error::Error>> {
    let document = b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n".to_vec();
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut())?;
    let (secret, public) = q_periapt_backends::MlDsa65::generate(*seed);
    seed.zeroize();
    let secret = Zeroizing::new(secret);
    let mut randomness = Zeroizing::new([0; 32]);
    getrandom::fill(randomness.as_mut())?;
    let mut signature = vec![0; 3309];
    let signed = q_periapt_backends::MlDsa65.sign(
        &secret[..],
        &q_periapt_policy::policy_signature_message(&document),
        &randomness[..],
        &mut signature,
    );
    signed.map_err(|e| format!("test SDK signature: {e:?}"))?;
    let runtime =
        Runtime::from_signed_policy(&document, &signature, &public, None, Limits::default())?;
    Ok(SdkInput {
        root: public.to_vec(),
        state: runtime.trusted_state().encode().to_vec(),
        document,
        signature,
    })
}
