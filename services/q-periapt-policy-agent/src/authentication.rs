//! Exact ML-DSA-65 signed-envelope primitive shared by remote and local transports.

use q_periapt_backends::{MlDsa65, ML_DSA_65_SIGN_RAND_LEN, ML_DSA_65_SIG_LEN};
use q_periapt_core::ZeroizingBytes;
use q_periapt_sig::{Signer, Verifier};

use crate::codec::{CodecError, Decoder, Encoder, MAX_FRAME_BYTES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticationError {
    Authentication,
    Entropy,
    InvalidEnvelope,
}

pub(crate) fn sign_envelope(
    body: &[u8],
    signing_key: &[u8],
) -> Result<Vec<u8>, AuthenticationError> {
    let mut randomness = ZeroizingBytes::<ML_DSA_65_SIGN_RAND_LEN>::zeroed();
    getrandom::fill(randomness.as_mut_bytes()).map_err(|_| AuthenticationError::Entropy)?;
    let mut signature = [0u8; ML_DSA_65_SIG_LEN];
    let written = MlDsa65
        .sign(signing_key, body, randomness.as_bytes(), &mut signature)
        .map_err(|_| AuthenticationError::Authentication)?;
    if written != ML_DSA_65_SIG_LEN {
        return Err(AuthenticationError::Authentication);
    }
    let mut encoder = Encoder::new(MAX_FRAME_BYTES);
    encoder
        .lp16(body)
        .and_then(|()| encoder.lp16(&signature))
        .map_err(map_codec)?;
    Ok(encoder.finish())
}

pub(crate) fn verify_envelope<'a>(
    envelope: &'a [u8],
    verification_key: &[u8],
) -> Result<&'a [u8], AuthenticationError> {
    let mut decoder = Decoder::new(envelope);
    let body = decoder.lp16(MAX_FRAME_BYTES).map_err(map_codec)?;
    let signature = decoder.lp16(ML_DSA_65_SIG_LEN).map_err(map_codec)?;
    if signature.len() != ML_DSA_65_SIG_LEN {
        return Err(AuthenticationError::InvalidEnvelope);
    }
    decoder.finish().map_err(map_codec)?;
    MlDsa65
        .verify(verification_key, body, signature)
        .map_err(|_| AuthenticationError::Authentication)?;
    Ok(body)
}

fn map_codec(_: CodecError) -> AuthenticationError {
    AuthenticationError::InvalidEnvelope
}
