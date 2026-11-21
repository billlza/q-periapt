// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Isolated study worker. stdin carries public policy and one authenticated KEM request.
//! stdout is a private pipe to its parent. It must never be redirected into evidence.
use q_periapt_policy::TrustedPolicyState;
use q_periapt_sdk::{Limits, PublicKey, Runtime, PUBLIC_KEY_LEN};
use std::io::{self, Read, Write};

fn field(input: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut value = vec![0; length];
    input.read_exact(&mut value)?;
    Ok(value)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = io::stdin().lock();
    let policy = field(&mut input, 4096)?;
    let signature = field(&mut input, 8192)?;
    let root = field(&mut input, 8192)?;
    let mut checkpoint = [0; TrustedPolicyState::ENCODED_LEN];
    let mut peer = [0; PUBLIC_KEY_LEN];
    let mut context = [0; 32];
    input.read_exact(&mut checkpoint)?;
    input.read_exact(&mut peer)?;
    input.read_exact(&mut context)?;
    if input.read(&mut [0])? != 0 {
        return Err("trailing request bytes".into());
    }
    let checkpoint = TrustedPolicyState::decode(&checkpoint).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("policy checkpoint: {e:?}"),
        )
    })?;
    let runtime = Runtime::from_signed_policy(
        &policy,
        &signature,
        &root,
        Some(&checkpoint),
        Limits::default(),
    )?;
    if runtime.trusted_state() != checkpoint {
        return Err("different policy checkpoint".into());
    }
    let result = runtime.encapsulate(&PublicKey::from_bytes(&peer)?, &context)?;
    let shared = result.secret.export_for_protocol()?;
    let mut pipe = io::stdout().lock();
    pipe.write_all(&result.ciphertext.to_bytes())?;
    pipe.write_all(shared.as_bytes())?;
    pipe.flush()?;
    Ok(())
}
