// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public artifact readback under separately retained device and policy inputs.
use super::{sdk, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
};

fn array<const N: usize>(input: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn verify(
    wire: &[u8],
    id: [u8; 32],
    device: &sdk::VerifiedDevice,
    policy: &sdk::VerifiedSessionPolicy,
    now: u64,
) -> Result<()> {
    if wire.len() > 2 * 1024 * 1024 {
        return Err("Publication size bound".into());
    }
    let mut input = Cursor::new(wire);
    if array::<8>(&mut input)? != *b"QPPUBA01" || array::<32>(&mut input)? != id {
        return Err("Publication identity differs".into());
    }
    // These are producer intent/artifact commitments, not trust inputs. The
    // signed manifest and Merkle proofs below authenticate the public keys.
    for _ in 0..2 {
        if array::<32>(&mut input)? == [0; 32] {
            return Err("Zero publication commitment".into());
        }
    }
    let length = usize::try_from(u32::from_be_bytes(array(&mut input)?))?;
    if length != 3667 {
        return Err("Publication manifest width".into());
    }
    let mut manifest = vec![0; length];
    input.read_exact(&mut manifest)?;
    let checked = device.verify_manifest(&manifest, now)?;
    let epoch = u64::from_be_bytes(id[..8].try_into()?);
    if checked.context().bundle_epoch() != epoch
        || checked.context().directory_checkpoint() != [68; 32]
        || checked.context().suite_digest() != sdk::bootstrap_suite_digest()
        || Some(checked.context().policy_digest().as_slice()) != policy.sdk_binding().get(36..)
    {
        return Err("Publication manifest context differs".into());
    }
    let count = usize::from(u16::from_be_bytes(array(&mut input)?));
    if count != 2 {
        return Err("Reusable publication requires exactly two roles".into());
    }
    let mut requests = BTreeSet::new();
    for _ in 0..count {
        let request = array::<32>(&mut input)?;
        if request == [0; 32] || !requests.insert(request) {
            return Err("Duplicate or zero inventory identity".into());
        }
    }
    let mut proofs = BTreeMap::new();
    for index in 0..count {
        let length = usize::from(u16::from_be_bytes(array(&mut input)?));
        if !(62..=1534).contains(&length) {
            return Err("Publication proof bound".into());
        }
        let mut encoded = vec![0; length];
        input.read_exact(&mut encoded)?;
        if encoded.get(..2) != Some(u16::try_from(index)?.to_be_bytes().as_slice()) {
            return Err("Publication proof order differs".into());
        }
        let proof = sdk::LeafProof::decode(&encoded)?;
        if proofs
            .insert(checked.verify_leaf(&proof, now)?.kind() as u8, proof)
            .is_some()
        {
            return Err("Duplicate publication role".into());
        }
    }
    if usize::try_from(input.position())? != wire.len()
        || proofs.keys().copied().collect::<BTreeSet<_>>() != BTreeSet::from([1, 3])
    {
        return Err("Publication content differs".into());
    }
    let selection = checked.select_prekeys(
        proofs.get(&1).ok_or("Missing classical member")?,
        proofs.get(&3).ok_or("Missing PQ member")?,
        sdk::ClassicalChoice::SignedOnly,
        sdk::PqChoice::LastResort,
        now,
    )?;
    policy.check_mode(sdk::PrekeyQuality::ReusableBoth, now)?;
    if selection.quality() != sdk::PrekeyQuality::ReusableBoth {
        return Err("Publication selection differs".into());
    }
    Ok(())
}
