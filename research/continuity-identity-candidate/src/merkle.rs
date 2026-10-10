// SPDX-License-Identifier: Apache-2.0 OR MIT
use crate::{crypto::digest, Error};

fn split(length: usize) -> Result<usize, Error> {
    if !(2..=1024).contains(&length) {
        return Err(Error::Encoding);
    }
    let mut value = 1;
    while value * 2 < length {
        value *= 2;
    }
    Ok(value)
}

fn join(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(&left);
    body.extend_from_slice(&right);
    digest(b"Q-PERIAPT-CONTINUITY-PREKEY-NODE-CANDIDATE/v1", &body)
}

pub(crate) fn root(leaves: &[[u8; 32]]) -> Result<[u8; 32], Error> {
    if leaves.len() == 1 {
        return leaves.first().copied().ok_or(Error::Encoding);
    }
    let split = split(leaves.len())?;
    let left = leaves.get(..split).ok_or(Error::Encoding)?;
    let right = leaves.get(split..).ok_or(Error::Encoding)?;
    Ok(join(root(left)?, root(right)?))
}

pub(crate) fn proof(leaves: &[[u8; 32]], index: usize) -> Result<Vec<[u8; 32]>, Error> {
    if index >= leaves.len() {
        return Err(Error::Encoding);
    }
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }
    let split = split(leaves.len())?;
    let left = leaves.get(..split).ok_or(Error::Encoding)?;
    let right = leaves.get(split..).ok_or(Error::Encoding)?;
    let mut path = if index < split {
        proof(left, index)?
    } else {
        proof(right, index - split)?
    };
    path.push(if index < split {
        root(right)?
    } else {
        root(left)?
    });
    Ok(path)
}

pub(crate) fn reconstruct(
    leaf: [u8; 32],
    index: usize,
    length: usize,
    path: &[[u8; 32]],
) -> Result<[u8; 32], Error> {
    if index >= length || path.len() > 10 {
        return Err(Error::Encoding);
    }
    if length == 1 {
        return if path.is_empty() {
            Ok(leaf)
        } else {
            Err(Error::Encoding)
        };
    }
    let split = split(length)?;
    let (sibling, rest) = path.split_last().ok_or(Error::Encoding)?;
    if index < split {
        Ok(join(reconstruct(leaf, index, split, rest)?, *sibling))
    } else {
        Ok(join(
            *sibling,
            reconstruct(leaf, index - split, length - split, rest)?,
        ))
    }
}
