// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_periapt_core::{secure_wipe, Xof256, SHARED_SECRET_LEN};
use sha3::{
    digest::{
        core_api::{Buffer, FixedOutputCore, UpdateCore},
        Output,
    },
    Sha3_256Core,
};

/// Allocation-free incremental SHA3-256 for large ContextBound transcripts.
///
/// Uses the pinned RustCrypto core and its standard buffering/padding. The
/// `sha3/zeroize` feature erases the Keccak state on drop; this wrapper also
/// volatile-wipes the entire residual block, which `CoreWrapper` does not erase.
/// It never stores a full transcript. Compiler/primitive internal copies are
/// outside this owner-level guarantee, as with the existing primitive backends.
pub struct StreamingSha3_256Xof {
    core: Sha3_256Core,
    buffer: Buffer<Sha3_256Core>,
}

impl Default for StreamingSha3_256Xof {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StreamingSha3_256Xof {
    fn drop(&mut self) {
        // pad_with_zeros exposes the complete initialized block, including the
        // prefix and stale bytes outside the current logical message length.
        secure_wipe(self.buffer.pad_with_zeros().as_mut_slice());
        // `core`'s Sha3State is wiped by RustCrypto's feature-gated Drop next.
    }
}

impl Xof256 for StreamingSha3_256Xof {
    fn new() -> Self {
        Self {
            core: Sha3_256Core::default(),
            buffer: Buffer::<Sha3_256Core>::default(),
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        let core = &mut self.core;
        self.buffer
            .digest_blocks(data, |blocks| core.update_blocks(blocks));
    }

    fn squeeze32(mut self) -> [u8; SHARED_SECRET_LEN] {
        let mut output = [0u8; SHARED_SECRET_LEN];
        self.core.finalize_fixed_core(
            &mut self.buffer,
            Output::<Sha3_256Core>::from_mut_slice(&mut output),
        );
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    #[test]
    fn incremental_matches_standard_hash_at_rate_and_context_boundaries() {
        for len in [
            0, 1, 32, 134, 135, 136, 137, 271, 272, 273, 4096, 65_536, 68_000,
        ] {
            let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let expected: [u8; 32] = Sha3_256::digest(&input).into();
            for chunk_len in [1, 7, 32, 135, 136, 137, 4096] {
                let mut hash = StreamingSha3_256Xof::new();
                for chunk in input.chunks(chunk_len) {
                    hash.absorb(chunk);
                }
                assert_eq!(hash.squeeze32(), expected, "len={len}, chunk={chunk_len}");
            }
        }
    }
}
