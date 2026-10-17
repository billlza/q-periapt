// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_periapt_core::{Xof256, SHARED_SECRET_LEN};
use sha3::{Digest, Sha3_256};

/// Allocation-free incremental SHA3-256 for large ContextBound transcripts.
///
/// Uses RustCrypto's sponge and standard padding. The `sha3/zeroize` feature
/// erases both the Keccak state and sponge cursor on drop. Version 0.12 absorbs
/// directly into the sponge, so there is no separate residual block to erase.
/// It never stores a full transcript. Compiler/primitive internal copies are
/// outside this owner-level guarantee, as with the existing primitive backends.
pub struct StreamingSha3_256Xof {
    hash: Sha3_256,
}

impl Default for StreamingSha3_256Xof {
    fn default() -> Self {
        Self::new()
    }
}

impl Xof256 for StreamingSha3_256Xof {
    fn new() -> Self {
        Self {
            hash: Sha3_256::new(),
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    fn squeeze32(self) -> [u8; SHARED_SECRET_LEN] {
        self.hash.finalize().into()
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
