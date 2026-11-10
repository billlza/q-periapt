// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Reuse timeless signature/codec verification within one authenticated image.
use super::{DurableError, VerifiedRoster, MAX_ROSTERS};
use std::sync::Mutex;
use zeroize::Zeroizing;

// This limits encoded cache inputs, not accepted roster size or journal capacity.
// A full cache still runs the same authoritative decoder for every miss.
const MAX_CACHED_ENCODING_BYTES: usize = 64 * 1024;

struct Entry {
    encoded: Zeroizing<Vec<u8>>,
    roster: VerifiedRoster,
}

#[derive(Default)]
struct State {
    entries: Vec<Entry>,
    encoded_bytes: usize,
}

/// Private to one decoded Image, dropped with it and absent from sealed bytes.
/// The complete input includes account, family, checkpoint, root and signed wire.
/// This memo never caches current time, membership, image scope or witness state.
#[derive(Default)]
pub(in crate::durable) struct RosterDecodeCache {
    state: Mutex<State>,
}

impl RosterDecodeCache {
    pub(super) fn decode(&self, encoded: &[u8]) -> Result<VerifiedRoster, DurableError> {
        let cached = {
            let state = self.state.lock().map_err(|_| DurableError::Corrupt)?;
            state
                .entries
                .iter()
                .find(|entry| entry.encoded.as_slice() == encoded)
                .map(|entry| entry.roster.clone())
        };
        if let Some(roster) = cached {
            return Ok(roster);
        }

        // No lock is held while parsing or verifying signatures. Failed decoding
        // is never cached, and all record/image/current-authority checks remain
        // outside this pure historical-input computation.
        let roster =
            VerifiedRoster::from_journal(encoded).map_err(DurableError::InvalidCheckpoint)?;
        let mut state = self.state.lock().map_err(|_| DurableError::Corrupt)?;
        if !state
            .entries
            .iter()
            .any(|entry| entry.encoded.as_slice() == encoded)
            && state.entries.len() < MAX_ROSTERS
        {
            if let Some(total) = state
                .encoded_bytes
                .checked_add(encoded.len())
                .filter(|total| *total <= MAX_CACHED_ENCODING_BYTES)
            {
                state.entries.push(Entry {
                    encoded: Zeroizing::new(encoded.to_vec()),
                    roster: roster.clone(),
                });
                state.encoded_bytes = total;
            }
        }
        Ok(roster)
    }
}

#[cfg(test)]
mod tests;
