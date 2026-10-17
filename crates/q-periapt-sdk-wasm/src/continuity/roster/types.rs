// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::continuity::status::Checkpoint;

/// Current root-approved same-credential target, checked against an independent pin.
#[wasm_bindgen(js_name = QPeriaptContinuityRosterTarget)]
pub struct Target {
    pub(super) inner: engine::VerifiedDevice,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRosterTarget)]
impl Target {
    #[wasm_bindgen(constructor)]
    pub fn new(
        trust: &AccountTrust,
        certificate: &Uint8Array,
        roster: &Uint8Array,
        #[wasm_bindgen(unchecked_param_type = "bigint")] now: JsValue,
    ) -> Result<Target, JsValue> {
        Ok(Self {
            inner: trust
                .inner
                .verify_device(
                    &read_input(certificate, 1, 8192)?,
                    &read_input(roster, 1, 8192)?,
                    read_time(now)?,
                )
                .map_err(protocol)?,
        })
    }
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            inner: self.inner.roster().checkpoint(),
        }
    }
}
/// Canonical public expectations of one exact sealed target; parsing grants no authority.
#[wasm_bindgen(js_name = QPeriaptContinuityRosterProposal)]
pub struct Proposal {
    pub(super) inner: engine::AnchorRosterRefreshProposal,
}
#[wasm_bindgen(js_class = QPeriaptContinuityRosterProposal)]
impl Proposal {
    /// Restore original retained bytes. The original enrollment and witness must
    /// still match the entire proposal before any action can succeed.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &Uint8Array) -> Result<Proposal, JsValue> {
        Ok(Self {
            inner: engine::AnchorRosterRefreshProposal::from_trusted_state(&read_input(
                bytes, 417, 417,
            )?)
            .map_err(protocol)?,
        })
    }
    pub fn new_operation_id() -> Result<Vec<u8>, JsValue> {
        Ok(engine::RosterRefreshId::generate()
            .map_err(protocol)?
            .as_bytes()
            .to_vec())
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
    pub fn binding(&self) -> Vec<u8> {
        self.inner.binding().to_vec()
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.scope().operation.as_bytes().to_vec()
    }
    pub fn previous(&self) -> Checkpoint {
        Checkpoint {
            inner: self.inner.scope().previous,
        }
    }
    pub fn target(&self) -> Checkpoint {
        Checkpoint {
            inner: self.inner.scope().target,
        }
    }
}
/// Local original coordination stage, separate from current traffic admission.
#[wasm_bindgen(js_name = QPeriaptContinuityWitnessRosterStage)]
pub enum Stage {
    Staged = 1,
    AbandonedBeforePreparation = 2,
    Reserved = 3,
    Applied = 4,
    Closed = 5,
}
/// Exact witness observation. Unavailable and Acknowledged never mean uncommitted.
#[wasm_bindgen(js_name = QPeriaptContinuityWitnessRosterState)]
pub enum WitnessState {
    Prepared = 1,
    Applied = 2,
    Closed = 3,
    Acknowledged = 4,
    Unavailable = 5,
}
impl From<engine::AnchorRosterRefreshState> for WitnessState {
    fn from(value: engine::AnchorRosterRefreshState) -> Self {
        match value {
            engine::AnchorRosterRefreshState::Prepared => Self::Prepared,
            engine::AnchorRosterRefreshState::Applied => Self::Applied,
            engine::AnchorRosterRefreshState::Closed => Self::Closed,
            engine::AnchorRosterRefreshState::Acknowledged => Self::Acknowledged,
            engine::AnchorRosterRefreshState::Unavailable => Self::Unavailable,
        }
    }
}
/// Authenticated local snapshot. Keep its exact operation across unknown outcomes.
#[wasm_bindgen(js_name = QPeriaptContinuityWitnessRosterProgress)]
pub struct Progress {
    pub(super) inner: engine::WitnessedRosterRefreshProgress,
}
impl Progress {
    fn scope(&self) -> engine::RosterRefreshScope {
        match self.inner {
            engine::WitnessedRosterRefreshProgress::Staged(scope)
            | engine::WitnessedRosterRefreshProgress::AbandonedBeforePreparation(scope) => scope,
            engine::WitnessedRosterRefreshProgress::Reserved(p)
            | engine::WitnessedRosterRefreshProgress::Terminal { proposal: p, .. } => *p.scope(),
        }
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityWitnessRosterProgress)]
impl Progress {
    pub fn stage(&self) -> Stage {
        use engine::{WitnessedRosterRefreshDisposition as D, WitnessedRosterRefreshProgress as P};
        match self.inner {
            P::Staged(_) => Stage::Staged,
            P::AbandonedBeforePreparation(_) => Stage::AbandonedBeforePreparation,
            P::Reserved(_) => Stage::Reserved,
            P::Terminal {
                disposition: D::Applied,
                ..
            } => Stage::Applied,
            P::Terminal {
                disposition: D::Closed,
                ..
            } => Stage::Closed,
        }
    }
    /// Whether local original pending cleanup finished; never remote removal or permission.
    pub fn retired(&self) -> bool {
        match self.inner {
            engine::WitnessedRosterRefreshProgress::AbandonedBeforePreparation(_) => true,
            engine::WitnessedRosterRefreshProgress::Terminal { retired, .. } => retired,
            _ => false,
        }
    }
    pub fn operation_id(&self) -> Vec<u8> {
        self.scope().operation.as_bytes().to_vec()
    }
    pub fn previous(&self) -> Checkpoint {
        Checkpoint {
            inner: self.scope().previous,
        }
    }
    pub fn target(&self) -> Checkpoint {
        Checkpoint {
            inner: self.scope().target,
        }
    }
    pub fn proposal(&self) -> Option<Proposal> {
        match self.inner {
            engine::WitnessedRosterRefreshProgress::Reserved(inner)
            | engine::WitnessedRosterRefreshProgress::Terminal {
                proposal: inner, ..
            } => Some(Proposal { inner }),
            _ => None,
        }
    }
}
