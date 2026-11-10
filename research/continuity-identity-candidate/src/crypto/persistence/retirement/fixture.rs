// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual journal replacement and signed host acknowledgement for file-layer tests.
use super::super::*;
use crate::{
    AccountPin, AnchorIdentity, AnchorRetiredCleanupProposal, AnchorSigningKey, AnchorStore,
    DeviceJournal, DeviceSigningKey, JournalIdentity, PrekeyQuality, RootSigningKey,
};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::path::PathBuf;

pub(super) struct Case {
    pub(super) key: JournalKey,
    pub(super) identity: SigningKeyId,
    pub(super) original: VerifiedDevice,
    pub(super) ack: AnchorRetiredReportAcknowledgement,
    pub(super) path: PathBuf,
    pub(super) storage: crate::storage::Storage,
    _directory: tempfile::TempDir,
}
impl Case {
    pub(super) fn new() -> Self {
        #[cfg(unix)]
        let directory = crate::durable::tests::directory();
        #[cfg(windows)]
        let directory = crate::windows_key_reopen::directory();
        let root = directory.path().canonicalize().expect("private root");
        let key = JournalKey::provision(&root.join("key")).expect("original wrapping key");
        let identity = SigningKeyId::generate().expect("signer identity");
        let path = root.join("signer");
        let device_signer =
            DeviceSigningKey::provision(&path, &key, identity).expect("device signer");
        let wrapping = JournalKey::provision(&root.join("witness-key")).expect("witness wrapping");
        let signer = AnchorSigningKey::provision(
            &root.join("witness-signer"),
            &wrapping,
            SigningKeyId::generate().expect("witness id"),
        )
        .expect("witness signer");
        let mut witness = AnchorStore::provision(
            &root.join("witness.redb"),
            wrapping,
            signer,
            AnchorIdentity::generate().expect("instance"),
        )
        .expect("witness store");
        let pin = witness.pin().expect("witness pin");
        let peers = crate::bootstrap::tests::fixture_with_signers_and_anchor(
            PrekeyQuality::OneTimeBoth,
            None,
            (
                DeviceSigningKey::generate().expect("initiator signer"),
                device_signer,
            ),
            crate::AnchorRequirement::required(&pin),
        );
        let (policy, original, _) = peers.responder.inventory_inputs().expect("verified inputs");
        let mut original_journal = journal(&root, "original", original, policy);
        let genesis = original_journal
            .anchor_genesis(original, policy)
            .expect("original genesis");
        witness
            .enroll(&genesis, original, policy, 150)
            .expect("enroll original");
        let authority =
            RootSigningKey::deterministic([94; 32], [95; 32]).expect("same account root");
        let next_signer = DeviceSigningKey::generate().expect("successor signer");
        let mut description = original.description.clone();
        description.generation = 2;
        let certificate = authority
            .issue_device(
                description.clone(),
                next_signer.public_key().expect("public"),
            )
            .expect("successor certificate");
        let roster = authority
            .issue_roster(
                2,
                original.roster_validity,
                &[authority.roster_entry(&certificate).expect("roster member")],
            )
            .expect("successor roster");
        let account = AccountPin::new(
            authority.account_id().expect("account"),
            authority.public_key().expect("root public"),
            roster.checkpoint(),
            description.family,
        )
        .expect("account pin");
        let successor = account
            .verify_device(&certificate, roster.as_bytes(), 150)
            .expect("verified successor");
        let mut next_journal = journal(&root, "successor", &successor, policy);
        let next_genesis = next_journal
            .anchor_genesis(&successor, policy)
            .expect("successor genesis");
        let predecessors = [(
            genesis.subject(),
            original.roster().checkpoint(),
            policy.historical(),
        )];
        let replacement = witness
            .device_replacement_proposal(&next_genesis, &successor, policy, &predecessors, 150)
            .expect("replacement proposal");
        assert_eq!(
            witness
                .replace_device(
                    &replacement,
                    &next_genesis,
                    &successor,
                    policy,
                    &predecessors,
                    150
                )
                .expect("replace original"),
            crate::AnchorDeviceReplacementState::Committed
        );
        let receipt = witness
            .retired_subject_receipt(&replacement, genesis.subject())
            .expect("retired receipt");
        let retired = pin
            .verify_retired_subject(&replacement, genesis.subject(), &receipt)
            .expect("verified retirement");
        let inventory = AnchorRetiredCleanupProposal::from_journal(
            retired,
            retired.observed_head().digest(),
            None,
        )
        .expect("exact empty journal inventory");
        // This test controller's expected component report ID exercises real
        // retention/ACK signing; it does not stand in for a managed loss report.
        let report = AnchorRetiredReportProposal::from_report(inventory.clone(), [171; 32])
            .expect("component report");
        witness
            .retain_retired_cleanup(&inventory)
            .expect("retain inventory");
        witness
            .retain_retired_report(&report)
            .expect("retain report");
        witness
            .acknowledge_retired_report(&report)
            .expect("host acknowledgement");
        let wire = witness
            .retired_report_acknowledgement_receipt(&report)
            .expect("signed host receipt");
        let ack = pin
            .verify_retired_report_acknowledgement(retired, &report, &wire)
            .expect("authenticated host ACK");
        Self {
            key,
            identity,
            original: original.clone(),
            ack,
            path,
            storage: crate::storage::Storage::native().expect("native storage"),
            _directory: directory,
        }
    }
    pub(super) fn capture(&self, path: &Path) -> SigningFilePlan {
        SigningFilePlan::capture(
            &self.storage,
            path,
            &self.key,
            self.identity,
            &self.original,
            &self.ack,
        )
        .expect("capture exact authorized signer file")
    }
    pub(super) fn erase(&self, plan: &SigningFilePlan, path: &Path) -> Result<(), DurableError> {
        plan.erase(&self.storage, path, &self.key, &self.original, &self.ack)
    }
    pub(super) fn erased(&self, plan: &SigningFilePlan, path: &Path) -> Result<bool, DurableError> {
        plan.erased(&self.storage, path, &self.key, &self.original, &self.ack)
    }
}

fn journal(
    root: &Path,
    name: &str,
    device: &VerifiedDevice,
    policy: &crate::VerifiedSessionPolicy,
) -> DeviceJournal {
    let identity = JournalIdentity::generate().expect("independent journal identity");
    publish_private_bytes(&root.join(format!("{name}.id")), identity.as_bytes())
        .expect("retain identity before creation");
    let key = JournalKey::provision(&root.join(format!("{name}.key"))).expect("journal wrapping");
    DeviceJournal::provision_anchored(
        &root.join(format!("{name}.redb")),
        key,
        device,
        policy,
        identity,
        150,
    )
    .expect("journal")
}
