// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{HistoricalSessionPolicy, PolicyCheckpoint, PolicyPin, RosterCheckpoint};
use std::{
    fs,
    path::{Path, PathBuf},
};

// Public outputs and independently retained trust pins produced by the older
// implementation at the commit recorded in PROVENANCE.json. Loading this corpus
// constructs no SDK runtime, signing key, current policy or device service.
struct Corpus {
    directory: PathBuf,
    bundle: BootstrapBundle,
    policy: Arc<HistoricalSessionPolicy>,
    initiator: AccountPin,
    responder: AccountPin,
    quality: PrekeyQuality,
}
fn array<const N: usize>(directory: &Path, name: &str) -> [u8; N] {
    fs::read(directory.join(name))
        .expect("public corpus input")
        .try_into()
        .expect("exact public width")
}
impl Corpus {
    fn load(quality: PrekeyQuality) -> Self {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/historical-context")
            .join(format!("{}", quality as u8));
        let family = array(&directory, "policy-family.bin");
        let pin = PolicyPin::new(
            family,
            crate::PublicKey::decode(
                &fs::read(directory.join("policy-root.bin")).expect("public root"),
            )
            .expect("root encoding"),
            PolicyCheckpoint::from_trusted_state(
                u64::from_be_bytes(array(&directory, "policy-version.bin")),
                array(&directory, "policy-digest.bin"),
            )
            .expect("independent policy checkpoint"),
        )
        .expect("independent policy pin");
        let policy = Arc::new(
            pin.verify_historical(
                &fs::read(directory.join("policy-wire.bin")).expect("original signed P0"),
            )
            .expect("historical signature verification without runtime"),
        );
        let account = |label: &str| {
            AccountPin::new(
                array(&directory, &format!("{label}-account.bin")),
                crate::PublicKey::decode(
                    &fs::read(directory.join(format!("{label}-root.bin")))
                        .expect("public account root"),
                )
                .expect("root encoding"),
                RosterCheckpoint::from_trusted_state(
                    u64::from_be_bytes(array(&directory, &format!("{label}-roster-version.bin"))),
                    array(&directory, &format!("{label}-roster-digest.bin")),
                )
                .expect("independent roster checkpoint"),
                family,
            )
            .expect("independent account pin")
        };
        let initiator = account("initiator");
        let responder = account("responder");
        let bundle = BootstrapBundle::from_bytes(
            &fs::read(directory.join("bundle.bin")).expect("original bundle"),
        )
        .expect("outer grammar");
        Self {
            directory,
            bundle,
            policy,
            initiator,
            responder,
            quality,
        }
    }
    fn requirements(&self) -> BootstrapRequirements<'_> {
        let expected = |account, label: &str| {
            ExpectedDevice::new(
                account,
                array(&self.directory, &format!("{label}-device.bin")),
                u64::from_be_bytes(array(&self.directory, &format!("{label}-generation.bin"))),
            )
            .expect("independent exact device")
        };
        BootstrapRequirements {
            initiator: expected(&self.initiator, "initiator"),
            responder: expected(&self.responder, "responder"),
            quality: self.quality,
            directory: DirectoryExpectation::from_trusted_state(array(
                &self.directory,
                "directory.bin",
            ))
            .expect("independent directory"),
        }
    }
}
const QUALITIES: [PrekeyQuality; 4] = [
    PrekeyQuality::OneTimeBoth,
    PrekeyQuality::ReusableBoth,
    PrekeyQuality::SignedClassicalOneTimePq,
    PrekeyQuality::OneTimeClassicalLastResortPq,
];

#[test]
fn historical_request_matches_old_contexts_after_policy_expiry_without_a_runtime() {
    for quality in QUALITIES {
        let c = Corpus::load(quality);
        assert!(matches!(
            c.policy.validity().check(250),
            Err(Error::Validity)
        ));
        for role in [BootstrapRole::Initiator, BootstrapRole::Responder] {
            let request = c
                .bundle
                .request_historical_reopen(
                    Arc::clone(&c.policy),
                    c.requirements(),
                    role,
                    [17; 32],
                    250,
                )
                .expect("authenticate original expired snapshot only");
            assert_eq!(
                request.context.digest(),
                array(&c.directory, "context-digest.bin")
            );
            assert_eq!(
                request
                    .context
                    .original_policy()
                    .application_send_budget()
                    .messages(),
                u16::from_be_bytes(array(&c.directory, "send-budget.bin"))
            );
            assert_eq!(request.session, [17; 32]);
            assert_eq!(request.role, role);
            assert!(matches!(
                request.context.current_policy(),
                Err(Error::Scope)
            ));
            assert!(matches!(
                request.context.inventory_inputs(),
                Err(Error::Scope)
            ));
            for now in [150, 250] {
                assert!(matches!(request.context.check(now), Err(Error::Scope)));
                assert!(matches!(
                    request.context.check_session_identity(now),
                    Err(Error::Scope)
                ));
                assert!(matches!(
                    request.context.require_fresh_identity(now),
                    Err(Error::Scope)
                ));
            }
        }
    }
}

#[test]
fn historical_request_still_authenticates_every_signed_material_and_proof() {
    for quality in QUALITIES {
        let c = Corpus::load(quality);
        let original = fields(&c.bundle);
        for (index, field) in original
            .iter()
            .enumerate()
            .filter(|(_, field)| !field.is_empty())
        {
            let mut changed = original.clone();
            assert!(!field.is_empty());
            *changed
                .get_mut(index)
                .expect("field")
                .last_mut()
                .expect("nonempty") ^= 1;
            assert!(
                untrusted(&changed, quality)
                    .request_historical_reopen(
                        Arc::clone(&c.policy),
                        c.requirements(),
                        BootstrapRole::Initiator,
                        [17; 32],
                        250,
                    )
                    .is_err(),
                "unverified historical field {index}, quality {}",
                quality as u8
            );
        }
    }
}

#[test]
fn historical_request_preserves_independent_scope_pins_and_snapshot_intersection() {
    let c = Corpus::load(PrekeyQuality::OneTimeBoth);
    let request = |required, session, now| {
        c.bundle.request_historical_reopen(
            Arc::clone(&c.policy),
            required,
            BootstrapRole::Initiator,
            session,
            now,
        )
    };
    assert!(request(c.requirements(), [0; 32], 250).is_err());
    assert!(matches!(
        request(c.requirements(), [17; 32], 99),
        Err(Error::Validity)
    ));
    let mut required = c.requirements();
    required.directory =
        DirectoryExpectation::from_trusted_state([98; 32]).expect("wrong directory");
    assert!(matches!(
        request(required, [17; 32], 250),
        Err(Error::Scope)
    ));
    let mut required = c.requirements();
    required.quality = PrekeyQuality::ReusableBoth;
    assert!(matches!(
        request(required, [17; 32], 250),
        Err(Error::Scope)
    ));
    let mut required = c.requirements();
    required.responder = ExpectedDevice::new(&c.responder, [94; 16], 2).expect("wrong generation");
    assert!(matches!(
        request(required, [17; 32], 250),
        Err(Error::Scope)
    ));
    let wrong = AccountPin::new(
        array(&c.directory, "responder-account.bin"),
        crate::PublicKey::decode(&fs::read(c.directory.join("responder-root.bin")).expect("root"))
            .expect("encoding"),
        RosterCheckpoint::from_trusted_state(1, [77; 32]).expect("wrong head"),
        c.policy.family(),
    )
    .expect("same authority different independent head");
    let mut required = c.requirements();
    required.responder = ExpectedDevice::new(&wrong, [94; 16], 1).expect("same identity");
    assert!(matches!(
        request(required, [17; 32], 250),
        Err(Error::Checkpoint)
    ));
}
