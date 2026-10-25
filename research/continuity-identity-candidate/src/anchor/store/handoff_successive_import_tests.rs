// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "handoff_successive_import_tests/recovery.rs"]
mod recovery;
#[path = "handoff_successive_import_tests/validation.rs"]
mod validation;

fn setup(kind: &str, applied: bool, cancelled_before: bool) -> (Prepared, TargetFixture) {
    next_from(Prepared::new(Some((kind, applied))), cancelled_before)
}
fn next_from(mut f: Prepared, cancelled_before: bool) -> (Prepared, TargetFixture) {
    f.active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("existing B client approval");
    let directory = f.c.server.join("next-import");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .expect("independent C directory");
    let wrapping = JournalKey::provision(&directory.join("wrapping")).expect("C storage key");
    let signer = AnchorSigningKey::provision(&directory.join("signer"), &wrapping, target_key_id())
        .expect("C signer");
    let pin = AnchorPin::new(
        AnchorIdentity::generate().expect("C identity"),
        signer.public_key().expect("C key"),
    );
    if cancelled_before {
        let source = f
            .active
            .handoff_source_state()
            .expect("earlier exact capture");
        let plan = AnchorHandoffPlan::from_trusted_state(
            [243; 32],
            &source,
            pin.clone(),
            Validity::new(180, 200).expect("window"),
            [244; 32],
        )
        .expect("earlier independent plan");
        f.active.freeze_handoff(&plan, 181).expect("earlier freeze");
        f.active
            .cancel_handoff(&plan)
            .expect("exact earlier cancellation");
    }
    let source = f
        .active
        .handoff_source_state()
        .expect("complete unresolved B state");
    let plan = AnchorHandoffPlan::from_trusted_state(
        [245; 32],
        &source,
        pin.clone(),
        Validity::new(180, 200).expect("source window"),
        [246; 32],
    )
    .expect("independent B operator approval");
    let approval = AnchorHandoffTargetApproval::from_trusted_state(
        &plan,
        &f.f.pin,
        &pin,
        Validity::new(180, 200).expect("target window"),
        [247; 32],
    )
    .expect("independent C operator approval");
    let freeze = f
        .active
        .freeze_handoff(&plan, 185)
        .expect("B source committed freeze");
    for (name, pin) in [("source-pin", &f.f.pin), ("target-pin", &pin)] {
        fs::write(
            directory.join(name),
            [
                pin.identity().as_bytes().as_slice(),
                &pin.public_key().encode(),
            ]
            .concat(),
        )
        .expect("independently retained pin");
    }
    fs::write(directory.join("approval"), approval.to_bytes()).expect("retained approval");
    fs::write(directory.join("source"), source.as_bytes()).expect("complete source");
    fs::write(directory.join("freeze"), freeze.as_bytes()).expect("original freeze");
    let next = TargetFixture {
        now: 185,
        directory,
        plan,
        approval,
        pin,
        source: source.as_bytes().to_vec(),
        freeze: freeze.as_bytes().to_vec(),
    };
    (f, next)
}

#[test]
fn successive_import_preserves_complete_source_and_exact_cancellation() {
    for kind in ["G", "P", "R"] {
        for applied in [false, true] {
            let (mut f, next) = setup(kind, applied, applied);
            let original = image_codec::encode_content(
                &f.history,
                &f.active.handoff_image().expect("complete original data"),
            )
            .expect("original content");
            let mut target = next.provision();
            assert_eq!(
                target.status().expect("inactive status"),
                AnchorHandoffTargetState::ImportedInactive
            );
            assert_eq!(
                target.retained_source_state().expect("complete source"),
                next.source
            );
            let ack = target.import_receipt().expect("exact C acknowledgement");
            next.approval
                .verify_import_receipt(&next.freeze, ack.as_bytes())
                .expect("C signer and approved plan");
            assert!(matches!(
                target.activate(&f.retired, next.signer()),
                Err(DurableError::Protocol(Error::Scope))
            ));
            target.close();
            let withheld = [next.directory.join("signer"), f.f.directory.join("signer")];
            for path in &withheld {
                fs::rename(path, path.with_extension("withheld"))
                    .expect("withhold owned signer files");
            }
            let mut target = next.open();
            for path in &withheld {
                fs::rename(path.with_extension("withheld"), path)
                    .expect("restore owned signer files");
            }
            assert_eq!(
                target
                    .import_receipt()
                    .expect("exact keyless retry")
                    .as_bytes(),
                ack.as_bytes()
            );
            assert!(matches!(
                f.active.retire_handoff(&next.approval, &[], || Ok(185)),
                Err(DurableError::Protocol(Error::Encoding))
            ));
            let cancelled = f
                .active
                .cancel_handoff(&next.plan)
                .expect("exact source cancellation");
            assert_eq!(
                target
                    .close_cancelled(cancelled.as_bytes())
                    .expect("exact inactive cancellation"),
                AnchorHandoffTargetState::Cancelled
            );
            assert!(matches!(
                target.activate(&f.retired, next.signer()),
                Err(DurableError::Protocol(Error::Retired))
            ));
            assert_eq!(
                target
                    .cancellation_receipt()
                    .expect("retained source decision"),
                cancelled.as_bytes()
            );
            assert_eq!(
                target.retained_source_state().expect("full source remains"),
                next.source
            );
            target.close();
            assert_eq!(
                next.open()
                    .cancellation_receipt()
                    .expect("cold terminal retry"),
                cancelled.as_bytes()
            );
            assert!(f.active.handoff_client_authorization(f.c.subject).is_ok());
            f.reopen();
            assert!(f.active.handoff_source_state().is_ok());
            assert_eq!(
                image_codec::encode_content(
                    &f.history,
                    &f.active.image().expect("same original data")
                )
                .expect("restored content"),
                original
            );
        }
    }
}

#[path = "handoff_successive_activation_tests.rs"]
mod activation;
