// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "process.rs"]
mod process;
#[path = "sync.rs"]
mod sync;
#[path = "validation.rs"]
mod validation;

struct RecoveryCase {
    c: PolicyCase,
    source: TargetFixture,
    prior_retirement: Vec<u8>,
    active: AnchorStore,
    history: AnchorHandoffHistory,
    next: TargetFixture,
    acknowledgement: Vec<u8>,
    before: Vec<u8>,
    proposal: crate::AnchorPolicyRenewalProposal,
}
impl RecoveryCase {
    fn new(archived_source: bool) -> Self {
        let mut c = PolicyCase::new();
        let proof = c.approval(&c.original, None, &c.target);
        let proposal = c.proposal(&proof, c.initial, 241);
        c.prepare(proposal, &proof).expect("original actual P");
        let device = c.device.clone();
        let policy = c.original.clone();
        let (f, mut next) = next_from(Prepared::from_case(c, device, policy), true);
        let Prepared {
            c,
            f: mut source,
            retired: mut prior_retirement,
            mut active,
            mut history,
            ..
        } = f;
        if archived_source {
            let mut target = next.provision();
            let ack = target.import_receipt().expect("C import");
            let retired = active
                .retire_handoff(&next.approval, ack.as_bytes(), || Ok(185))
                .expect("B already retired before C-D test");
            history = target
                .verify_source_retirement(retired.as_bytes())
                .expect("C history");
            let (mut current, receipt) = target
                .activate(retired.as_bytes(), next.signer())
                .expect("C already active");
            fresh_grant(
                &c,
                &mut current,
                &c.device,
                &c.original,
                &history,
                &receipt,
                186,
            );
            active.close();
            active = current;
            source = next;
            prior_retirement = retired.as_bytes().to_vec();
            let root = c.server.join("recovery-next");
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .expect("owned D root");
            next = TargetFixture::from_store_operation(
                &mut active,
                &root,
                &source.pin,
                190,
                false,
                249,
            );
        }
        let before = image_codec::encode_content(
            &history,
            &active.handoff_image().expect("complete frozen source"),
        )
        .expect("unchanged original GPR image");
        let mut target = next.provision();
        let acknowledgement = target
            .import_receipt()
            .expect("committed import")
            .as_bytes()
            .to_vec();
        target.close();
        fs::write(source.directory.join("retirement"), &prior_retirement)
            .expect("original source activation input");
        fs::write(next.directory.join("ack"), &acknowledgement).expect("exact imported receipt");
        Self {
            c,
            source,
            prior_retirement,
            active,
            history,
            next,
            acknowledgement,
            before,
            proposal,
        }
    }
    fn reopen_source(&mut self) {
        self.active.close();
        self.active = self
            .source
            .open()
            .activate(&self.prior_retirement, self.source.signer())
            .expect("same existing source owner")
            .0;
    }
    fn retire(&mut self) -> AnchorHandoffReceipt {
        self.active
            .retire_handoff(&self.next.approval, &self.acknowledgement, || {
                Ok(self.next.now)
            })
            .expect("exact original retirement retry")
    }
    fn check_source(&mut self, retirement: &AnchorHandoffReceipt) {
        assert_eq!(retirement.state(), AnchorHandoffState::Retired);
        assert_eq!(
            self.active
                .observe_handoff(&self.next.plan)
                .expect("retained decision")
                .as_bytes(),
            retirement.as_bytes()
        );
        assert_eq!(
            self.active
                .frozen_handoff_state(&self.next.plan)
                .expect("complete original archive")
                .as_bytes(),
            self.next.source
        );
        assert_eq!(
            image_codec::encode_content(
                &self.history,
                &self.active.handoff_image().expect("retired data")
            )
            .expect("original image"),
            self.before
        );
        assert!(matches!(
            self.active.cancel_handoff(&self.next.plan),
            Err(DurableError::Protocol(Error::Retired))
        ));
        let mut clock_calls = 0;
        assert_eq!(
            self.active
                .retire_handoff(&self.next.approval, &self.acknowledgement, || {
                    clock_calls += 1;
                    Err(std::io::Error::other("historical retry clock unavailable"))
                })
                .expect("exact decision")
                .as_bytes(),
            retirement.as_bytes()
        );
        assert_eq!(clock_calls, 0, "historical retry cannot consult the clock");
    }
    fn finish(&mut self, retirement: &AnchorHandoffReceipt, prior: Option<&[u8]>) {
        self.check_source(retirement);
        let mut target = self.next.open();
        assert_eq!(
            target
                .retained_source_state()
                .expect("full original source"),
            self.next.source
        );
        let history = target
            .verify_source_retirement(retirement.as_bytes())
            .expect("full chain");
        assert_eq!(history.sequence(), self.history.sequence() + 1);
        assert_eq!(history.namespace_binding(), self.c.pin.binding());
        let (mut current, activation) = target
            .activate(retirement.as_bytes(), self.next.signer())
            .expect("recover original activation");
        if let Some(prior) = prior {
            assert_eq!(activation.as_bytes(), prior);
        }
        assert_eq!(
            image_codec::encode_content(
                &history,
                &current.handoff_image().expect("recovered complete image")
            )
            .expect("same image"),
            self.before
        );
        let (approved, request, grant) = fresh_grant(
            &self.c,
            &mut current,
            &self.c.device,
            &self.c.original,
            &history,
            &activation,
            self.next.now + 1,
        );
        let authority = Authority::verified(&approved, &history, grant.as_bytes(), &request)
            .expect("fresh dual-authorized current witness");
        let archive = archived_bytes(&current);
        crate::anchor::store::handoff::take_archive_reads();
        for (operation, state) in [
            (
                AnchorOperation::policy_renewal_status(&self.proposal),
                crate::AnchorPolicyRenewalState::Prepared,
            ),
            (
                AnchorOperation::commit_policy_renewal(&self.proposal),
                crate::AnchorPolicyRenewalState::Applied,
            ),
            (
                AnchorOperation::commit_policy_renewal(&self.proposal),
                crate::AnchorPolicyRenewalState::Applied,
            ),
        ] {
            let request = authority
                .request(self.c.subject, operation, &self.c.signer)
                .expect("fresh challenge");
            let wire = current
                .handle(request.as_bytes(), self.next.now + 1)
                .expect("original P through recovered owner");
            let reply = authority
                .verify(&request, &wire)
                .expect("current signer, original logical ID");
            assert_eq!(
                reply
                    .policy_renewal_state(&self.proposal)
                    .expect("original exact P"),
                state
            );
            assert_eq!(reply.logical_witness_binding(), self.c.pin.binding());
            assert_eq!(reply.signing_witness_binding(), self.next.pin.binding());
        }
        assert_eq!(crate::anchor::store::handoff::take_archive_reads(), 0);
        assert_eq!(archived_bytes(&current), archive);
        current.close();
        let mut observer = self.next.open();
        assert_eq!(
            observer
                .activation_receipt()
                .expect("cold exact activation")
                .as_bytes(),
            activation.as_bytes()
        );
        assert_eq!(
            observer
                .retained_source_state()
                .expect("cold original archive"),
            self.next.source
        );
    }
}
