// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real imported-state request and issuer tests; no durable client adoption claim.
use super::*;
#[path = "handoff_client_authorization_tests.rs"]
mod authorization;
use crate::anchor::store::policy_renewal::tests::{policy, Case as PolicyCase};
use crate::{
    AnchorHandoffAdoptionApproval as Approval, AnchorHandoffAdoptionId as Id,
    AnchorHandoffAdoptionMaterials as Materials, AnchorHandoffAdoptionScope as Scope,
    AnchorHandoffAdoptionStatement as Statement, HistoricalAnchorHandoffAdoption as Approved,
    HistoricalSessionPolicy, PolicySigningKey, RootSigningKey,
};

fn activated(
    c: &mut PolicyCase,
) -> (
    TargetFixture,
    AnchorStore,
    AnchorHandoffHistory,
    AnchorHandoffActivationReceipt,
) {
    let f = TargetFixture::from_store(&mut c.store, &c.server, &c.pin, 175, false);
    let mut target = f.provision();
    let acknowledgement = target.import_receipt().expect("original exact import");
    let retired = c
        .store
        .retire_handoff(&f.approval, acknowledgement.as_bytes(), || Ok(175))
        .expect("source commit");
    let history = target
        .verify_source_retirement(retired.as_bytes())
        .expect("verified history");
    let (active, receipt) = target
        .activate(retired.as_bytes(), f.signer())
        .expect("target commit");
    (f, active, history, receipt)
}
fn materials<'a>(
    c: &'a PolicyCase,
    current: &'a VerifiedDevice,
    current_policy: &'a HistoricalSessionPolicy,
    history: &'a AnchorHandoffHistory,
    receipt: &'a AnchorHandoffActivationReceipt,
) -> Materials<'a> {
    Materials {
        original_device: &c.device,
        current_device: current,
        original_policy: &c.original,
        current_policy,
        history,
        activation: receipt,
    }
}
fn scope(active: &mut AnchorStore, c: &PolicyCase, m: &Materials<'_>) -> Scope {
    active
        .handoff_adoption_scope(
            Id::generate().expect("operation"),
            c.subject,
            m,
            Validity::new(180, 190).expect("decision window"),
        )
        .expect("actual inherited scope")
}
fn approved(c: &PolicyCase, s: &Scope, m: &Materials<'_>) -> (Approval, Approval, Approved) {
    let statement = Statement::new(s, m, 180).expect("new independent decision");
    let account = c
        .account
        .approve_anchor_handoff_adoption(&statement)
        .expect("account consent");
    let policy = c
        .issuer
        .approve_anchor_handoff_adoption(&statement)
        .expect("separate policy consent");
    let both =
        Approved::from_approvals(&account, &policy, s, m).expect("verify both exact decisions");
    (account, policy, both)
}

#[test]
fn handoff_adoption_approvals_bind_both_roots_and_exact_import_without_granting_service() {
    let mut c = PolicyCase::new();
    let (f, mut active, history, activation) = activated(&mut c);
    let before = fs::read(f.db_path()).expect("original target bytes");
    let m = materials(&c, &c.device, &c.original, &history, &activation);
    let s = scope(&mut active, &c, &m);
    assert_eq!(s.to_bytes().len(), 512);
    assert_eq!(
        Scope::from_trusted_state(&s.to_bytes()).expect("retained scope"),
        s
    );
    assert!(s.operation().as_bytes().iter().any(|byte| *byte != 0));
    assert_eq!(s.subject(), c.subject);
    assert_eq!(s.history_checkpoint(), activation.history_checkpoint());
    let (a, p, both) = approved(&c, &s, &m);
    assert_eq!(both.scope(), &s);
    assert_eq!(
        both.as_bytes().len(),
        crate::MAX_ANCHOR_HANDOFF_ADOPTION_BYTES
    );
    assert!(Approved::from_approvals(&a, &a, &s, &m).is_err());
    assert!(Approved::from_approvals(&p, &a, &s, &m).is_err());
    assert!(Statement::new(&s, &m, 179).is_err());
    assert!(Statement::new(&s, &m, 191).is_err());
    both.check_admission(180).expect("decision interval only");
    assert!(both.check_admission(191).is_err());
    assert!(
        c.original.validity().check(180).is_err(),
        "old policy is actually expired"
    );
    Approved::from_bytes(both.as_bytes(), &s, &m)
        .expect("historical observation remains authenticated");
    let request = AnchorRequest::new(&f.pin, c.subject, AnchorOperation::query(), &c.signer)
        .expect("new target request");
    assert!(matches!(
        active.handle(request.as_bytes(), 180),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
    assert_eq!(
        fs::read(f.db_path()).expect("no decision was silently committed"),
        before
    );
    let repeat = active
        .handoff_adoption_scope(s.operation(), c.subject, &m, s.validity())
        .expect("exact read-only retry");
    assert_eq!(repeat, s);
    active.close();
    let mut reopened = f.open();
    assert_eq!(
        reopened
            .retained_source_state()
            .expect("complete original state"),
        f.source
    );
    assert_eq!(
        reopened
            .activation_receipt()
            .expect("same activation")
            .as_bytes(),
        activation.as_bytes()
    );
}

#[test]
fn handoff_adoption_rejects_scope_substitution_wrong_signer_purpose_and_noncanonical_wire() {
    let mut c = PolicyCase::new();
    let (f, mut active, history, activation) = activated(&mut c);
    let m = materials(&c, &c.device, &c.original, &history, &activation);
    let s = scope(&mut active, &c, &m);
    let statement = Statement::new(&s, &m, 180).expect("decision");
    assert!(RootSigningKey::generate()
        .expect("other account")
        .approve_anchor_handoff_adoption(&statement)
        .is_err());
    assert!(PolicySigningKey::generate()
        .expect("other policy")
        .approve_anchor_handoff_adoption(&statement)
        .is_err());
    let (a, p, both) = approved(&c, &s, &m);
    // Every canonical statement byte is covered, including the pending-entry
    // digest which cannot be inferred from ordinary head equality.
    for index in 0..s.to_bytes().len() {
        let mut changed = s.to_bytes();
        *changed.get_mut(index).expect("inside body") ^= 1;
        if let Ok(other) = Scope::from_trusted_state(&changed) {
            assert!(
                Approved::from_approvals(&a, &p, &other, &m).is_err(),
                "changed byte {index}"
            );
        }
    }
    let wrong_purpose = Approval::from_bytes(
        &envelope(
            &s.to_bytes(),
            &c.account
                .sign(Purpose::PolicyRenewal, &s.to_bytes())
                .expect("owned wrong-domain signature"),
        )
        .expect("envelope"),
    )
    .expect("grammar alone accepts a well-formed envelope");
    assert!(Approved::from_approvals(&wrong_purpose, &p, &s, &m).is_err());
    for bytes in [
        Vec::new(),
        both.as_bytes()
            .get(..both.as_bytes().len() - 1)
            .expect("short")
            .to_vec(),
        [both.as_bytes(), &[0]].concat(),
    ] {
        assert!(Approved::from_bytes(&bytes, &s, &m).is_err());
    }
    let mut signature = a.as_bytes().to_vec();
    *signature.last_mut().expect("signature") ^= 1;
    let changed = Approval::from_bytes(&signature).expect("well-formed tampered signature");
    assert!(Approved::from_approvals(&changed, &p, &s, &m).is_err());
    assert!(Approval::from_bytes(activation.as_bytes()).is_err());
    let mut wrong_materials =
        materials(&c, &c.device, c.target.historical(), &history, &activation);
    assert!(active
        .handoff_adoption_scope(s.operation(), c.subject, &wrong_materials, s.validity())
        .is_err());
    wrong_materials.current_policy = &c.original;
    let other = PolicyCase::new();
    wrong_materials.current_device = &other.device;
    assert!(active
        .handoff_adoption_scope(s.operation(), c.subject, &wrong_materials, s.validity())
        .is_err());
    assert_eq!(
        active
            .pin()
            .expect("ordinary refusals leave owner open")
            .binding(),
        f.pin.binding()
    );
}

fn commit(c: &mut PolicyCase, operation: AnchorOperation) {
    let request = AnchorRequest::new(&c.pin, c.subject, operation, &c.signer)
        .expect("actual signed original command");
    let response = c
        .store
        .handle(request.as_bytes(), 150)
        .expect("actual original transaction");
    c.pin
        .verify_reply(&request, &response)
        .expect("fresh original reply");
}
fn pending(
    c: &mut PolicyCase,
    kind: &str,
    applied: bool,
) -> (VerifiedDevice, HistoricalSessionPolicy) {
    let original = policy(&c.issuer, &c.runtime, &c.pin, 1, 160, 150);
    match kind {
        "G" => {
            let g = crate::anchor::store::policy_renewal::tests::credential_cycle::grant(
                c, &c.device, 2,
            );
            let p = crate::AnchorCredentialRenewalProposal::from_journal(
                c.pin.binding(),
                c.subject,
                g.operation(),
                g.statement_digest(),
                c.initial,
                AnchorHead::from_trusted_state(1, 2, [243; 32]).expect("explicit component target"),
            )
            .expect("original G");
            c.store
                .prepare_credential_renewal(p, &g, &original, 150)
                .expect("real pending G");
            if applied {
                commit(c, AnchorOperation::commit_credential_renewal(&p));
            }
            (
                if applied {
                    g.successor_device().clone()
                } else {
                    c.device.clone()
                },
                c.original.clone(),
            )
        }
        "P" => {
            let approval = c.approval(&c.original, None, &c.target);
            let p = c.proposal(&approval, c.initial, 244);
            c.prepare(p, &approval).expect("real pending P");
            if applied {
                c.exchange(&p, AnchorOperation::commit_policy_renewal(&p), 170);
            }
            (
                c.device.clone(),
                if applied {
                    c.target.historical().clone()
                } else {
                    c.original.clone()
                },
            )
        }
        _ => {
            assert_eq!(kind, "R");
            let roster = c
                .account
                .issue_roster(
                    2,
                    Validity::new(100, 400).expect("roster validity"),
                    &[c.account
                        .roster_entry(&c.certificate)
                        .expect("unchanged credential")],
                )
                .expect("signed roster");
            let next = crate::AccountPin::new(
                c.device.account_id(),
                c.account.public_key().expect("root"),
                roster.checkpoint(),
                c.original.family(),
            )
            .expect("independent pin")
            .verify_device(&c.certificate, roster.as_bytes(), 150)
            .expect("actual roster proof");
            let p = crate::AnchorRosterRefreshProposal::from_journal(
                c.pin.binding(),
                c.subject,
                crate::RosterRefreshScope {
                    operation: crate::RosterRefreshId::generate().expect("R operation"),
                    previous: c.device.roster().checkpoint(),
                    target: next.roster().checkpoint(),
                    policy: c.original.checkpoint(),
                    policy_authorization: None,
                },
                c.initial,
                AnchorHead::from_trusted_state(1, 2, [245; 32]).expect("explicit component target"),
            )
            .expect("original R");
            c.store
                .prepare_roster_refresh(p, &c.device, &next, &original, 150)
                .expect("real pending R");
            if applied {
                commit(c, AnchorOperation::commit_roster_refresh(&p));
            }
            (
                if applied { next } else { c.device.clone() },
                c.original.clone(),
            )
        }
    }
}

#[test]
fn handoff_adoption_scope_preserves_real_prepared_and_applied_g_p_r() {
    for kind in ["G", "P", "R"] {
        for applied in [false, true] {
            let mut c = PolicyCase::new();
            let (current, current_policy) = pending(&mut c, kind, applied);
            let (f, mut active, history, activation) = activated(&mut c);
            let before = fs::read(f.db_path()).expect("retained exact pending state");
            let m = materials(&c, &current, &current_policy, &history, &activation);
            let s = scope(&mut active, &c, &m);
            let (_, _, both) = approved(&c, &s, &m);
            assert_eq!(
                both.scope().inherited_entry_digest(),
                s.inherited_entry_digest()
            );
            if applied && kind != "P" {
                let stale = materials(&c, &c.device, &current_policy, &history, &activation);
                assert!(
                    active
                        .handoff_adoption_scope(s.operation(), c.subject, &stale, s.validity())
                        .is_err(),
                    "wrong {kind} predecessor"
                );
            }
            let image = active.image().expect("same authenticated complete image");
            let entry = image
                .entries
                .get(&c.subject.id(&c.pin.binding()))
                .expect("original subject ID");
            assert_eq!(entry.head.revision(), if applied { 2 } else { 1 });
            assert!(match kind {
                "G" => entry.renewal.is_some(),
                "P" => entry
                    .independent_policy
                    .as_ref()
                    .is_some_and(|p| p.pending()),
                _ => entry.independent_roster.is_some(),
            });
            assert_eq!(
                fs::read(f.db_path()).expect("no implicit GPR reconciliation"),
                before
            );
        }
    }
}

#[test]
fn handoff_adoption_scope_keeps_legacy_identity_unclassified_and_rejects_false_original() {
    let mut c = PolicyCase::new();
    let mut image = c.store.image().expect("owned fixture image");
    image
        .entries
        .get_mut(&c.subject.id(&c.pin.binding()))
        .expect("subject")
        .original_identity = None;
    c.store
        .persist(&mut image)
        .expect("actual legacy classification fixture");
    let (_f, mut active, history, activation) = activated(&mut c);
    let m = materials(&c, &c.device, &c.original, &history, &activation);
    let s = scope(&mut active, &c, &m);
    approved(&c, &s, &m);
    assert!(active
        .image()
        .expect("still same state")
        .entries
        .values()
        .all(|e| e.original_identity.is_none()));
    let other = PolicyCase::new();
    let mut false_original = materials(&c, &c.device, &c.original, &history, &activation);
    false_original.original_device = &other.device;
    assert!(active
        .handoff_adoption_scope(s.operation(), c.subject, &false_original, s.validity())
        .is_err());
}
