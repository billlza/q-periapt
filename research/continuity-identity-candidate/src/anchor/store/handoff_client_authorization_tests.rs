// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
#[path = "handoff_account_freeze_tests.rs"]
mod account_freeze;
#[path = "handoff_transferred_control_tests.rs"]
mod control;
#[path = "handoff_client_authorization_recovery_tests.rs"]
mod recovery;
#[path = "handoff_successive_freeze_tests.rs"]
mod successive_freeze;
#[path = "handoff_successive_import_tests.rs"]
mod successive_import;
#[path = "handoff_successive_source_tests.rs"]
mod successive_source;
#[path = "handoff_client_authorization_validation_tests.rs"]
mod validation;

struct Prepared {
    c: PolicyCase,
    f: TargetFixture,
    active: AnchorStore,
    history: AnchorHandoffHistory,
    activation: AnchorHandoffActivationReceipt,
    retired: Vec<u8>,
    approved: Approved,
    request: Vec<u8>,
}
impl Prepared {
    fn new(kind: Option<(&str, bool)>) -> Self {
        let mut c = PolicyCase::new();
        let (device, policy) = if let Some((kind, applied)) = kind {
            pending(&mut c, kind, applied)
        } else {
            (c.device.clone(), c.original.clone())
        };
        Self::from_case(c, device, policy)
    }
    fn from_case(
        mut c: PolicyCase,
        device: VerifiedDevice,
        policy: HistoricalSessionPolicy,
    ) -> Self {
        let f = TargetFixture::from_store(&mut c.store, &c.server, &c.pin, 175, false);
        let mut target = f.provision();
        let ack = target.import_receipt().expect("import");
        let retired = c
            .store
            .retire_handoff(&f.approval, ack.as_bytes(), || Ok(175))
            .expect("retired")
            .as_bytes()
            .to_vec();
        let history = target
            .verify_source_retirement(&retired)
            .expect("verified history");
        let (mut active, activation) = target.activate(&retired, f.signer()).expect("activated");
        let m = materials(&c, &device, &policy, &history, &activation);
        let scope = scope(&mut active, &c, &m);
        let (_, _, approved) = approved(&c, &scope, &m);
        let request = approved
            .prepare_witness_authorization(&m)
            .expect("bounded complete public request");
        Self {
            c,
            f,
            active,
            history,
            activation,
            retired,
            approved,
            request,
        }
    }
    fn reopen(&mut self) {
        self.active.close();
        self.active = self
            .f
            .open()
            .activate(&self.retired, self.f.signer())
            .expect("original target")
            .0;
    }
    fn original_entry(&mut self) -> Vec<u8> {
        let image = self.active.image().expect("authenticated current content");
        let entry = image
            .entries
            .get(&self.c.subject.id(&self.c.pin.binding()))
            .expect("original ID");
        let mut bytes = Vec::new();
        encode_entry(entry, &self.history, EntryFormat::COMPLETE, &mut bytes)
            .expect("complete entry");
        bytes
    }
}

#[test]
fn client_authorization_commits_exact_rows_and_recovers_without_signing_keys() {
    let mut f = Prepared::new(None);
    let old_entry = f.original_entry();
    assert!(matches!(
        f.active.handoff_client_authorization(f.c.subject),
        Err(DurableError::Absent)
    ));
    let mut calls = 0;
    let receipt = f
        .active
        .authorize_handoff_client(&f.request, || {
            calls += 1;
            Ok(180)
        })
        .expect("durable server authorization");
    assert_eq!(calls, 2);
    assert_eq!(receipt.scope(), f.approved.scope());
    assert_eq!(receipt.admitted_at(), 180);
    crate::AnchorHandoffClientAuthorizationReceipt::verify(
        receipt.as_bytes(),
        &f.approved,
        &f.history,
    )
    .expect("independent public verification");
    assert_eq!(
        f.original_entry(),
        old_entry,
        "metadata commit cannot rewrite old GPR/head/last"
    );
    let before = fs::read(f.f.db_path()).expect("committed bytes");
    let retry = f
        .active
        .authorize_handoff_client(&f.request, || Err(DurableError::Conflict))
        .expect("no fresh clock on exact retry");
    assert_eq!(retry.as_bytes(), receipt.as_bytes());
    assert_eq!(fs::read(f.f.db_path()).expect("no rewrite"), before);
    let request = AnchorRequest::new(&f.f.pin, f.c.subject, AnchorOperation::query(), &f.c.signer)
        .expect("legacy request");
    assert!(f.f.pin.verify_reply(&request, receipt.as_bytes()).is_err());
    assert!(matches!(
        f.active.handle(request.as_bytes(), 180),
        Err(AnchorError::Storage(DurableError::Suspended))
    ));
    f.active.close();
    f.c.store.close();
    fs::remove_file(f.c.server.join("signer")).expect("remove owned old source key");
    fs::remove_file(f.f.directory.join("signer")).expect("remove owned target signer");
    let mut observer = f.f.open();
    assert_eq!(
        observer
            .client_authorization_receipt(f.c.subject)
            .expect("keyless exact observer")
            .as_bytes(),
        receipt.as_bytes()
    );
    assert_eq!(
        observer
            .retained_source_state()
            .expect("whole original source"),
        f.f.source
    );
    assert_eq!(
        observer
            .activation_receipt()
            .expect("original activation")
            .as_bytes(),
        f.activation.as_bytes()
    );
}

#[test]
fn client_authorization_preserves_prepared_and_applied_g_p_r_across_reopen() {
    for kind in ["G", "P", "R"] {
        for applied in [false, true] {
            let mut f = Prepared::new(Some((kind, applied)));
            let original = f.original_entry();
            let receipt = f
                .active
                .authorize_handoff_client(&f.request, || Ok(180))
                .expect("authorization with unresolved original work");
            f.reopen();
            assert_eq!(f.original_entry(), original);
            assert_eq!(
                f.active
                    .handoff_client_authorization(f.c.subject)
                    .expect("original receipt")
                    .as_bytes(),
                receipt.as_bytes()
            );
            let retry = f
                .active
                .authorize_handoff_client(&f.request, || Err(DurableError::Conflict))
                .expect("historical exact recovery");
            assert_eq!(retry.as_bytes(), receipt.as_bytes());
        }
    }
}

#[test]
fn client_authorization_rechecks_admission_and_refuses_changed_or_cross_client_requests() {
    for clock in [[179, 180], [180, 191], [180, 179]] {
        let mut f = Prepared::new(None);
        let mut times = clock.into_iter();
        assert!(f
            .active
            .authorize_handoff_client(&f.request, || times.next().ok_or(DurableError::Conflict))
            .is_err());
        f.reopen();
        assert!(matches!(
            f.active.handoff_client_authorization(f.c.subject),
            Err(DurableError::Absent)
        ));
        f.active
            .authorize_handoff_client(&f.request, || Ok(180))
            .expect("original request after proven local noncommit");
    }
    let mut f = Prepared::new(None);
    let before = fs::read(f.f.db_path()).expect("unchanged target");
    for at in [0, 8, 8 + PUBLIC_KEY_BYTES, f.request.len() - 1] {
        let mut changed = f.request.clone();
        *changed.get_mut(at).expect("bounded offset") ^= 1;
        assert!(f
            .active
            .authorize_handoff_client(&changed, || Ok(180))
            .is_err());
    }
    let other = Prepared::new(None);
    assert!(f
        .active
        .authorize_handoff_client(&other.request, || Ok(180))
        .is_err());
    assert_eq!(fs::read(f.f.db_path()).expect("no rejected write"), before);
    let original = f
        .active
        .authorize_handoff_client(&f.request, || Ok(180))
        .expect("intended original");
    let m = materials(&f.c, &f.c.device, &f.c.original, &f.history, &f.activation);
    let changed_scope = scope(&mut f.active, &f.c, &m);
    let (_, _, changed) = approved(&f.c, &changed_scope, &m);
    let changed = changed
        .prepare_witness_authorization(&m)
        .expect("another valid decision");
    assert!(matches!(
        f.active.authorize_handoff_client(&changed, || Ok(180)),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        f.active
            .handoff_client_authorization(f.c.subject)
            .expect("no replacement")
            .as_bytes(),
        original.as_bytes()
    );
}
