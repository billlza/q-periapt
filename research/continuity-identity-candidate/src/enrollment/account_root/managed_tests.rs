// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityCheckpoint, AccountAuthorityIdentity,
    AccountAuthorityReplacementState as State, AccountAuthorityStore, AnchorAccountFreezeId,
    AnchorAccountFreezeRequest, AnchorAccountReplacementPlan, ApplicationAccountId,
    JournalAccountAuthority, ManagedAccountRootReplacement as Managed,
};
#[path = "managed_tests/process.rs"]
mod process;

fn enrollment_rows(enrollment: &DeviceEnrollment) -> Vec<(String, Vec<u8>)> {
    let transaction = enrollment
        .active
        .as_ref()
        .expect("original enrollment")
        .database
        .begin_read()
        .expect("read");
    let table = transaction.open_table(TABLE).expect("original table");
    table
        .iter()
        .expect("all original rows")
        .map(|row| {
            let (key, value) = row.expect("authenticated database row");
            (key.value().to_owned(), value.value().to_vec())
        })
        .collect()
}

struct Setup {
    f: Fixture,
    identity: AccountAuthorityIdentity,
    expected: AccountAuthorityCheckpoint,
    plan: AnchorAccountReplacementPlan,
}
impl Setup {
    fn new(until: u64) -> (Self, AccountAuthorityStore, EnrolledDevice) {
        let f = fixture_with_target_until(until);
        let base = f._dir.path().canonicalize().expect("private fixture");
        let identity = AccountAuthorityIdentity::generate().expect("original registry identity");
        let mut registry = AccountAuthorityStore::provision(
            &base.join("registry"),
            JournalKey::provision(&base.join("registry-key")).expect("original key"),
            identity,
            f.policy.family(),
            f.pin.clone(),
        )
        .expect("original registry");
        let expected = registry
            .associate(
                ApplicationAccountId::from_trusted_state([93; 32]).expect("application"),
                &f.original.device,
            )
            .expect("independent association");
        let authority = JournalAccountAuthority::new(registry.access().expect("access"), expected)
            .expect("original descriptor");
        let mut enrollment = DeviceEnrollment::open_with_account_authority(
            f.original.paths.clone(),
            f.original.intent.clone(),
            authority,
        )
        .expect("original enrollment");
        let client = enrollment
            .anchor_client(
                &f.policy,
                150,
                f.pin.clone(),
                Box::new(Carrier(Arc::clone(&f.witness))),
                Duration::from_secs(3),
            )
            .expect("original witness");
        let original = enrollment
            .activate(&f.policy, 150, Some(client))
            .expect("managed original owner");
        let request = AnchorAccountFreezeRequest::from_trusted_state(
            AnchorAccountFreezeId::from_trusted_state([94; 32]).expect("freeze identity"),
            f.original.root.public_key().expect("original root"),
            &f.pin,
        )
        .expect("independently approved freeze");
        let plan = f
            .witness
            .lock()
            .expect("witness")
            .account_replacement_plan(
                AnchorAccountReplacementId::from_trusted_state([95; 32])
                    .expect("original operation"),
                request,
                &f.target.genesis,
                &f.target.device,
                &f.policy,
                150,
            )
            .expect("independently approved successor");
        (
            Self {
                f,
                identity,
                expected,
                plan,
            },
            registry,
            original,
        )
    }
    fn begin(&self, registry: AccountAuthorityStore, original: EnrolledDevice) -> Managed {
        Managed::begin(
            registry,
            self.expected,
            self.plan.clone(),
            original,
            self.f.pin.clone(),
        )
        .expect("managed prepare")
    }
    fn registry(&self) -> AccountAuthorityStore {
        let base = self.f._dir.path().canonicalize().expect("original root");
        AccountAuthorityStore::open(
            &base.join("registry"),
            JournalKey::open(&base.join("registry-key")).expect("same key"),
            self.identity,
            self.f.policy.family(),
            self.f.pin.clone(),
        )
        .expect("reopen same registry")
    }
    fn resume(&self) -> Managed {
        Managed::resume_original(
            self.registry(),
            self.expected,
            self.plan.clone(),
            self.f.original.paths.clone(),
            self.f.original.intent.clone(),
            self.f.pin.clone(),
        )
        .expect("resume exact original cutover")
    }
    fn freeze(&self) -> Vec<u8> {
        let mut witness = self.f.witness.lock().expect("witness");
        witness
            .freeze_account(self.plan.request())
            .expect("actual freeze");
        witness
            .account_freeze_receipt(self.plan.request())
            .expect("signed snapshot")
    }
    fn activate(&self, managed: &mut Managed, now: u64) -> Result<EnrolledDevice, DurableError> {
        let enrollment =
            DeviceEnrollment::open(self.f.target.paths.clone(), self.f.target.intent.clone())?;
        managed.activate_successor(
            enrollment,
            &self.f.policy,
            now,
            Box::new(Carrier(Arc::clone(&self.f.witness))),
            Duration::from_secs(3),
        )
    }
}

#[test]
fn managed_root_round_trip_retains_one_revision_and_revokes_successor_on_close() {
    let (s, registry, original) = Setup::new(200);
    let old_access = registry.access().expect("old cached access");
    let mut managed = s.begin(registry, original);
    assert_eq!(managed.state().expect("state"), State::Preparing);
    assert!(matches!(
        old_access.current(s.expected.application()),
        Err(DurableError::Suspended)
    ));
    let freeze = s.freeze();
    let proposal = managed
        .bind_witness_freeze(&freeze)
        .expect("bound and fenced");
    let receipt = s.f.receipt(&proposal);
    let successor = managed
        .retain_witness_retirement(&receipt)
        .expect("all local commits");
    assert_eq!(successor.revision(), 2);
    assert_eq!(successor.account(), s.f.target.device.account_id());
    assert_eq!(
        managed
            .retain_witness_retirement(&receipt)
            .expect("same receipt retry"),
        successor
    );
    managed.close();
    let mut managed = s.resume();
    assert_eq!(managed.state().expect("restored state"), State::Committed);
    assert_eq!(
        managed
            .retain_witness_retirement(&receipt)
            .expect("same original after restart"),
        successor
    );
    let mut current = s
        .activate(&mut managed, 150)
        .expect("actual managed successor");
    current
        .next_prekey_publication_id()
        .expect("controlled successor operation");
    current.close();
    let authority = managed
        .successor_authority()
        .expect("same registry for ordinary successor lifecycle");
    let mut enrollment = DeviceEnrollment::open_with_account_authority(
        s.f.target.paths.clone(),
        s.f.target.intent.clone(),
        authority,
    )
    .expect("original managed successor reopen");
    let client = enrollment
        .anchor_client(
            &s.f.policy,
            150,
            s.f.pin.clone(),
            Box::new(Carrier(Arc::clone(&s.f.witness))),
            Duration::from_secs(3),
        )
        .expect("fresh witness");
    let mut current = enrollment
        .activate(&s.f.policy, 150, Some(client))
        .expect("ordinary lifecycle keeps original binding");
    drop(managed);
    assert!(matches!(
        current.next_prekey_publication_id(),
        Err(DurableError::Closed)
    ));
    current.close();
    s.f.assert_fenced();
}

#[test]
fn managed_root_resume_never_creates_an_absent_operation() {
    let (s, registry, mut original) = Setup::new(200);
    original.close();
    assert!(matches!(
        Managed::resume_original(
            registry,
            s.expected,
            s.plan.clone(),
            s.f.original.paths.clone(),
            s.f.original.intent.clone(),
            s.f.pin.clone()
        ),
        Err(DurableError::Absent)
    ));
    let registry = s.registry();
    assert_eq!(
        registry
            .access()
            .expect("fresh access")
            .current(s.expected.application())
            .expect("original still selected"),
        s.expected
    );
    assert!(matches!(
        registry.preparation(s.plan.operation()),
        Err(DurableError::Absent)
    ));
}

#[test]
fn managed_root_preparation_keeps_exclusive_original_enrollment_ownership() {
    let (s, registry, original) = Setup::new(200);
    let mut managed = s.begin(registry, original);
    assert!(DeviceEnrollment::open(s.f.original.paths.clone(),s.f.original.intent.clone()).is_err(), "managed preparation must retain the original enrollment lease while waiting for the witness");
    managed.close();
    let mut managed = s.resume();
    assert!(
        DeviceEnrollment::open(s.f.original.paths.clone(), s.f.original.intent.clone()).is_err(),
        "resumed preparation must retain that same enrollment lease"
    );
    managed
        .bind_witness_freeze(&s.freeze())
        .expect("transfer original parent into restricted recovery");
    managed.close();
    s.f.assert_fenced();
}

#[test]
fn managed_root_rejects_wrong_freeze_and_recovers_original_after_owner_closure() {
    let (s, registry, original) = Setup::new(200);
    let access = registry.access().expect("original read access");
    let mut managed = s.begin(registry, original);
    let freeze = s.freeze();
    let mut wrong = freeze.clone();
    *wrong.last_mut().expect("signed wire") ^= 1;
    assert!(managed.bind_witness_freeze(&wrong).is_err());
    assert!(matches!(managed.state(), Err(DurableError::Closed)));
    assert!(matches!(
        access.current(s.expected.application()),
        Err(DurableError::Closed)
    ));
    let mut managed = s.resume();
    assert_eq!(managed.state().expect("original state"), State::Preparing);
    let proposal = managed
        .bind_witness_freeze(&freeze)
        .expect("same original freeze");
    assert_eq!(proposal.operation(), s.plan.operation());
    managed.close();
    s.f.assert_fenced();
}

#[test]
fn managed_root_pending_does_not_activate_target_or_reset_the_original_fence() {
    let (s, registry, original) = Setup::new(200);
    let mut managed = s.begin(registry, original);
    managed
        .bind_witness_freeze(&s.freeze())
        .expect("pending exact proposal");
    let enrollment = DeviceEnrollment::open(s.f.target.paths.clone(), s.f.target.intent.clone())
        .expect("prepared target");
    let before = enrollment_rows(&enrollment);
    assert!(matches!(
        managed.activate_successor(
            enrollment,
            &s.f.policy,
            150,
            Box::new(Carrier(Arc::clone(&s.f.witness))),
            Duration::from_secs(3)
        ),
        Err(DurableError::Suspended)
    ));
    let enrollment = DeviceEnrollment::open(s.f.target.paths.clone(), s.f.target.intent.clone())
        .expect("same target");
    assert!(
        before == enrollment_rows(&enrollment),
        "refused activation must preserve every enrollment row"
    );
    drop(enrollment);
    let mut managed = s.resume();
    assert_eq!(
        managed.state().expect("same original operation"),
        State::Pending
    );
    managed.close();
    s.f.assert_fenced();
}

#[test]
fn managed_root_committed_retirement_does_not_bypass_current_credential_expiry() {
    let (s, registry, original) = Setup::new(160);
    let mut managed = s.begin(registry, original);
    let proposal = managed
        .bind_witness_freeze(&s.freeze())
        .expect("exact target");
    managed
        .retain_witness_retirement(&s.f.receipt(&proposal))
        .expect("historical retirement at 150");
    assert!(matches!(
        s.activate(&mut managed, 170),
        Err(DurableError::Protocol(Error::Validity))
    ));
    let mut managed = s.resume();
    assert_eq!(
        managed.state().expect("history stays committed"),
        State::Committed
    );
    managed.close();
    s.f.assert_fenced();
}

#[test]
fn managed_root_requires_the_original_device_registry_before_mutation() {
    let (s, registry, original) = Setup::new(200);
    let base = s.f._dir.path().canonicalize().expect("owned root");
    let mut other = AccountAuthorityStore::provision(
        &base.join("other-registry"),
        JournalKey::provision(&base.join("other-key")).expect("other key"),
        AccountAuthorityIdentity::generate().expect("other identity"),
        s.f.policy.family(),
        s.f.pin.clone(),
    )
    .expect("other registry");
    let same_public_checkpoint = other
        .associate(s.expected.application(), &s.f.original.device)
        .expect("separate association");
    assert_eq!(same_public_checkpoint, s.expected);
    assert!(matches!(
        Managed::begin(other, s.expected, s.plan.clone(), original, s.f.pin.clone()),
        Err(DurableError::Conflict)
    ));
    assert_eq!(
        registry
            .access()
            .expect("original registry remains open")
            .current(s.expected.application())
            .expect("not suspended"),
        s.expected
    );
    assert!(matches!(
        registry.preparation(s.plan.operation()),
        Err(DurableError::Absent)
    ));
}

#[test]
fn managed_root_wrong_successor_is_refused_before_witness_dispatch() {
    use std::sync::atomic::AtomicUsize;
    struct Observed(Arc<AtomicUsize>);
    impl AnchorTransport for Observed {
        fn exchange(&mut self, _: &[u8], _: Instant) -> io::Result<Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::ErrorKind::ConnectionRefused.into())
        }
    }
    let (s, registry, original) = Setup::new(200);
    let mut managed = s.begin(registry, original);
    let proposal = managed
        .bind_witness_freeze(&s.freeze())
        .expect("approved target");
    managed
        .retain_witness_retirement(&s.f.receipt(&proposal))
        .expect("historical commitment");
    let other = account(
        &s.f._dir
            .path()
            .canonicalize()
            .expect("private root")
            .join("unapproved-target"),
        &s.f.policy,
    );
    let enrollment = DeviceEnrollment::open(other.paths.clone(), other.intent.clone())
        .expect("different accepted enrollment");
    let before = enrollment_rows(&enrollment);
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(matches!(
        managed.activate_successor(
            enrollment,
            &s.f.policy,
            150,
            Box::new(Observed(Arc::clone(&calls))),
            Duration::from_secs(3)
        ),
        Err(DurableError::Conflict)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let enrollment =
        DeviceEnrollment::open(other.paths, other.intent).expect("same unapproved enrollment");
    assert!(
        before == enrollment_rows(&enrollment),
        "wrong successor must retain every original row"
    );
    let mut resumed = s.resume();
    assert_eq!(
        resumed.state().expect("retained original decision"),
        State::Committed
    );
    s.activate(&mut resumed, 150)
        .expect("original target still admitted")
        .close();
    resumed.close();
}

#[test]
fn managed_root_invalid_retirement_does_not_select_successor() {
    let (s, registry, original) = Setup::new(200);
    let mut managed = s.begin(registry, original);
    let proposal = managed
        .bind_witness_freeze(&s.freeze())
        .expect("approved target");
    let receipt = s.f.receipt(&proposal);
    let mut wrong = receipt.clone();
    *wrong.last_mut().expect("signature byte") ^= 1;
    assert!(managed.retain_witness_retirement(&wrong).is_err());
    let mut resumed = s.resume();
    assert_eq!(
        resumed.state().expect("no local selection from bad proof"),
        State::Pending
    );
    assert_eq!(
        resumed
            .retain_witness_retirement(&receipt)
            .expect("original authenticated outcome")
            .revision(),
        2
    );
    resumed.close();
}
