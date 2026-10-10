// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{
    AccountAuthorityIdentity, AccountAuthorityStore, ApplicationAccountId, JournalAccountAuthority,
};
pub(super) fn bind(f: &Fixture) -> (AccountAuthorityStore, JournalAccountAuthority) {
    let root = f
        ._witness_dir
        .path()
        .canonicalize()
        .expect("owned canonical fixture");
    let mut registry = AccountAuthorityStore::provision(
        &root.join("registry"),
        JournalKey::provision(&root.join("registry-key")).expect("key"),
        AccountAuthorityIdentity::generate().expect("identity"),
        f.c.policy.family(),
        f.pin.clone(),
    )
    .expect("registry");
    let expected = registry
        .associate(
            ApplicationAccountId::from_trusted_state([86; 32]).expect("application"),
            &f.original,
        )
        .expect("original root association");
    let authority = JournalAccountAuthority::new(registry.access().expect("owner"), expected)
        .expect("original descriptor");
    let mut owner = open(&f.c)
        .with_account_authority(authority.clone())
        .expect("original descriptor");
    let anchor = client(f, &mut owner, 150);
    owner
        .activate(&f.c.policy, 150, Some(anchor))
        .expect("initial registry binding")
        .close();
    (registry, authority)
}
struct Managed {
    f: Fixture,
    registry: AccountAuthorityStore,
    authority: JournalAccountAuthority,
}
impl Managed {
    fn new() -> Self {
        let f = fixture();
        let (registry, authority) = bind(&f);
        Self {
            f,
            registry,
            authority,
        }
    }
    fn open(&self) -> DeviceEnrollment {
        open(&self.f.c)
            .with_account_authority(self.authority.clone())
            .expect("same original registry")
    }
    fn prepare(&self) -> crate::VerifiedCredentialRenewal {
        let f = &self.f;
        let proof = grant(f, &f.original, 2, 190);
        f.carrier.clock.store(170, Ordering::SeqCst);
        let mut owner = self.open();
        assert_eq!(
            owner
                .stage_credential_renewal(&proof, proof.operation(), &f.c.policy, 170)
                .expect("original credential intent"),
            renewal::pending(&proof)
        );
        let anchor = client(f, &mut owner, 170);
        let proposal = owner
            .prepare_witnessed_credential_renewal(&f.c.policy, 170, anchor)
            .expect("managed exact witness preparation");
        f.carrier
            .store
            .lock()
            .expect("witness")
            .prepare_credential_renewal(proposal, &proof, &f.c.policy, 170)
            .expect("independent approval");
        owner.close();
        proof
    }
}
impl Drop for Managed {
    fn drop(&mut self) {
        self.registry.close();
    }
}
#[test]
fn managed_enrollment_witnessed_credential_renewal_retains_registry_and_original_signer() {
    let m = Managed::new();
    let f = &m.f;
    let signer = fs::read(&f.c.paths.signer).expect("original signer file");
    let proof = m.prepare();
    let mut owner = m.open();
    let mut anchor = client(f, &mut owner, 170);
    assert_eq!(
        owner
            .commit_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &f.c.policy,
                170,
                &mut anchor
            )
            .expect("managed original commit"),
        renewal::committed(&proof)
    );
    owner.close();
    let mut owner = m.open();
    let anchor = client(f, &mut owner, 170);
    let mut current = owner
        .activate(&f.c.policy, 170, Some(anchor))
        .expect("current renewed owner under the same registry");
    assert_eq!(
        current
            .parts()
            .expect("controlled owner")
            .2
            .credential_digest(),
        proof.successor_device().credential_digest()
    );
    current.close();
    assert!(fs::read(&f.c.paths.signer).expect("same signer") == signer);
    assert!(
        activate(f, 170).is_err(),
        "renewal does not remove mandatory registry admission"
    );
    eprintln!("MANAGED_ENROLLMENT_RENEWAL original_expired=160 renewed_activation=170 same_signer=true registry_binding_retained=true");
}
fn rejects_dispatch(closed: bool) {
    let mut m = Managed::new();
    let proof = m.prepare();
    let mut owner = if closed { m.open() } else { open(&m.f.c) };
    let mut anchor = client(&m.f, &mut owner, 170);
    if closed {
        m.registry.close();
    }
    let before =
        m.f.carrier
            .requests
            .lock()
            .expect("recorded requests")
            .len();
    let result = owner.commit_witnessed_credential_renewal(
        proof.operation(),
        proof.statement_digest(),
        &m.f.c.policy,
        170,
        &mut anchor,
    );
    if closed {
        assert!(
            matches!(result, Err(DurableError::Closed)),
            "closed original registry must deny new commit dispatch"
        );
    } else {
        assert!(
            matches!(result, Err(DurableError::Conflict)),
            "missing original registry must deny new commit dispatch"
        );
    }
    assert_eq!(
        m.f.carrier
            .requests
            .lock()
            .expect("recorded requests")
            .len(),
        before,
        "no command may be dispatched without required authority"
    );
    owner.close();
}
#[test]
fn managed_enrollment_missing_registry_cannot_dispatch_a_new_credential_commit() {
    rejects_dispatch(false);
}
#[test]
fn managed_enrollment_closed_registry_cannot_dispatch_a_new_credential_commit() {
    rejects_dispatch(true);
}

#[test]
fn managed_enrollment_registry_closure_still_allows_exact_historical_recovery_after_lost_commit_reply(
) {
    let mut m = Managed::new();
    let proof = m.prepare();
    let mut owner = m.open();
    let mut anchor = client(&m.f, &mut owner, 170);
    *m.f.carrier.cut.lock().expect("original reply loss") = Some((5, true));
    assert!(owner
        .commit_witnessed_credential_renewal(
            proof.operation(),
            proof.statement_digest(),
            &m.f.c.policy,
            170,
            &mut anchor
        )
        .is_err());
    assert!(owner.active.is_none());
    m.registry.close();
    let before = m.f.carrier.requests.lock().expect("commands").len();
    let mut owner = open(&m.f.c);
    let mut anchor = client(&m.f, &mut owner, 170);
    assert_eq!(
        owner
            .reconcile_witnessed_credential_renewal(
                proof.operation(),
                proof.statement_digest(),
                &m.f.c.policy,
                170,
                &mut anchor
            )
            .expect("exact historical outcome without new commit authorization"),
        renewal::committed(&proof)
    );
    assert!(!m
        .f
        .carrier
        .requests
        .lock()
        .expect("commands")
        .get(before..)
        .expect("only recovery requests")
        .contains(&5));
    owner.close();
    assert!(matches!(
        open(&m.f.c).with_account_authority(m.authority.clone()),
        Err(DurableError::Closed)
    ));
    assert!(
        activate(&m.f, 170).is_err(),
        "historical recovery never removes required registry admission"
    );
}
