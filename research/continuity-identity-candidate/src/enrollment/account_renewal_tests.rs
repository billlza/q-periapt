// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Common-roster three-device renewal through the original enrollment owner.
use super::*;
use crate::{
    CredentialRenewalAuthorization, CredentialRenewalMaterials, VerifiedCredentialRenewal,
};
#[path = "account_renewal_recovery_tests.rs"]
mod recovery;
#[path = "account_renewal_session_tests.rs"]
mod session;

struct OtherEnrollment {
    _directory: tempfile::TempDir,
    paths: EnrollmentPaths,
    intent: EnrollmentIntent,
    device: VerifiedDevice,
    id: JournalIdentity,
}
struct AccountCase {
    f: Fixture,
    grants: [VerifiedCredentialRenewal; 3],
    alternate: VerifiedCredentialRenewal,
    resigned: VerifiedCredentialRenewal,
    witnessed: bool,
    peers: [OtherEnrollment; 2],
    certificates: [Vec<u8>; 3],
}
impl AccountCase {
    fn new(witnessed: bool) -> Self {
        let dir = directory();
        let path = dir.path().canonicalize().expect("witness path");
        let store = AnchorStore::provision(
            &path.join("witness.redb"),
            JournalKey::provision(&path.join("wrap")).expect("witness wrapping key"),
            crate::AnchorSigningKey::deterministic([226; 32], [227; 32]).expect("fixture signer"),
            crate::AnchorIdentity::generate().expect("witness identity"),
        )
        .expect("witness store");
        let pin = store.pin().expect("pin");
        let carrier = Carrier {
            store: Arc::new(Mutex::new(store)),
            clock: Arc::new(AtomicU64::new(150)),
            cut: Arc::new(Mutex::new(None)),
            requests: Arc::new(Mutex::new(Vec::new())),
            after_reply: Arc::new(Mutex::new(None)),
        };
        let mut c = case_with_anchor(if witnessed {
            crate::AnchorRequirement::required(&pin)
        } else {
            crate::AnchorRequirement::local_only()
        });
        c.intent.description.validity = Validity::new(100, 160).expect("original expiry");
        let mut owner = create(&c);
        let request = owner.request(150).expect("original request");
        let request =
            VerifiedEnrollmentRequest::verify(&request, &c.intent, 150).expect("possession");
        let mut originals = vec![c
            .root
            .issue_enrollment(&request, 150)
            .expect("local credential")];
        let mut pending_peers = Vec::new();
        for id in [8, 9] {
            let dir = directory();
            let root = dir.path().canonicalize().expect("peer path");
            let paths = paths(&root);
            JournalKey::provision(&paths.wrapping).expect("peer wrapping key");
            let intent = EnrollmentIntent::new(
                c.intent.root.clone(),
                DeviceDescription::new(
                    [id; 16],
                    1,
                    c.policy.family(),
                    Validity::new(100, 160).expect("original time"),
                )
                .expect("peer intent"),
            );
            let mut owner = DeviceEnrollment::provision(paths.clone(), intent.clone())
                .expect("peer enrollment");
            let wire = owner.request(150).expect("peer request");
            let request =
                VerifiedEnrollmentRequest::verify(&wire, &intent, 150).expect("peer possession");
            originals.push(
                c.root
                    .issue_enrollment(&request, 150)
                    .expect("peer credential"),
            );
            pending_peers.push((dir, paths, intent, owner));
        }
        let originals: [Vec<u8>; 3] = originals
            .try_into()
            .map_err(|_| "three enrolled credentials")
            .expect("fixture shape");
        let entries = originals
            .iter()
            .map(|c0| c.root.roster_entry(c0).expect("member"))
            .collect::<Vec<_>>();
        let roster = c
            .root
            .issue_roster(1, interval(), &entries)
            .expect("common original roster");
        let original_pin = AccountPin::new(
            c.root.account_id().expect("account"),
            c.root.public_key().expect("root"),
            roster.checkpoint(),
            c.policy.family(),
        )
        .expect("original pin");
        let (original, id) = Self::initialize(
            owner,
            &originals[0],
            &original_pin,
            roster.as_bytes(),
            &c,
            &carrier,
        );
        let peers: [OtherEnrollment; 2] = pending_peers
            .into_iter()
            .zip(originals.iter().skip(1))
            .map(|((dir, paths, intent, owner), certificate)| {
                let (device, id) = Self::initialize(
                    owner,
                    certificate,
                    &original_pin,
                    roster.as_bytes(),
                    &c,
                    &carrier,
                );
                OtherEnrollment {
                    _directory: dir,
                    paths,
                    intent,
                    device,
                    id,
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "two original peers")
            .expect("fixture shape");
        let successors = originals
            .iter()
            .map(|certificate| {
                let previous = original_pin
                    .verify_device(certificate, roster.as_bytes(), 150)
                    .expect("previous");
                c.root
                    .issue_credential_extension(&previous, 190, 150)
                    .expect("same-key extension")
            })
            .collect::<Vec<_>>();
        let entries = successors
            .iter()
            .map(|cert| c.root.roster_entry(cert).expect("successor"))
            .collect::<Vec<_>>();
        let target = c
            .root
            .issue_roster(2, interval(), &entries)
            .expect("common target");
        let target_pin = AccountPin::new(
            c.root.account_id().expect("account"),
            c.root.public_key().expect("root"),
            target.checkpoint(),
            c.policy.family(),
        )
        .expect("target pin");
        let grant = |index: usize, operation: u8| {
            let issued = c
                .root
                .issue_credential_renewal(
                    CredentialRenewalMaterials {
                        original_credential: originals.get(index).expect("original member"),
                        previous_credential: originals.get(index).expect("original member"),
                        successor_credential: successors.get(index).expect("successor member"),
                        previous_roster: roster.as_bytes(),
                        successor_roster: target.as_bytes(),
                    },
                    &CredentialRenewalAuthorization {
                        operation: crate::CredentialRenewalId::from_trusted_state([operation; 32])
                            .expect("operation"),
                        previous: roster.checkpoint(),
                        policy_digest: c.policy.checkpoint().digest(),
                    },
                    &target_pin,
                    170,
                )
                .expect("root-approved grant");
            VerifiedCredentialRenewal::verify(
                issued.as_bytes(),
                &target_pin,
                c.policy.checkpoint().digest(),
                170,
            )
            .expect("verify")
        };
        let grants = [grant(0, 100), grant(1, 101), grant(2, 102)];
        let alternate = grant(1, 110);
        let resigned = grant(1, 101);
        Self {
            f: Fixture {
                _witness_dir: Arc::new(dir),
                c,
                pin,
                carrier,
                original,
                id,
            },
            grants,
            alternate,
            resigned,
            witnessed,
            peers,
            certificates: originals,
        }
    }
    fn initialize(
        mut owner: DeviceEnrollment,
        certificate: &[u8],
        account: &AccountPin,
        roster: &[u8],
        c: &Case,
        carrier: &Carrier,
    ) -> (VerifiedDevice, JournalIdentity) {
        let id = owner
            .accept(certificate, roster, account, &c.policy, 150)
            .expect("accept original enrollment");
        let original = account
            .verify_device(certificate, roster, 150)
            .expect("original device");
        let anchor = match owner.prepare(&c.policy, 150).expect("prepare original") {
            InstallationPreparation::Local => None,
            InstallationPreparation::RequiresEnrollment(genesis) => {
                let pin = {
                    let mut store = carrier.store.lock().expect("store");
                    store
                        .enroll(&genesis, &original, &c.policy, 150)
                        .expect("independent enrollment");
                    store.pin().expect("original witness pin")
                };
                Some(
                    owner
                        .anchor_client(
                            &c.policy,
                            150,
                            pin,
                            Box::new(carrier.clone()),
                            Duration::from_secs(3),
                        )
                        .expect("original client"),
                )
            }
        };
        owner
            .activate(&c.policy, 150, anchor)
            .expect("original active installation")
            .close();
        (original, id)
    }
    fn stage(&self, owner: &mut DeviceEnrollment) {
        assert_eq!(
            owner
                .stage_account_credential_renewal(
                    &self.grants[0],
                    &[&self.grants[1], &self.grants[2]],
                    self.grants[0].operation(),
                    &self.f.c.policy,
                    170,
                )
                .expect("complete intent"),
            renewal::pending(&self.grants[0])
        );
    }
    fn activate(&self, mut owner: DeviceEnrollment) -> EnrolledDevice {
        let anchor = if self.witnessed {
            Some(client(&self.f, &mut owner, 170))
        } else {
            None
        };
        owner
            .activate(&self.f.c.policy, 170, anchor)
            .expect("same original owner")
    }
    fn verify_active(&self, mut active: EnrolledDevice) {
        let (service, signer, local) = active.parts().expect("controlled owners");
        signer.check_device(local).expect("original signer");
        assert_eq!(
            local.credential_digest(),
            self.grants[0].successor_device().credential_digest()
        );
        let journal = service.stores().expect("stores").0;
        let snapshot = journal.test_snapshot();
        assert_eq!(snapshot.id, *self.f.id.as_bytes());
        assert_eq!(
            snapshot.owner,
            crate::bootstrap::storage_owner(&self.f.original)
        );
        for grant in &self.grants {
            assert_eq!(
                journal
                    .roster_checkpoint(grant.successor_device().account_id())
                    .expect("shared head"),
                grant.successor_device().roster().checkpoint()
            );
        }
        active.close();
    }
}

#[test]
fn account_intent_preserves_complete_original_set_and_rejects_partial_or_retargeted_retries() {
    for witnessed in [false, true] {
        let c = AccountCase::new(witnessed);
        let before = fs::read(&c.f.c.paths.signer).expect("original protected key");
        let mut owner = open(&c.f.c);
        assert!(owner
            .stage_account_credential_renewal(
                &c.grants[0],
                &[&c.grants[1]],
                c.grants[0].operation(),
                &c.f.c.policy,
                170
            )
            .is_err());
        let mut owner = open(&c.f.c);
        assert_eq!(
            owner
                .credential_renewal_status()
                .expect("no partial intent"),
            CredentialRenewalStatus::Absent
        );
        c.stage(&mut owner);
        let retained = encode(
            &JournalKey::open(&c.f.c.paths.wrapping).expect("wrap"),
            owner.binding,
            &owner.image().expect("image"),
        )
        .expect("encoded");
        assert_eq!(retained.get(..8).expect("complete format tag"), b"QPENST20");
        assert_eq!(
            owner
                .stage_account_credential_renewal(
                    &c.grants[0],
                    &[&c.grants[2], &c.resigned],
                    c.grants[0].operation(),
                    &c.f.c.policy,
                    170
                )
                .expect("semantic reordered retry"),
            renewal::pending(&c.grants[0])
        );
        assert_eq!(
            encode(
                &JournalKey::open(&c.f.c.paths.wrapping).expect("wrap"),
                owner.binding,
                &owner.image().expect("image")
            )
            .expect("encoded"),
            retained
        );
        owner.close();
        for companion in [None, Some(&c.alternate)] {
            let mut owner = open(&c.f.c);
            let result = match companion {
                None => owner.stage_credential_renewal(
                    &c.grants[0],
                    c.grants[0].operation(),
                    &c.f.c.policy,
                    170,
                ),
                Some(peer) => owner.stage_account_credential_renewal(
                    &c.grants[0],
                    &[peer, &c.grants[2]],
                    c.grants[0].operation(),
                    &c.f.c.policy,
                    170,
                ),
            };
            assert!(matches!(result, Err(DurableError::Conflict)));
        }
        let mut owner = open(&c.f.c);
        if witnessed {
            c.f.carrier.clock.store(170, Ordering::SeqCst);
            let anchor = client(&c.f, &mut owner, 170);
            let proposal = owner
                .prepare_witnessed_credential_renewal(&c.f.c.policy, 170, anchor)
                .expect("original sealed target");
            owner.close();
            let mut owner = open(&c.f.c);
            let anchor = client(&c.f, &mut owner, 170);
            assert_eq!(
                owner
                    .prepare_witnessed_credential_renewal(&c.f.c.policy, 170, anchor)
                    .expect("same sealed target"),
                proposal
            );
            c.f.carrier
                .store
                .lock()
                .expect("store")
                .prepare_credential_renewal(proposal, &c.grants[0], &c.f.c.policy, 170)
                .expect("independent witness approval");
            *c.f.carrier.cut.lock().expect("reply cut") = Some((5, true));
            let mut anchor = client(&c.f, &mut owner, 170);
            assert!(owner
                .commit_witnessed_credential_renewal(
                    c.grants[0].operation(),
                    c.grants[0].statement_digest(),
                    &c.f.c.policy,
                    170,
                    &mut anchor
                )
                .is_err());
            owner.close();
            let mut owner = open(&c.f.c);
            let mut anchor = client(&c.f, &mut owner, 170);
            owner
                .reconcile_witnessed_credential_renewal(
                    c.grants[0].operation(),
                    c.grants[0].statement_digest(),
                    &c.f.c.policy,
                    170,
                    &mut anchor,
                )
                .expect("recover Applied");
            c.verify_active(c.activate(owner));
        } else {
            c.verify_active(c.activate(owner));
        }
        let mut owner = open(&c.f.c);
        assert_eq!(
            owner
                .stage_account_credential_renewal(
                    &c.grants[0],
                    &[&c.grants[2], &c.resigned],
                    c.grants[0].operation(),
                    &c.f.c.policy,
                    170
                )
                .expect("completed original readback"),
            renewal::committed(&c.grants[0])
        );
        owner.close();
        c.verify_active(c.activate(open(&c.f.c)));
        assert_eq!(
            fs::read(&c.f.c.paths.signer).expect("same protected key"),
            before
        );
    }
}
