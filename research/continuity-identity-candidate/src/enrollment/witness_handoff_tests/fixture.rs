// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use std::sync::Mutex;

pub(super) struct Fixture {
    _witnesses: tempfile::TempDir,
    pub(super) c: Case,
    pub(super) origin: AnchorPin,
    pub(super) identity: JournalIdentity,
    pub(super) transfer: super::transfer::Transfer,
    pub(super) prekey: PrekeyId,
    pub(super) leaf: PrekeyLeaf,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let witnesses = directory();
        let path = witnesses.path().canonicalize().expect("owned witnesses");
        let source = AnchorStore::provision(
            &path.join("source.redb"),
            JournalKey::provision(&path.join("source.key")).expect("source wrapping"),
            AnchorSigningKey::generate().expect("source signer"),
            AnchorIdentity::generate().expect("source ID"),
        )
        .expect("source");
        let origin = source.pin().expect("original pin");
        let source = Arc::new(Mutex::new(source));
        let c = case_with_anchor(AnchorRequirement::required(&origin));
        let (mut owner, _, identity) = accepted(&c);
        let image = owner.image().expect("parent");
        let original = owner
            .original_device_metadata(&image)
            .expect("original device");
        let genesis = match owner
            .prepare(&c.policy, 150)
            .expect("original installation")
        {
            InstallationPreparation::RequiresEnrollment(genesis) => Some(genesis),
            _ => None,
        }
        .expect("required witness genesis");
        source
            .lock()
            .expect("source")
            .enroll(&genesis, &original, &c.policy, 150)
            .expect("independent enrollment");
        let client = owner
            .anchor_client(
                &c.policy,
                150,
                origin.clone(),
                Box::new(NativeWitness(Arc::clone(&source))),
                Duration::from_secs(3),
            )
            .expect("original signer client");
        let mut active = owner
            .activate(&c.policy, 150, Some(client))
            .expect("actual registered owner");
        let prekey = PrekeyId::from_trusted_state([73; 32]).expect("ID");
        let (service, _, device) = active.parts().expect("controlled original owners");
        let leaf = service
            .stores()
            .expect("children")
            .0
            .generate_prekey(
                &c.policy,
                device,
                prekey,
                LeafKind::OneTimePq,
                interval(),
                150,
            )
            .expect("real secret key");
        active.close();
        let transfer = super::transfer::Transfer::new(
            &mut source.lock().expect("source"),
            &c,
            &original,
            &original,
            c.policy.historical(),
            genesis.subject(),
            175,
        );
        transfer.set_time(190);
        Self {
            _witnesses: witnesses,
            c,
            origin,
            identity,
            transfer,
            prekey,
            leaf,
        }
    }
    pub(super) fn carrier(&self) -> Box<dyn AnchorTransport> {
        self.transfer.carrier()
    }
}
