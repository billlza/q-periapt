// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::AnchorStore;
use std::{io, sync::Mutex, time::Instant};

#[derive(Clone)]
struct Carrier(Arc<Mutex<AnchorStore>>);
impl AnchorTransport for Carrier {
    fn exchange(&mut self, request: &[u8], deadline: Instant) -> io::Result<Vec<u8>> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.0
            .lock()
            .map_err(|_| io::Error::other("witness store lock"))?
            .handle(request, 210)
            .map_err(io::Error::other)
    }
}

#[test]
fn extended_first_installation_requires_the_original_independent_witness() {
    let dir = directory();
    let path = dir.path().canonicalize().expect("witness directory");
    let store = AnchorStore::provision(
        &path.join("witness.redb"),
        JournalKey::provision(&path.join("witness.key")).expect("independent wrapping key"),
        crate::AnchorSigningKey::generate().expect("independent witness signing key"),
        crate::AnchorIdentity::generate().expect("witness identity"),
    )
    .expect("real witness store");
    let pin = store.pin().expect("trusted witness pin");
    let carrier = Carrier(Arc::new(Mutex::new(store)));
    let mut c = case_with_anchor(crate::AnchorRequirement::required(&pin));
    c.intent.description.validity = Validity::new(100, 160).expect("original validity");
    let (mut owner, _, journal) = accepted(&c);
    let image = owner.image().expect("image");
    let original = owner
        .original_device_metadata(&image)
        .expect("historical device");
    let next = target(&c, &original, 43, None, 300, 210);
    let p2 = policy_continuation::policy(&c, 2, 400, 210);
    owner
        .adopt_credential_extension(next.inputs(), &next.pin, &p2, 210)
        .expect("fresh authorization");
    let genesis = match owner
        .prepare(&p2, 210)
        .expect("original selected installation")
    {
        InstallationPreparation::RequiresEnrollment(g) => Ok(g),
        _ => Err("required witness was weakened"),
    }
    .expect("required witness preparation");
    assert!(owner.activate(&p2, 210, None).is_err(), "no local fallback");
    let mut owner = open(&c);
    let anchor = owner
        .anchor_client(
            &p2,
            210,
            pin.clone(),
            Box::new(carrier.clone()),
            Duration::from_secs(3),
        )
        .expect("exact witness client");
    assert!(
        owner.activate(&p2, 210, Some(anchor)).is_err(),
        "no implicit witness enrollment"
    );
    carrier
        .0
        .lock()
        .expect("witness")
        .enroll(&genesis, &next.device(210), &p2, 210)
        .expect("independent witness admission");
    let mut owner = open(&c);
    let anchor = owner
        .anchor_client(&p2, 210, pin, Box::new(carrier), Duration::from_secs(3))
        .expect("same witness");
    let mut active = owner
        .activate(&p2, 210, Some(anchor))
        .expect("witness-backed original installation");
    let (service, signer, device) = active.parts().expect("live owners");
    signer
        .check_device(device)
        .expect("original full device key");
    assert_eq!(
        service.stores().expect("stores").0.test_snapshot().id,
        *journal.as_bytes()
    );
    assert_eq!(
        device.credential_digest(),
        next.device(210).credential_digest()
    );
    active.close();
}
