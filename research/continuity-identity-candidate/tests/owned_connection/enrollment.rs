// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original enrollment retained through the public service and every restart.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SetupKind {
    Installed,
    RosterRenewal,
    Enrolled,
}

pub(super) enum PendingOwner {
    Installed(Box<p::DeviceSigningKey>),
    Enrolling(Box<p::DeviceEnrollment>),
}
impl PendingOwner {
    pub(super) fn close(&mut self) {
        match self {
            Self::Installed(key) => key.close(),
            Self::Enrolling(owner) => owner.close(),
        }
    }
}

/// The same peer transport borrows either explicitly configured installation
/// inputs or an enrollment owner. No enrollment is dropped before traffic.
pub(crate) struct ConfiguredDevice {
    service: p::DeviceService,
    signer: p::DeviceSigningKey,
}
pub(crate) enum DeviceOwner {
    Installed(Box<ConfiguredDevice>),
    Enrolled(Box<p::EnrolledDevice>),
}
impl DeviceOwner {
    pub(crate) fn installed(service: p::DeviceService, signer: p::DeviceSigningKey) -> Self {
        Self::Installed(Box::new(ConfiguredDevice { service, signer }))
    }
    pub(crate) fn parts(&mut self) -> Result<(&mut p::DeviceService, &p::DeviceSigningKey)> {
        match self {
            Self::Installed(owner) => Ok((&mut owner.service, &owner.signer)),
            Self::Enrolled(owner) => {
                let (service, signer, _) = owner.parts()?;
                Ok((service, signer))
            }
        }
    }
    pub(crate) fn stores(
        &mut self,
    ) -> Result<(&mut p::DeviceJournal, &mut p::SessionArchiveStore)> {
        Ok(self.parts()?.0.stores()?)
    }
    pub(crate) fn close(&mut self) {
        match self {
            Self::Installed(owner) => {
                owner.service.close();
                owner.signer.close();
            }
            Self::Enrolled(owner) => owner.close(),
        }
    }
}

pub(super) fn paths(path: &Path) -> Result<p::EnrollmentPaths> {
    Ok(p::EnrollmentPaths::new(
        &path.join("wrap.key"),
        &path.join("signer.key"),
        &path.join("enrollment.redb"),
        super::paths(path)?,
    )?)
}
fn intent(path: &Path) -> Result<p::EnrollmentIntent> {
    let validity = array::<16>(path, "enrollment-validity")?;
    Ok(p::EnrollmentIntent::new(
        p::PublicKey::decode(&read(path, "local-root", 8192)?)?,
        p::DeviceDescription::new(
            array(path, "local-device")?,
            u64::from_be_bytes(array(path, "local-generation")?),
            array(path, "family")?,
            p::Validity::new(
                u64::from_be_bytes(validity[..8].try_into()?),
                u64::from_be_bytes(validity[8..].try_into()?),
            )?,
        )?,
    ))
}

/// Remove only the reference's own record temporarily. Original child files are
/// still present, so an accidental installation fallback would return a peer.
pub(super) fn missing_record_control(path: &Path) -> Result<()> {
    let original = path.join("enrollment.redb");
    let retained = path.join("enrollment-retained.redb");
    fs::rename(&original, &retained)?;
    let opened = Peer::open(path);
    let absent = matches!(fs::symlink_metadata(&original), Err(error) if error.kind() == io::ErrorKind::NotFound);
    fs::rename(&retained, &original)?;
    assert!(
        absent,
        "opening a lost active enrollment recreated its record"
    );
    let error = match opened {
        Ok(_) => return Err("missing enrollment fell back to installation activation".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error.downcast_ref::<p::DurableError>(),
        Some(p::DurableError::Database(PrivateDatabaseError::File))
    ));
    Ok(())
}

pub(super) fn activate_pending(
    owner: PendingOwner,
    path: &Path,
    device: &p::VerifiedDevice,
    policy: &p::VerifiedSessionPolicy,
    at: u64,
    witness: Option<&WitnessFixture>,
) -> Result<DeviceOwner> {
    match owner {
        PendingOwner::Installed(signer) => {
            let mut install = p::DeviceInstallation::provision(
                super::paths(path)?,
                &key(path)?,
                device,
                policy,
                at,
            )?;
            let prepared = install.prepare(key(path)?, device, policy, at)?;
            enroll_witness(prepared, path, device, policy, at, witness)?;
            let anchor = witness.map(|value| value.client(path)).transpose()?;
            let service = install.activate(key(path)?, device, policy, at, anchor)?;
            Ok(DeviceOwner::installed(service, *signer))
        }
        PendingOwner::Enrolling(mut enrollment) => {
            let prepared = enrollment.prepare(policy, at)?;
            enroll_witness(prepared, path, device, policy, at, witness)?;
            let anchor = match witness {
                Some(value) => Some(enrollment.anchor_client(
                    policy,
                    at,
                    value.pin()?,
                    Box::new(p::AnchorTcpTransport::new(value.address)),
                    Duration::from_secs(3),
                )?),
                None => None,
            };
            let mut active = enrollment.activate(policy, at, anchor)?;
            let (service, signer, admitted) = active.parts()?;
            assert_eq!(admitted.credential_digest(), device.credential_digest());
            assert_eq!(
                signer.public_key()?.encode(),
                read(path, "public-key", 8192)?
            );
            let journal = service.stores()?.0.identity()?;
            assert_eq!(journal.as_bytes(), &array::<32>(path, "accepted-journal")?);
            store(path, "active-journal", journal.as_bytes())?;
            Ok(DeviceOwner::Enrolled(Box::new(active)))
        }
    }
}
fn enroll_witness(
    preparation: p::InstallationPreparation,
    path: &Path,
    device: &p::VerifiedDevice,
    policy: &p::VerifiedSessionPolicy,
    at: u64,
    witness: Option<&WitnessFixture>,
) -> Result<()> {
    match (witness, preparation) {
        (None, p::InstallationPreparation::Local) => {}
        (Some(witness), p::InstallationPreparation::RequiresEnrollment(genesis)) => {
            store(path, "witness-subject", &genesis.subject().to_bytes())?;
            witness
                .store
                .lock()
                .map_err(|_| "witness enrollment lock poisoned")?
                .enroll(&genesis, device, policy, at)?;
        }
        _ => return Err("installation changed the requested witness profile".into()),
    }
    Ok(())
}

pub(super) fn open(
    path: &Path,
    policy: &p::VerifiedSessionPolicy,
    expected: &p::VerifiedDevice,
    at: u64,
    anchor: Option<p::AnchorClient>,
) -> Result<DeviceOwner> {
    let approved = intent(path)?;
    let mut enrollment = p::DeviceEnrollment::open(paths(path)?, approved.clone())?;
    let request = enrollment.request(at)?;
    assert_eq!(request, read(path, "request", 8192)?);
    let verified = p::VerifiedEnrollmentRequest::verify(&request, &approved, at)?;
    assert_eq!(
        verified.identity().as_bytes(),
        &array::<32>(path, "signer-id")?
    );
    assert_eq!(enrollment.identity()?, verified.identity());
    assert_eq!(
        verified.public_key().encode(),
        read(path, "public-key", 8192)?
    );
    let journal = match enrollment.status()? {
        p::EnrollmentStatus::Active(id) => id,
        _ => return Err("connection requires the original active enrollment".into()),
    };
    assert_eq!(journal.as_bytes(), &array::<32>(path, "accepted-journal")?);
    let mut active = enrollment.activate(policy, at, anchor)?;
    let (service, signer, device) = active.parts()?;
    if device.credential_digest() != expected.credential_digest() {
        return Err(p::DurableError::Conflict.into());
    }
    signer.check_device(expected)?;
    assert_eq!(service.stores()?.0.identity()?, journal);
    // create_new observations may be published only on the first actual reopen;
    // all later reopenings must read back exactly the same values.
    for (name, bytes) in [
        ("reopened-request", request.as_slice()),
        ("reopened-journal", journal.as_bytes()),
    ] {
        match store(path, name, bytes) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                assert_eq!(read(path, name, 8192)?, bytes)
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(DeviceOwner::Enrolled(Box::new(active)))
}

pub(super) fn export(
    s: &Setup,
    session: [u8; 32],
    forward: p::MessageId,
    reverse: p::MessageId,
) -> Result<()> {
    let public = s
        .initiator
        .parent()
        .ok_or("enrollment evidence root")?
        .join("enrollment-public");
    fs::DirBuilder::new().mode(0o700).create(&public)?;
    let forward_effect = read(
        &s.responder,
        &format!("application-{}", hex(forward.as_bytes())),
        65536,
    )?;
    let reverse_effect = read(
        &s.initiator,
        &format!("application-{}", hex(reverse.as_bytes())),
        65536,
    )?;
    for (role, path) in [("initiator", &s.initiator), ("responder", &s.responder)] {
        let destination = public.join(role);
        fs::DirBuilder::new().mode(0o700).create(&destination)?;
        for name in [
            "request",
            "reopened-request",
            "signer-id",
            "public-key",
            "local-account",
            "local-root",
            "local-device",
            "local-generation",
            "enrollment-validity",
            "family",
            "local-certificate",
            "local-roster",
            "local-roster-version",
            "local-roster-digest",
            "accepted-journal",
            "active-journal",
            "reopened-journal",
            "lease-observation",
        ] {
            store(&destination, name, &read(path, name, 65536)?)?;
        }
        for (name, bytes) in [
            ("session", session.as_slice()),
            ("forward-message", forward.as_bytes()),
            ("reverse-message", reverse.as_bytes()),
            ("forward-effect", forward_effect.as_slice()),
            ("reverse-effect", reverse_effect.as_slice()),
        ] {
            store(&destination, name, bytes)?;
        }
    }
    Ok(())
}
