// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[test]
fn c_peer_grants_restore_original_expired_session_and_fence_cached_children() -> Result<()> {
    let c = registered(60)?;
    let peer = peer_bundle(&c._setup, &c.path, &c.root, &c.certificate, &c.roster)?;
    let server_path = &c._setup.responder;
    let (mut server, address) = fixture::spawn(server_path, 81, "bootstrap")?;
    let initiation = p::InitiationId::generate()?;
    let args = vec![
        "--enrollment-parent".into(),
        c.path.as_os_str().into(),
        "1".into(),
        "connect".into(),
        peer.as_os_str().into(),
        address.to_string().into(),
        fixture::hex(initiation.as_bytes()).into(),
    ];
    let session = decode_id(run(&c.path, "original-connect", &args)?.trim_end())?;
    assert!(fixture::wait(&mut server)?.success());
    assert_eq!(fixture::array::<32>(server_path, "session")?, session);
    let mut owner = fixture::Peer::open(server_path)?;
    let message =
        owner
            .service
            .stores()?
            .0
            .next_message_id(&owner.context, session, fixture::now()?)?;
    let original_wire = owner.service.stores()?.0.send_message(
        &owner.context,
        session,
        message,
        b"original peer outbox",
        b"renewal qualification",
        fixture::now()?,
    )?;
    let context_digest = owner.context.digest();
    owner.close();
    let sdk = fixture::sdk(&c.path)?;
    let policy = fixture::protocol_policy(&c.path, &sdk)?;
    let mut previous_certificate = c.certificate.clone();
    let mut previous_roster = c.roster.as_bytes().to_vec();
    let mut previous_checkpoint = c.roster.checkpoint();
    let mut grants = Vec::new();
    for version in [2u64, 3] {
        let certificate = c.root.issue_device(
            p::DeviceDescription::new(
                [71; 16],
                1,
                c.family,
                p::Validity::new(
                    c.validity.from(),
                    c.at.checked_add(version * 300).ok_or("clock overflow")?,
                )?,
            )?,
            c.verified.public_key().clone(),
        )?;
        let roster = c.root.issue_roster(
            version,
            c.roster_validity,
            &[c.root.roster_entry(&certificate)?],
        )?;
        let pin = p::AccountPin::new(
            c.root.account_id()?,
            c.root.public_key()?,
            roster.checkpoint(),
            c.family,
        )?;
        let operation = p::CredentialRenewalId::generate()?;
        let grant = c.root.issue_credential_renewal(
            p::CredentialRenewalMaterials {
                original_credential: &c.certificate,
                previous_credential: &previous_certificate,
                successor_credential: &certificate,
                previous_roster: &previous_roster,
                successor_roster: roster.as_bytes(),
            },
            &p::CredentialRenewalAuthorization {
                operation,
                previous: previous_checkpoint,
                policy_digest: policy.checkpoint().digest(),
            },
            &pin,
            fixture::now()?,
        )?;
        let path = c.path.join(format!("peer-grant-{version}"));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        for name in ["enrollment-root", "enrollment-intent", "trusted-account"] {
            fixture::store(&path, name, &fixture::read(&c.path, name, 8192)?)?;
        }
        for (name, bytes) in [
            ("credential-renewal", grant.as_bytes().to_vec()),
            ("credential-operation", operation.as_bytes().to_vec()),
            ("renewal-version", version.to_be_bytes().to_vec()),
            ("renewal-digest", roster.checkpoint().digest().to_vec()),
        ] {
            fixture::store(&path, name, &bytes)?;
        }
        grants.push(path);
        previous_certificate = certificate;
        previous_checkpoint = roster.checkpoint();
        previous_roster = roster.as_bytes().to_vec();
    }
    policy.close();
    drop(sdk);
    wait_until_expired(c.validity.until())?;
    let args = vec![
        "credential-peer-check".into(),
        server_path.as_os_str().into(),
        grants.first().ok_or("first grant")?.as_os_str().into(),
        grants.get(1).ok_or("next grant")?.as_os_str().into(),
        fixture::hex(&session).into(),
        fixture::hex(message.as_bytes()).into(),
    ];
    assert_eq!(
        run(&c.path, "peer-renewal", &args)?,
        "credential-peer-passed\n"
    );
    // Independent public native readback checks the exact ciphertext and original
    // transcript after the C process installed both grants and reopened its owner.
    let mut sdk = fixture::sdk(server_path)?;
    let policy = fixture::protocol_policy(server_path, &sdk)?;
    let root = p::PublicKey::decode(&fixture::read(server_path, "local-root", 8192)?)?;
    let family = fixture::array(server_path, "family")?;
    let pin = p::AccountPin::new(
        fixture::array(server_path, "local-account")?,
        root,
        p::RosterCheckpoint::from_trusted_state(
            u64::from_be_bytes(fixture::array(server_path, "local-roster-version")?),
            fixture::array(server_path, "local-roster-digest")?,
        )?,
        family,
    )?;
    let device = pin.verify_device(
        &fixture::read(server_path, "local-certificate", 8192)?,
        &fixture::read(server_path, "local-roster", 8192)?,
        fixture::now()?,
    )?;
    let key = p::JournalKey::open(&server_path.join("wrap.key"))?;
    let mut service = p::DeviceInstallation::open(
        p::InstallationPaths::new(
            &server_path.join("installation.redb"),
            &server_path.join("journal.redb"),
            &server_path.join("archives.redb"),
        )?,
        &key,
        &device,
        &policy,
        fixture::now()?,
    )?
    .activate(key, &device, &policy, fixture::now()?, None)?;
    let restored = fixture::with_bundle_for_family(server_path, family, |bundle, requirements| {
        Ok(service.reopen_peer_bundle(
            &bundle,
            Arc::clone(&policy),
            requirements,
            p::BootstrapRole::Responder,
            session,
            fixture::now()?,
        )?)
    })?;
    assert_eq!(restored.context().digest(), context_digest);
    assert_eq!(
        service.stores()?.0.resume_message(
            restored.context(),
            session,
            message,
            fixture::now()?
        )?,
        original_wire
    );
    service.close();
    policy.close();
    sdk.close();
    println!("C_PEER_CREDENTIAL_RENEWAL original_tls_session=true actual_expiry=true wrong_pin_and_operation_refused=true cached_child_fenced=true persisted_grant=true exact_outbox_readback=true");
    Ok(())
}
