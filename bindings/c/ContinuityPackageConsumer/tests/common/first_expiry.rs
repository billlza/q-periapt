// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real-clock expiry composition for independently configured consumers.
use crate::first_policy::historical;
use crate::{fixture, p, run, run_carrier, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{fs, os::unix::fs::DirBuilderExt};

pub(crate) fn wait_and_refuse_expired(
    case: &crate::first_connection::Case<'_>,
    original: &[u8],
) -> Result<()> {
    let until = historical(case.source)?.validity().until();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while fixture::now()? < until {
        if std::time::Instant::now() >= deadline {
            return Err("policy expiry deadline".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let at = fixture::now()?;
    let refused = case.base.join("expired-activation");
    run_carrier(
        case.client,
        "activate-expired",
        case.profile,
        case.source,
        case.target,
        &refused,
        case.carrier,
    )?;
    assert_eq!(fs::read(&refused)?, 104i32.to_ne_bytes());
    let replay = case.base.join("expired-original-request");
    run_carrier(
        case.client,
        "resume",
        case.profile,
        case.source,
        case.target,
        &replay,
        case.carrier,
    )?;
    assert_eq!(fs::read(replay)?, original);
    let adopted = fixture::array::<8>(case.base, "receiver-policy-adopted")?;
    let mut observed = until.to_be_bytes().to_vec();
    observed.extend_from_slice(&at.to_be_bytes());
    observed.extend_from_slice(&adopted);
    publish_private_bytes(&case.base.join("expired-policy-observation"), &observed)?;
    println!("\nINDEPENDENT_CONFIGURATION_EXPIRED_POLICY_PASS language={} carrier={} profile={} old_activation_refused=true original_request=true receiver_adopted_before_expiry=true", case.language, case.carrier.unwrap_or("local"), case.profile);
    Ok(())
}

pub(crate) fn renew_receiver_before_expiry(
    case: &crate::first_connection::Case<'_>,
    reference: &fixture::Setup,
    witness: Option<&fixture::WitnessFixture>,
) -> Result<()> {
    assert_eq!(case.carrier.is_some(), witness.is_some());
    let path = &reference.responder;
    let root = reference.responder_issuer.as_ref().ok_or("receiver root")?;
    let policy_root = reference.policy_issuer.as_ref().ok_or("policy root")?;
    let original = historical(path)?;
    let now = fixture::now()?;
    assert!(now < original.validity().until());
    let validity = fixture::array::<16>(path, "enrollment-validity")?;
    let intent = p::EnrollmentIntent::new(
        root.public_key()?,
        p::DeviceDescription::new(
            fixture::array(path, "responder-device")?,
            u64::from_be_bytes(fixture::array(path, "responder-generation")?),
            original.family(),
            p::Validity::new(
                u64::from_be_bytes(validity.get(..8).ok_or("validity start")?.try_into()?),
                u64::from_be_bytes(validity.get(8..).ok_or("validity end")?.try_into()?),
            )?,
        )?,
    );
    let paths = p::EnrollmentPaths::new(
        &path.join("wrap.key"),
        &path.join("signer.key"),
        &path.join("enrollment.redb"),
        p::InstallationPaths::new(
            &path.join("installation.redb"),
            &path.join("journal.redb"),
            &path.join("archives.redb"),
        )?,
    )?;
    let mut enrollment = p::DeviceEnrollment::open(paths, intent)?;
    let operation = p::PolicyRenewalId::generate()?;
    let request = if let Some(witness) = witness {
        let client = receiver_client(case, witness, &mut enrollment, &original)?;
        enrollment.witnessed_policy_renewal_request(operation, &original, client)?
    } else {
        enrollment.policy_renewal_request(operation, &original)?
    };
    let mut sdk = fixture::sdk(path)?;
    let issued = policy_root.issue_session_policy(
        sdk.runtime()?.as_ref(),
        p::SessionPolicyParameters::new(
            2,
            p::Validity::new(
                original.validity().from(),
                original
                    .validity()
                    .until()
                    .checked_add(600)
                    .ok_or("clock overflow")?,
            )?,
            original.allowed_modes(),
            original.anchor_requirement(),
            original.application_send_budget(),
        )?,
    )?;
    let target = p::PolicyPin::new(
        original.family(),
        policy_root.public_key()?,
        issued.checkpoint(),
    )?
    .verify(issued.as_bytes(), sdk.runtime()?, now)?;
    let materials = request.materials(&original, &original, &target);
    let statement = p::PolicyRenewalStatement::new(request.scope(), &materials, now)?;
    let approval = p::VerifiedPolicyRenewal::verify(
        &root.approve_policy_renewal(&statement)?,
        &policy_root.approve_policy_renewal(&statement)?,
        request.scope(),
        &materials,
        now,
    )?;
    assert!(matches!(
        enrollment.stage_policy_renewal(&approval, operation, &original, &target, now)?,
        p::PolicyRenewalStatus::Pending { .. }
    ));
    if let Some(witness) = witness {
        let client = receiver_client(case, witness, &mut enrollment, &original)?;
        let proposal = enrollment.prepare_witnessed_policy_renewal(
            &original,
            &original,
            &target,
            fixture::now()?,
            client,
        )?;
        assert_eq!(
            witness
                .store
                .lock()
                .map_err(|_| "witness lock")?
                .prepare_policy_renewal(proposal, &approval, &materials, fixture::now()?)?,
            p::AnchorPolicyRenewalState::Prepared
        );
        let mut client = receiver_client(case, witness, &mut enrollment, &original)?;
        assert_eq!(
            enrollment.commit_witnessed_policy_renewal(
                &proposal,
                &original,
                &target,
                fixture::now()?,
                &mut client
            )?,
            p::AnchorPolicyRenewalState::Applied
        );
        assert_eq!(
            enrollment.reconcile_witnessed_policy_renewal(
                operation,
                statement.digest(),
                &original,
                &mut client
            )?,
            p::AnchorPolicyRenewalState::Applied
        );
    } else {
        assert!(matches!(
            enrollment.reconcile_policy_renewal(&original, &target, fixture::now()?)?,
            p::PolicyRenewalStatus::Committed { .. }
        ));
    }
    assert_eq!(
        enrollment.policy_renewal_status()?,
        p::PolicyRenewalStatus::Committed {
            operation,
            statement: statement.digest(),
            target: issued.checkpoint(),
        }
    );
    enrollment.close();
    target.close();
    sdk.close();
    let inputs = case.base.join("receiver-target-inputs");
    fs::DirBuilder::new().mode(0o700).create(&inputs)?;
    for name in [
        "sdk-policy",
        "sdk-signature",
        "sdk-root",
        "family",
        "policy-root",
        "tls-cert",
        "tls-key",
    ] {
        let bytes = zeroize::Zeroizing::new(fs::read(path.join(name))?);
        publish_private_bytes(&inputs.join(name), &bytes)?;
    }
    publish_private_bytes(
        &inputs.join("policy-version"),
        &issued.checkpoint().version().to_be_bytes(),
    )?;
    publish_private_bytes(&inputs.join("policy-digest"), &issued.checkpoint().digest())?;
    publish_private_bytes(&inputs.join("protocol-policy"), issued.as_bytes())?;
    let target_path = path.join("independent-sdk");
    assert!(!target_path.exists());
    run(
        case.client,
        "policy-target-create",
        "fixed",
        &inputs,
        &target_path,
        &case.base.join("receiver-target-created"),
    )?;
    let adopted = fixture::now()?;
    assert!(adopted < original.validity().until());
    publish_private_bytes(
        &case.base.join("receiver-policy-adopted"),
        &adopted.to_be_bytes(),
    )?;
    publish_private_bytes(&case.base.join("receiver-policy"), issued.as_bytes())?;
    Ok(())
}

fn receiver_client(
    case: &crate::first_connection::Case<'_>,
    witness: &fixture::WitnessFixture,
    enrollment: &mut p::DeviceEnrollment,
    original: &p::HistoricalSessionPolicy,
) -> Result<p::AnchorClient> {
    let address = fs::read_to_string(case.source.join("witness-address"))?.parse()?;
    let transport: Box<dyn p::AnchorTransport> = match case.carrier {
        Some("signed") => Box::new(p::AnchorTcpTransport::new(address)),
        Some("tls") => {
            use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
            let path = case.receiver;
            let peer = fixture::read(path, "witness-tls-peer", 8192)?;
            let certificate = fixture::read(path, "witness-tls-cert", 8192)?;
            let secret = zeroize::Zeroizing::new(fixture::read(path, "witness-tls-key", 8192)?);
            let name = ServerName::try_from(String::from_utf8(fixture::read(
                path,
                "witness-tls-name",
                128,
            )?)?)?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(peer.clone()))?;
            let config = q_periapt_rustls::standard::MutualTlsClient::new(
                roots,
                vec![CertificateDer::from(certificate)],
                PrivateKeyDer::try_from(secret.as_slice())?.clone_key(),
            )?;
            Box::new(p::anchor_tls::AnchorTlsTransport::new(
                address,
                name,
                peer,
                config,
                p::connection_transport::Cancellation::default(),
            )?)
        }
        _ => return Err("receiver policy witness carrier".into()),
    };
    let pin = witness.store.lock().map_err(|_| "witness lock")?.pin()?;
    Ok(enrollment.policy_renewal_anchor_client(
        original,
        pin,
        transport,
        std::time::Duration::from_secs(3),
    )?)
}

pub(crate) fn prepare_receiver_metadata(reference: &fixture::Setup) -> Result<()> {
    let path = &reference.responder;
    let root = reference.responder_issuer.as_ref().ok_or("receiver root")?;
    let mut intent = fixture::array::<16>(path, "responder-device")?.to_vec();
    intent.extend_from_slice(&fixture::array::<8>(path, "responder-generation")?);
    intent.extend_from_slice(&fixture::array::<32>(path, "family")?);
    intent.extend_from_slice(&fixture::array::<16>(path, "enrollment-validity")?);
    publish_private_bytes(&path.join("enrollment-root"), &root.public_key()?.encode())?;
    publish_private_bytes(&path.join("enrollment-intent"), &intent)?;
    Ok(())
}
