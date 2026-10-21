// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated host, real enrollment owners and the original signed witness decisions.
use super::*;
use crate::{
    account_authority::{CutoverRequest, CutoverStatus, Retirement},
    enrollment::{CredentialExtensionRequest, RosterSnapshot},
    native_device::NativeDevice,
    root_preparation::{Request, Status, SuccessorRequest},
    witness::{
        AccountRootFreeze, AccountRootOutcome, AccountRootTrust, EnrollmentRequest, EnrollmentTrust,
    },
};
mod crash;

struct Target {
    input: CutoverRequest,
    trust: AccountRootTrust,
    invitation: Invitation,
    issued: Vec<u8>,
    root: RootInfo,
    device_path: PathBuf,
    wrapping: PathBuf,
    installation: [u8; 32],
}
fn now() -> Result<u64> {
    Ok(crate::enrollment::now()?)
}
fn witness(c: &Case) -> Result<Witness> {
    Witness::open(&c.path.join("witness.redb"), [100; 32])
}
fn enrollment(prepared: sdk::InstallationPreparation) -> Result<EnrollmentRequest> {
    let sdk::InstallationPreparation::RequiresEnrollment(genesis) = prepared else {
        return Err("expected original prepared witness genesis".into());
    };
    Ok(EnrollmentRequest {
        preparation: "RequiresWitnessEnrollment".into(),
        subject: genesis.subject().to_bytes(),
        head: genesis.image_digest(),
    })
}
fn associate(c: &mut Case) -> Result<()> {
    c.host.store.enable_account_authorities()?;
    c.host.associate_account_authority(&c.token, &c.request)?;
    // Prepare the already-issued original installation using its retained key and intent.
    let dir = c.path.join(URL_SAFE_NO_PAD.encode(c.original.operation));
    let paths = sdk::EnrollmentPaths::new(
        &dir.join("wrap.key"),
        &dir.join("signer.key"),
        &dir.join("enrollment.redb"),
        sdk::InstallationPaths::new(
            &dir.join("installation.redb"),
            &dir.join("journal.redb"),
            &dir.join("archive.redb"),
        )?,
    )?;
    let mut owner = sdk::DeviceEnrollment::open(paths, c.original.intent()?)?;
    let issued: IssuedEnrollment =
        serde_json::from_slice(&c.host.issue_enrollment(&c.token, c.original.operation)?)?;
    let (policy, _) =
        c.request
            .policy
            .pins
            .verify(&c.request.policy.materials, c.root.family, now()?)?;
    let pin = sdk::AccountPin::new(
        c.root.account,
        sdk::PublicKey::decode(&c.root.public_key)?,
        issued.checkpoint.as_sdk()?,
        c.root.family,
    )?;
    owner.accept(&issued.certificate, &issued.roster, &pin, &policy, now()?)?;
    let request = enrollment(owner.prepare(&policy, now()?)?)?;
    let trust = EnrollmentTrust {
        schema: "qperiapt-witness-enrollment-trust/1".into(),
        account: c.root.clone(),
        device: c.original.device,
        generation: c.original.generation,
        journal: *owner.public_admission()?.journal().as_bytes(),
        genesis_head: request.head,
        certificate: issued.certificate,
        policy: c.request.policy.clone(),
    };
    witness(c)?.enroll(&trust, &request, now()?)?;
    owner.close();
    Ok(())
}
impl Target {
    fn new(c: &mut Case) -> Result<Self> {
        Self::prepare(c, None)
    }
    fn prepare(c: &mut Case, prior: Option<(&Self, &AccountRootFreeze)>) -> Result<Self> {
        let current = c.host.enrollment_root(&c.token)?;
        let prepared = c.host.prepare_account_root(
            &c.token,
            &Request {
                request_id: crate::enrollment::random()?,
                predecessor: Predecessor {
                    revision: current.revision,
                    account: current.account,
                },
            },
        )?;
        let Status::Prepared { candidate } = prepared.status else {
            return Err("prepared candidate".into());
        };
        let invitation = c.host.invite_root_successor(
            &c.token,
            &SuccessorRequest {
                preparation: prepared.operation,
                request_id: crate::enrollment::random()?,
            },
        )?;
        let device_path = c.path.join(format!(
            "native-{}",
            URL_SAFE_NO_PAD.encode(invitation.operation)
        ));
        fs::DirBuilder::new().mode(0o700).create(&device_path)?;
        let wrapping = device_path.join("wrap.key");
        drop(sdk::JournalKey::provision(&wrapping)?);
        let mut owner = NativeDevice::begin(&device_path, &wrapping, invitation.clone(), now()?)?;
        c.host
            .approve_enrollment(&c.token, invitation.operation, &owner.request(now()?)?)?;
        let issued = c.host.issue_enrollment(&c.token, invitation.operation)?;
        let response: IssuedEnrollment = serde_json::from_slice(&issued)?;
        let root = RootInfo {
            revision: candidate.revision,
            account: candidate.account,
            public_key: candidate.public_key,
            family: candidate.family,
            suspended: false,
            roster: Some(RosterSnapshot {
                checkpoint: response.checkpoint,
                bytes: response.roster.clone(),
            }),
        };
        let (policy, _) =
            c.request
                .policy
                .pins
                .verify(&c.request.policy.materials, root.family, now()?)?;
        let installation = owner.accept(&response, &root, &policy, now()?)?;
        let target = enrollment(owner.prepare(&root, &policy, now()?)?)?;
        let status = serde_json::to_value(owner.status()?)?;
        let journal = serde_json::from_value(status["journal"].clone())?;
        let trust = AccountRootTrust {
            schema: "qperiapt-witness-account-root-trust/1".into(),
            operation: crate::enrollment::random()?,
            freeze_operation: prior.map_or_else(crate::enrollment::random, |p| {
                Ok(p.0.trust.freeze_operation)
            })?,
            previous_root: current.public_key,
            successor: EnrollmentTrust {
                schema: "qperiapt-witness-enrollment-trust/1".into(),
                account: root.clone(),
                device: invitation.device,
                generation: invitation.generation,
                journal,
                genesis_head: target.head,
                certificate: response.certificate,
                policy: c.request.policy.clone(),
            },
        };
        let mut witness = witness(c)?;
        let plan = if let Some((prior, frozen)) = prior {
            witness.replan_frozen_account_root(
                &trust,
                &target,
                &prior.input.plan,
                frozen,
                now()?,
            )?
        } else {
            witness.plan_account_root_replacement(&trust, &target, now()?)?
        };
        owner.close();
        Ok(Self {
            input: CutoverRequest {
                preparation: prepared.operation,
                enrollment: invitation.operation,
                roster: response.checkpoint,
                journal,
                genesis_head: target.head,
                policy: c.request.policy.clone(),
                plan,
                target,
            },
            trust,
            invitation,
            issued,
            root,
            device_path,
            wrapping,
            installation,
        })
    }
    fn retirement(&self, c: &Case) -> Result<Retirement> {
        let mut owner = witness(c)?;
        let frozen = owner.freeze_account_root(&self.input.plan)?;
        let decision = owner.bind_account_root_replacement(
            &self.trust,
            &self.input.target,
            &self.input.plan,
            &frozen,
            now()?,
        )?;
        let AccountRootOutcome::Committed { receipt, .. } = owner.commit_account_root_replacement(
            &self.trust,
            &self.input.target,
            &self.input.plan,
            &frozen,
            &decision,
            now()?,
        )?
        else {
            return Err("committed witness root".into());
        };
        Ok(Retirement { decision, receipt })
    }
    fn extension(&self) -> Result<CredentialExtensionRequest> {
        Ok(CredentialExtensionRequest {
            request_id: crate::enrollment::random()?,
            enrollment: self.invitation.operation,
            previous_extension: None,
            predecessor: self.input.roster,
            valid_until: self.invitation.valid_until + 3600,
        })
    }
}

#[test]
fn cutover_selects_one_root_preserves_history_and_reopens_original_installation() -> Result {
    let mut c = Case::new()?;
    associate(&mut c)?;
    let t = Target::new(&mut c)?;
    let old = c.host.issue_enrollment(&c.token, c.original.operation)?;
    let key = fs::read(t.device_path.join("device.key"))?;
    let wrap = fs::read(&t.wrapping)?;
    let approved = c.host.approve_account_root(&c.token, &t.input)?;
    assert_eq!(approved.status, CutoverStatus::AwaitingOutcome);
    assert!(c.host.enrollment_root(&c.token)?.suspended);
    assert!(matches!(
        c.host
            .invite_enrollment(&c.token, crate::enrollment::random()?),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        c.host
            .close_account_root_preparation(&c.token, t.input.preparation),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        c.host
            .extend_enrollment_credential(&c.token, &t.extension()?),
        Err(Error::Conflict(_))
    ));
    let retired = t.retirement(&c)?;
    let result = c
        .host
        .commit_account_root(&c.token, approved.operation, &retired)?;
    assert_eq!(
        result.status,
        CutoverStatus::Committed {
            successor: t.root.clone()
        }
    );
    assert_eq!(c.host.enrollment_root(&c.token)?, t.root);
    assert_eq!(
        c.host.retired_account_root(&c.token, c.root.revision)?,
        RootInfo {
            suspended: true,
            ..c.root.clone()
        }
    );
    assert_eq!(
        c.host.issue_enrollment(&c.token, c.original.operation)?,
        old
    );
    assert_eq!(
        c.host.issue_enrollment(&c.token, t.invitation.operation)?,
        t.issued
    );
    let all_keys = super::super::root_preparation::keys(&c.path)?;
    drop(c.host);
    c.host = reopen(&c.path)?;
    c.token = login(&mut c.host, &mut c.auth, "alice")?.0;
    assert_eq!(
        c.host.resume_account_root(&c.token, approved.operation)?,
        result
    );
    assert_eq!(c.host.approve_account_root(&c.token, &t.input)?, result);
    assert_eq!(
        c.host
            .commit_account_root(&c.token, approved.operation, &retired)?,
        result
    );
    let (policy, _) =
        c.request
            .policy
            .pins
            .verify(&c.request.policy.materials, t.root.family, now()?)?;
    let mut device = NativeDevice::open(&t.device_path, &t.wrapping, t.invitation.clone())?;
    assert_eq!(
        device.accept(
            &serde_json::from_slice(&t.issued)?,
            &t.root,
            &policy,
            now()?
        )?,
        t.installation
    );
    assert!(enrollment(device.prepare(&t.root, &policy, now()?)?)? == t.input.target);
    device.close();
    assert!(fs::read(t.device_path.join("device.key"))? == key && fs::read(&t.wrapping)? == wrap);
    let extended: crate::enrollment::IssuedCredentialExtension = serde_json::from_slice(
        &c.host
            .extend_enrollment_credential(&c.token, &t.extension()?)?,
    )?;
    assert_eq!(extended.root_revision, t.root.revision);
    assert_eq!(extended.checkpoint.version, t.input.roster.version + 1);
    sdk::AccountPin::new(
        t.root.account,
        sdk::PublicKey::decode(&t.root.public_key)?,
        extended.checkpoint.as_sdk()?,
        t.root.family,
    )?
    .verify_device(&extended.certificate, &extended.roster, now()?)?;
    let fresh = c
        .host
        .invite_enrollment(&c.token, crate::enrollment::random()?)?;
    assert_eq!(fresh.root, t.root.public_key);
    assert_eq!(fresh.root_revision, t.root.revision);
    let (_, proof) = request(&c.path, &fresh)?;
    c.host
        .approve_enrollment(&c.token, fresh.operation, &proof)?;
    let issued: IssuedEnrollment =
        serde_json::from_slice(&c.host.issue_enrollment(&c.token, fresh.operation)?)?;
    verify(&c.host.enrollment_root(&c.token)?, &issued)?;
    assert!(matches!(
        c.host.extend_enrollment_credential(
            &c.token,
            &CredentialExtensionRequest {
                request_id: crate::enrollment::random()?,
                enrollment: c.original.operation,
                previous_extension: None,
                predecessor: c.request.roster,
                valid_until: c.original.valid_until + 3600
            }
        ),
        Err(Error::Conflict(_))
    ));
    super::super::root_preparation::unchanged(&all_keys)?;
    assert_eq!(
        c.host.account_root_cutover(&c.token, approved.operation)?,
        result
    );
    Ok(())
}

#[test]
fn cutover_historical_retirement_survives_real_policy_expiry_and_old_signer_loss() -> Result {
    let mut c = Case::with_duration(20)?;
    associate(&mut c)?;
    let keys = super::super::root_preparation::keys(&c.path)?;
    let mut retained = Vec::new();
    for file in keys.keys().filter(|p| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("enrollment-"))
    }) {
        let moved = file.with_extension(format!(
            "{}.retained",
            file.extension().ok_or("extension")?.to_string_lossy()
        ));
        fs::rename(file, &moved)?;
        retained.push((file.clone(), moved));
    }
    assert_eq!(retained.len(), 2);
    let t = Target::new(&mut c)?;
    c.host.approve_account_root(&c.token, &t.input)?;
    let proof = t.retirement(&c)?;
    let (historical, _) = c
        .request
        .policy
        .pins
        .verify_historical(&c.request.policy.materials, c.root.family)?;
    let deadline = Instant::now() + std::time::Duration::from_secs(25);
    while now()? < historical.validity().until() {
        assert!(
            Instant::now() < deadline,
            "actual policy expiry exceeded fixture bound"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // Historical verification still succeeds, proving expiry rather than a corrupted policy.
    c.request
        .policy
        .pins
        .verify_historical(&c.request.policy.materials, c.root.family)?;
    let result = c
        .host
        .commit_account_root(&c.token, t.trust.operation, &proof)?;
    assert_eq!(
        result.status,
        CutoverStatus::Committed {
            successor: t.root.clone()
        }
    );
    assert_eq!(c.host.enrollment_root(&c.token)?, t.root);
    assert_eq!(
        c.host.resume_account_root(&c.token, t.trust.operation)?,
        result
    );
    assert!(c
        .request
        .policy
        .pins
        .verify(&c.request.policy.materials, c.root.family, now()?)
        .is_err());
    for (file, moved) in retained {
        assert!(!file.exists());
        assert!(fs::read(moved)? == *keys.get(&file).ok_or("original key")?);
    }
    Ok(())
}

#[test]
fn cutover_rejects_changed_scope_and_bad_proofs_before_retaining_terminal_intent() -> Result {
    let mut c = Case::new()?;
    associate(&mut c)?;
    let t = Target::new(&mut c)?;
    for field in [
        "journal",
        "head",
        "roster",
        "preparation",
        "enrollment",
        "plan",
    ] {
        let mut changed = t.input.clone();
        match field {
            "journal" => changed.journal = [73; 32],
            "head" => changed.genesis_head = [74; 32],
            "roster" => changed.roster.version += 1,
            "preparation" => changed.preparation = [75; 32],
            "enrollment" => changed.enrollment = c.original.operation,
            "plan" => changed.plan.binding = [76; 32],
            _ => unreachable!(),
        }
        assert!(
            c.host.approve_account_root(&c.token, &changed).is_err(),
            "{field}"
        );
        assert_eq!(c.host.enrollment_root(&c.token)?, c.root);
    }
    assert!(matches!(
        c.host.approve_account_root("absent", &t.input),
        Err(Error::Unauthorized)
    ));
    let approved = c.host.approve_account_root(&c.token, &t.input)?;
    assert!(c
        .host
        .close_account_root(&c.token, approved.operation, &[])
        .is_err());
    let proof = t.retirement(&c)?;
    let mut changed = proof.clone();
    *changed.receipt.last_mut().ok_or("signature")? ^= 1;
    assert!(c
        .host
        .commit_account_root(&c.token, approved.operation, &changed)
        .is_err());
    assert_eq!(
        c.host
            .account_root_cutover(&c.token, approved.operation)?
            .status,
        CutoverStatus::AwaitingOutcome
    );
    changed = proof.clone();
    changed.decision.plan_binding = [77; 32];
    assert!(c
        .host
        .commit_account_root(&c.token, approved.operation, &changed)
        .is_err());
    assert_eq!(
        c.host
            .account_root_cutover(&c.token, approved.operation)?
            .status,
        CutoverStatus::AwaitingOutcome
    );
    c.host
        .commit_account_root(&c.token, approved.operation, &proof)?;
    Ok(())
}

#[test]
fn cutover_permanent_noncommit_retains_freeze_and_allows_new_independently_approved_winner(
) -> Result {
    let mut c = Case::new()?;
    associate(&mut c)?;
    let first = Target::new(&mut c)?;
    let approved = c.host.approve_account_root(&c.token, &first.input)?;
    let frozen = witness(&c)?.freeze_account_root(&first.input.plan)?;
    let AccountRootOutcome::Closed { receipt, .. } =
        witness(&c)?.close_account_root_plan(&first.input.plan)?
    else {
        return Err("closed plan".into());
    };
    let closed = c
        .host
        .close_account_root(&c.token, approved.operation, &receipt)?;
    assert_eq!(closed.status, CutoverStatus::Closed);
    assert_eq!(
        c.host
            .close_account_root(&c.token, approved.operation, &receipt)?,
        closed
    );
    assert!(c.host.enrollment_root(&c.token)?.suspended);
    assert!(matches!(
        c.host
            .invite_enrollment(&c.token, crate::enrollment::random()?),
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        c.host
            .extend_enrollment_credential(&c.token, &first.extension()?),
        Err(Error::Conflict(_))
    ));
    let next = Target::prepare(&mut c, Some((&first, &frozen)))?;
    assert_eq!(
        c.host.approve_account_root(&c.token, &next.input)?.status,
        CutoverStatus::AwaitingOutcome
    );
    let proof = next.retirement(&c)?;
    c.host
        .commit_account_root(&c.token, next.trust.operation, &proof)?;
    assert_eq!(c.host.enrollment_root(&c.token)?, next.root);
    assert_eq!(
        c.host.resume_account_root(&c.token, approved.operation)?,
        closed
    );
    assert_eq!(
        c.host
            .issue_enrollment(&c.token, first.invitation.operation)?,
        first.issued
    );
    Ok(())
}
