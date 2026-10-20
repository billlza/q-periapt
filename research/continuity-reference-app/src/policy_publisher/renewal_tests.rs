// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real protected issuer, original device and process cuts; no private-key scan.
use super::super::renewal_store::{Phase, Record, RENEWALS};
use super::*;
use crate::enrollment::{Invitation, IssuedEnrollment, RootInfo, RosterSnapshot};
use crate::native_device::NativeDevice;
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    directory: Directory,
    path: PathBuf,
    account: RootInfo,
    request: RenewalRequest,
    until: u64,
}
impl Fixture {
    fn new(seconds: u64) -> Result<Self> {
        let directory = directory()?;
        let path = directory.path().join("publisher.redb");
        let mut publisher = Publisher::provision(&path, [1; 32], input()?)?;
        let authority = publisher.prepare()?;
        let root = sdk::RootSigningKey::generate()?;
        let at = crate::enrollment::now()?;
        let invitation = Invitation {
            operation: [3; 32],
            request_id: [4; 32],
            application: [5; 32],
            root_revision: 1,
            root: root.public_key()?.encode(),
            family: authority.family,
            device: [6; 16],
            generation: 1,
            valid_from: at,
            valid_until: at + 600,
            deadline: at + 600,
            predecessor: None,
        };
        let device = directory.path().join("device");
        fs::create_dir(&device)?;
        fs::set_permissions(&device, fs::Permissions::from_mode(0o700))?;
        let wrap = directory.path().join("device.wrap");
        drop(sdk::JournalKey::provision(&wrap)?);
        let mut owner = NativeDevice::begin(&device, &wrap, invitation.clone(), at)?;
        let request =
            sdk::VerifiedEnrollmentRequest::verify(&owner.request(at)?, &invitation.intent()?, at)?;
        let certificate = root.issue_enrollment(&request, at)?;
        let roster = root.issue_roster(
            1,
            sdk::Validity::new(at, at + 600)?,
            &[root.roster_entry(&certificate)?],
        )?;
        let issued = IssuedEnrollment {
            operation: invitation.operation,
            root_revision: 1,
            certificate,
            roster: roster.as_bytes().to_vec(),
            checkpoint: roster.checkpoint().into(),
        };
        let account = RootInfo {
            revision: 1,
            account: root.account_id()?,
            public_key: root.public_key()?.encode(),
            family: authority.family,
            suspended: false,
            roster: Some(RosterSnapshot {
                checkpoint: issued.checkpoint,
                bytes: issued.roster.clone(),
            }),
        };
        let original = Request {
            bootstrap_mode: BootstrapMode::ReusableBoth,
            valid_from: at,
            valid_until: at + seconds,
            send_budget: 8,
            anchor: Anchor::LocalOnly {},
        };
        publisher.issue([7; 32], original.clone(), at)?;
        publisher.issue(
            [8; 32],
            Request {
                valid_until: at + seconds + 10,
                ..original
            },
            at,
        )?;
        let (pins, materials) = publisher.export([7; 32])?;
        let (policy, _) = pins.verify(&materials, authority.family, at)?;
        owner.accept(&issued, &account, &policy, at)?;
        owner.prepare(&account, &policy, at)?;
        owner.activate(&account, &policy, None, None, at)?.close();
        let mut owner = NativeDevice::open(&device, &wrap, invitation)?;
        let retained = owner.policy_renewal_request(
            sdk::PolicyRenewalId::from_trusted_state([9; 32])?,
            policy.historical(),
        )?;
        owner.close();
        let request = RenewalRequest {
            retained,
            original_publication: [7; 32],
            previous_publication: [7; 32],
            target_publication: [8; 32],
        };
        publish_private_bytes(
            &directory.path().join("renewal.json"),
            &serde_json::to_vec(&request)?,
        )?;
        publish_private_bytes(
            &directory.path().join("account.json"),
            &serde_json::to_vec(&account)?,
        )?;
        drop(publisher);
        Ok(Self {
            directory,
            path,
            account,
            request,
            until: at + seconds + 10,
        })
    }
    fn open(&self) -> Result<Publisher> {
        Ok(Publisher::open(&self.path, [1; 32])?)
    }
}

pub(super) fn child(owner: &mut Publisher, action: &str) -> Result {
    if action == "renewal-enable" {
        owner.enable_renewals()?;
        return Ok(());
    }
    let parent = owner.path.parent().ok_or("publisher parent")?;
    let request = serde_json::from_slice(&fs::read(parent.join("renewal.json"))?)?;
    let account = serde_json::from_slice(&fs::read(parent.join("account.json"))?)?;
    match action {
        "renewal-approve" => {
            owner.approve_renewal(&request, &account)?;
        }
        "renewal-cancel" => owner.cancel_renewal(&request, &account)?,
        _ => return Err("Unknown renewal child action".into()),
    }
    Ok(())
}

#[test]
fn explicit_renewal_upgrade_preserves_original_signer_and_publications_at_both_cuts() -> Result {
    for stage in [
        "policy-renewal-upgrade-before",
        "policy-renewal-upgrade-after",
    ] {
        let c = Fixture::new(600)?;
        let mut owner = c.open()?;
        let original = owner.result([7; 32])?;
        let paths = owner.paths(&owner.config()?)?;
        let keys = (fs::read(&paths.0)?, fs::read(&paths.1)?);
        assert!(owner.approve_renewal(&c.request, &c.account).is_err());
        drop(owner);
        kill(&c.path, "renewal-enable", stage)?;
        let mut owner = c.open()?;
        assert_eq!(
            owner.config()?.schema,
            if stage.ends_with("before") { 1 } else { 2 }
        );
        owner.enable_renewals()?;
        owner.enable_renewals()?;
        assert_eq!(owner.result([7; 32])?, original);
        assert_eq!((fs::read(&paths.0)?, fs::read(&paths.1)?), keys);
        assert_eq!(
            owner.renewal_status(&c.request, &c.account)?,
            RenewalStatus::Absent
        );
    }
    Ok(())
}

#[test]
fn original_renewal_survives_five_signing_and_commit_cuts() -> Result {
    for stage in [
        "policy-renewal-pending-before",
        "policy-renewal-pending-after",
        "policy-renewal-signed-before-commit",
        "policy-renewal-issued-before",
        "policy-renewal-issued-after",
    ] {
        let c = Fixture::new(600)?;
        c.open()?.enable_renewals()?;
        let marker = kill(&c.path, "renewal-approve", stage)?;
        let mut owner = c.open()?;
        let before = owner.renewal_status(&c.request, &c.account)?;
        if stage == "policy-renewal-pending-before" {
            assert_eq!(before, RenewalStatus::Absent);
        } else if stage != "policy-renewal-issued-after" {
            assert!(matches!(before, RenewalStatus::Pending { .. }));
        }
        // Status is not a signing or resumption operation.
        assert_eq!(owner.renewal_status(&c.request, &c.account)?, before);
        if stage != "policy-renewal-pending-before" {
            let mut changed = c.request.clone();
            changed.retained.scope.journal[0] ^= 1;
            assert!(owner.approve_renewal(&changed, &c.account).is_err());
        }
        let issued = owner.approve_renewal(&c.request, &c.account)?;
        if stage == "policy-renewal-issued-after" {
            let record: Record = serde_json::from_slice(&marker)?;
            let Phase::Issued { result } = record.phase else {
                return Err("issued phase".into());
            };
            assert_eq!(issued, result);
        }
        drop(owner);
        let mut owner = c.open()?;
        assert_eq!(owner.approve_renewal(&c.request, &c.account)?, issued);
        assert!(owner.cancel_renewal(&c.request, &c.account).is_err());
        let paths = owner.paths(&owner.config()?)?;
        drop(owner);
        fs::rename(&paths.0, paths.0.with_extension("held-wrap"))?;
        fs::rename(&paths.1, paths.1.with_extension("held-signer"))?;
        let mut owner = c.open()?;
        assert_eq!(owner.approve_renewal(&c.request, &c.account)?, issued);
        let mut next = c.request.clone();
        next.retained.scope.operation = [10; 32];
        assert!(owner.approve_renewal(&next, &c.account).is_err());
        assert!(!paths.0.exists() && !paths.1.exists());
    }
    Ok(())
}

#[test]
fn original_renewal_cancellation_fences_delayed_issuance_across_commit_cuts() -> Result {
    for stage in [
        "policy-renewal-closed-before",
        "policy-renewal-closed-after",
    ] {
        let c = Fixture::new(600)?;
        c.open()?.enable_renewals()?;
        kill(&c.path, "renewal-cancel", stage)?;
        let mut owner = c.open()?;
        assert_eq!(
            owner.renewal_status(&c.request, &c.account)?,
            if stage.ends_with("before") {
                RenewalStatus::Absent
            } else {
                RenewalStatus::Closed
            }
        );
        owner.cancel_renewal(&c.request, &c.account)?;
        owner.cancel_renewal(&c.request, &c.account)?;
        drop(owner);
        let mut owner = c.open()?;
        assert_eq!(
            owner.renewal_status(&c.request, &c.account)?,
            RenewalStatus::Closed
        );
        assert!(owner.approve_renewal(&c.request, &c.account).is_err());
    }
    Ok(())
}

#[test]
fn policy_issuer_rejects_unselected_roots_profiles_corruption_and_schema_loss() -> Result {
    use redb::ReadableTable;
    let c = Fixture::new(600)?;
    let mut owner = c.open()?;
    owner.enable_renewals()?;
    for field in ["target", "journal", "credential", "scope"] {
        let mut bad = c.request.clone();
        match field {
            "target" => bad.target_publication = [7; 32],
            "journal" => bad.retained.scope.original_owner[0] ^= 1,
            "credential" => bad.retained.current_certificate[20] ^= 1,
            "scope" => bad.retained.scope.previous_authorization = Some([11; 32]),
            _ => return Err("test field".into()),
        }
        assert!(owner.approve_renewal(&bad, &c.account).is_err());
        assert_eq!(
            owner.renewal_status(&c.request, &c.account)?,
            RenewalStatus::Absent
        );
    }
    let mut suspended = c.account.clone();
    suspended.suspended = true;
    assert!(owner.approve_renewal(&c.request, &suspended).is_err());
    let mut other = c.account.clone();
    other.public_key = sdk::RootSigningKey::generate()?.public_key()?.encode();
    assert!(owner.approve_renewal(&c.request, &other).is_err());
    let original = owner.result([7; 32])?;
    owner.issue(
        [12; 32],
        Request {
            valid_until: original.request.valid_until + 20,
            send_budget: 9,
            ..original.request
        },
        crate::enrollment::now()?,
    )?;
    let mut changed = c.request.clone();
    changed.target_publication = [12; 32];
    assert!(owner.approve_renewal(&changed, &c.account).is_err());
    owner.approve_renewal(&c.request, &c.account)?;
    assert!(owner.renewal_status(&c.request, &suspended).is_err());
    let tx = super::super::store::transaction(&owner.db)?;
    {
        let mut table = tx.open_table(RENEWALS)?;
        let mut saved: Record =
            super::super::store::decode(table.get([9u8; 32].as_slice())?.ok_or("record")?.value())?;
        let Phase::Issued { result } = &mut saved.phase else {
            return Err("issued".into());
        };
        let last = result.approval.last_mut().ok_or("signature")?;
        *last ^= 1;
        table.insert(
            [9u8; 32].as_slice(),
            super::super::store::encode(&saved)?.as_slice(),
        )?;
    }
    tx.commit()?;
    assert!(owner.renewal_status(&c.request, &c.account).is_err());
    let tx = super::super::store::transaction(&owner.db)?;
    tx.delete_table(RENEWALS)?;
    tx.commit()?;
    drop(owner);
    assert!(c.open().is_err());
    assert!(c.directory.path().exists());
    Ok(())
}

#[test]
fn expired_pending_policy_approval_remains_pending_until_explicit_cancellation() -> Result {
    let c = Fixture::new(10)?;
    c.open()?.enable_renewals()?;
    kill(&c.path, "renewal-approve", "policy-renewal-pending-after")?;
    let mut owner = c.open()?;
    let pending = owner.renewal_status(&c.request, &c.account)?;
    assert!(matches!(pending, RenewalStatus::Pending { .. }));
    let limit = Instant::now() + Duration::from_secs(30);
    while crate::enrollment::now()? < c.until {
        if Instant::now() >= limit {
            return Err("Actual policy expiry exceeded bound".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(owner.approve_renewal(&c.request, &c.account).is_err());
    assert_eq!(owner.renewal_status(&c.request, &c.account)?, pending);
    owner.cancel_renewal(&c.request, &c.account)?;
    drop(owner);
    assert_eq!(
        c.open()?.renewal_status(&c.request, &c.account)?,
        RenewalStatus::Closed
    );
    Ok(())
}
