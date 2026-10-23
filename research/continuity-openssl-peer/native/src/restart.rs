// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Reopen the explicit successor test fixture, never provision replacement state.
//! Only public metadata is read from artifacts. Secrets stay in the original
//! owner-only directory and use the SDK's sealed exact-operation API.
use crate::{
    fixture::{Fixture, Times},
    Result,
};
use q_periapt_continuity_identity_candidate::{
    AccountPin, BootstrapContext, BootstrapRole, ClassicalChoice, DirectoryExpectation, LeafProof,
    PolicyCheckpoint, PolicyPin, PqChoice, PublicKey, RosterCheckpoint, VerifiedDevice,
};
use q_periapt_core::ZeroizingBytes;
use q_periapt_host_store::filesystem::{open_private_parent, publish_private_bytes};
use q_periapt_sdk::{
    expert::replay::{RecoveryKey, SealedOperation},
    HybridKey, Limits, Runtime,
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

pub(super) fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    fs::File::open(path)?
        .take(u64::try_from(maximum + 1)?)
        .read_to_end(&mut value)?;
    if value.len() > maximum {
        return Err("restart metadata capacity".into());
    }
    Ok(value)
}

pub(super) fn private_path(public: &Path, name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(String::from_utf8(read(&public.join(name), 4096)?)?);
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err("original private path must be canonical".into());
    }
    Ok(path)
}

pub(super) struct Selection {
    pub control: Vec<u8>,
    pub previous: [u8; 32],
    pub later: bool,
}

pub(super) fn unactivated_account(
    fixture: &Fixture,
    public: &Path,
    original: [u8; 32],
) -> Result<Option<[u8; 32]>> {
    let first = public.join("root-successor");
    if !first.join("unactivated").try_exists()? {
        return Ok(None);
    }
    if read(&first.join("unactivated"), 64)? != crate::approval::UNACTIVATED
        || private_path(&first, "private-fixture-path")?
            != private_path(public, "private-fixture-path")?
    {
        return Err("unactivated predecessor metadata differs".into());
    }
    let account = fixture
        .witness
        .as_ref()
        .ok_or("unactivated predecessor requires original witness")?
        .successor_account(fixture, &read(&first.join("control"), 32768)?, original)?;
    Ok(Some(account))
}

pub(super) fn retain_unactivated(
    fixture: &Fixture,
    public: &Path,
    control: &[u8],
    publication_started: &mut bool,
) -> Result<Vec<u8>> {
    let original = fixture
        .context
        .device(BootstrapRole::Initiator)
        .account_id();
    let account = fixture
        .witness
        .as_ref()
        .ok_or("unactivated predecessor requires original witness")?
        .successor_account(fixture, control, original)?;
    let first = public.join("root-successor");
    if first.try_exists()?
        && (unactivated_account(fixture, public, original)? != Some(account)
            || read(&first.join("control"), 32768)? != control)
    {
        return Err("unactivated predecessor cannot retarget original metadata".into());
    }
    crate::approval::publish(
        public,
        crate::approval::Kind::Unactivated,
        control,
        publication_started,
    )?;
    if unactivated_account(fixture, public, original)? != Some(account) {
        return Err("unactivated predecessor readback differs".into());
    }
    Ok(account.to_vec())
}

impl Selection {
    pub(super) fn open(fixture: &Fixture, public: &Path) -> Result<Option<Self>> {
        let first_directory = public.join("root-successor");
        let later = public.join("root-successor-later");
        if !first_directory.try_exists()? && !later.try_exists()? {
            // Publication never reached its atomic commit. No peer is selected;
            // the explicit controller must resend its signed, committed request.
            return Ok(None);
        }
        let first = read(&public.join("root-successor/control"), 32768)?;
        if private_path(&first_directory, "private-fixture-path")?
            != private_path(public, "private-fixture-path")?
        {
            return Err("successor journal differs from original native journal".into());
        }
        let original = fixture
            .context
            .device(BootstrapRole::Initiator)
            .account_id();
        let unactivated = unactivated_account(fixture, public, original)?;
        if !later.try_exists()? {
            if unactivated.is_some() {
                return Ok(None);
            }
            return Ok(Some(Self {
                control: first,
                previous: original,
                later: false,
            }));
        }
        // A retained later selection must be complete. Never fall back to the
        // previous controller if its metadata is missing, corrupt, or unreadable.
        let control = read(&later.join("control"), 32768)?;
        if private_path(&later, "private-fixture-path")?
            != private_path(public, "private-fixture-path")?
        {
            return Err("later successor journal differs from original native journal".into());
        }
        let previous = fixture
            .witness
            .as_ref()
            .ok_or("restart requires original witness")?
            .successor_account(fixture, &first, original)?;
        Ok(Some(Self {
            control,
            previous,
            later: true,
        }))
    }
}

pub(super) fn prekey(path: &Path, runtime: &Runtime, create: bool) -> Result<HybridKey> {
    let key_path = path.join("prekey-host-key");
    let mut key = ZeroizingBytes::<32>::zeroed();
    if create {
        getrandom::fill(key.as_mut_bytes())?;
        publish_private_bytes(&key_path, key.as_bytes())?;
    } else {
        let (parent, leaf) = open_private_parent(&key_path)?;
        let mut file = parent.open_state_file(leaf)?;
        if file.metadata()?.len() != 32 {
            return Err("original prekey host key length".into());
        }
        file.read_exact(key.as_mut_bytes())?;
        file.sync_all()?;
        parent.sync_entries()?;
    }
    let recovery = RecoveryKey::from_host_key(key.as_bytes())?;
    let scope = runtime.trusted_state().digest();
    let token_path = path.join("prekey-reservation");
    let token = if create {
        let token = recovery.reserve_key(runtime, &scope)?;
        publish_private_bytes(&token_path, token.as_bytes())?;
        token
    } else {
        let (parent, leaf) = open_private_parent(&token_path)?;
        let mut wire = Vec::new();
        parent
            .open_state_file(leaf)?
            .take(278)
            .read_to_end(&mut wire)?;
        SealedOperation::from_bytes(&wire)?
    };
    Ok(recovery.generate_key(runtime, &scope, &token)?)
}

fn device(public: &Path, role: &str, family: [u8; 32]) -> Result<Arc<VerifiedDevice>> {
    let head = read(&public.join(format!("pin-{role}-head")), 96)?;
    if head.len() != 96 {
        return Err("original device pin length".into());
    }
    let pin = AccountPin::new(
        head[..32].try_into()?,
        PublicKey::decode(&read(&public.join(format!("pin-{role}-root")), 1985)?)?,
        RosterCheckpoint::from_trusted_state(
            u64::from_be_bytes(head[32..40].try_into()?),
            head[40..72].try_into()?,
        )?,
        family,
    )?;
    let device = pin.verify_historical_device(
        &read(&public.join(format!("{role}-credential")), 8192)?,
        &read(&public.join(format!("{role}-roster")), 8192)?,
    )?;
    if device.device_id() != head[72..88]
        || device.generation() != u64::from_be_bytes(head[88..].try_into()?)
    {
        return Err("original device pin differs".into());
    }
    Ok(Arc::new(device))
}

pub(super) fn fixture(public: &Path, now: u64) -> Result<Fixture> {
    let get = |name: &str| read(&public.join(name), 32768);
    let bootstrap = u64::from_be_bytes(get("restart-bootstrap-time")?.as_slice().try_into()?);
    if now < bootstrap {
        return Err("restart clock precedes original fixture".into());
    }
    let expected = q_periapt_policy::TrustedPolicyState::decode(&get("pin-sdk-state")?)
        .map_err(|error| format!("original SDK state: {error:?}"))?;
    let runtime = Arc::new(Runtime::from_signed_policy(
        &get("sdk-document")?,
        &get("sdk-signature")?,
        &get("pin-sdk-root")?,
        Some(&expected),
        Limits::default(),
    )?);
    let family = get("pin-policy-family")?.as_slice().try_into()?;
    let head = get("pin-policy-head")?;
    if head.len() != 40 {
        return Err("original policy pin length".into());
    }
    let pin = PolicyPin::new(
        family,
        PublicKey::decode(&get("pin-policy-root")?)?,
        PolicyCheckpoint::from_trusted_state(
            u64::from_be_bytes(head[..8].try_into()?),
            head[8..].try_into()?,
        )?,
    )?;
    let policy = Arc::new(pin.verify(&get("policy")?, Arc::clone(&runtime), now)?);
    let initiator = device(public, "i", family)?;
    let responder = device(public, "r", family)?;
    // Reconstruct the original fixture commitment at its recorded admission
    // instant only. Resume mode forbids its old operational controller. The
    // successor is separately verified at `now` against persisted retirement.
    let manifest = responder.verify_manifest(&get("manifest")?, bootstrap)?;
    let selection = manifest.select_prekeys(
        &LeafProof::decode(&get("proof-1")?)?,
        &LeafProof::decode(&get("proof-3")?)?,
        ClassicalChoice::SignedOnly,
        PqChoice::LastResort,
        bootstrap,
    )?;
    let context = Arc::new(BootstrapContext::new(
        Arc::clone(&policy),
        initiator,
        Arc::clone(&responder),
        Arc::new(selection),
        DirectoryExpectation::from_trusted_state(get("pin-directory")?.as_slice().try_into()?)?,
        bootstrap,
    )?);
    if context.digest().as_slice() != get("expected-context")? {
        return Err("original context changed".into());
    }
    let witness = crate::witness::Witness::open(public, now)?;
    let signer = witness.open_device()?;
    let prekey = witness.prekey(&runtime, false)?;
    Ok(Fixture {
        times: Times {
            bootstrap,
            traffic: now,
        },
        context,
        policy,
        signer,
        prekey,
        responder,
        witness: Some(witness),
        local_grants: Vec::new(),
        local_rosters: Vec::new(),
        registration: None,
        enrolled_peer: None,
        policy_renewal: None,
    })
}
