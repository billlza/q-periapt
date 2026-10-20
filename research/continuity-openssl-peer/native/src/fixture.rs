// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fresh public enrollment for the independent counterpart.
use q_periapt_continuity_identity_candidate::{
    bootstrap_suite_digest, AccountPin, AllowedPrekeyModes, AnchorRequirement,
    ApplicationSendBudget, BootstrapContext, ClassicalChoice, DeviceDescription, DeviceSigningKey,
    DirectoryExpectation, LeafKind, ManifestContext, PolicyPin, PolicySigningKey, PqChoice,
    PrekeyLeaf, PrekeyQuality, PublicKey, RootSigningKey, SessionPolicyParameters, Validity,
    VerifiedCredentialRenewal, VerifiedDevice,
};
use q_periapt_core::ZeroizingBytes;
use q_periapt_sdk::{Limits, Runtime};
use q_periapt_sig::Signer;
use std::{fs, io::Write, path::Path, sync::Arc};
use zeroize::Zeroize;

use crate::{Result, NOW};

#[path = "fixture_extension.rs"]
mod extension;

pub(super) struct Fixture {
    pub times: Times,
    pub context: Arc<BootstrapContext>,
    pub signer: DeviceSigningKey,
    pub prekey: q_periapt_sdk::HybridKey,
    pub responder: Arc<VerifiedDevice>,
    pub witness: Option<Arc<crate::witness::Witness>>,
    pub local_grants: Vec<VerifiedCredentialRenewal>,
    pub registration: Option<crate::registration::Retained>,
}

pub(super) fn save(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))?;
    file.write_all(bytes)?;
    Ok(())
}

fn runtime(directory: &Path) -> Result<Arc<Runtime>> {
    let document = b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n";
    let mut seed = ZeroizingBytes::<32>::zeroed();
    getrandom::fill(seed.as_mut_bytes())?;
    let (mut secret, public) = q_periapt_backends::MlDsa65::generate(*seed.as_bytes());
    let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
    getrandom::fill(seed.as_mut_bytes())?;
    let result = q_periapt_backends::MlDsa65.sign(
        &secret,
        &q_periapt_policy::policy_signature_message(document),
        seed.as_bytes(),
        &mut signature,
    );
    secret.zeroize();
    result.map_err(|error| format!("SDK policy sign: {error:?}"))?;
    let runtime = Arc::new(Runtime::from_signed_policy(
        document,
        &signature,
        &public,
        None,
        Limits::default(),
    )?);
    save(directory, "sdk-document", document)?;
    save(directory, "sdk-signature", &signature)?;
    save(directory, "pin-sdk-root", &public)?;
    save(
        directory,
        "pin-sdk-state",
        &runtime.trusted_state().encode(),
    )?;
    Ok(runtime)
}

pub(super) struct Options {
    pub budget: u16,
    pub peer_lifecycle: bool,
    pub intermediate_peer: bool,
    pub local_lifecycle: bool,
    pub short_roster: bool,
    pub extension: bool,
    pub account_members: Option<u8>,
}
#[derive(Clone, Copy)]
pub(super) struct Times {
    pub bootstrap: u64,
    pub traffic: u64,
}
impl Options {
    pub fn times(&self) -> Times {
        if self.extension || self.intermediate_peer {
            Times {
                bootstrap: 210,
                traffic: 220,
            }
        } else {
            Times {
                bootstrap: NOW,
                traffic: 170,
            }
        }
    }
}

pub(super) fn create(
    directory: &Path,
    peer_key: PublicKey,
    options: Options,
    witness: Option<Arc<crate::witness::Witness>>,
    registration: Option<crate::registration::Approved>,
) -> Result<Fixture> {
    let times = options.times();
    let Options {
        budget,
        peer_lifecycle,
        intermediate_peer,
        local_lifecycle,
        short_roster,
        extension,
        account_members,
    } = options;
    let runtime = runtime(directory)?;
    let (authority, mut registered, retained) = match registration {
        Some(value) => (
            value.policy,
            Some((value.root, value.certificate)),
            Some(value.retained),
        ),
        None => (PolicySigningKey::generate()?, None, None),
    };
    let validity = Validity::new(
        100,
        if peer_lifecycle || local_lifecycle || extension || account_members.is_some() {
            400
        } else {
            200
        },
    )?;
    let family = authority.policy_family()?;
    if extension {
        extension::publish_original_policy(
            directory,
            &authority,
            &runtime,
            witness.as_ref(),
            budget,
        )?;
    }
    let policy = authority.issue_session_policy(
        &runtime,
        SessionPolicyParameters::new(
            if extension { 2 } else { 1 },
            validity,
            AllowedPrekeyModes::new(&[PrekeyQuality::ReusableBoth])?,
            witness
                .as_ref()
                .map_or_else(AnchorRequirement::local_only, |w| {
                    AnchorRequirement::required(&w.pin)
                }),
            ApplicationSendBudget::new(budget)?,
        )?,
    )?;
    save(
        directory,
        "pin-policy-root",
        &authority.public_key()?.encode(),
    )?;
    let mut checkpoint = policy.checkpoint().version().to_be_bytes().to_vec();
    checkpoint.extend_from_slice(&policy.checkpoint().digest());
    save(directory, "pin-policy-head", &checkpoint)?;
    save(directory, "policy", policy.as_bytes())?;
    save(directory, "pin-directory", &[99; 32])?;
    let policy_pin = PolicyPin::new(family, authority.public_key()?, policy.checkpoint())?;
    let verified_policy =
        Arc::new(policy_pin.verify(policy.as_bytes(), Arc::clone(&runtime), times.bootstrap)?);
    let signer = match &witness {
        Some(w) => w.provision_device()?,
        None => DeviceSigningKey::generate()?,
    };
    let (devices, local_grants) = if let Some(count) = account_members {
        shared_devices(
            directory,
            [peer_key, signer.public_key()?],
            family,
            policy.checkpoint().digest(),
            count,
            registered.take(),
        )?
    } else {
        let mut devices = Vec::new();
        let mut local_grants = Vec::new();
        for (role, id, public) in [("i", 1, peer_key), ("r", 2, signer.public_key()?)] {
            let registered_device = if role == "i" { registered.take() } else { None };
            let (root, existing_certificate) = match registered_device {
                Some((root, certificate)) => (root, Some(certificate)),
                None => (RootSigningKey::generate()?, None),
            };
            let certificate = match existing_certificate {
                Some(certificate) => certificate,
                None => root.issue_device(
                    DeviceDescription::new(
                        [id; 16],
                        1,
                        family,
                        if local_lifecycle || peer_lifecycle {
                            let renewed =
                                (local_lifecycle && id == 1) || (peer_lifecycle && id == 2);
                            Validity::new(100, if renewed { 200 } else { 350 })?
                        } else {
                            validity
                        },
                    )?,
                    public,
                )?,
            };
            let (certificate, roster) = if extension && role == "i" {
                extension::credential(directory, &root, certificate, family, times)?
            } else {
                let roster = root.issue_roster(1, validity, &[root.roster_entry(&certificate)?])?;
                (certificate, roster)
            };
            let pin = AccountPin::new(
                root.account_id()?,
                root.public_key()?,
                roster.checkpoint(),
                family,
            )?;
            let original = Arc::new(pin.verify_device(
                &certificate,
                roster.as_bytes(),
                if intermediate_peer && role == "r" {
                    NOW
                } else {
                    times.bootstrap
                },
            )?);
            let grants = if (peer_lifecycle && role == "r") || (local_lifecycle && role == "i") {
                crate::peer_lifecycle::publish(
                    directory,
                    &root,
                    &certificate,
                    &original,
                    roster.as_bytes(),
                    crate::peer_lifecycle::Scope {
                        policy: policy.checkpoint().digest(),
                        family,
                        local: role == "i",
                        short_roster: role == "i" && short_roster,
                    },
                )?
            } else {
                Vec::new()
            };
            let (certificate, roster_bytes, device) = if intermediate_peer && role == "r" {
                let current = grants
                    .first()
                    .ok_or("missing intermediate peer grant")?
                    .successor_device();
                let certificate = root.issue_credential_extension(&original, 300, 170)?;
                (
                    certificate,
                    current.roster().as_bytes().to_vec(),
                    Arc::new(current.clone()),
                )
            } else {
                (certificate, roster.as_bytes().to_vec(), original)
            };
            let mut expectation = root.account_id()?.to_vec();
            expectation.extend_from_slice(&device.roster().checkpoint().version().to_be_bytes());
            expectation.extend_from_slice(&device.roster().checkpoint().digest());
            expectation.extend_from_slice(&[id; 16]);
            expectation.extend_from_slice(&1u64.to_be_bytes());
            save(
                directory,
                &format!("pin-{role}-root"),
                &root.public_key()?.encode(),
            )?;
            save(directory, &format!("pin-{role}-head"), &expectation)?;
            save(directory, &format!("{role}-credential"), &certificate)?;
            save(directory, &format!("{role}-roster"), &roster_bytes)?;
            devices.push(device);
            if role == "i" {
                local_grants = grants;
            }
        }
        (devices, local_grants)
    };
    let initiator = devices.first().ok_or("missing initiator")?;
    let responder = devices.get(1).ok_or("missing responder")?;
    let key = runtime.generate_key()?;
    let public = key.public_key()?.to_bytes();
    let (pq, classical) = public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let advertisement = if extension || intermediate_peer {
        Validity::new(times.bootstrap, 260)?
    } else {
        Validity::new(100, 160)?
    };
    let manifest = signer.issue_manifest(
        responder,
        ManifestContext::new(
            1,
            runtime.trusted_state().digest(),
            bootstrap_suite_digest(),
            [99; 32],
            advertisement,
        )?,
        &[
            PrekeyLeaf::new(LeafKind::SignedClassical, classical, advertisement)?,
            PrekeyLeaf::new(LeafKind::LastResortPq, pq, advertisement)?,
        ],
    )?;
    let verified = responder.verify_manifest(manifest.as_bytes(), times.bootstrap)?;
    let mut proofs = std::collections::BTreeMap::new();
    for index in 0..2 {
        let proof = manifest.proof(index)?;
        let kind = verified.verify_leaf(&proof, times.bootstrap)?.kind() as u8;
        save(directory, &format!("proof-{kind}"), &proof.encode()?)?;
        proofs.insert(kind, proof);
    }
    save(directory, "manifest", manifest.as_bytes())?;
    let selection = Arc::new(verified.select_prekeys(
        proofs.get(&1).ok_or("missing classical proof")?,
        proofs.get(&3).ok_or("missing PQ proof")?,
        ClassicalChoice::SignedOnly,
        PqChoice::LastResort,
        times.bootstrap,
    )?);
    save(directory, "expected-selection", selection.as_bytes())?;
    let context = Arc::new(BootstrapContext::new(
        verified_policy,
        Arc::clone(initiator),
        Arc::clone(responder),
        selection,
        DirectoryExpectation::from_trusted_state([99; 32])?,
        times.bootstrap,
    )?);
    save(directory, "expected-context", &context.digest())?;
    Ok(Fixture {
        times,
        context,
        signer,
        prekey: key,
        responder: Arc::clone(responder),
        witness,
        local_grants,
        registration: retained,
    })
}

fn shared_devices(
    directory: &Path,
    keys: [PublicKey; 2],
    family: [u8; 32],
    policy: [u8; 32],
    count: u8,
    registered: Option<(RootSigningKey, Vec<u8>)>,
) -> Result<(Vec<Arc<VerifiedDevice>>, Vec<VerifiedCredentialRenewal>)> {
    let (root, original) = match registered {
        Some((root, certificate)) => (root, Some(certificate)),
        None => (RootSigningKey::generate()?, None),
    };
    let mut certificates = Vec::new();
    for (index, public) in keys.into_iter().enumerate() {
        let id = u8::try_from(index + 1)?;
        let certificate = if index == 0 {
            match &original {
                Some(certificate) => certificate.clone(),
                None => root.issue_device(
                    DeviceDescription::new([id; 16], 1, family, Validity::new(100, 200)?)?,
                    public,
                )?,
            }
        } else {
            root.issue_device(
                DeviceDescription::new([id; 16], 1, family, Validity::new(100, 200)?)?,
                public,
            )?
        };
        certificates.push(certificate);
    }
    for id in 3..=count {
        certificates.push(root.issue_device(
            DeviceDescription::new([id; 16], 1, family, Validity::new(100, 200)?)?,
            DeviceSigningKey::generate()?.public_key()?,
        )?);
    }
    let published = crate::account_fixture::publish(
        &directory.join("account"),
        &root,
        certificates,
        family,
        policy,
    )?;
    let pin = AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        published.checkpoint,
        family,
    )?;
    let mut devices = Vec::new();
    for (role, id) in [("i", 1u8), ("r", 2)] {
        let certificate = fs::read(directory.join("account").join(format!("credential-1-{id}")))?;
        let device = Arc::new(pin.verify_device(&certificate, &published.initial_roster, NOW)?);
        let mut expectation = root.account_id()?.to_vec();
        expectation.extend_from_slice(&published.checkpoint.version().to_be_bytes());
        expectation.extend_from_slice(&published.checkpoint.digest());
        expectation.extend_from_slice(&[id; 16]);
        expectation.extend_from_slice(&1u64.to_be_bytes());
        save(
            directory,
            &format!("pin-{role}-root"),
            &root.public_key()?.encode(),
        )?;
        save(directory, &format!("pin-{role}-head"), &expectation)?;
        save(directory, &format!("{role}-credential"), &certificate)?;
        save(
            directory,
            &format!("{role}-roster"),
            &published.initial_roster,
        )?;
        devices.push(device);
    }
    Ok((devices, published.local_grants))
}
