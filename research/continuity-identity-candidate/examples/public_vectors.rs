// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Emit public-only, freshly generated fixtures for an independent verifier.
use q_periapt_backends::{MlKem768, X25519};
use q_periapt_continuity_identity_candidate::{
    AccountPin, ClassicalChoice, DeviceDescription, DeviceSigningKey, LeafKind, ManifestContext,
    PqChoice, PrekeyLeaf, RootSigningKey, Validity,
};
use q_periapt_core::ZeroizingBytes;
use std::sync::Arc;
use std::{error::Error, fs, io::Write, path::Path};

fn save(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))?;
    file.write_all(bytes)?;
    Ok(())
}

fn public_prekey(kind: LeafKind, validity: Validity) -> Result<PrekeyLeaf, Box<dyn Error>> {
    let public = match kind {
        LeafKind::SignedClassical | LeafKind::OneTimeClassical => {
            let mut secret = ZeroizingBytes::<32>::zeroed();
            getrandom::fill(secret.as_mut_bytes())?;
            X25519::public_key(secret.as_bytes()).to_vec()
        }
        LeafKind::LastResortPq | LeafKind::OneTimePq => {
            let mut seed = ZeroizingBytes::<64>::zeroed();
            getrandom::fill(seed.as_mut_bytes())?;
            let (_secret, public) = MlKem768::generate_zeroizing(seed.as_bytes())
                .map_err(|error| format!("fixture ML-KEM generation failed: {error:?}"))?;
            public.to_vec()
        }
    };
    Ok(PrekeyLeaf::new(kind, &public, validity)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let output = arguments
        .next()
        .ok_or("expected one new output directory")?;
    let anchors = match arguments.next() {
        Some(option) if option == "--with-anchor" => true,
        None => false,
        Some(_) => return Err("expected optional --with-anchor".into()),
    };
    if arguments.next().is_some() {
        return Err("expected one new output directory".into());
    }
    let directory = Path::new(&output);
    fs::create_dir(directory)?;
    let mut root = RootSigningKey::generate()?;
    let mut signer = DeviceSigningKey::generate()?;
    let validity = Validity::new(100, 200)?;
    let family = [6; 32];
    let description = DeviceDescription::new([5; 16], 1, family, validity)?;
    let certificate = root.issue_device(description, signer.public_key()?)?;
    let entry = root.roster_entry(&certificate)?;
    let roster = root.issue_roster(1, validity, &[entry])?;
    // Enrollment is local to this fixture generator. A real receiver must retain
    // its expected root/checkpoint independently of incoming signed messages.
    let pin = AccountPin::new(
        root.account_id()?,
        root.public_key()?,
        roster.checkpoint(),
        family,
    )?;
    let device = pin.verify_device(&certificate, roster.as_bytes(), 150)?;
    save(directory, "root.pub", &root.public_key()?.encode())?;
    save(directory, "device.pub", &signer.public_key()?.encode())?;
    save(directory, "account.bin", &root.account_id()?)?;
    save(directory, "family.bin", &family)?;
    save(directory, "credential.bin", &certificate)?;
    save(directory, "roster.bin", roster.as_bytes())?;
    save(
        directory,
        "roster-digest.bin",
        &roster.checkpoint().digest(),
    )?;
    save(directory, "authority.bin", &device.authority_binding())?;
    root.close();

    let mut leaves = Vec::new();
    for index in 0..17 {
        let kind = match index {
            0 => LeafKind::SignedClassical,
            1 => LeafKind::OneTimeClassical,
            2 => LeafKind::LastResortPq,
            _ => LeafKind::OneTimePq,
        };
        leaves.push(public_prekey(kind, validity)?);
    }
    for count in [1, 2, 3, 5, 17] {
        let context = ManifestContext::new(count as u64, [7; 32], [8; 32], [9; 32], validity)?;
        let issued = signer.issue_manifest(
            &device,
            context,
            leaves.get(..count).ok_or("fixture count exceeds leaves")?,
        )?;
        let verified = device.verify_manifest(issued.as_bytes(), 150)?;
        save(
            directory,
            &format!("manifest-{count}.bin"),
            issued.as_bytes(),
        )?;
        save(
            directory,
            &format!("manifest-{count}.digest"),
            &verified.digest(),
        )?;
        let mut by_kind = std::collections::BTreeMap::new();
        for index in 0..count {
            let proof = issued.proof(index)?;
            let leaf = verified.verify_leaf(&proof, 150)?;
            save(
                directory,
                &format!("proof-{count}-{index}.bin"),
                &proof.encode()?,
            )?;
            save(directory, &format!("proof-{count}-{index}.id"), &leaf.id())?;
            save(
                directory,
                &format!("proof-{count}-{index}.fingerprint"),
                &leaf.key_fingerprint(),
            )?;
            by_kind.entry(leaf.kind() as u8).or_insert(proof);
        }
        if count >= 5 {
            let signed = by_kind.get(&1).ok_or("missing signed classical")?;
            let once_c = by_kind.get(&2).ok_or("missing one-time classical")?;
            let last = by_kind.get(&3).ok_or("missing last-resort PQ")?;
            let once_p = by_kind.get(&4).ok_or("missing one-time PQ")?;
            for (classical, pq) in [
                (ClassicalChoice::OneTime(once_c), PqChoice::OneTime(once_p)),
                (ClassicalChoice::SignedOnly, PqChoice::LastResort),
                (ClassicalChoice::SignedOnly, PqChoice::OneTime(once_p)),
                (ClassicalChoice::OneTime(once_c), PqChoice::LastResort),
            ] {
                let selection = verified.select_prekeys(signed, last, classical, pq, 150)?;
                let quality = selection.quality() as u8;
                save(
                    directory,
                    &format!("selection-{count}-{quality}.record"),
                    selection.as_bytes(),
                )?;
                save(
                    directory,
                    &format!("selection-{count}-{quality}.digest"),
                    &selection.digest(),
                )?;
                save(
                    directory,
                    &format!("selection-{count}-{quality}.quality"),
                    &[quality],
                )?;
            }
        }
    }
    signer.close();
    bootstrap_vectors(directory, anchors)?;
    println!("public fixtures written; private fixture keys discarded");
    Ok(())
}

fn bootstrap_vectors(directory: &Path, anchors: bool) -> Result<(), Box<dyn Error>> {
    use q_periapt_continuity_identity_candidate::{
        bootstrap_suite_digest, AllowedPrekeyModes, BootstrapContext, DirectoryExpectation,
        InitiatorOperation, PolicyPin, PolicySigningKey, PrekeyQuality, ResponderOperation,
        SessionPolicyParameters,
    };
    use q_periapt_sdk::{
        expert::{PqKeySource, TraditionalKeySource},
        Limits, Runtime,
    };
    use q_periapt_sig::Signer;
    use zeroize::Zeroize;
    let document = b"schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile=\"ContextBound\"\nallowed_kems=[\"ML-KEM-768\",\"X25519\"]\nallowed_sigs=[\"ML-DSA-65\"]\ndeprecated=[]\n";
    let mut seed = ZeroizingBytes::<32>::zeroed();
    getrandom::fill(seed.as_mut_bytes())?;
    let (mut secret, public) = q_periapt_backends::MlDsa65::generate(*seed.as_bytes());
    let mut signature = vec![0; q_periapt_backends::ML_DSA_65_SIG_LEN];
    getrandom::fill(seed.as_mut_bytes())?;
    let signed = q_periapt_backends::MlDsa65.sign(
        &secret,
        &q_periapt_policy::policy_signature_message(document),
        seed.as_bytes(),
        &mut signature,
    );
    secret.zeroize();
    signed.map_err(|error| format!("fixture policy sign: {error:?}"))?;
    let ri = Arc::new(Runtime::from_signed_policy(
        document,
        &signature,
        &public,
        None,
        Limits::default(),
    )?);
    let rr = Arc::new(Runtime::from_signed_policy(
        document,
        &signature,
        &public,
        None,
        Limits::default(),
    )?);
    save(directory, "bootstrap-sdk-policy.toml", document)?;
    save(directory, "bootstrap-sdk-policy.sig", &signature)?;
    save(directory, "bootstrap-sdk-root.pub", &public)?;
    let authority = PolicySigningKey::generate()?;
    let validity = Validity::new(100, 200)?;
    let family = authority.policy_family()?;
    let policy = authority.issue_session_policy(
        &rr,
        SessionPolicyParameters::new(
            1,
            validity,
            AllowedPrekeyModes::new(&[PrekeyQuality::ReusableBoth])?,
            q_periapt_continuity_identity_candidate::AnchorRequirement::local_only(),
        )?,
    )?;
    save(
        directory,
        "bootstrap-policy.pub",
        &authority.public_key()?.encode(),
    )?;
    save(directory, "bootstrap-policy.bin", policy.as_bytes())?;
    let pin = PolicyPin::new(family, authority.public_key()?, policy.checkpoint())?;
    let pi = Arc::new(pin.verify(policy.as_bytes(), Arc::clone(&ri), 150)?);
    let pr = Arc::new(pin.verify(policy.as_bytes(), Arc::clone(&rr), 150)?);
    let mut devices = Vec::new();
    for (role, id) in [("i", 1), ("r", 2)] {
        let root = RootSigningKey::generate()?;
        let device = DeviceSigningKey::generate()?;
        let cert = root.issue_device(
            DeviceDescription::new([id; 16], 1, family, validity)?,
            device.public_key()?,
        )?;
        let roster = root.issue_roster(1, validity, &[root.roster_entry(&cert)?])?;
        let pin = AccountPin::new(
            root.account_id()?,
            root.public_key()?,
            roster.checkpoint(),
            family,
        )?;
        let verified = Arc::new(pin.verify_device(&cert, roster.as_bytes(), 150)?);
        save(
            directory,
            &format!("bootstrap-{role}-root.pub"),
            &root.public_key()?.encode(),
        )?;
        save(
            directory,
            &format!("bootstrap-{role}-device.pub"),
            &device.public_key()?.encode(),
        )?;
        save(
            directory,
            &format!("bootstrap-{role}-credential.bin"),
            &cert,
        )?;
        save(
            directory,
            &format!("bootstrap-{role}-roster.bin"),
            roster.as_bytes(),
        )?;
        devices.push((device, verified));
    }
    let (signer_i, device_i) = devices.first().ok_or("initiator missing")?;
    let (signer_r, device_r) = devices.get(1).ok_or("responder missing")?;
    if anchors {
        anchor_vectors(directory, signer_r, device_r, &pr)?;
    }
    let key = rr.generate_key()?;
    let public = key.public_key()?.to_bytes();
    let (pq, classical) = public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let leaves = [
        PrekeyLeaf::new(LeafKind::SignedClassical, classical, validity)?,
        PrekeyLeaf::new(LeafKind::LastResortPq, pq, validity)?,
    ];
    let manifest = signer_r.issue_manifest(
        device_r,
        ManifestContext::new(
            1,
            rr.trusted_state().digest(),
            bootstrap_suite_digest(),
            [99; 32],
            validity,
        )?,
        &leaves,
    )?;
    save(directory, "bootstrap-manifest.bin", manifest.as_bytes())?;
    let verified = device_r.verify_manifest(manifest.as_bytes(), 150)?;
    let mut proofs = std::collections::BTreeMap::new();
    for index in 0..2 {
        let proof = manifest.proof(index)?;
        save(
            directory,
            &format!("bootstrap-proof-{index}.bin"),
            &proof.encode()?,
        )?;
        proofs.insert(verified.verify_leaf(&proof, 150)?.kind() as u8, proof);
    }
    let selection = Arc::new(verified.select_prekeys(
        proofs.get(&1).ok_or("classical")?,
        proofs.get(&3).ok_or("PQ")?,
        ClassicalChoice::SignedOnly,
        PqChoice::LastResort,
        150,
    )?);
    save(
        directory,
        "bootstrap-selection.record",
        selection.as_bytes(),
    )?;
    let directory_pin = DirectoryExpectation::from_trusted_state([99; 32])?;
    let ci = Arc::new(BootstrapContext::new(
        pi,
        Arc::clone(device_i),
        Arc::clone(device_r),
        Arc::clone(&selection),
        directory_pin,
        150,
    )?);
    let cr = Arc::new(BootstrapContext::new(
        pr,
        Arc::clone(device_i),
        Arc::clone(device_r),
        selection,
        directory_pin,
        150,
    )?);
    if ci.digest() != cr.digest() {
        return Err("fixture context differs".into());
    }
    save(directory, "bootstrap-context.digest", &ci.digest())?;
    let mut initiator = InitiatorOperation::start(ci, signer_i, 150)?;
    let mut responder = ResponderOperation::new(cr);
    let initial = initiator.initial_message(150)?;
    save(directory, "bootstrap-initial.bin", initial)?;
    let reply = responder.respond(
        initial,
        signer_r,
        PqKeySource::from_key(&key),
        TraditionalKeySource::from_key(&key),
        150,
    )?;
    save(directory, "bootstrap-reply.bin", reply)?;
    let result = initiator.finish(reply, 150)?;
    let session = responder.finish(result.final_message(), 150)?;
    if session.id() != result.pending_session().id() {
        return Err("fixture session differs".into());
    }
    save(directory, "bootstrap-final.bin", result.final_message())?;
    save(directory, "bootstrap-session.id", &session.id())?;
    Ok(())
}

#[cfg(unix)]
fn anchor_vectors(
    directory: &Path,
    signer: &DeviceSigningKey,
    device: &q_periapt_continuity_identity_candidate::VerifiedDevice,
    policy: &q_periapt_continuity_identity_candidate::VerifiedSessionPolicy,
) -> Result<(), Box<dyn Error>> {
    use q_periapt_continuity_identity_candidate::{
        AnchorHead, AnchorIdentity, AnchorOperation, AnchorRequest, AnchorSigningKey, AnchorStore,
        DeviceJournal, JournalKey,
    };
    use std::os::unix::fs::PermissionsExt;
    let private = tempfile::Builder::new()
        .prefix("anchor-vector-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let path = private.path().canonicalize()?;
    let mut journal = DeviceJournal::provision(
        &path.join("journal"),
        JournalKey::provision(&path.join("journal-key"))?,
        device,
    )?;
    let genesis = journal.anchor_genesis(device, policy)?;
    let initial = AnchorHead::from_trusted_state(1, 1, genesis.image_digest())?;
    let identity = AnchorIdentity::generate()?;
    let mut witness = AnchorStore::provision(
        &path.join("witness"),
        JournalKey::provision(&path.join("witness-key"))?,
        AnchorSigningKey::generate()?,
        identity,
    )?;
    witness.enroll(&genesis, device, policy, 150)?;
    let pin = witness.pin()?;
    save(directory, "anchor-witness.pub", &pin.public_key().encode())?;
    save(directory, "anchor-instance.id", identity.as_bytes())?;
    save(directory, "anchor-authority.digest", &pin.binding())?;
    save(
        directory,
        "anchor-journal.id",
        journal.identity()?.as_bytes(),
    )?;
    save(directory, "anchor-genesis.digest", &genesis.image_digest())?;
    let advance = AnchorOperation::advance(initial, [42; 32])?;
    let next = AnchorHead::from_trusted_state(1, 2, [42; 32])?;
    let operations = [
        AnchorOperation::query(),
        advance,
        advance,
        AnchorOperation::fence_writer(next)?,
        AnchorOperation::advance(next, [43; 32])?,
        AnchorOperation::query(),
    ];
    for (index, operation) in operations.into_iter().enumerate() {
        let request = AnchorRequest::new(&pin, genesis.subject(), operation, signer)?;
        let response = witness.handle(request.as_bytes(), 150)?;
        pin.verify_reply(&request, &response)?;
        save(
            directory,
            &format!("anchor-{index}-request.bin"),
            request.as_bytes(),
        )?;
        save(directory, &format!("anchor-{index}-reply.bin"), &response)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn anchor_vectors(
    _: &Path,
    _: &DeviceSigningKey,
    _: &q_periapt_continuity_identity_candidate::VerifiedDevice,
    _: &q_periapt_continuity_identity_candidate::VerifiedSessionPolicy,
) -> Result<(), Box<dyn Error>> {
    Err("anchor witness vectors require the private Unix storage adapter".into())
}
