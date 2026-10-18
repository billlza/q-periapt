// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real Rust responder for the independent peer. The control pipe is a test
//! harness, not a new Continuity network carrier or trust-distribution protocol.
use q_periapt_continuity_identity_candidate::{
    bootstrap_suite_digest, AccountPin, AllowedPrekeyModes, AnchorRequirement,
    ApplicationSendBudget, BootstrapContext, ClassicalChoice, DeviceDescription, DeviceSigningKey,
    DirectoryExpectation, LeafKind, ManifestContext, PolicyPin, PolicySigningKey, PqChoice,
    PrekeyLeaf, PrekeyQuality, PublicKey, ResponderOperation, RootSigningKey,
    SessionPolicyParameters, Validity,
};
use q_periapt_core::ZeroizingBytes;
use q_periapt_sdk::{
    expert::{PqKeySource, TraditionalKeySource},
    Limits, Runtime,
};
use q_periapt_sig::Signer;
use std::{
    error::Error,
    fs,
    io::{self, Read, Write},
    path::Path,
    sync::Arc,
};
use zeroize::Zeroize;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const NOW: u64 = 150;

fn save(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))?;
    file.write_all(bytes)?;
    Ok(())
}

fn receive(input: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    input.read_exact(&mut prefix)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))?;
    if length == 0 || length > 8192 {
        return Err("control frame size".into());
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn send(output: &mut impl Write, status: u8, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len().checked_add(1).ok_or("frame overflow")?)?;
    output.write_all(&length.to_be_bytes())?;
    output.write_all(&[status])?;
    output.write_all(bytes)?;
    output.flush()?;
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

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().ok_or("expected new public output directory")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let directory = Path::new(&path);
    fs::create_dir(directory)?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    // An explicit harness enrollment: the independent peer owns this private
    // signing key. Only its public pair crosses this pipe.
    let peer_key = PublicKey::decode(&receive(&mut input)?)?;
    let runtime = runtime(directory)?;
    let authority = PolicySigningKey::generate()?;
    let validity = Validity::new(100, 200)?;
    let family = authority.policy_family()?;
    let policy = authority.issue_session_policy(
        &runtime,
        SessionPolicyParameters::new(
            1,
            validity,
            AllowedPrekeyModes::new(&[PrekeyQuality::ReusableBoth])?,
            AnchorRequirement::local_only(),
            ApplicationSendBudget::new(1024)?,
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
        Arc::new(policy_pin.verify(policy.as_bytes(), Arc::clone(&runtime), NOW)?);
    let signer = DeviceSigningKey::generate()?;
    let mut devices = Vec::new();
    for (role, id, public) in [("i", 1, peer_key), ("r", 2, signer.public_key()?)] {
        let root = RootSigningKey::generate()?;
        let certificate = root.issue_device(
            DeviceDescription::new([id; 16], 1, family, validity)?,
            public,
        )?;
        let roster = root.issue_roster(1, validity, &[root.roster_entry(&certificate)?])?;
        let pin = AccountPin::new(
            root.account_id()?,
            root.public_key()?,
            roster.checkpoint(),
            family,
        )?;
        devices.push(Arc::new(pin.verify_device(
            &certificate,
            roster.as_bytes(),
            NOW,
        )?));
        let mut expectation = root.account_id()?.to_vec();
        expectation.extend_from_slice(&roster.checkpoint().version().to_be_bytes());
        expectation.extend_from_slice(&roster.checkpoint().digest());
        expectation.extend_from_slice(&[id; 16]);
        expectation.extend_from_slice(&1u64.to_be_bytes());
        save(
            directory,
            &format!("pin-{role}-root"),
            &root.public_key()?.encode(),
        )?;
        save(directory, &format!("pin-{role}-head"), &expectation)?;
        save(directory, &format!("{role}-credential"), &certificate)?;
        save(directory, &format!("{role}-roster"), roster.as_bytes())?;
    }
    let initiator = devices.first().ok_or("missing initiator")?;
    let responder = devices.get(1).ok_or("missing responder")?;
    let key = runtime.generate_key()?;
    let public = key.public_key()?.to_bytes();
    let (pq, classical) = public.split_at(q_periapt_backends::ML_KEM_768_PK_LEN);
    let manifest = signer.issue_manifest(
        responder,
        ManifestContext::new(
            1,
            runtime.trusted_state().digest(),
            bootstrap_suite_digest(),
            [99; 32],
            validity,
        )?,
        &[
            PrekeyLeaf::new(LeafKind::SignedClassical, classical, validity)?,
            PrekeyLeaf::new(LeafKind::LastResortPq, pq, validity)?,
        ],
    )?;
    let verified = responder.verify_manifest(manifest.as_bytes(), NOW)?;
    let mut proofs = std::collections::BTreeMap::new();
    for index in 0..2 {
        let proof = manifest.proof(index)?;
        let kind = verified.verify_leaf(&proof, NOW)?.kind() as u8;
        save(directory, &format!("proof-{kind}"), &proof.encode()?)?;
        proofs.insert(kind, proof);
    }
    save(directory, "manifest", manifest.as_bytes())?;
    let selection = Arc::new(verified.select_prekeys(
        proofs.get(&1).ok_or("missing classical proof")?,
        proofs.get(&3).ok_or("missing PQ proof")?,
        ClassicalChoice::SignedOnly,
        PqChoice::LastResort,
        NOW,
    )?);
    save(directory, "expected-selection", selection.as_bytes())?;
    let context = Arc::new(BootstrapContext::new(
        verified_policy,
        Arc::clone(initiator),
        Arc::clone(responder),
        selection,
        DirectoryExpectation::from_trusted_state([99; 32])?,
        NOW,
    )?);
    save(directory, "expected-context", &context.digest())?;
    let mut operation = ResponderOperation::new(context);
    send(&mut output, 1, b"ready")?;
    loop {
        let frame = receive(&mut input)?;
        let (&command, payload) = frame.split_first().ok_or("empty frame")?;
        let result = match command {
            1 => operation
                .respond(
                    payload,
                    &signer,
                    PqKeySource::from_key(&key),
                    TraditionalKeySource::from_key(&key),
                    NOW,
                )
                .map(<[u8]>::to_vec),
            2 => operation
                .finish(payload, NOW)
                .map(|session| session.id().to_vec()),
            3 if payload.is_empty() => {
                operation.close();
                send(&mut output, 1, b"closed")?;
                break;
            }
            _ => return Err("unknown control command".into()),
        };
        match result {
            Ok(bytes) => send(&mut output, 1, &bytes)?,
            Err(error) => send(&mut output, 2, format!("{error:?}").as_bytes())?,
        }
    }
    Ok(())
}
