// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public-only advertisement readback and original-owner publication consumers.
use super::*;
use std::collections::BTreeSet;

pub(crate) struct Advertisement {
    pub(crate) manifest: Vec<u8>,
    pub(crate) proofs: BTreeMap<u8, Vec<u8>>,
}
impl Advertisement {
    pub(crate) fn proof(&self, kind: p::LeafKind) -> Result<&[u8]> {
        Ok(self
            .proofs
            .get(&(kind as u8))
            .ok_or("publication role missing")?)
    }
}

/// Decode the closed four-role workload, then verify its actual signatures/proofs.
/// The expected device and ID come from the retained enrollment and operation.
pub(crate) fn decode(
    wire: &[u8],
    id: [u8; 32],
    device: &p::VerifiedDevice,
    at: u64,
) -> Result<Advertisement> {
    if wire.len() > 2 * 1024 * 1024 {
        return Err("publication bound".into());
    }
    let mut d = io::Cursor::new(wire);
    fn array<const N: usize>(d: &mut io::Cursor<&[u8]>) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        d.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    if array::<8>(&mut d)? != *b"QPPUBA01" || array::<32>(&mut d)? != id {
        return Err("publication identity differs".into());
    }
    for _ in 0..2 {
        if array::<32>(&mut d)? == [0; 32] {
            return Err("publication commitment is zero".into());
        }
    }
    let length = usize::try_from(u32::from_be_bytes(array(&mut d)?))?;
    if length != 3667 {
        return Err("publication manifest width".into());
    }
    let mut manifest = vec![0; length];
    d.read_exact(&mut manifest)?;
    let count = usize::from(u16::from_be_bytes(array(&mut d)?));
    if count != 4 {
        return Err("publication requires all four roles".into());
    }
    let mut requests = BTreeSet::new();
    for _ in 0..count {
        let request = array::<32>(&mut d)?;
        if request == [0; 32] || !requests.insert(request) {
            return Err("publication inventory identity differs".into());
        }
    }
    let checked = device.verify_manifest(&manifest, at)?;
    let ordinal = u64::from_be_bytes(id[..8].try_into()?);
    if checked.context().bundle_epoch() != ordinal {
        return Err("publication manifest epoch differs".into());
    }
    let mut proofs = BTreeMap::new();
    for index in 0..count {
        let length = usize::from(u16::from_be_bytes(array(&mut d)?));
        if !(62..=1534).contains(&length) {
            return Err("publication proof bound".into());
        }
        let mut encoded = vec![0; length];
        d.read_exact(&mut encoded)?;
        if encoded.get(..2) != Some(u16::try_from(index)?.to_be_bytes().as_slice()) {
            return Err("publication proof order differs".into());
        }
        let proof = p::LeafProof::decode(&encoded)?;
        if proofs
            .insert(checked.verify_leaf(&proof, at)?.kind() as u8, encoded)
            .is_some()
        {
            return Err("duplicate publication role".into());
        }
    }
    if usize::try_from(d.position())? != wire.len()
        || proofs.keys().copied().collect::<BTreeSet<_>>() != BTreeSet::from([1, 2, 3, 4])
    {
        return Err("publication complete artifact differs".into());
    }
    Ok(Advertisement { manifest, proofs })
}

fn invoke(
    client: &Path,
    path: &Path,
    witness: &WitnessFixture,
    operation: &str,
    id: Option<&str>,
    trace: &mut Vec<u8>,
) -> Result<String> {
    let create = |suffix: &str| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(format!("successor-{operation}.{suffix}")))
    };
    let mut command = Command::new(client);
    command
        .arg("--witness")
        .arg(witness.address.to_string())
        .arg("--enrollment-parent")
        .arg(path)
        .arg("2")
        .arg(operation)
        .arg(path);
    if let Some(id) = id {
        command.arg(id);
    }
    let mut child = OwnedChild(
        command
            .stdout(Stdio::from(create("stdout")?))
            .stderr(Stdio::from(create("stderr")?))
            .spawn()?,
    );
    let pid = child.0.id();
    let status = wait(&mut child)?;
    let stderr_path = path.join(format!("successor-{operation}.stderr"));
    if fs::metadata(&stderr_path)?.len() > 8192 {
        return Err("publication diagnostics bound".into());
    }
    let stderr = fs::read(stderr_path)?;
    if !status.success() || !stderr.is_empty() {
        return Err(format!(
            "successor publication {operation}: {status}; {}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(read(path, &format!("successor-{operation}.stdout"), 8192)?)?;
    trace.extend_from_slice(format!("{operation} {pid}\n").as_bytes());
    Ok(stdout)
}

fn identifier_bytes(identifier: &str) -> Result<[u8; 32]> {
    if identifier.len() != 64
        || !identifier
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("publication ID encoding".into());
    }
    let mut id = [0; 32];
    for (index, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&identifier[index * 2..index * 2 + 2], 16)?;
    }
    if id == [0; 32] {
        return Err("zero publication ID".into());
    }
    Ok(id)
}

pub(super) fn foreign(client: &Path, path: &Path, witness: &WitnessFixture) -> Result<()> {
    let mut trace = Vec::new();
    let text = invoke(client, path, witness, "publication-next", None, &mut trace)?;
    let identifier = text.strip_suffix('\n').ok_or("publication ID terminator")?;
    let id = identifier_bytes(identifier)?;
    store(path, "publication-id", &id)?;
    let first = invoke(
        client,
        path,
        witness,
        "publication-prepare",
        Some(identifier),
        &mut trace,
    )?;
    if !first.starts_with("publication-state:2\n")
        || invoke(
            client,
            path,
            witness,
            "publication-retry",
            Some(identifier),
            &mut trace,
        )? != first
        || read(path, "publication-artifact", 2 * 1024 * 1024)?
            != read(path, "publication-retry", 2 * 1024 * 1024)?
    {
        return Err("publication changed after process reopen".into());
    }
    let lines: Vec<_> = first.lines().collect();
    let ["publication-state:2", intent, manifest, artifact] = lines.as_slice() else {
        return Err("publication prepared status shape".into());
    };
    let status = [
        identifier_bytes(intent)?,
        identifier_bytes(manifest)?,
        identifier_bytes(artifact)?,
    ]
    .concat();
    store(path, "publication-status", &status)?;
    store(path, "successor-publication-trace", &trace)?;
    Ok(())
}

pub(super) fn native(
    path: &Path,
    device: &mut p::EnrolledDevice,
    policy: &p::VerifiedSessionPolicy,
    validity: p::Validity,
) -> Result<()> {
    let keys = [
        p::LeafKind::SignedClassical,
        p::LeafKind::OneTimeClassical,
        p::LeafKind::LastResortPq,
        p::LeafKind::OneTimePq,
    ]
    .map(|kind| p::PrekeyPublicationKey::generate(kind, validity));
    let plan = p::PrekeyPublicationPlan::new([99; 32], validity, &keys)?;
    let id = device.next_prekey_publication_id()?;
    store(path, "publication-id", id.as_bytes())?;
    let cancel = Cancellation::default();
    for name in ["publication-artifact", "publication-retry"] {
        let result = device.prepare_prekey_publication(
            id,
            &plan,
            policy,
            p::PrekeyPublicationRun {
                cancel: &cancel,
                deadline: Instant::now() + Duration::from_secs(20),
            },
            now,
        )?;
        store(path, name, result.as_bytes())?;
    }
    if read(path, "publication-artifact", 2 * 1024 * 1024)?
        != read(path, "publication-retry", 2 * 1024 * 1024)?
    {
        return Err("native original publication changed".into());
    }
    let p::PrekeyPublicationStatus::Prepared {
        intent,
        manifest,
        artifact,
    } = device.prekey_publication_status(id)?
    else {
        return Err("native publication not prepared".into());
    };
    store(
        path,
        "publication-status",
        &[intent, manifest, artifact].concat(),
    )?;
    store(path, "successor-publication-trace", b"native\n")?;
    Ok(())
}
