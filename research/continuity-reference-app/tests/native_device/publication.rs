// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public artifact readback under separately retained device and policy inputs.
use super::{sdk, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
};

fn array<const N: usize>(input: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn verify(
    wire: &[u8],
    id: [u8; 32],
    device: &sdk::VerifiedDevice,
    policy: &sdk::VerifiedSessionPolicy,
    now: u64,
) -> Result<()> {
    if wire.len() > 2 * 1024 * 1024 {
        return Err("Publication size bound".into());
    }
    let mut input = Cursor::new(wire);
    if array::<8>(&mut input)? != *b"QPPUBA01" || array::<32>(&mut input)? != id {
        return Err("Publication identity differs".into());
    }
    // These are producer intent/artifact commitments, not trust inputs. The
    // signed manifest and Merkle proofs below authenticate the public keys.
    for _ in 0..2 {
        if array::<32>(&mut input)? == [0; 32] {
            return Err("Zero publication commitment".into());
        }
    }
    let length = usize::try_from(u32::from_be_bytes(array(&mut input)?))?;
    if length != 3667 {
        return Err("Publication manifest width".into());
    }
    let mut manifest = vec![0; length];
    input.read_exact(&mut manifest)?;
    let checked = device.verify_manifest(&manifest, now)?;
    let epoch = u64::from_be_bytes(id[..8].try_into()?);
    if checked.context().bundle_epoch() != epoch
        || checked.context().directory_checkpoint() != [68; 32]
        || checked.context().suite_digest() != sdk::bootstrap_suite_digest()
        || Some(checked.context().policy_digest().as_slice()) != policy.sdk_binding().get(36..)
    {
        return Err("Publication manifest context differs".into());
    }
    let count = usize::from(u16::from_be_bytes(array(&mut input)?));
    if count != 2 {
        return Err("Reusable publication requires exactly two roles".into());
    }
    let mut requests = BTreeSet::new();
    for _ in 0..count {
        let request = array::<32>(&mut input)?;
        if request == [0; 32] || !requests.insert(request) {
            return Err("Duplicate or zero inventory identity".into());
        }
    }
    let mut proofs = BTreeMap::new();
    for index in 0..count {
        let length = usize::from(u16::from_be_bytes(array(&mut input)?));
        if !(62..=1534).contains(&length) {
            return Err("Publication proof bound".into());
        }
        let mut encoded = vec![0; length];
        input.read_exact(&mut encoded)?;
        if encoded.get(..2) != Some(u16::try_from(index)?.to_be_bytes().as_slice()) {
            return Err("Publication proof order differs".into());
        }
        let proof = sdk::LeafProof::decode(&encoded)?;
        if proofs
            .insert(checked.verify_leaf(&proof, now)?.kind() as u8, proof)
            .is_some()
        {
            return Err("Duplicate publication role".into());
        }
    }
    if usize::try_from(input.position())? != wire.len()
        || proofs.keys().copied().collect::<BTreeSet<_>>() != BTreeSet::from([1, 3])
    {
        return Err("Publication content differs".into());
    }
    let selection = checked.select_prekeys(
        proofs.get(&1).ok_or("Missing classical member")?,
        proofs.get(&3).ok_or("Missing PQ member")?,
        sdk::ClassicalChoice::SignedOnly,
        sdk::PqChoice::LastResort,
        now,
    )?;
    policy.check_mode(sdk::PrekeyQuality::ReusableBoth, now)?;
    if selection.quality() != sdk::PrekeyQuality::ReusableBoth {
        return Err("Publication selection differs".into());
    }
    Ok(())
}

fn cli_publication(mode: super::BootstrapMode, plan_schema: &str, quality: &str) -> Result<()> {
    use super::{clock, invoke, private_dir, write, Case, URL_SAFE_NO_PAD};
    use base64::Engine;
    use std::{ffi::OsString, fs, path::Path};

    fn snapshot(directory: &Path) -> Result<BTreeMap<std::path::PathBuf, Vec<u8>>> {
        let mut files = BTreeMap::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                files.extend(snapshot(&path)?);
            } else {
                files.insert(path.clone(), fs::read(path)?);
            }
        }
        Ok(files)
    }

    let c = Case::open_with_bootstrap_mode(1200, 2400, None, mode)?;
    let accepted = c.accept()?;
    c.call(
        "prepare",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    )?;
    let mut next = c.args(
        "publication-next",
        &["current.json", "policy-pins.json", "policy-materials.json"],
    );
    next.push("none".into());
    let observed: serde_json::Value = serde_json::from_slice(&invoke(&next, true)?)?;
    let id: [u8; 32] = serde_json::from_value(observed["publication"].clone())?;
    let plan = serde_json::json!({
        "schema":plan_schema, "directory":vec![68u8;32],
        "valid_from":c.start, "valid_until":c.start+600,
    });
    write(&c.path.join("verify-plan.json"), &plan)?;
    for output in ["verify-export1", "verify-export2"] {
        private_dir(&c.path.join(output))?;
        let mut args = c.args(
            "publish",
            &["current.json", "policy-pins.json", "policy-materials.json"],
        );
        args.extend([
            "none".into(),
            URL_SAFE_NO_PAD.encode(id).into(),
            c.path.join("verify-plan.json").into_os_string(),
            c.path.join(output).into_os_string(),
        ]);
        invoke(&args, true)?;
    }
    let bytes = fs::read(c.path.join("verify-export1/publication.json"))?;
    assert_eq!(
        bytes,
        fs::read(c.path.join("verify-export2/publication.json"))?
    );
    let public: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        public["schema"],
        if quality == "one_time_both" {
            "qperiapt-native-one-time-publication/1"
        } else {
            "qperiapt-native-publication/1"
        }
    );
    let trust = serde_json::json!({
        "schema":"qperiapt-native-publication-trust/1",
        "current":c.current, "device":c.invitation.device,
        "generation":c.invitation.generation,
        "journal":accepted["journal"], "publication":id,
    });
    write(&c.path.join("verify-trust.json"), &trust)?;
    let args: Vec<OsString> = vec![
        "verify-publication".into(),
        c.path.join("verify-trust.json").into_os_string(),
        c.path.join("policy-pins.json").into_os_string(),
        c.path.join("policy-materials.json").into_os_string(),
        c.path.join("verify-plan.json").into_os_string(),
        c.path
            .join("verify-export1/publication.json")
            .into_os_string(),
    ];
    let before = snapshot(&c.path.join("device"))?;
    let wrapping = fs::read(c.path.join("wrap.key"))?;
    let verified: serde_json::Value = serde_json::from_slice(&invoke(&args, true)?)?;
    assert_eq!(
        verified,
        serde_json::json!({"verified":true,"quality":quality})
    );
    let mut counter = 0;
    let mut refuse = |position: usize, value: serde_json::Value| -> Result<()> {
        let path = c.path.join(format!("verification-refusal-{counter}.json"));
        counter += 1;
        write(&path, &value)?;
        let mut changed = args.clone();
        changed[position] = path.into_os_string();
        invoke(&changed, false)?;
        Ok(())
    };
    for (field, value) in [
        ("schema", serde_json::json!("unknown")),
        ("device", serde_json::json!(vec![9u8; 16])),
        ("generation", serde_json::json!(2)),
        ("journal", serde_json::json!(vec![9u8; 32])),
        ("publication", serde_json::json!(vec![9u8; 32])),
    ] {
        let mut changed = trust.clone();
        changed[field] = value;
        refuse(1, changed)?;
    }
    for (field, value) in [
        ("suspended", serde_json::json!(true)),
        ("revision", serde_json::json!(0)),
        ("account", serde_json::json!(vec![9u8; 32])),
        ("family", serde_json::json!(vec![9u8; 32])),
        ("public_key", serde_json::json!("AA")),
        ("roster", serde_json::Value::Null),
    ] {
        let mut changed = trust.clone();
        changed["current"][field] = value;
        refuse(1, changed)?;
    }
    let mut changed = trust.clone();
    changed["current"]["roster"]["checkpoint"]["version"] = serde_json::json!(2);
    refuse(1, changed)?;
    for (field, value) in [
        ("schema", serde_json::json!("unknown")),
        ("journal", serde_json::json!(vec![9u8; 32])),
        ("publication", serde_json::json!(vec![9u8; 32])),
        ("certificate", serde_json::json!("AA")),
        ("roster", serde_json::json!("AA")),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut changed = public.clone();
        changed[field] = value;
        refuse(5, changed)?;
    }
    let mut changed = public.clone();
    changed["checkpoint"]["version"] = serde_json::json!(2);
    refuse(5, changed)?;
    let artifact = URL_SAFE_NO_PAD.decode(public["artifact"].as_str().ok_or("artifact")?)?;
    for offset in [40, 72, 108, artifact.len() - 1] {
        let mut altered = artifact.clone();
        altered[offset] ^= 1;
        let mut changed = public.clone();
        changed["artifact"] = serde_json::json!(URL_SAFE_NO_PAD.encode(altered));
        refuse(5, changed)?;
    }
    for (field, value) in [
        ("directory", serde_json::json!(vec![9u8; 32])),
        ("valid_from", serde_json::json!(c.start + 1)),
        ("valid_until", serde_json::json!(c.start + 599)),
        (
            "schema",
            serde_json::json!(if quality == "one_time_both" {
                "qperiapt-native-publication-plan/1"
            } else {
                "qperiapt-native-one-time-publication-plan/1"
            }),
        ),
    ] {
        let mut changed = plan.clone();
        changed[field] = value;
        refuse(4, changed)?;
    }
    let mut pins: serde_json::Value =
        serde_json::from_slice(&fs::read(c.path.join("policy-pins.json"))?)?;
    pins["policy_version"] = serde_json::json!(2);
    refuse(2, pins)?;
    let mut materials: serde_json::Value =
        serde_json::from_slice(&fs::read(c.path.join("policy-materials.json"))?)?;
    materials["policy"] = serde_json::json!("AA");
    refuse(3, materials)?;
    if quality == "one_time_both" {
        super::directory_leases::exercise(
            &c.path,
            c.start,
            &plan,
            &trust,
            serde_json::from_value(accepted["signing_id"].clone())?,
        )?;
    }
    assert_eq!(snapshot(&c.path.join("device"))?, before);
    assert_eq!(fs::read(c.path.join("wrap.key"))?, wrapping);
    assert!(
        clock()? < c.start + 600,
        "qualification exceeded its actual validity"
    );
    Ok(())
}

#[test]
fn actual_cli_verifies_reusable_publication_without_opening_state() -> Result<()> {
    cli_publication(
        super::BootstrapMode::ReusableBoth,
        "qperiapt-native-publication-plan/1",
        "reusable_both",
    )
}

#[test]
fn actual_cli_verifies_one_time_publication_without_opening_state() -> Result<()> {
    cli_publication(
        super::BootstrapMode::OneTimeBoth,
        "qperiapt-native-one-time-publication-plan/1",
        "one_time_both",
    )
}
