// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Normal operation uses one original private store. A second test store with
//! the same signer deliberately models a dishonest or rolled-back directory.
use super::{private_dir, sdk, write, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_host_store::filesystem::publish_private_bytes;
use serde_json::{json, Value};
use std::{ffi::OsString, fs, io::Write, path::Path, process::Command};

fn run(root: &Path, args: &[&str], success: bool) -> Result<Vec<u8>> {
    let expanded = args.iter().map(|arg| match arg.strip_prefix('@') {
        Some(name) => root.join(name).into_os_string(),
        None => OsString::from(*arg),
    });
    let out = Command::new(env!("CARGO_BIN_EXE_q-periapt-prekey-directory"))
        .args(expanded)
        .output()?;
    // The trace contains public CLI results and relative test input names only.
    let trace = json!({"arguments":args,"exit":out.status.code(),
        "stdout":String::from_utf8(out.stdout.clone())?,
        "stderr":String::from_utf8(out.stderr.clone())?.replace(root.to_str().ok_or("fixture path")?, "<fixture>")});
    writeln!(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("directory-trace.jsonl"))?,
        "{trace}"
    )?;
    assert_eq!(
        out.status.success(),
        success,
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    if success {
        assert!(out.stderr.is_empty());
    }
    Ok(if success { out.stdout } else { out.stderr })
}

fn assert_refused(bytes: &[u8], error: &str) -> Result<()> {
    assert_eq!(std::str::from_utf8(bytes)?, format!("Error: {error}\n"));
    Ok(())
}

fn operation_count(root: &Path) -> Result<u64> {
    use redb::{ReadableDatabase, ReadableTableMetadata, TableDefinition};
    // Test-only readback; no database bytes or private configuration are exported.
    let database = redb::ReadOnlyDatabase::open(root.join("directory.redb"))?;
    let transaction = database.begin_read()?;
    let operations =
        transaction.open_table(TableDefinition::<&[u8], &[u8]>::new("directory_operations"))?;
    Ok(operations.len()?)
}

/// Re-sign a test publication while changing exactly one or both selected keys.
/// This controls the actual CLI's reservation check without changing production
/// state or pretending that the honest publication owner generated these aliases.
fn variant_publications(
    root: &Path,
    plan: &Value,
    trust: &Value,
    signing_id: [u8; 32],
) -> Result<()> {
    use q_periapt_continuity_reference_app::{
        native_device::{Publication, PublicationPlan, PublicationTrust},
        policy_publisher::{PolicyMaterials, PolicyPins},
    };
    use q_periapt_core::Xof256;
    use std::io::{Cursor, Read};
    fn array<const N: usize>(input: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
        let mut out = [0; N];
        input.read_exact(&mut out)?;
        Ok(out)
    }
    let read = |name| -> Result<Value> { Ok(serde_json::from_slice(&fs::read(root.join(name))?)?) };
    let original = read("verify-export1/publication.json")?;
    let publication: Publication = serde_json::from_value(original.clone())?;
    let trusted: PublicationTrust = serde_json::from_value(trust.clone())?;
    let planned: PublicationPlan = serde_json::from_value(plan.clone())?;
    let pins: PolicyPins = serde_json::from_value(read("policy-pins.json")?)?;
    let materials: PolicyMaterials = serde_json::from_value(read("policy-materials.json")?)?;
    let now = super::clock()?;
    let (policy, _) = pins.verify(&materials, trusted.family(), now)?;
    let (device, _) = trusted.verify_for_directory(&publication, &planned, &policy, now)?;
    let signer = sdk::DeviceSigningKey::open(
        &root.join("device/device.key"),
        &sdk::JournalKey::open(&root.join("wrap.key"))?,
        sdk::SigningKeyId::from_trusted_state(signing_id)?,
    )?;
    let wire = URL_SAFE_NO_PAD.decode(original["artifact"].as_str().ok_or("artifact")?)?;
    let mut input = Cursor::new(wire.as_slice());
    let header = array::<104>(&mut input)?;
    let length = usize::try_from(u32::from_be_bytes(array(&mut input)?))?;
    let mut manifest = vec![0; length];
    input.read_exact(&mut manifest)?;
    let verified = device.verify_manifest(&manifest, now)?;
    let count = u16::from_be_bytes(array(&mut input)?);
    assert_eq!(count, 4);
    let requests = array::<128>(&mut input)?;
    let mut leaves = Vec::new();
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(array(&mut input)?));
        let mut proof = vec![0; length];
        input.read_exact(&mut proof)?;
        let proof = sdk::LeafProof::decode(&proof)?;
        let leaf = verified.verify_leaf(&proof, now)?;
        leaves.push(sdk::PrekeyLeaf::new(
            leaf.kind(),
            leaf.public_key(),
            leaf.validity(),
        )?);
    }
    assert_eq!(usize::try_from(input.position())?, wire.len());
    leaves.sort_by_key(|leaf| leaf.kind() as u8);
    let classical = q_periapt_backends::X25519::public_key(&[103; 32]);
    let (_, pq) = q_periapt_backends::MlKem768::generate_zeroizing(&[104; 64])
        .map_err(|error| format!("test ML-KEM key generation: {error:?}"))?;
    for (name, change_classical, change_pq) in [
        ("reuse-classical", false, true),
        ("reuse-pq", true, false),
        ("fresh-pair", true, true),
    ] {
        let mut selected = leaves.clone();
        for leaf in &mut selected {
            let public = match leaf.kind() {
                sdk::LeafKind::OneTimeClassical if change_classical => Some(classical.as_slice()),
                sdk::LeafKind::OneTimePq if change_pq => Some(pq.as_slice()),
                _ => None,
            };
            if let Some(public) = public {
                assert_ne!(leaf.public_key(), public);
                *leaf = sdk::PrekeyLeaf::new(leaf.kind(), public, leaf.validity())?;
            }
        }
        let issued = signer.issue_manifest(&device, verified.context(), &selected)?;
        let mut payload = header.get(40..72).ok_or("intent")?.to_vec();
        payload.extend_from_slice(issued.as_bytes());
        for leaf in &selected {
            payload.extend_from_slice(leaf.public_key());
        }
        let domain = b"Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ARTIFACT/v1";
        let mut hash = q_periapt_backends::Sha3_256Xof::new();
        hash.absorb(&u64::try_from(domain.len())?.to_be_bytes());
        hash.absorb(domain);
        hash.absorb(&u64::try_from(payload.len())?.to_be_bytes());
        hash.absorb(&payload);
        let mut artifact = header.get(..72).ok_or("publication header")?.to_vec();
        artifact.extend_from_slice(&hash.squeeze32());
        artifact.extend_from_slice(&u32::try_from(issued.as_bytes().len())?.to_be_bytes());
        artifact.extend_from_slice(issued.as_bytes());
        artifact.extend_from_slice(&count.to_be_bytes());
        artifact.extend_from_slice(&requests);
        for index in 0..issued.leaf_count() {
            let proof = issued.proof(index)?.encode()?;
            artifact.extend_from_slice(&u16::try_from(proof.len())?.to_be_bytes());
            artifact.extend_from_slice(&proof);
        }
        let mut value = original.clone();
        value["artifact"] = json!(URL_SAFE_NO_PAD.encode(&artifact));
        let candidate: Publication = serde_json::from_value(value.clone())?;
        trusted.verify_for_directory(&candidate, &planned, &policy, now)?;
        write(&root.join(format!("{name}.json")), &value)?;
    }
    Ok(())
}

fn verify_isolated_history(
    root: &Path,
    pin: &Value,
    receipt: &[u8],
    expected: &Value,
) -> Result<()> {
    let directory = root.join("isolated-history");
    private_dir(&directory)?;
    write(&directory.join("pin.json"), pin)?;
    publish_private_bytes(&directory.join("receipt.bin"), receipt)?;
    // These are the only inputs: no database, signer, wrapping key or policy.
    assert_eq!(fs::read_dir(&directory)?.count(), 2);
    let checked: Value = serde_json::from_slice(&run(
        &directory,
        &["check-historical-receipt", "@pin.json", "@receipt.bin"],
        true,
    )?)?;
    assert_eq!(&checked, expected);
    assert_eq!(checked["historical"], true);
    for permission in ["active", "cancelled", "consumed"] {
        assert!(checked.get(permission).is_none());
    }
    assert_eq!(fs::read(directory.join("receipt.bin"))?, receipt);

    let mut corrupted = receipt.to_vec();
    *corrupted.last_mut().ok_or("empty receipt")? ^= 1;
    publish_private_bytes(&directory.join("bad-signature.bin"), &corrupted)?;
    run(
        &directory,
        &[
            "check-historical-receipt",
            "@pin.json",
            "@bad-signature.bin",
        ],
        false,
    )?;
    let mut wrong_service = pin.clone();
    wrong_service["service"] = json!(vec![98u8; 32]);
    write(&directory.join("wrong-service.json"), &wrong_service)?;
    run(
        &directory,
        &[
            "check-historical-receipt",
            "@wrong-service.json",
            "@receipt.bin",
        ],
        false,
    )?;
    let other = sdk::DirectorySigningKey::generate()?;
    let mut wrong_key = pin.clone();
    wrong_key["public_key"] = json!(URL_SAFE_NO_PAD.encode(other.public_key()?.encode()));
    write(&directory.join("wrong-key.json"), &wrong_key)?;
    run(
        &directory,
        &[
            "check-historical-receipt",
            "@wrong-key.json",
            "@receipt.bin",
        ],
        false,
    )?;
    Ok(())
}

pub(super) fn exercise(
    root: &Path,
    start: u64,
    plan: &Value,
    trust: &Value,
    signing_id: [u8; 32],
) -> Result<()> {
    let read_json =
        |name: &str| -> Result<Value> { Ok(serde_json::from_slice(&fs::read(root.join(name))?)?) };
    let service = URL_SAFE_NO_PAD.encode([91; 32]);
    let owner = URL_SAFE_NO_PAD.encode([92; 32]);
    let first_id = URL_SAFE_NO_PAD.encode([93; 32]);
    drop(sdk::JournalKey::provision(&root.join("directory.wrap"))?);
    let key = |verb| {
        run(
            root,
            &[verb, &service, &owner, "@directory.wrap", "@directory.key"],
            true,
        )
    };
    let pin = key("prepare-key")?;
    assert_eq!(pin, key("show-key")?);
    let pin: Value = serde_json::from_slice(&pin)?;
    write(&root.join("directory-pin.json"), &pin)?;
    for (db, name) in [
        ("directory.redb", "service.json"),
        ("fork.redb", "fork.json"),
    ] {
        let file = format!("@{db}");
        run(root, &["init", "@directory-pin.json", &file, "8"], true)?;
        write(
            &root.join(name),
            &json!({
                "schema":"qperiapt-directory-service/1", "pin":pin,
                "database":root.join(db), "signer":root.join("directory.key"),
                "wrapping":root.join("directory.wrap"), "signing_id":vec![92u8;32]
            }),
        )?;
    }
    write(
        &root.join("admission.json"),
        &json!({
            "schema":"qperiapt-directory-admission/1", "trust":trust, "plan":plan,
            "policy_pins":read_json("policy-pins.json")?, "policy_materials":read_json("policy-materials.json")?
        }),
    )?;
    let publication = "@verify-export1/publication.json";
    let inspection: Value = serde_json::from_slice(&run(
        root,
        &[
            "inspect",
            "@directory-pin.json",
            "@admission.json",
            publication,
        ],
        true,
    )?)?;
    let request = |op: u8, requester: u8| {
        json!({
            "operation":vec![op;32], "requester":vec![requester;32],
            "checkpoint":inspection["checkpoint"], "valid_from":start, "valid_until":start+500,
        })
    };
    let grant = |request: &Value, action: &str| {
        json!({
            "schema":"qperiapt-directory-approval/1","action":action,
            "service_binding":inspection["service_binding"],"selection_digest":inspection["selection_digest"],
            "request":request,"not_before":start,"not_after":start+500,
        })
    };
    let first = request(93, 94);
    let other = request(95, 96);
    write(&root.join("first.json"), &first)?;
    write(&root.join("other.json"), &other)?;
    write(&root.join("issue-first.json"), &grant(&first, "issue"))?;
    write(&root.join("cancel-first.json"), &grant(&first, "cancel"))?;
    write(&root.join("issue-other.json"), &grant(&other, "issue"))?;
    let issue = |config, approval, request, output, success| {
        run(
            root,
            &[
                "issue",
                config,
                approval,
                request,
                "@admission.json",
                publication,
                output,
            ],
            success,
        )
    };
    // A clean negative before any reservation, then force a real post-commit
    // output publication failure without replacing the caller's existing file.
    issue(
        "@service.json",
        "@issue-other.json",
        "@first.json",
        "@unused.bin",
        false,
    )?;
    write(&root.join("occupied.bin"), &"retain me")?;
    let original = fs::read(root.join("occupied.bin"))?;
    issue(
        "@service.json",
        "@issue-first.json",
        "@first.json",
        "@occupied.bin",
        false,
    )?;
    assert_eq!(fs::read(root.join("occupied.bin"))?, original);
    let lookup = |output| {
        run(
            root,
            &[
                "lookup",
                "@directory-pin.json",
                "@directory.redb",
                &first_id,
                output,
            ],
            true,
        )
    };
    lookup("@first.bin")?;
    let original_history: Value = serde_json::from_slice(&run(
        root,
        &[
            "check-historical-receipt",
            "@directory-pin.json",
            "@first.bin",
        ],
        true,
    )?)?;
    assert_eq!(original_history["request"], first);
    assert_eq!(original_history["historical"], true);
    assert_eq!(
        original_history["original_statement"]
            .as_array()
            .map(Vec::len),
        Some(32)
    );
    issue(
        "@service.json",
        "@issue-first.json",
        "@first.json",
        "@first-retry.bin",
        true,
    )?;
    assert_eq!(
        fs::read(root.join("first.bin"))?,
        fs::read(root.join("first-retry.bin"))?
    );
    let after_exact_retry = operation_count(root)?;
    assert_eq!(after_exact_retry, 1);
    let changed = request(93, 97);
    write(&root.join("changed.json"), &changed)?;
    write(&root.join("issue-changed.json"), &grant(&changed, "issue"))?;
    assert_refused(
        &issue(
            "@service.json",
            "@issue-changed.json",
            "@changed.json",
            "@changed.bin",
            false,
        )?,
        "Conflict",
    )?;
    assert!(!root.join("changed.bin").exists());
    variant_publications(root, plan, trust, signing_id)?;
    for (name, operation) in [
        ("reuse-classical", 101),
        ("reuse-pq", 102),
        ("fresh-pair", 105),
    ] {
        let publication = format!("@{name}.json");
        let inspected: Value = serde_json::from_slice(&run(
            root,
            &[
                "inspect",
                "@directory-pin.json",
                "@admission.json",
                &publication,
            ],
            true,
        )?)?;
        let request = request(operation, 106);
        let mut approval = grant(&request, "issue");
        approval["selection_digest"] = inspected["selection_digest"].clone();
        write(&root.join(format!("{name}-request.json")), &request)?;
        write(&root.join(format!("{name}-approval.json")), &approval)?;
    }
    let partial = |name: &str, suffix: &str, success| {
        run(
            root,
            &[
                "issue",
                "@service.json",
                &format!("@{name}-approval.json"),
                &format!("@{name}-request.json"),
                "@admission.json",
                &format!("@{name}.json"),
                &format!("@{name}-{suffix}.bin"),
            ],
            success,
        )
    };
    for name in ["reuse-classical", "reuse-pq"] {
        assert_refused(
            &partial(name, "before-cancel", false)?,
            "KeyAlreadyReserved",
        )?;
        assert!(!root.join(format!("{name}-before-cancel.bin")).exists());
    }
    run(
        root,
        &[
            "check-receipt",
            "@directory-pin.json",
            "@first.json",
            "@admission.json",
            publication,
            "@first.bin",
        ],
        true,
    )?;
    issue(
        "@service.json",
        "@issue-other.json",
        "@other.json",
        "@duplicate.bin",
        false,
    )?;
    run(
        root,
        &[
            "cancel",
            "@directory-pin.json",
            "@directory.redb",
            &first_id,
            "@issue-first.json",
        ],
        false,
    )?;
    for _ in 0..2 {
        run(
            root,
            &[
                "cancel",
                "@directory-pin.json",
                "@directory.redb",
                &first_id,
                "@cancel-first.json",
            ],
            true,
        )?;
    }
    let historical: Value = serde_json::from_slice(&lookup("@cancelled.bin")?)?;
    assert_eq!(historical["cancelled"], true);
    assert_eq!(
        fs::read(root.join("first.bin"))?,
        fs::read(root.join("cancelled.bin"))?
    );
    verify_isolated_history(
        root,
        &pin,
        &fs::read(root.join("cancelled.bin"))?,
        &original_history,
    )?;
    issue(
        "@service.json",
        "@issue-first.json",
        "@first.json",
        "@reactivated.bin",
        false,
    )?;
    issue(
        "@service.json",
        "@issue-other.json",
        "@other.json",
        "@reassigned.bin",
        false,
    )?;
    for name in ["reuse-classical", "reuse-pq"] {
        assert_refused(&partial(name, "after-cancel", false)?, "KeyAlreadyReserved")?;
        assert!(!root.join(format!("{name}-after-cancel.bin")).exists());
    }
    let after_cancel_and_refusals = operation_count(root)?;
    assert_eq!(after_cancel_and_refusals, 1);
    partial("fresh-pair", "after-cancel", true)?;
    let after_fresh_pair = operation_count(root)?;
    assert_eq!(after_fresh_pair, 2);
    // A deliberately forked signer really issues a second, independently verifiable receipt.
    issue(
        "@fork.json",
        "@issue-other.json",
        "@other.json",
        "@fork.bin",
        true,
    )?;
    private_dir(&root.join("proof"))?;
    run(
        root,
        &[
            "prove-conflict",
            "@directory-pin.json",
            "@first.bin",
            "@first-retry.bin",
            "@proof",
        ],
        false,
    )?;
    run(
        root,
        &[
            "prove-conflict",
            "@directory-pin.json",
            "@first.bin",
            "@fork.bin",
            "@proof",
        ],
        true,
    )?;
    run(
        root,
        &[
            "check-conflict",
            "@directory-pin.json",
            "@proof/conflict.bin",
        ],
        true,
    )?;
    write(&root.join("original-history.json"), &original_history)?;
    write(&root.join("inspection.json"), &inspection)?;
    write(
        &root.join("expected.json"),
        &json!({
            "schema":"qperiapt-directory-cli-public/1", "completed":true,
            "request":first,"other_request":other,"account":trust["current"]["account"],
            "device":trust["device"],"generation":trust["generation"],"family":trust["current"]["family"],
            "cancelled":true,"output_loss_preserved_existing_file":true,
            "exact_retry_preserved_original":true,"changed_request_refused":true,
        "ledger_operation_counts":{"after_exact_retry":after_exact_retry,
            "after_cancel_and_refusals":after_cancel_and_refusals,"after_fresh_pair":after_fresh_pair},
            "both_algorithm_reservations_checked_before_and_after_cancel":true,
            "fresh_pair_issued_after_cancel":true,"historical_inputs_only_pin_and_receipt":true,
            "rust_live_scope_checked":true,"rust_canonical_conflict_checked":true,
            "directory_cli":"source-build","historical_only":true,"private_keys_exported":false,
            "release_claim_eligible":false
        }),
    )?;
    if let Some(destination) = std::env::var_os("QPERIAPT_DIRECTORY_PUBLIC_OUTPUT") {
        let destination = std::path::PathBuf::from(destination);
        assert!(
            destination.is_absolute(),
            "public export path must be explicit and absolute"
        );
        private_dir(&destination)?;
        // Explicit whitelist: never recursively copy the private test installation.
        for (from, to) in [
            ("directory-pin.json", "pin.json"),
            ("first.bin", "first.bin"),
            ("first-retry.bin", "retry.bin"),
            ("cancelled.bin", "cancelled.bin"),
            ("fork.bin", "fork.bin"),
            ("fresh-pair-after-cancel.bin", "fresh.bin"),
            ("proof/conflict.bin", "conflict.bin"),
            ("original-history.json", "original-history.json"),
            ("inspection.json", "inspection.json"),
            ("expected.json", "expected.json"),
            ("directory-trace.jsonl", "cli-trace.jsonl"),
            (
                "isolated-history/directory-trace.jsonl",
                "history-trace.jsonl",
            ),
            ("isolated-history/bad-signature.bin", "bad-signature.bin"),
            ("isolated-history/wrong-service.json", "wrong-service.json"),
            ("isolated-history/wrong-key.json", "wrong-key.json"),
        ] {
            publish_private_bytes(&destination.join(to), &fs::read(root.join(from))?)?;
        }
    }
    Ok(())
}
