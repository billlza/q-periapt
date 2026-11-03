// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Normal operation uses one original private store. A second test store with
//! the same signer deliberately models a dishonest or rolled-back directory.
use super::{private_dir, sdk, write, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::{ffi::OsString, fs, path::Path, process::Command};

fn run(root: &Path, args: &[&str], success: bool) -> Result<Vec<u8>> {
    let args = args.iter().map(|arg| match arg.strip_prefix('@') {
        Some(name) => root.join(name).into_os_string(),
        None => OsString::from(*arg),
    });
    let out = Command::new(env!("CARGO_BIN_EXE_q-periapt-prekey-directory"))
        .args(args)
        .output()?;
    assert_eq!(out.status.success(), success, "{}", String::from_utf8_lossy(&out.stderr));
    if success {
        assert!(out.stderr.is_empty());
    }
    Ok(out.stdout)
}

pub(super) fn exercise(root: &Path, start: u64, plan: &Value, trust: &Value) -> Result<()> {
    let read_json = |name: &str| -> Result<Value> {
        Ok(serde_json::from_slice(&fs::read(root.join(name))?)?)
    };
    let service = URL_SAFE_NO_PAD.encode([91; 32]);
    let owner = URL_SAFE_NO_PAD.encode([92; 32]);
    let first_id = URL_SAFE_NO_PAD.encode([93; 32]);
    drop(sdk::JournalKey::provision(&root.join("directory.wrap"))?);
    let key = |verb| run(root, &[verb, &service, &owner, "@directory.wrap", "@directory.key"], true);
    let pin = key("prepare-key")?;
    assert_eq!(pin, key("show-key")?);
    let pin: Value = serde_json::from_slice(&pin)?;
    write(&root.join("directory-pin.json"), &pin)?;
    for (db, name) in [("directory.redb", "service.json"), ("fork.redb", "fork.json")] {
        let file = format!("@{db}");
        run(root, &["init", "@directory-pin.json", &file, "8"], true)?;
        write(&root.join(name), &json!({
            "schema":"qperiapt-directory-service/1", "pin":pin,
            "database":root.join(db), "signer":root.join("directory.key"),
            "wrapping":root.join("directory.wrap"), "signing_id":vec![92u8;32]
        }))?;
    }
    write(&root.join("admission.json"), &json!({
        "schema":"qperiapt-directory-admission/1", "trust":trust, "plan":plan,
        "policy_pins":read_json("policy-pins.json")?, "policy_materials":read_json("policy-materials.json")?
    }))?;
    let publication = "@verify-export1/publication.json";
    let inspection: Value = serde_json::from_slice(&run(root, &[
        "inspect", "@directory-pin.json", "@admission.json", publication
    ], true)?)?;
    let request = |op: u8, requester: u8| json!({
        "operation":vec![op;32], "requester":vec![requester;32],
        "checkpoint":inspection["checkpoint"], "valid_from":start, "valid_until":start+500,
    });
    let grant = |request: &Value, action: &str| json!({
        "schema":"qperiapt-directory-approval/1","action":action,
        "service_binding":inspection["service_binding"],"selection_digest":inspection["selection_digest"],
        "request":request,"not_before":start,"not_after":start+500,
    });
    let first = request(93,94);
    let other = request(95,96);
    write(&root.join("first.json"), &first)?;
    write(&root.join("other.json"), &other)?;
    write(&root.join("issue-first.json"), &grant(&first, "issue"))?;
    write(&root.join("cancel-first.json"), &grant(&first, "cancel"))?;
    write(&root.join("issue-other.json"), &grant(&other, "issue"))?;
    let issue = |config, approval, request, output, success| {
        run(root, &["issue", config, approval, request, "@admission.json", publication, output], success)
    };
    // A clean negative before any reservation, then force a real post-commit
    // output publication failure without replacing the caller's existing file.
    issue("@service.json","@issue-other.json","@first.json","@unused.bin",false)?;
    write(&root.join("occupied.bin"), &"retain me")?;
    let original = fs::read(root.join("occupied.bin"))?;
    issue("@service.json","@issue-first.json","@first.json","@occupied.bin",false)?;
    assert_eq!(fs::read(root.join("occupied.bin"))?, original);
    let lookup = |output| run(root,&["lookup","@directory-pin.json","@directory.redb",&first_id,output],true);
    lookup("@first.bin")?;
    issue("@service.json","@issue-first.json","@first.json","@first-retry.bin",true)?;
    assert_eq!(fs::read(root.join("first.bin"))?, fs::read(root.join("first-retry.bin"))?);
    run(root,&["check-receipt","@directory-pin.json","@first.json","@admission.json",publication,"@first.bin"],true)?;
    issue("@service.json","@issue-other.json","@other.json","@duplicate.bin",false)?;
    run(root,&["cancel","@directory-pin.json","@directory.redb",&first_id,"@issue-first.json"],false)?;
    for _ in 0..2 {
        run(root,&["cancel","@directory-pin.json","@directory.redb",&first_id,"@cancel-first.json"],true)?;
    }
    let historical: Value = serde_json::from_slice(&lookup("@cancelled.bin")?)?;
    assert_eq!(historical["cancelled"], true);
    assert_eq!(fs::read(root.join("first.bin"))?, fs::read(root.join("cancelled.bin"))?);
    issue("@service.json","@issue-first.json","@first.json","@reactivated.bin",false)?;
    issue("@service.json","@issue-other.json","@other.json","@reassigned.bin",false)?;
    // A deliberately forked signer really issues a second, independently verifiable receipt.
    issue("@fork.json","@issue-other.json","@other.json","@fork.bin",true)?;
    private_dir(&root.join("proof"))?;
    run(root,&["prove-conflict","@directory-pin.json","@first.bin","@first-retry.bin","@proof"],false)?;
    run(root,&["prove-conflict","@directory-pin.json","@first.bin","@fork.bin","@proof"],true)?;
    run(root,&["check-conflict","@directory-pin.json","@proof/conflict.bin"],true)?;
    Ok(())
}
