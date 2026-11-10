// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local operator tool; authentication/pinning is supplied by the embedding host.
use q_periapt_continuity_reference_app::policy_publisher::{Publisher, Request, SdkInput};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "../operator_io.rs"]
mod operator_io;
#[path = "../publisher_renewal_cli.rs"]
mod publisher_renewal_cli;
use operator_io::{export_directory, identifier, print, read};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const USAGE: &str = concat!(
    "Usage: q-periapt-policy-publisher <init|prepare|authority|issue|result|cancel|renewal-enable|renewal-approve|renewal-status|renewal-cancel|renewal-policies> <absolute-db> <base64url-publisher-id> [arguments]\n",
    "init: <sdk-root-file> <sdk-state-file> <sdk-document-file> <sdk-signature-file>\n",
    "issue: <base64url-operation-id> <request-json> <existing-empty-private-export-dir>\n",
    "result: <base64url-operation-id> <existing-empty-private-export-dir>\n",
    "cancel: <base64url-operation-id>\n",
    "renewal-enable: explicit schema-2 upgrade, no further arguments\n",
    "renewal-policies: <original-publication-id> <previous-publication-id> <target-publication-id> <new-policy-inputs-json>\n",
    "renewal-status/renewal-cancel: <retained-device-request> <independent-account-pins> <original-publication-id> <previous-publication-id> <target-publication-id>\n",
    "renewal-approve: same arguments, then <new-binary-approval-output>\n",
    "All input files must be private regular files. No account login or clock override.",
);

fn export(owner: &Publisher, operation: [u8; 32], directory: &Path) -> Result<()> {
    export_directory(directory)?;
    let (pins, materials) = owner.export(operation)?;
    // Each destination is exclusive and durable. A partial export is retained;
    // retry `result` into another empty directory to retrieve the original bytes.
    publish_private_bytes(
        &directory.join("policy-pins.json"),
        &serde_json::to_vec(&pins)?,
    )?;
    publish_private_bytes(
        &directory.join("policy-materials.json"),
        &serde_json::to_vec(&materials)?,
    )?;
    publish_private_bytes(
        &directory.join("authority.json"),
        &serde_json::to_vec(&owner.authority()?)?,
    )?;
    print(&owner.result(operation)?)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() < 4 {
        return Err(USAGE.into());
    }
    let command = args[1].to_str().ok_or(USAGE)?;
    let expected = match command {
        "init" => 8,
        "issue" => 7,
        "result" => 6,
        "cancel" => 5,
        "prepare" | "authority" => 4,
        "renewal-enable" => 4,
        "renewal-policies" => 8,
        "renewal-approve" => 10,
        "renewal-status" | "renewal-cancel" => 9,
        _ => return Err(USAGE.into()),
    };
    if args.len() != expected {
        return Err(USAGE.into());
    }
    let path = PathBuf::from(&args[2]);
    if !path.is_absolute() {
        return Err("Publisher database path must be absolute".into());
    }
    let identity = identifier(&args[3])?;
    if command == "init" {
        let input = SdkInput {
            root: read(Path::new(&args[4]), 1952)?,
            state: read(Path::new(&args[5]), 36)?,
            document: read(Path::new(&args[6]), 65536)?,
            signature: read(Path::new(&args[7]), 3309)?,
        };
        let mut owner = Publisher::provision(&path, identity, input)?;
        return print(&owner.prepare()?);
    }
    let mut owner = Publisher::open(&path, identity)?;
    if matches!(
        command,
        "renewal-enable"
            | "renewal-policies"
            | "renewal-approve"
            | "renewal-status"
            | "renewal-cancel"
    ) {
        return publisher_renewal_cli::run(owner, &args);
    }
    match command {
        "prepare" => print(&owner.prepare()?),
        "authority" => print(&owner.authority()?),
        "issue" => {
            let operation = identifier(&args[4])?;
            let request: Request = serde_json::from_slice(&read(Path::new(&args[5]), 16384)?)?;
            export_directory(Path::new(&args[6]))?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            owner.issue(operation, request, now)?;
            export(&owner, operation, Path::new(&args[6]))
        }
        "result" => export(&owner, identifier(&args[4])?, Path::new(&args[5])),
        "cancel" => {
            owner.cancel(identifier(&args[4])?)?;
            println!(
                "Original pending publication cancelled; its version and identity remain retained."
            );
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}
