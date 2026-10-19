// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local operator tool; authentication/pinning is supplied by the embedding host.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_continuity_reference_app::policy_publisher::{Publisher, Request, SdkInput};
use q_periapt_host_store::filesystem::{
    open_private_file, open_private_parent, publish_private_bytes,
};
use serde::Serialize;
use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const USAGE: &str = "Usage: q-periapt-policy-publisher <init|prepare|authority|issue|result|cancel> <absolute-db> <base64url-publisher-id> [arguments]\ninit: <sdk-root-file> <sdk-state-file> <sdk-document-file> <sdk-signature-file>\nissue: <base64url-operation-id> <request-json> <existing-empty-private-export-dir>\nresult: <base64url-operation-id> <existing-empty-private-export-dir>\ncancel: <base64url-operation-id>\nAll input files must be private regular files. No account login or clock override.";

fn identifier(value: &OsString) -> Result<[u8; 32]> {
    let text = value.to_str().ok_or("Identity is not UTF-8")?;
    let bytes = URL_SAFE_NO_PAD.decode(text)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err("Noncanonical identifier".into());
    }
    let result: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Identity must contain 32 bytes")?;
    if result == [0; 32] {
        return Err("Identity must be nonzero".into());
    }
    Ok(result)
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut file = open_private_file(path, false)?;
    let before = file.metadata()?;
    if before.len() == 0 || before.len() > maximum as u64 {
        return Err("Input file size exceeds bound".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() != before.len() as usize
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err("Input changed while reading".into());
    }
    Ok(bytes)
}
fn print<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}
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
fn export_directory(directory: &Path) -> Result<()> {
    open_private_parent(&directory.join("policy-pins.json"))?;
    if let Some(entry) = std::fs::read_dir(directory)?.next() {
        entry?;
        return Err(
            "Export directory must be empty; retain partial exports and select a new directory"
                .into(),
        );
    }
    Ok(())
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
