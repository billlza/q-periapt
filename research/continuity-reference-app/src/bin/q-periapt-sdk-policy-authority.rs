// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Local operator authority; it does not select a consumer's trust or recovery root.
use q_periapt_continuity_reference_app::sdk_authority::AuthorityStore;
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::path::{Path, PathBuf};
#[path = "../operator_io.rs"]
mod operator_io;
use operator_io::{export_directory, identifier, print, read, Result};

const USAGE:&str = "Usage: q-periapt-sdk-policy-authority <init|prepare|authority|issue|result|cancel> <absolute-db> <base64url-authority-id> [arguments]\nissue: <base64url-operation-id> <private-policy-toml> <existing-empty-private-export-dir>\nresult: <base64url-operation-id> <existing-empty-private-export-dir>\ncancel: <base64url-operation-id>\nThe policy must contain the next allocated version. Root trust and consumer activation are separate operator actions.";

fn export(owner: &AuthorityStore, operation: [u8; 32], directory: &Path) -> Result<()> {
    export_directory(directory)?;
    let publication = owner.result(operation)?;
    let input = &publication.input;
    for (name, bytes) in [
        ("sdk-root", input.root.as_slice()),
        ("sdk-state", input.state.as_slice()),
        ("sdk-document", input.document.as_slice()),
        ("sdk-signature", input.signature.as_slice()),
    ] {
        publish_private_bytes(&directory.join(name), bytes)?;
    }
    print(&publication)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() < 4 {
        return Err(USAGE.into());
    }
    let command = args[1].to_str().ok_or(USAGE)?;
    let expected = match command {
        "init" | "prepare" | "authority" => 4,
        "issue" => 7,
        "result" => 6,
        "cancel" => 5,
        _ => return Err(USAGE.into()),
    };
    if args.len() != expected {
        return Err(USAGE.into());
    }
    let path = PathBuf::from(&args[2]);
    if !path.is_absolute() {
        return Err("SDK authority database path must be absolute".into());
    }
    let identity = identifier(&args[3])?;
    if command == "init" {
        let mut owner = AuthorityStore::provision(&path, identity)?;
        return print(&owner.prepare()?);
    }
    let mut owner = AuthorityStore::open(&path, identity)?;
    match command {
        "prepare" => print(&owner.prepare()?),
        "authority" => print(&owner.authority()?),
        "issue" => {
            let operation = identifier(&args[4])?;
            let document = read(Path::new(&args[5]), 65536)?;
            export_directory(Path::new(&args[6]))?;
            owner.issue(operation, document)?;
            export(&owner, operation, Path::new(&args[6]))
        }
        "result" => export(&owner, identifier(&args[4])?, Path::new(&args[5])),
        "cancel" => {
            owner.cancel(identifier(&args[4])?)?;
            println!(
                "Original SDK publication cancelled; its version and identity remain retained."
            );
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}
