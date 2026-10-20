// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared bounded private-file inputs for local operator commands.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use q_periapt_host_store::filesystem::{open_private_file, open_private_parent};
use serde::Serialize;
use std::{
    ffi::OsString,
    io::{Read, Write},
    path::Path,
};

pub(super) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) fn identifier(value: &OsString) -> Result<[u8; 32]> {
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
pub(super) fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
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
pub(super) fn print<T: Serialize>(value: &T) -> Result<()> {
    let mut output = serde_json::to_vec(value)?;
    output.push(b'\n');
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}
pub(super) fn export_directory(directory: &Path) -> Result<()> {
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
