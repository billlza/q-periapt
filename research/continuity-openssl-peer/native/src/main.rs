// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real Rust counterpart. The bounded control pipe is test orchestration,
//! not a new Continuity carrier or trust-distribution protocol.
use q_periapt_continuity_identity_candidate::{PublicKey, ResponderOperation};
use q_periapt_sdk::expert::{PqKeySource, TraditionalKeySource};
use std::{
    error::Error,
    fs,
    io::{self, Read, Write},
    path::Path,
    sync::Arc,
};
mod fixture;
mod journal;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const NOW: u64 = 150;

fn receive(input: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    input.read_exact(&mut prefix)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))?;
    if length == 0 || length > 32768 {
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
    let peer_key = PublicKey::decode(&receive(&mut input)?)?;
    let fixture = fixture::create(directory, peer_key)?;
    let mut operation = ResponderOperation::new(Arc::clone(&fixture.context));
    let mut durable: Option<journal::Journal> = None;
    send(&mut output, 1, b"ready")?;
    loop {
        let frame = receive(&mut input)?;
        let (&command, payload) = frame.split_first().ok_or("empty frame")?;
        let result = match command {
            1 => operation
                .respond(
                    payload,
                    &fixture.signer,
                    PqKeySource::from_key(&fixture.prekey),
                    TraditionalKeySource::from_key(&fixture.prekey),
                    NOW,
                )
                .map(<[u8]>::to_vec)
                .map_err(|error| format!("{error:?}")),
            2 => operation
                .finish(payload, NOW)
                .map(|session| session.id().to_vec())
                .map_err(|error| format!("{error:?}")),
            3 if payload.is_empty() => {
                operation.close();
                if let Some(journal) = durable {
                    journal.close();
                }
                send(&mut output, 1, b"closed")?;
                break;
            }
            4..=20 => {
                if durable.is_none() {
                    if command != 4 {
                        return Err("durable operation before explicit creation".into());
                    }
                    durable = Some(journal::Journal::create(&fixture, directory)?);
                }
                durable
                    .as_mut()
                    .ok_or("missing created journal")?
                    .command(&fixture, command, payload)
                    .map_err(|error| format!("{error:?}"))
            }
            _ => return Err("unknown control command".into()),
        };
        match result {
            Ok(bytes) => send(&mut output, 1, &bytes)?,
            Err(error) => send(&mut output, 2, error.as_bytes())?,
        }
    }
    Ok(())
}
