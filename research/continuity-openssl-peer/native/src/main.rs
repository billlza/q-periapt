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
mod peer_lifecycle;
mod registration;
mod resolution;
mod witness;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const NOW: u64 = 150;

fn receive(input: &mut impl Read, control: bool) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    input.read_exact(&mut prefix)?;
    let length = usize::try_from(u32::from_be_bytes(prefix))?;
    if length == 0 {
        return Err("control frame size".into());
    }
    let mut first = [0];
    input.read_exact(&mut first)?;
    // Only explicit test-controller metadata may exceed the ordinary pipe cap.
    // This is not a device/network request format or a larger traffic allowance.
    let limit = if control && first[0] == 36 {
        8 * 1024 * 1024 + 394
    } else {
        32768
    };
    if length > limit {
        return Err("control frame size".into());
    }
    let mut bytes = vec![0; length];
    bytes[0] = first[0];
    input.read_exact(&mut bytes[1..])?;
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
    let mut budget = 1024;
    let mut required = false;
    let mut peer_lifecycle = false;
    let mut local_lifecycle = false;
    let mut short_roster = false;
    let mut registration = false;
    while let Some(flag) = args.next() {
        match flag.to_str() {
            Some("--send-budget") => {
                budget = args
                    .next()
                    .ok_or("missing send budget")?
                    .to_str()
                    .ok_or("non-UTF8 budget")?
                    .parse::<u16>()?
            }
            Some("--required-witness") if !required => required = true,
            Some("--peer-lifecycle") if !peer_lifecycle => peer_lifecycle = true,
            Some("--local-lifecycle") if !local_lifecycle => local_lifecycle = true,
            Some("--local-roster-expiry") if !short_roster => short_roster = true,
            Some("--registration") if !registration => registration = true,
            _ => return Err("unexpected argument".into()),
        }
    }
    if short_roster && !local_lifecycle {
        return Err("local roster expiry requires local lifecycle fixture".into());
    }
    let directory = Path::new(&path);
    fs::create_dir(directory)?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let (peer_key, registration) = if registration {
        let pending = registration::Pending::new(local_lifecycle, peer_lifecycle)?;
        send(&mut output, 1, pending.independent_intent())?;
        let accepted = pending.accept(&receive(&mut input, false)?)?;
        (accepted.public.clone(), Some(accepted))
    } else {
        (PublicKey::decode(&receive(&mut input, false)?)?, None)
    };
    let witness = if required {
        Some(witness::Witness::create(directory)?)
    } else {
        None
    };
    let fixture = fixture::create(
        directory,
        peer_key,
        fixture::Options {
            budget,
            peer_lifecycle,
            local_lifecycle,
            short_roster,
        },
        witness,
        registration,
    )?;
    let mut operation = ResponderOperation::new(Arc::clone(&fixture.context));
    let mut durable: Option<journal::Journal> = None;
    send(&mut output, 1, b"ready")?;
    loop {
        let frame = receive(&mut input, true)?;
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
            38 => fixture
                .registration
                .as_ref()
                .ok_or("registration fixture unavailable")?
                .retry(payload)
                .map_err(|error| error.to_string()),
            30..=37 => fixture
                .witness
                .as_ref()
                .ok_or("required witness not configured")?
                .command(&fixture, command, payload)
                .map_err(|error| error.to_string()),
            4..=27 => {
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
