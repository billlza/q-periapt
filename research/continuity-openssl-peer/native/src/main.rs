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
mod account_fixture;
mod enrolled_peer;
mod fixture;
mod journal;
mod peer_lifecycle;
mod policy_lifecycle;
mod prekey_refresh;
mod registration;
mod resolution;
mod restart;
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
    let mut intermediate_peer = false;
    let mut local_lifecycle = false;
    let mut short_roster = false;
    let mut registration = false;
    let mut extension = false;
    let mut account_members = None;
    let mut enrolled_peer = false;
    let mut policy_lifecycle = false;
    let mut policy_composition = false;
    let mut restartable_successor = false;
    let mut resume_successor = None;
    while let Some(flag) = args.next() {
        match flag.to_str() {
            Some("--restartable-successor") if !restartable_successor => {
                restartable_successor = true
            }
            Some("--resume-successor") if resume_successor.is_none() => {
                resume_successor = Some(
                    args.next()
                        .ok_or("missing restart time")?
                        .to_str()
                        .ok_or("non-UTF8 restart time")?
                        .parse::<u64>()?,
                );
            }
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
            Some("--intermediate-peer") if !intermediate_peer => intermediate_peer = true,
            Some("--local-lifecycle") if !local_lifecycle => local_lifecycle = true,
            Some("--local-roster-expiry") if !short_roster => short_roster = true,
            Some("--registration") if !registration => registration = true,
            Some("--enrolled-peer") if !enrolled_peer => enrolled_peer = true,
            Some("--policy-lifecycle") if !policy_lifecycle => policy_lifecycle = true,
            Some("--policy-composition") if !policy_composition => policy_composition = true,
            Some("--registration-extension") if !extension => extension = true,
            Some("--shared-account") if account_members.is_none() => {
                account_members = Some(
                    args.next()
                        .ok_or("missing account member count")?
                        .to_str()
                        .ok_or("non-UTF8 account member count")?
                        .parse::<u8>()?,
                );
            }
            _ => return Err("unexpected argument".into()),
        }
    }
    if short_roster && !local_lifecycle {
        return Err("local roster expiry requires local lifecycle fixture".into());
    }
    if extension && (!registration || local_lifecycle || peer_lifecycle || short_roster) {
        return Err("registration extension requires its separate registration fixture".into());
    }
    if intermediate_peer && (!peer_lifecycle || local_lifecycle || registration || extension) {
        return Err("intermediate peer requires its separate peer lifecycle fixture".into());
    }
    if let Some(count) = account_members {
        if !matches!(count, 3 | 32)
            || peer_lifecycle
            || local_lifecycle
            || intermediate_peer
            || short_roster
            || extension
        {
            return Err(
                "shared account requires 3 or 32 members and its separate lifecycle fixture".into(),
            );
        }
    }
    if enrolled_peer && (!registration || account_members.is_none()) {
        return Err("enrolled peer requires registered shared account".into());
    }
    if policy_lifecycle && !enrolled_peer {
        return Err("policy lifecycle requires its original enrolled peer".into());
    }
    if policy_composition && !policy_lifecycle {
        return Err("policy composition requires its policy lifecycle fixture".into());
    }
    if restartable_successor
        && (!required
            || !registration
            || !local_lifecycle
            || enrolled_peer
            || extension
            || peer_lifecycle
            || short_roster)
    {
        return Err("restart requires the separate witnessed local-credential fixture".into());
    }
    if resume_successor.is_some()
        && (required
            || registration
            || restartable_successor
            || local_lifecycle
            || peer_lifecycle
            || enrolled_peer
            || account_members.is_some()
            || extension
            || policy_lifecycle
            || short_roster
            || intermediate_peer
            || policy_composition
            || budget != 1024)
    {
        return Err("resume cannot provision another fixture".into());
    }
    let options = fixture::Options {
        restartable_successor,
        budget,
        peer_lifecycle,
        intermediate_peer,
        local_lifecycle,
        short_roster,
        extension,
        account_members,
        enrolled_peer,
        policy_lifecycle,
        policy_composition,
    };
    let times = options.times();
    let directory = Path::new(&path);
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let fixture = if let Some(now) = resume_successor {
        restart::fixture(directory, now)?
    } else {
        fs::create_dir(directory)?;
        let (peer_key, registration) = if registration {
            let pending = registration::Pending::new(
                local_lifecycle,
                peer_lifecycle,
                extension,
                policy_lifecycle,
                policy_composition,
            )?;
            send(&mut output, 1, pending.independent_intent())?;
            let accepted = pending.accept(&receive(&mut input, false)?)?;
            (accepted.public.clone(), Some(accepted))
        } else {
            (PublicKey::decode(&receive(&mut input, false)?)?, None)
        };
        let witness = if required {
            Some(witness::Witness::create(directory, times.bootstrap)?)
        } else {
            None
        };
        fixture::create(directory, peer_key, options, witness, registration)?
    };
    let mut operation = ResponderOperation::new(Arc::clone(&fixture.context));
    let resumed = if resume_successor.is_some() {
        Some(restart::Selection::open(&fixture, directory)?)
    } else {
        None
    };
    let mut durable: Option<journal::Journal> = None;
    let mut successor: Option<journal::Journal> = None;
    let mut later_successor = resumed
        .as_ref()
        .filter(|selected| selected.later)
        .map(|selected| selected.previous);
    send(&mut output, 1, b"ready")?;
    loop {
        let frame = receive(&mut input, true)?;
        let (&command, payload) = frame.split_first().ok_or("empty frame")?;
        if resume_successor.is_some() && !matches!(command, 3 | 31..=33 | 45 | 50..=59) {
            send(
                &mut output,
                2,
                b"resumed fixture only admits its original successor",
            )?;
            continue;
        }
        let result = match command {
            45 => prekey_refresh::issue(&fixture, payload).map_err(|error| error.to_string()),
            50 | 51 | 54 | 55 | 58 | 59 => fixture
                .witness
                .as_ref()
                .ok_or("required witness not configured")?
                .root_command(&fixture, command, payload)
                .map_err(|error| error.to_string()),
            52 | 56 => (|| -> Result<Vec<u8>> {
                let later = command == 56;
                if !later && later_successor.is_some() {
                    return Err("previous successor controller retired".into());
                }
                if let Some(selected) = &resumed {
                    if later == selected.later && selected.control != payload {
                        return Err("restart cannot select another successor".into());
                    }
                }
                let expected = if later {
                    match later_successor {
                        Some(previous) => previous,
                        None => successor
                            .as_ref()
                            .ok_or("later successor before original peer")?
                            .peer_account(),
                    }
                } else {
                    fixture
                        .context
                        .device(q_periapt_continuity_identity_candidate::BootstrapRole::Initiator)
                        .account_id()
                };
                let (context, now, previous) = fixture
                    .witness
                    .as_ref()
                    .ok_or("required witness not configured")?
                    .successor_context(&fixture, payload, expected)?;
                if later && later_successor.is_none() {
                    let owner = successor
                        .as_mut()
                        .ok_or("later successor before original peer")?;
                    owner.verify_successor(&context, previous)?;
                    let output = directory.join("root-successor-later");
                    fs::create_dir(&output)?;
                    owner.select_successor(&output, Arc::clone(&context), now, previous)?;
                    fixture::save(&output, "control", payload)?;
                    later_successor = Some(previous);
                } else if let Some(owner) = &successor {
                    if !owner.matches_context(&context, now) {
                        return Err("successor peer control cannot retarget existing owner".into());
                    }
                } else if resume_successor.is_some() {
                    successor = Some(journal::Journal::open_successor(
                        &fixture,
                        directory,
                        Arc::clone(&context),
                        now,
                        later,
                    )?);
                } else {
                    let output = directory.join("root-successor");
                    fs::create_dir(&output)?;
                    durable
                        .as_mut()
                        .ok_or("successor peer requires original native journal")?
                        .select_successor(&output, Arc::clone(&context), now, previous)?;
                    successor = durable.take();
                    fixture::save(&output, "control", payload)?;
                }
                Ok(context.digest().to_vec())
            })()
            .map_err(|error| error.to_string()),
            53 | 57 => (|| -> Result<Vec<u8>> {
                if command == 53 && later_successor.is_some() {
                    return Err("previous successor controller retired".into());
                }
                if command == 57 && later_successor.is_none() {
                    return Err("later successor peer before explicit approval".into());
                }
                let (&inner, wire) = payload.split_first().ok_or("empty successor command")?;
                if !(4..=27).contains(&inner) {
                    return Err("unsupported successor journal command".into());
                }
                Ok(successor
                    .as_mut()
                    .ok_or("successor peer before explicit approval")?
                    .command(&fixture, inner, wire)?)
            })()
            .map_err(|error| error.to_string()),
            1 => operation
                .respond(
                    payload,
                    &fixture.signer,
                    PqKeySource::from_key(&fixture.prekey),
                    TraditionalKeySource::from_key(&fixture.prekey),
                    fixture.times.bootstrap,
                )
                .map(<[u8]>::to_vec)
                .map_err(|error| format!("{error:?}")),
            2 => operation
                .finish(payload, fixture.times.bootstrap)
                .map(|session| session.id().to_vec())
                .map_err(|error| format!("{error:?}")),
            3 if payload.is_empty() => {
                operation.close();
                if let Some(journal) = durable {
                    journal.close();
                }
                if let Some(journal) = successor {
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
            30..=37 | 39 | 43 | 44 => fixture
                .witness
                .as_ref()
                .ok_or("required witness not configured")?
                .command(&fixture, command, payload)
                .map_err(|error| error.to_string()),
            40 => durable
                .as_mut()
                .ok_or("native maintenance before original session")?
                .maintain(&fixture, payload)
                .map_err(|error| format!("{error:?}")),
            41 => fixture
                .policy_renewal
                .as_ref()
                .ok_or("policy issuer unavailable")?
                .approve_request(&fixture, payload)
                .map_err(|error| error.to_string()),
            42 => durable
                .as_mut()
                .ok_or("policy maintenance before original session")?
                .renew_policy(&fixture, payload)
                .map_err(|error| error.to_string()),
            12 if payload.is_empty()
                && durable.as_ref().is_some_and(|owner| owner.has_policy()) =>
            {
                durable
                    .as_mut()
                    .ok_or("missing native policy owner")?
                    .reopen_policy(&fixture)
                    .map_err(|error| error.to_string())
            }
            4..=27 if successor.is_some() => {
                Err("original peer controller retired; use successor commands".into())
            }
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
