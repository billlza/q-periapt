// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Matched local-only experiment. Each branch gets the same closed fixture files.
//! All copied keys stay inside disposable owner-only test directories.
use super::*;
use crate::durable::tests::ChildGuard;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn branch(source: &Path) -> tempfile::TempDir {
    let dest = directory();
    for name in ["state.redb", "key", "store-id"] {
        let original = source.join(name);
        let copy = dest.path().join(name);
        fs::copy(&original, &copy).expect("copy closed synthetic fixture");
        // Compare inside the harness without printing private bytes or their digests.
        let a = Zeroizing::new(fs::read(original).expect("original bytes"));
        let b = Zeroizing::new(fs::read(copy).expect("branch bytes"));
        assert!(a.as_slice() == b.as_slice());
    }
    dest
}

fn capture(
    path: &Path,
    p: &Pair,
    offer: &[u8],
    candidate: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut public = p.f.reusable.public_key()?.to_bytes().to_vec();
    public.extend_from_slice(&p.f.once.public_key()?.to_bytes());
    for (name, data) in [
        ("public-keys", public.as_slice()),
        ("session", p.session.as_slice()),
        ("rekey-offer", offer),
        ("offer", offer),
    ] {
        fs::write(path.join(name), data)?;
    }
    fs::write(
        path.join("operation"),
        if candidate {
            "study-input"
        } else {
            "rekey-response"
        },
    )?;
    let mut child = ChildGuard(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "durable::messages::tests::message_crash_child",
                "--nocapture",
            ])
            .env("QPERIAPT_MESSAGES_CRASH_DIR", path)
            .env("QPERIAPT_STAGE4_INPUT_CUT", path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(25);
    while !path.join("input-cut").is_file() {
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("did not reach pending cut".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!path.join("returned").exists());
    child.0.kill()?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.0.wait()?.signal(), Some(9));
    Ok(fs::read_to_string(path.join("input-cut"))?)
}

#[test]
fn same_snapshot_offer_and_wrapping_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut p = Pair::new();
    p.activate();
    let offer =
        p.ji.prepare_rekey_offer(&p.f.initiator, p.session, &p.f.signer_i, 150)?;
    p.jr.close();
    p.ji.close();
    for candidate in [false, true] {
        let r = branch(&p.pr);
        let i = branch(&p.pi);
        let rp = r.path().canonicalize()?;
        let ip = i.path().canonicalize()?;
        let observed = capture(&rp, &p, &offer, candidate)?;
        let (phase, bytes) = if candidate { (10, 0) } else { (4, 245) };
        assert_eq!(observed,format!("current_phase=0 pending_phase={phase} encapsulation_token_bytes={bytes} exact_offer=true normalized_prior_equal=true wrong_key_rejected=true\n"));
        p.jr = reopen(&rp, p.f.local_device());
        p.ji = reopen(&ip, p.f.initiator_device());
        if candidate {
            // At this matched cut the authenticated encoding ended exactly at the
            // public offer. The bytes at the legacy observer's fixed tail are
            // therefore publicly available. Run the original SDK decoder on them.
            let start = offer.len().checked_sub(245).ok_or("short public offer")?;
            let public_tail = offer.get(start..).ok_or("missing public suffix")?;
            assert!(matches!(
                q_periapt_sdk::expert::replay::SealedOperation::from_bytes(public_tail),
                Err(q_periapt_sdk::Error::InvalidPrivateKey)
            ));
            println!("STAGE4_DECODER phase=10 fixed_tail=public_offer result=InvalidPrivateKey");
            let ctx = &p.f.responder;
            p.jr.stage4_select(ctx, p.session, &offer, 150, |key, context, policy| {
                let runtime = &ctx.current_policy()?.runtime;
                assert_eq!(runtime.trusted_state(), policy);
                let output = runtime.encapsulate(key, &context).map_err(Error::from)?;
                Ok((
                    output.ciphertext,
                    output.secret.export_for_protocol().map_err(Error::from)?,
                ))
            })?;
        }
        if !candidate {
            // study_input_records already parsed the actual 245-byte field with the same decoder.
            println!("STAGE4_DECODER phase=4 fixed_tail=stored_reservation result=Parsed");
        }
        assert_eq!(complete_rekey(&mut p), 1);
        for reverse in [false, true] {
            let (sender, receiver, sc, rc) = if reverse {
                (&mut p.jr, &mut p.ji, &p.f.responder, &p.f.initiator)
            } else {
                (&mut p.ji, &mut p.jr, &p.f.initiator, &p.f.responder)
            };
            for _ in 0..3 {
                let mut plaintext = [0; 128];
                getrandom::fill(&mut plaintext)?;
                let id = sender.next_message_id(sc, p.session, 150)?;
                let wire =
                    sender.send_message(sc, p.session, id, &plaintext, b"application", 150)?;
                let opened = receiver.receive_message(rc, p.session, &wire, b"application", 150)?;
                assert_eq!(opened.as_bytes(), plaintext);
            }
        }
        println!("STAGE4_MATCHED phase={phase} reservation_bytes={bytes} identical_starting_files=true identical_offer=true authenticated_pending=true honest_deliveries=6");
        p.ji.close();
        p.jr.close();
    }
    Ok(())
}
