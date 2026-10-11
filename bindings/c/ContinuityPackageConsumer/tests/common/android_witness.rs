// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independent witness operator authorizes only the exported public genesis.
use super::{fixture, independent_inputs, issue_grant, p, run_foreign, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, sync::Arc};
#[path = "witness.rs"]
mod witness;
#[path = "witness_tls.rs"]
mod witness_tls;

#[test]
fn required_witness_registration() -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("case output")?);
    let client = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("client driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    for carrier in ["signed", "tls"] {
        for profile in ["fixed", "recoverable"] {
            let mut witness = witness::Witness::start()?;
            let reference = fixture::setup_with_witness(Some(&witness.configured))?;
            let base = output.join(format!("{carrier}-{profile}"));
            fs::DirBuilder::new().mode(0o700).create(&base)?;
            let inputs = base.join("inputs");
            fs::DirBuilder::new().mode(0o700).create(&inputs)?;
            let (authority, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
            let pin = witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness store")?
                .pin()?;
            for (name, bytes) in [
                ("witness-id", pin.identity().as_bytes().to_vec()),
                ("witness-public", pin.public_key().encode()),
                (
                    "witness-address",
                    witness.configured.address.to_string().into_bytes(),
                ),
                ("witness-carrier", b"signed".to_vec()),
            ] {
                publish_private_bytes(&inputs.join(name), &bytes)?;
            }
            let run = |mode: &str, label: &str| {
                run_foreign(&client, profile, &inputs, &base, mode, label)
            };
            let original = run("witness-create", "original.request")?;
            let before = witness.captured.lock().map_err(|_| "capture")?.len();
            assert_eq!(run("witness-wrong", "wrong-pin")?, vec![1]);
            assert_eq!(
                witness.captured.lock().map_err(|_| "capture")?.len(),
                before
            );
            assert_eq!(run("witness-resume", "resumed.request")?, original);
            let (certificate, roster) =
                issue_grant(&inputs, &authority, &intent, validity, &original)?;
            let exported = run("witness-prepare", "genesis")?;
            assert_eq!(exported.len(), 164);
            assert_eq!(exported.get(..4), Some(&2u32.to_be_bytes()[..]));
            let before = witness.captured.lock().map_err(|_| "capture")?.len();
            assert_eq!(run("witness-missing", "missing")?, original);
            assert_eq!(
                witness.captured.lock().map_err(|_| "capture")?.len(),
                before
            );
            let journal = p::JournalIdentity::from_trusted_state(
                exported.get(4..36).ok_or("journal")?.try_into()?,
            )?;
            let subject =
                p::AnchorSubject::from_trusted_state(exported.get(36..132).ok_or("subject")?)?;
            let genesis = p::AnchorGenesis::from_trusted_state(
                subject,
                exported.get(132..164).ok_or("digest")?.try_into()?,
            )?;
            let account = p::AccountPin::new(
                authority.account_id()?,
                authority.public_key()?,
                roster.checkpoint(),
                fixture::array(&inputs, "family")?,
            )?;
            let device = account.verify_device(&certificate, roster.as_bytes(), fixture::now()?)?;
            let mut sdk = fixture::sdk(&reference.initiator)?;
            let policy = fixture::protocol_policy(&reference.initiator, &sdk)?;
            assert_eq!(
                subject,
                p::AnchorSubject::for_device(journal, &device, policy.as_ref())?
            );
            witness
                .configured
                .store
                .lock()
                .map_err(|_| "witness store")?
                .enroll(&genesis, &device, &policy, fixture::now()?)?;
            policy.close();
            sdk.close();
            let mut tls = if carrier == "tls" {
                publish_private_bytes(&inputs.join("witness-subject"), &subject.to_bytes())?;
                let server = witness_tls::TlsWitness::start(
                    Arc::clone(&witness.configured.store),
                    [inputs.as_path()],
                )?;
                fs::write(inputs.join("witness-address"), server.address.to_string())?;
                fs::write(inputs.join("witness-carrier"), b"tls")?;
                Some(server)
            } else {
                witness.arm(2)?;
                assert_eq!(run("witness-bad-receipt", "bad-receipt")?, original);
                None
            };
            let before = witness.captured.lock().map_err(|_| "capture")?.len();
            assert_eq!(run("witness-activate", "activated.request")?, original);
            assert_eq!(
                run("witness-active-reopen", "active-reopened.request")?,
                original
            );
            if let Some(server) = tls.as_mut() {
                assert!(server.finish()?.is_empty());
                assert!(server.records.lock().map_err(|_| "TLS records")?.len() >= 2);
            } else {
                assert!(witness.captured.lock().map_err(|_| "capture")?.len() >= before + 2);
            }
            witness.join()?;
            let records = witness.captured.lock().map_err(|_| "capture")?;
            let mut transcript = String::new();
            for record in records.iter() {
                transcript.push_str(&format!(
                    "{} {} {}\n",
                    fixture::hex(&record.request),
                    fixture::hex(&record.reply),
                    record.delivered
                ));
            }
            publish_private_bytes(
                &base.join("signed-witness-transcript"),
                transcript.as_bytes(),
            )?;
            println!("qualified witness {carrier}/{profile}: original registration, independent genesis, refused missing or wrong trust, authenticated activation and reopen");
        }
    }
    Ok(())
}
