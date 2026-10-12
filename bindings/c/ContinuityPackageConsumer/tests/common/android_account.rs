// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Same original aggregate transaction across separate Java/JNI processes.
use crate::{fixture, independent_inputs, issue_grant, p, peer_bundle, run_foreign, Result};
use q_periapt_host_store::filesystem::publish_private_bytes;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

#[test]
fn original_account_delivery() -> Result<()> {
    let output = PathBuf::from(std::env::var_os("QPC_ANDROID_CASES").ok_or("case output")?);
    let client = PathBuf::from(std::env::var_os("QPC_ANDROID_DRIVER").ok_or("client driver")?);
    fs::DirBuilder::new().mode(0o700).create(&output)?;
    for profile in ["fixed", "recoverable"] {
        let (reference, extra) = fixture::setup_devices(None, None, None, true, false, true)?;
        let second = extra.ok_or("second recipient")?;
        let recipients = [&reference.responder, &second];
        let base = output.join(profile);
        fs::DirBuilder::new().mode(0o700).create(&base)?;
        let inputs = base.join("inputs");
        fs::DirBuilder::new().mode(0o700).create(&inputs)?;
        let (authority, intent, validity) = independent_inputs(&reference.initiator, &inputs)?;
        let run =
            |mode: &str, label: &str| run_foreign(&client, profile, &inputs, &base, mode, label);
        let request = run("enrollment-create", "request")?;
        let (certificate, roster) = issue_grant(&inputs, &authority, &intent, validity, &request)?;
        assert_eq!(run("enrollment-activate", "activated")?, request);
        let mut servers = Vec::new();
        for (index, remote) in recipients.iter().enumerate() {
            peer_bundle::peer_bundle_at(
                remote,
                &inputs.join(format!("account-peer-{index}")),
                &authority,
                &certificate,
                &roster,
                None,
            )?;
            let (server, address) = fixture::spawn(remote, 81, "bootstrap")?;
            servers.push(server);
            publish_private_bytes(
                &inputs.join(format!("account-address-{index}")),
                address.to_string().as_bytes(),
            )?;
            publish_private_bytes(
                &inputs.join(format!("account-initiation-{index}")),
                p::InitiationId::generate()?.as_bytes(),
            )?;
        }
        let sessions = run("account-connect", "sessions")?;
        assert_eq!(sessions.len(), 64);
        for server in &mut servers {
            assert!(fixture::wait(server)?.success());
        }
        for (index, remote) in recipients.iter().enumerate() {
            assert_eq!(
                sessions
                    .get(index * 32..(index + 1) * 32)
                    .ok_or("session pair width")?,
                fixture::array::<32>(remote, "session")?
            );
        }
        publish_private_bytes(&inputs.join("account-sessions"), &sessions)?;
        let recipient = fixture::array::<32>(&reference.responder, "local-account")?;
        assert_eq!(recipient, fixture::array::<32>(&second, "local-account")?);
        publish_private_bytes(&inputs.join("account-recipient"), &recipient)?;
        let operation = run("account-next", "original-operation")?;
        assert_eq!(operation.len(), 32);
        publish_private_bytes(&inputs.join("account-operation"), &operation)?;
        publish_private_bytes(&inputs.join("account-selected"), &0u32.to_be_bytes())?;
        publish_private_bytes(&inputs.join("account-address"), b"127.0.0.1:1")?;
        assert_eq!(run("account-status", "absent-before")?, [0; 33]);
        for (mode, label, code) in [
            ("account-omit", "omit", 106u32),
            ("account-duplicate-peer", "duplicate-peer", 1),
            ("account-duplicate-session", "duplicate-session", 1),
            ("account-cancelled-peer", "cancelled-peer", 302),
        ] {
            assert_eq!(run(mode, label)?, code.to_be_bytes());
            assert_eq!(run("account-status", &format!("absent-{label}"))?, [0; 33]);
        }
        let (mut server, address) =
            fixture::spawn(&reference.responder, 82, "crash-after-application")?;
        fs::write(inputs.join("account-address"), address.to_string())?;
        assert_eq!(run("account-unknown", "unknown")?, 311u32.to_be_bytes());
        assert_eq!(fixture::wait(&mut server)?.code(), Some(77));
        let effects = fs::read_dir(&reference.responder)?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("application-")
            })
            .collect::<Vec<_>>();
        assert_eq!(effects.len(), 1);
        let original_effect = fs::read(effects.first().ok_or("missing committed effect")?.path())?;
        publish_private_bytes(&base.join("effect-before-retry"), &original_effect)?;
        let mut committed = [0; 33];
        committed[0] = 2;
        assert_eq!(run("account-status", "committed-after-unknown")?, committed);
        for (mode, label) in [
            ("account-changed", "changed"),
            ("account-omit-retained", "omit-retained"),
        ] {
            assert_eq!(run(mode, label)?, 211u32.to_be_bytes());
        }
        let mut messages = Vec::new();
        for (index, remote) in recipients.iter().enumerate() {
            let (mut server, address) = fixture::spawn(remote, 83, "application")?;
            fs::write(inputs.join("account-address"), address.to_string())?;
            fs::write(
                inputs.join("account-selected"),
                (index as u32).to_be_bytes(),
            )?;
            let result = run("account-send", &format!("delivered-{index}"))?;
            assert!(fixture::wait(&mut server)?.success());
            assert_eq!(result.len(), 88);
            assert_eq!(
                result.get(..16).ok_or("delivered device")?,
                fixture::array::<16>(remote, "local-device")?
            );
            assert_eq!(
                result.get(16..48).ok_or("delivered session")?,
                sessions
                    .get(index * 32..(index + 1) * 32)
                    .ok_or("session pair width")?
            );
            assert_eq!(
                result.get(80..84).ok_or("delivered outcome")?,
                1u32.to_be_bytes()
            );
            assert_eq!(
                result.get(84..).ok_or("delivered exchanges")?,
                1u32.to_be_bytes()
            );
            let session: [u8; 32] = result.get(16..48).ok_or("delivered session")?.try_into()?;
            let message: [u8; 32] = result.get(48..80).ok_or("delivered message")?.try_into()?;
            fixture::effect(
                remote,
                session,
                p::MessageId::from_trusted_state(message)?,
                b"persisted before process exit",
            )?;
            let effect = fs::read(remote.join(format!("application-{}", fixture::hex(&message))))?;
            if index == 0 {
                assert_eq!(effect, original_effect);
            }
            publish_private_bytes(&base.join(format!("effect-{index}")), &effect)?;
            fs::write(inputs.join("account-address"), b"127.0.0.1:1")?;
            let retained = run("account-reversed", &format!("retained-{index}"))?;
            assert_eq!(
                retained.get(..84).ok_or("retained member")?,
                result.get(..84).ok_or("delivered member")?
            );
            assert_eq!(
                retained.get(84..).ok_or("retained exchanges")?,
                0u32.to_be_bytes()
            );
            assert_eq!(
                fs::read(remote.join(format!("application-{}", fixture::hex(&message))))?,
                effect
            );
            messages.push(message);
        }
        assert_ne!(messages.first(), messages.get(1));
        assert_eq!(run("account-status", "committed-final")?, committed);
        let next = run("account-next", "cancel-operation")?;
        assert_ne!(next, operation);
        fs::write(inputs.join("account-operation"), &next)?;
        assert_eq!(
            run("account-concurrent", "concurrent-cancel")?,
            302u32.to_be_bytes()
        );
        assert_eq!(run("account-status", "cancel-committed")?, committed);
        for (index, remote) in recipients.iter().enumerate() {
            let (mut server, address) = fixture::spawn(remote, 84, "application")?;
            fs::write(inputs.join("account-address"), address.to_string())?;
            fs::write(
                inputs.join("account-selected"),
                (index as u32).to_be_bytes(),
            )?;
            let result = run("account-send", &format!("cancel-resumed-{index}"))?;
            assert!(fixture::wait(&mut server)?.success());
            assert_eq!(result.len(), 88);
            assert_eq!(
                result.get(80..84).ok_or("delivered outcome")?,
                1u32.to_be_bytes()
            );
            assert_eq!(
                result.get(84..).ok_or("delivered exchanges")?,
                1u32.to_be_bytes()
            );
            assert_eq!(
                result.get(16..48).ok_or("delivered session")?,
                sessions
                    .get(index * 32..(index + 1) * 32)
                    .ok_or("session pair width")?
            );
            let message: [u8; 32] = result.get(48..80).ok_or("delivered message")?.try_into()?;
            assert_ne!(message, *messages.get(index).ok_or("original message")?);
            fixture::effect(
                remote,
                result.get(16..48).ok_or("delivered session")?.try_into()?,
                p::MessageId::from_trusted_state(message)?,
                b"persisted before process exit",
            )?;
        }
        println!("qualified account {profile}: complete two-recipient original operation; receiver exit 77, exact retry, retained zero-exchange outcomes, omission and input conflict refused; active parent/member busy, member cancellation and original-operation recovery");
    }
    Ok(())
}
