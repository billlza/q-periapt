// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Actual C owner, independently approved P and signed TCP/mutual-TLS witness.
use super::*;
use redb::{ReadableDatabase, TableDefinition};
use std::sync::atomic::Ordering;

fn snapshot(c: &Registered) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let db = open_private_database(&c.path.join("journal.redb"))?;
    let tx = db.begin_read()?;
    let table = tx.open_table(TableDefinition::<&str, &[u8]>::new(
        "continuity_device_candidate_v21",
    ))?;
    let image = table.get("image")?.ok_or("journal image")?.value().to_vec();
    let pending = table.get("pending")?.map(|p| p.value().to_vec());
    Ok((image, pending))
}
fn target(saved: &(Vec<u8>, Option<Vec<u8>>)) -> Result<Vec<u8>> {
    let pending = saved.1.as_ref().ok_or("pending target")?;
    assert_eq!(pending.get(..8), Some(b"QPWINT06".as_slice()));
    Ok(pending
        .get(220..pending.len().checked_sub(32).ok_or("MAC")?)
        .ok_or("original target")?
        .to_vec())
}
fn proposal(c: &Registered) -> Result<p::AnchorPolicyRenewalProposal> {
    Ok(p::AnchorPolicyRenewalProposal::from_trusted_state(
        &fixture::read(&c.path, "independent-witness-proposal", 296)?,
    )?)
}
fn approve(
    f: &Prepared,
    witness: &witness::Witness,
    proposal: p::AnchorPolicyRenewalProposal,
) -> Result<()> {
    let c = &f.c;
    let pin = p::AccountPin::new(
        c.root.account_id()?,
        c.root.public_key()?,
        c.roster.checkpoint(),
        c.family,
    )?;
    let device = pin.verify_historical_device(&f.request.original_c, &f.request.original_r)?;
    let mut original_sdk = fixture::sdk(&c.path)?;
    let original = fixture::protocol_policy(&c.path, &original_sdk)?;
    let target_path = c.path.join("independent-sdk");
    let mut sdk = fixture::sdk(&target_path)?;
    let target = fixture::protocol_policy(&target_path, &sdk)?;
    let materials = p::PolicyRenewalMaterials {
        original: original.historical(),
        previous: original.historical(),
        target: &target,
        original_device: &device,
        current_device: &device,
    };
    let proof = p::VerifiedPolicyRenewal::from_bytes(
        &fixture::read(
            &c.path,
            "independent-first-approvals",
            p::MAX_POLICY_RENEWAL_BYTES,
        )?,
        &f.request.scope,
        &materials,
        fixture::now()?,
    )?;
    assert_eq!(
        witness
            .configured
            .store
            .lock()
            .map_err(|_| "witness lock")?
            .prepare_policy_renewal(proposal, &proof, &materials, fixture::now()?)?,
        p::AnchorPolicyRenewalState::Prepared
    );
    target.close();
    original.close();
    sdk.close();
    original_sdk.close();
    Ok(())
}
fn retained(f: &Prepared, phase: u32, retired: bool) -> String {
    format!(
        "{phase}\n{}\n{}\n{}\n",
        u32::from(retired),
        f.target.version(),
        hex(&f.target.digest())
    )
}
fn calls(witness: &witness::Witness) -> Result<usize> {
    Ok(witness.captured.lock().map_err(|_| "capture")?.len())
}
fn staged(c: Registered, root: p::PolicySigningKey) -> Result<Prepared> {
    let f = prepare_for(c, root)?;
    assert_eq!(
        invoke(&f.c, "witness-stage", "stage")?,
        expected_status(1, &f.request, f.statement, f.target)
    );
    assert_eq!(
        invoke(&f.c, "witness-local-absence", "witness-recover-absent")?,
        "preparation-absent\n"
    );
    assert_eq!(
        invoke(&f.c, "witness-local-progress", "witness-progress")?,
        format!("0\n0\n0\n{}\n", hex(&[0; 32]))
    );
    assert_eq!(
        invoke(&f.c, "witness-prepare", "witness-prepare")?,
        "proposal-saved\n"
    );
    assert_eq!(
        invoke(&f.c, "witness-recover", "witness-recover")?,
        "preparation-exact\n"
    );
    Ok(f)
}
#[test]
fn c_original_independent_policy_coordinates_applied_and_closed_over_tcp_and_mutual_tls(
) -> Result<()> {
    for tls in [false, true] {
        for closed in [false, true] {
            let mut witness = witness::Witness::start()?;
            let root = p::PolicySigningKey::generate()?;
            let mut c = registered_with_anchor_inputs(
                600,
                Some(&root),
                300,
                None,
                p::BootstrapRole::Initiator,
                Some(&witness.configured),
            )?;
            let mut server = if tls {
                Some(witness_tls::TlsWitness::start(
                    Arc::clone(&witness.configured.store),
                    [c.path.as_path()],
                )?)
            } else {
                None
            };
            if let Some(server) = &server {
                c.witness.as_mut().ok_or("configured")?.address = server.address;
                c.witness_tls = true;
            }
            let f = staged(c, root)?;
            let p = proposal(&f.c)?;
            let saved = snapshot(&f.c)?;
            assert_eq!(
                invoke(&f.c, "witness-progress-reserved", "witness-progress")?,
                retained(&f, 1, false)
            );
            assert_eq!(
                invoke(&f.c, "witness-unavailable", "witness-reconcile")?,
                "witness-state:5\n"
            );
            assert_eq!(
                snapshot(&f.c)?,
                saved,
                "unavailable cannot install or retire"
            );
            assert_eq!(
                invoke(&f.c, "witness-wrong-kind", "witness-wrong-kind")?,
                "witness-refused:101\n"
            );
            assert_eq!(
                invoke(&f.c, "witness-cancelled", "witness-cancelled")?,
                "witness-refused:302\n"
            );
            approve(&f, &witness, p)?;
            assert_eq!(
                invoke(&f.c, "witness-prepared", "witness-reconcile")?,
                "witness-state:1\n"
            );
            assert_eq!(
                invoke(&f.c, "witness-substituted-before", "witness-substitute")?,
                "witness-refused:211\n"
            );
            assert_eq!(snapshot(&f.c)?, saved);
            let signer = Zeroizing::new(fs::read(f.c.path.join("signer.key"))?);
            let wrapping = Zeroizing::new(fs::read(f.c.path.join("wrap.key"))?);
            assert_eq!(
                invoke(
                    &f.c,
                    "witness-terminal",
                    if closed {
                        "witness-close"
                    } else {
                        "witness-commit"
                    }
                )?,
                format!("witness-state:{}\n", if closed { 3 } else { 2 })
            );
            assert_eq!(
                snapshot(&f.c)?,
                (
                    if closed {
                        saved.0.clone()
                    } else {
                        target(&saved)?
                    },
                    None
                )
            );
            assert_eq!(
                invoke(&f.c, "witness-progress-terminal", "witness-progress")?,
                retained(&f, if closed { 3 } else { 2 }, true)
            );
            assert_eq!(
                invoke(&f.c, "witness-substituted-after", "witness-substitute")?,
                "witness-refused:211\n"
            );
            if !closed {
                assert_eq!(
                    invoke(&f.c, "witness-owner", "activate")?,
                    "independent-device-active\n"
                );
            }
            assert_eq!(fs::read(f.c.path.join("signer.key"))?, *signer);
            assert_eq!(fs::read(f.c.path.join("wrap.key"))?, *wrapping);
            // A metadata query must not acquire any signer, current runtime or TLS key.
            for name in [
                "sdk.redb",
                "sdk-policy",
                "sdk-signature",
                "sdk-root",
                "tls-cert",
                "tls-key",
                "signer.key",
            ] {
                let path = f.c.path.join(name);
                fs::rename(&path, path.with_extension("held"))?;
            }
            fs::rename(
                f.c.path.join("independent-sdk"),
                f.c.path.join("independent-sdk-held"),
            )?;
            assert_eq!(
                invoke(&f.c, "witness-historical-progress", "witness-progress")?,
                retained(&f, if closed { 3 } else { 2 }, true)
            );
            lease(&f.c.path, false)?;
            if let Some(server) = &mut server {
                assert!(server.admitted.load(Ordering::Acquire) > 0);
                assert!(server.finish()?.is_empty());
            }
            witness.join()?;
        }
    }
    eprintln!("C_INDEPENDENT_WITNESS tcp_and_mutual_tls=true actual_applied_and_closed=true original_target=true complete_proposal=true metadata_without_runtime_signer_TLS=true");
    Ok(())
}
#[test]
fn c_original_policy_lost_commit_or_ack_recovers_without_current_runtime_or_application_tls(
) -> Result<()> {
    for (closed, cut) in [(false, 31u8), (false, 34u8), (true, 34u8)] {
        let mut witness = witness::Witness::start()?;
        let root = p::PolicySigningKey::generate()?;
        let c = registered_with_anchor_inputs(
            600,
            Some(&root),
            300,
            None,
            p::BootstrapRole::Initiator,
            Some(&witness.configured),
        )?;
        let f = staged(c, root)?;
        let p = proposal(&f.c)?;
        let saved = snapshot(&f.c)?;
        approve(&f, &witness, p)?;
        witness.arm(cut)?;
        assert_eq!(
            invoke(
                &f.c,
                "witness-lost",
                if closed {
                    "witness-close-lost"
                } else {
                    "witness-commit-lost"
                }
            )?,
            "witness-refused:218\n"
        );
        assert_eq!(
            witness.fault.load(Ordering::Acquire),
            0,
            "actual targeted reply loss consumed"
        );
        assert!(
            snapshot(&f.c)?.1.is_some(),
            "lost reply cannot remove pending"
        );
        if cut == 34 {
            assert_eq!(
                invoke(&f.c, "witness-known-terminal", "witness-progress")?,
                retained(&f, if closed { 3 } else { 2 }, false)
            );
        }
        let before_calls = calls(&witness)?;
        assert_eq!(
            invoke(&f.c, "witness-grafted", "witness-substitute")?,
            "witness-refused:211\n"
        );
        assert_eq!(
            calls(&witness)?,
            before_calls,
            "substituted target dispatched"
        );
        for name in [
            "sdk.redb",
            "sdk-policy",
            "sdk-signature",
            "sdk-root",
            "tls-cert",
            "tls-key",
        ] {
            let path = f.c.path.join(name);
            fs::rename(&path, path.with_extension("held"))?;
        }
        fs::rename(
            f.c.path.join("independent-sdk"),
            f.c.path.join("independent-sdk-held"),
        )?;
        assert_eq!(
            invoke(&f.c, "witness-original-recovery", "witness-reconcile")?,
            format!("witness-state:{}\n", if closed { 3 } else { 2 })
        );
        assert_eq!(
            invoke(&f.c, "witness-retired-retry", "witness-reconcile")?,
            format!("witness-state:{}\n", if closed { 3 } else { 2 })
        );
        assert_eq!(
            snapshot(&f.c)?,
            (if closed { saved.0 } else { target(&saved)? }, None)
        );
        assert_eq!(
            invoke(&f.c, "witness-final-progress", "witness-progress")?,
            retained(&f, if closed { 3 } else { 2 }, true)
        );
        let captured = witness.captured.lock().map_err(|_| "captures")?;
        assert!(captured
            .iter()
            .any(|r| !r.delivered && r.request.get(204) == Some(&(cut - 20))));
        drop(captured);
        witness.join()?;
    }
    eprintln!("C_INDEPENDENT_WITNESS_REPLY_LOSS scenarios=3 exact_pending=true same_target=true original_terminal_before_ACK=true no_runtime_or_application_TLS=true");
    Ok(())
}

#[path = "witness_roster.rs"]
mod roster;
