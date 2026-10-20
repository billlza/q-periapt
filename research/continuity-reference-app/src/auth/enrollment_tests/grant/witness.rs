// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Real TCP witness; initial enrollment and G approval stay independent.
use super::*;
use crate::native_device::{clock, CredentialRecoveryInputs};
use std::{
    io::Write,
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};
#[path = "../../../test_support/witness.rs"]
mod transport;
pub(super) use transport::Server;

#[test]
fn witness_fixture_waits_for_a_request_sent_after_nonblocking_accept() -> Result {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let (start, go) = std::sync::mpsc::channel();
    let sender = thread::spawn(move || -> std::io::Result<()> {
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        go.recv_timeout(Duration::from_secs(3))
            .map_err(std::io::Error::other)?;
        thread::sleep(Duration::from_millis(100));
        socket.write_all(&3674u32.to_be_bytes())?;
        socket.write_all(&[7; 3674])
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let (mut socket, _) = loop {
        if Instant::now() >= deadline {
            return Err("Witness framing accept deadline".into());
        }
        match listener.accept() {
            Ok(value) => break value,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e.into()),
        }
    };
    start.send(())?;
    let received = transport::request_frame(&mut socket);
    sender
        .join()
        .map_err(|_| "Witness framing sender panicked")??;
    assert_eq!(received?, vec![7; 3674]); // Framing evidence only; no crypto claim.
    Ok(())
}
#[test]
fn native_credential_recovery_requires_independent_witness_approval_and_reopens_same_owner(
) -> Result {
    let mut server = Server::start()?;
    let mut c = Case::with_profile(false, Some(&server))?;
    c.host.store.enable_credential_grants()?;
    let issued: IssuedCredentialGrant = serde_json::from_slice(&c.issue()?)?;
    let pin = c.pin()?;
    let current = c.host.enrollment_root(&c.token)?;
    let inputs = CredentialRecoveryInputs {
        approval: &c.input,
        issued: &issued,
        current: &current,
        original_policy: &c.historical,
        policy: &c.policy,
    };
    let open = || {
        NativeDevice::open(
            &c.path.join("device"),
            &c.path.join("wrap.key"),
            c.invitation.clone(),
        )
    };
    assert!(open()?
        .activate_credential_recovery(&inputs, None, None, crate::enrollment::now()?)
        .is_err());
    // G alone cannot grant the independent witness's permission.
    assert!(open()?
        .activate_credential_recovery(
            &inputs,
            Some(server.pin.clone()),
            Some(server.address),
            crate::enrollment::now()?
        )
        .is_err());
    assert!(open()?
        .reconcile_expired_credential_recovery(&issued, &c.policy, crate::enrollment::now()?)
        .is_err());
    let mut owner = open()?;
    assert!(matches!(
        owner.credential_recovery_status()?,
        sdk::CredentialRenewalStatus::Pending { .. }
    ));
    let proposal = owner.prepare_credential_recovery_witness(
        &inputs,
        server.pin.clone(),
        server.address,
        crate::enrollment::now()?,
    )?;
    owner.close();
    let mut owner = open()?;
    assert_eq!(
        proposal,
        owner.prepare_credential_recovery_witness(
            &inputs,
            server.pin.clone(),
            server.address,
            crate::enrollment::now()?
        )?
    );
    owner.close();
    let grant = sdk::VerifiedCredentialRenewal::verify(
        &issued.grant,
        &pin,
        c.input.retained.original_policy.digest,
        crate::enrollment::now()?,
    )?;
    server
        .store
        .lock()
        .map_err(|_| "witness lock")?
        .prepare_credential_renewal(proposal, &grant, &c.policy, crate::enrollment::now()?)?;
    for _ in 0..2 {
        let mut active = open()?.activate_credential_recovery(
            &inputs,
            Some(server.pin.clone()),
            Some(server.address),
            crate::enrollment::now()?,
        )?;
        assert_eq!(active.journal(), c.input.retained.journal);
        active.next_publication()?;
        active.close();
    }
    let mut owner = open()?;
    assert!(matches!(
        owner.credential_recovery_status()?,
        sdk::CredentialRenewalStatus::Committed { .. }
    ));
    owner.close();
    assert!(server.close()? > 0);
    Ok(())
}
