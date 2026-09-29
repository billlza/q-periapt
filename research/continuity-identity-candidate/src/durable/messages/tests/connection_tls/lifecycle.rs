// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::control_transport::{ControlEndpoint, Run as ControlRun, Session};

fn rekey(n: &mut Network, session: [u8; 32], generation: u8, target: u64) {
    let (mut child, address) = spawn(n, generation, "control", 1);
    let context = &n.inventory.peer.initiator;
    let endpoint = ControlEndpoint::client(
        context,
        session,
        n.client_tls.credentials(&n.server_tls),
        tls_limits(),
    )
    .expect("same SDK control endpoint");
    assert_eq!(
        endpoint
            .run(
                Session {
                    journal: &mut n.journal,
                    context,
                    signer: &n.inventory.peer.signer_i
                },
                ControlRun {
                    target,
                    address,
                    server_name: "localhost",
                    limits: limits(),
                    cancel: &Cancellation::default()
                },
                || Ok(150)
            )
            .expect("actual network rekey")
            .epoch,
        target
    );
    wait(n, &mut child, generation);
}
#[test]
fn connection_tls_bootstrap_rekeys_and_both_application_directions_use_actual_network() {
    let mut n = Network::new();
    let endpoint = n.endpoint();
    let (mut child, address) = spawn(&n, 0, "none", 1);
    let session = n
        .establish(&endpoint, address, limits())
        .expect("network bootstrap")
        .session;
    wait(&n, &mut child, 0);
    for epoch in 1..=3 {
        rekey(&mut n, session, epoch as u8, epoch);
    }
    let context = Arc::clone(&n.inventory.peer.initiator);
    let id = n
        .journal
        .next_message_id(&context, session, 150)
        .expect("epoch-three ID");
    assert_eq!(id.epoch().expect("epoch"), 3);
    let (mut child, address) = spawn(&n, 4, "none", 1);
    let delivered = endpoint
        .send(
            n.actor(),
            Submission {
                session,
                message: id,
                plaintext: b"forward after three fresh contributions",
                associated_data: b"directional",
            },
            Run {
                address,
                server_name: "localhost",
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        )
        .expect("network application delivery");
    assert_eq!(delivered.consumption, Consumption::Confirmed);
    wait(&n, &mut child, 4);
    readback(&n, session, id, b"forward after three fresh contributions");
    n.journal.close();
    for (name, data) in [
        (
            "connection-public",
            [
                n.inventory.public.0.as_slice(),
                n.inventory.public.1.as_slice(),
            ]
            .concat(),
        ),
        ("connection-server.der", n.client_tls.certificate.clone()),
        ("connection-server.key", n.client_tls.key.to_vec()),
        ("connection-client.der", n.server_tls.certificate.clone()),
    ] {
        fs::write(n.client_path.join(name), data).expect("reverse endpoint fixture");
    }
    let (mut child, address) = spawn_at(&n.client_path, 1, 5, "none", 1);
    let context = &n.inventory.peer.responder;
    n.inventory.store = reopen(&n.inventory.path, n.inventory.peer.local_device());
    let reverse = ConnectionEndpoint::client(
        context,
        n.server_tls.credentials(&n.client_tls),
        tls_limits(),
    )
    .expect("reverse TLS direction");
    let id = n
        .inventory
        .store
        .next_message_id(context, session, 150)
        .expect("reverse message");
    let delivered = reverse
        .send(
            Actor {
                journal: &mut n.inventory.store,
                context,
                signer: &n.inventory.peer.signer_r,
            },
            Submission {
                session,
                message: id,
                plaintext: b"reverse independent disk readback",
                associated_data: b"directional",
            },
            Run {
                address,
                server_name: "client.test",
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        )
        .expect("reverse network delivery");
    assert_eq!(delivered.consumption, Consumption::Confirmed);
    wait_at(&n.client_path, &mut child, 5);
    let entries: Vec<_> = fs::read_dir(&n.client_path)
        .expect("dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|x| x.to_string_lossy().starts_with("application-"))
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let mut expected = session.to_vec();
    expected.extend_from_slice(id.as_bytes());
    expected.extend_from_slice(b"reverse independent disk readback");
    assert_eq!(
        fs::read(entries.first().expect("effect")).expect("independent readback"),
        expected
    );
    eprintln!("CONNECTION_TLS_LIFECYCLE network_bootstrap=true network_rekeys=3 network_application_directions=2 consumption_proofs=2 independent_readbacks=2");
}
#[test]
fn connection_tls_valid_old_epoch_ack_cannot_confirm_a_new_message() {
    let mut n = Network::new();
    let endpoint = n.endpoint();
    let (mut child, address) = spawn(&n, 0, "none", 1);
    let session = n
        .establish(&endpoint, address, limits())
        .expect("bootstrap")
        .session;
    wait(&n, &mut child, 0);
    n.inventory.store = reopen(&n.inventory.path, n.inventory.peer.local_device());
    let ack = n
        .inventory
        .store
        .message_acknowledgement(&n.inventory.peer.responder, session, 150)
        .expect("real epoch-zero MAC");
    fs::write(n.inventory.path.join("old-ack"), &ack).expect("adversarial replay input");
    n.inventory.store.close();
    rekey(&mut n, session, 1, 1);
    let context = Arc::clone(&n.inventory.peer.initiator);
    let id = n
        .journal
        .next_message_id(&context, session, 150)
        .expect("epoch-one ID");
    let (mut child, address) = spawn(&n, 2, "old-ack", 1);
    let result = endpoint.send(
        n.actor(),
        Submission {
            session,
            message: id,
            plaintext: b"new epoch requires its own proof",
            associated_data: b"",
        },
        Run {
            address,
            server_name: "localhost",
            limits: limits(),
            cancel: &Cancellation::default(),
        },
        || Ok(150),
    );
    assert!(matches!(
        result,
        Err(crate::connection_transport::Error::Protocol)
    ));
    wait(&n, &mut child, 2);
    assert_eq!(
        n.journal
            .message_status(&context, session, id)
            .expect("not invented"),
        MessageStatus::Committed
    );
    n.reopen();
    let (mut child, address) = spawn(&n, 3, "none", 1);
    let result = endpoint
        .send(
            n.actor(),
            Submission {
                session,
                message: id,
                plaintext: b"new epoch requires its own proof",
                associated_data: b"",
            },
            Run {
                address,
                server_name: "localhost",
                limits: limits(),
                cancel: &Cancellation::default(),
            },
            || Ok(150),
        )
        .expect("exact epoch proof after restart");
    assert_eq!(result.consumption, Consumption::Confirmed);
    wait(&n, &mut child, 3);
    readback(&n, session, id, b"new epoch requires its own proof");
}
