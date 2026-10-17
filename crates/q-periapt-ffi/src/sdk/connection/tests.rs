use super::*;
use crate::sdk::tests::{create, out, span, TESTS};

struct Identity {
    certificate: Vec<u8>,
    key: Vec<u8>,
}
impl Identity {
    fn new(name: &str) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec![name.into()]).expect("fixture");
        Self {
            certificate: cert.cert.der().to_vec(),
            key: cert.signing_key.serialize_der(),
        }
    }
}
impl Drop for Identity {
    fn drop(&mut self) {
        q_periapt_core::secure_wipe(&mut self.key);
    }
}
fn options(identity: &Identity, peer: &Identity) -> QPeriaptConnectionOptions {
    QPeriaptConnectionOptions {
        struct_size: size_of::<QPeriaptConnectionOptions>() as u32,
        extension_version: 1,
        certificate: span(&identity.certificate),
        private_key: span(&identity.key),
        peer_certificate: span(&peer.certificate),
        application_context: span(b"reference/test"),
        max_connections: 1,
        handshake_ms: 10_000,
        request_ms: 5_000,
        idle_ms: 10_000,
    }
}
fn endpoints(runtime: u64) -> (u64, u64) {
    let client = Identity::new("client.test");
    let server = Identity::new("localhost");
    let mut c = 0;
    let mut s = 0;
    // SAFETY: options and all referenced inputs/outputs remain live and disjoint.
    unsafe {
        assert_eq!(
            q_periapt_sdk_connection_client_new(runtime, &options(&client, &server), &mut c),
            0
        );
        assert_eq!(
            q_periapt_sdk_connection_server_new(runtime, &options(&server, &client), &mut s),
            0
        );
    }
    (c, s)
}
fn sessions(client: u64, server: u64) -> (u64, u64) {
    let mut c = 0;
    let mut s = 0;
    // SAFETY: caller-owned fixed outputs and immutable DNS input are disjoint.
    unsafe {
        assert_eq!(
            q_periapt_sdk_connection_connect(client, span(b"localhost"), &mut c),
            0
        );
        assert_eq!(q_periapt_sdk_connection_accept(server, &mut s), 0);
    }
    (c, s)
}
fn progress(handle: u64) -> Result<QPeriaptConnectionProgress, i32> {
    let mut value = QPeriaptConnectionProgress {
        phase: 0,
        wants_write: 0,
        remaining_ms: 0,
    };
    // SAFETY: complete initialized writable progress output.
    let status = unsafe { q_periapt_sdk_connection_progress(handle, &mut value) };
    if status == 0 {
        Ok(value)
    } else {
        Err(status)
    }
}
fn transfer(source: u64, target: u64) -> Result<bool, i32> {
    if progress(source)?.wants_write == 0 {
        return Ok(false);
    }
    let mut bytes = [0; 2048];
    let mut written = 0;
    // SAFETY: buffers/scalars are valid, initialized and disjoint throughout.
    unsafe {
        let status = q_periapt_sdk_connection_drain(source, out(&mut bytes), &mut written);
        if status != 0 {
            return Err(status);
        }
        let mut input = bytes.get(..written as usize).expect("valid written extent");
        while !input.is_empty() {
            let mut read = 0;
            let status = q_periapt_sdk_connection_feed(target, span(input), &mut read);
            if status != 0 {
                return Err(status);
            }
            assert!(read > 0, "native framing must make progress");
            input = input.get(read as usize..).expect("consumed extent");
        }
    }
    Ok(written != 0)
}
fn drive(client: u64, server: u64) -> Result<(), i32> {
    for _ in 0..256 {
        let a = transfer(client, server)?;
        let b = transfer(server, client)?;
        if !a && !b {
            return Ok(());
        }
    }
    Err(Q_PERIAPT_ERR_PROTOCOL)
}

#[test]
fn actual_abi2_tls_policy_message_roundtrip_and_revocation() {
    let _guard = TESTS.lock().expect("global budget serialization");
    let runtime = create();
    let (client_endpoint, server_endpoint) = endpoints(runtime);
    let (client, server) = sessions(client_endpoint, server_endpoint);
    let mut id = 99;
    // SAFETY: every call uses complete, disjoint and live I/O storage.
    unsafe {
        assert_eq!(
            q_periapt_sdk_connection_send_request(client, span(b"early"), &mut id),
            Q_PERIAPT_ERR_NOT_READY
        );
        assert_eq!(id, 0);
        drive(client, server).expect("actual TLS and policy confirmation");
        assert_eq!(
            progress(client).expect("state").phase,
            Q_PERIAPT_CONNECTION_READY
        );
        for payload in [Vec::new(), vec![42; Q_PERIAPT_CONNECTION_MAX_PAYLOAD_BYTES]] {
            assert_eq!(
                q_periapt_sdk_connection_send_request(client, span(&payload), &mut id),
                0
            );
            drive(client, server).expect("request transfer");
            let mut size = u32::MAX;
            assert_eq!(q_periapt_sdk_connection_message_size(server, &mut size), 0);
            assert_eq!(size as usize, payload.len());
            let mut length = 99;
            let mut received_id = 99;
            if payload.len() > 1 {
                let mut small = [0xa5];
                assert_eq!(
                    q_periapt_sdk_connection_take_request(
                        server,
                        out(&mut small),
                        &mut length,
                        &mut received_id
                    ),
                    Q_PERIAPT_ERR_LENGTH
                );
                assert_eq!((small, length, received_id), ([0], 0, 0));
                assert_eq!(
                    progress(server).expect("message retained").phase,
                    Q_PERIAPT_CONNECTION_REQUEST_READY
                );
            }
            let mut body = vec![0; payload.len().max(1)];
            assert_eq!(
                q_periapt_sdk_connection_take_request(
                    server,
                    out(&mut body),
                    &mut length,
                    &mut received_id
                ),
                0
            );
            assert_eq!(id, received_id);
            assert_eq!(body.get(..length as usize).expect("request"), payload);
            assert_eq!(
                q_periapt_sdk_connection_send_response(
                    server,
                    received_id,
                    span(body.get(..length as usize).expect("body"))
                ),
                0
            );
            drive(client, server).expect("response transfer");
            body.fill(0xa5);
            assert_eq!(
                q_periapt_sdk_connection_take_response(
                    client,
                    out(&mut body),
                    &mut length,
                    &mut received_id
                ),
                0
            );
            assert_eq!((received_id, length as usize), (id, payload.len()));
            assert_eq!(body.get(..length as usize).expect("response"), payload);
            q_periapt_core::secure_wipe(&mut body);
        }
        assert_eq!(q_periapt_sdk_close(runtime), 0);
        let mut size = 99;
        assert_eq!(
            q_periapt_sdk_connection_message_size(client, &mut size),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!(size, 0);
        assert_eq!(q_periapt_sdk_close(server), Q_PERIAPT_ERR_CLOSED);
    }
}

#[test]
fn connection_shape_alias_failures_are_atomic_and_endpoint_close_revokes_sessions() {
    let _guard = TESTS.lock().expect("global budget serialization");
    let runtime = create();
    let (client_endpoint, server_endpoint) = endpoints(runtime);
    let (client, server) = sessions(client_endpoint, server_endpoint);
    let mut output = [0xa5; 16];
    // SAFETY: deliberately overlapping outputs are rejected before dereference;
    // all remaining regions are valid exact-size caller storage.
    unsafe {
        assert_eq!(
            q_periapt_sdk_connection_drain(client, out(&mut output), output.as_mut_ptr().cast()),
            Q_PERIAPT_ERR_ALIASING
        );
        assert_eq!(output, [0xa5; 16]);
        let mut count = 99;
        assert_eq!(
            q_periapt_sdk_connection_feed(client, span(&[]), &mut count),
            Q_PERIAPT_ERR_LENGTH
        );
        assert_eq!(count, 99);
        let mut excess = 99;
        assert_eq!(
            q_periapt_sdk_connection_connect(client_endpoint, span(b"localhost"), &mut excess),
            Q_PERIAPT_ERR_RESOURCE_LIMIT
        );
        assert_eq!(excess, 0);
        assert_eq!(q_periapt_sdk_close(client_endpoint), 0);
        assert_eq!(
            q_periapt_sdk_connection_drain(client, out(&mut output), &mut count),
            Q_PERIAPT_ERR_CLOSED
        );
        assert_eq!((output, count), ([0; 16], 0));
        assert!(
            matches!(owner_registry().get(client), Err(Q_PERIAPT_ERR_CLOSED)),
            "dead engine must release its registry slot"
        );
        assert_eq!(q_periapt_sdk_close(server), 0);
        assert_eq!(q_periapt_sdk_close(runtime), 0);
    }
}

#[test]
fn orderly_close_is_distinct_from_truncated_input_and_returns_capacity() {
    let _guard = TESTS.lock().expect("global budget serialization");
    let runtime = create();
    let (client_endpoint, server_endpoint) = endpoints(runtime);
    let (client, server) = sessions(client_endpoint, server_endpoint);
    drive(client, server).expect("confirmation");
    assert_eq!(q_periapt_sdk_connection_shutdown(client), 0);
    transfer(client, server).expect("close_notify");
    assert!(matches!(progress(client), Err(Q_PERIAPT_ERR_CLOSED)));
    assert!(matches!(progress(server), Err(Q_PERIAPT_ERR_CLOSED)));
    let (client, server) = sessions(client_endpoint, server_endpoint);
    drive(client, server).expect("fresh reconnect");
    assert_eq!(q_periapt_sdk_connection_end_input(client), Q_PERIAPT_ERR_IO);
    assert_eq!(q_periapt_sdk_close(client), Q_PERIAPT_ERR_CLOSED);
    assert_eq!(q_periapt_sdk_close(server), 0);
    assert_eq!(q_periapt_sdk_close(runtime), 0);
}
