// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Additive ABI 2 transport-independent connection engine. Socket ownership,
//! network cancellation and wakeups remain in the host adapter.
use super::*;
use q_periapt_rustls::connection as transport;

#[cfg(test)]
mod tests;

/// TLS certificate/key/handshake authentication failure.
pub const Q_PERIAPT_ERR_TLS: i32 = -14;
/// Absolute connection phase deadline elapsed.
pub const Q_PERIAPT_ERR_TIMEOUT: i32 = -15;
/// Invalid ALPN, application confirmation, frame or sequence.
pub const Q_PERIAPT_ERR_PROTOCOL: i32 = -16;
/// Operation is not valid yet; a live connection is retained.
pub const Q_PERIAPT_ERR_NOT_READY: i32 = -17;
/// TLS input EOF/truncation or underlying I/O error.
pub const Q_PERIAPT_ERR_IO: i32 = -18;
/// Maximum application request/response bytes.
pub const Q_PERIAPT_CONNECTION_MAX_PAYLOAD_BYTES: usize = 65_536;
/// Maximum encrypted input/output bytes per synchronous call.
pub const Q_PERIAPT_CONNECTION_MAX_TLS_IO_BYTES: usize = 16_384;
/// TLS authentication in progress.
pub const Q_PERIAPT_CONNECTION_HANDSHAKING: u32 = 1;
/// TLS complete; application policy confirmation still pending.
pub const Q_PERIAPT_CONNECTION_CONFIRMING: u32 = 2;
/// Confirmed and ready for one request.
pub const Q_PERIAPT_CONNECTION_READY: u32 = 3;
/// Client waits for its response.
pub const Q_PERIAPT_CONNECTION_REQUEST_PENDING: u32 = 4;
/// Server has a request available.
pub const Q_PERIAPT_CONNECTION_REQUEST_READY: u32 = 5;
/// Server application is handling the request.
pub const Q_PERIAPT_CONNECTION_HANDLING_REQUEST: u32 = 6;
/// Client has a response available.
pub const Q_PERIAPT_CONNECTION_RESPONSE_READY: u32 = 7;
/// Drain an orderly local TLS close before releasing the transport.
pub const Q_PERIAPT_CONNECTION_CLOSING: u32 = 8;

/// Explicit TLS identity/pin and bounded connection settings. This chooses
/// standard TLS; the referenced SDK policy is confirmed as application metadata.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QPeriaptConnectionOptions {
    /// Exact sizeof this initialized structure.
    pub struct_size: u32,
    /// Must equal Q_PERIAPT_SDK_EXTENSION_VERSION.
    pub extension_version: u32,
    /// Local leaf certificate in DER, 1..=65536 bytes.
    pub certificate: QPeriaptInput,
    /// Local private key in DER, 1..=16384 bytes; caller protects/erases its copy.
    pub private_key: QPeriaptInput,
    /// Exact trusted peer leaf certificate in DER, 1..=65536 bytes. No TOFU.
    pub peer_certificate: QPeriaptInput,
    /// Application association bytes, at most 65536; peer must match the commitment.
    pub application_context: QPeriaptInput,
    /// Live connections for this endpoint, 1..=64.
    pub max_connections: u32,
    /// Entire handshake and confirmation budget, 1..=120000 ms.
    pub handshake_ms: u32,
    /// Outstanding request/response budget, 1..=120000 ms.
    pub request_ms: u32,
    /// Idle budget, 1..=300000 ms.
    pub idle_ms: u32,
}
/// Progress is descriptive, never authorization or a lease across close.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QPeriaptConnectionProgress {
    /// One of Q_PERIAPT_CONNECTION_* phase codes.
    pub phase: u32,
    /// Exactly 0 or 1; drain pending encrypted bytes before waiting for input.
    pub wants_write: u32,
    /// Adapter must wake and recheck by this many milliseconds, even without I/O.
    pub remaining_ms: u32,
}

fn map(error: transport::Error) -> i32 {
    match error {
        transport::Error::Closed => Q_PERIAPT_ERR_CLOSED,
        transport::Error::InvalidLength => Q_PERIAPT_ERR_LENGTH,
        transport::Error::InvalidOptions => Q_PERIAPT_ERR_LIMITS,
        transport::Error::ResourceLimit => Q_PERIAPT_ERR_RESOURCE_LIMIT,
        transport::Error::NotReady => Q_PERIAPT_ERR_NOT_READY,
        transport::Error::Timeout => Q_PERIAPT_ERR_TIMEOUT,
        transport::Error::Entropy => Q_PERIAPT_ERR_ENTROPY,
        transport::Error::PeerIdentity
        | transport::Error::Configuration(_)
        | transport::Error::Tls(_) => Q_PERIAPT_ERR_TLS,
        transport::Error::PolicyMismatch => Q_PERIAPT_ERR_POLICY,
        transport::Error::BindingMismatch | transport::Error::Protocol => Q_PERIAPT_ERR_PROTOCOL,
        transport::Error::Policy(error) => map_error(error),
        transport::Error::Io(_) => Q_PERIAPT_ERR_IO,
    }
}
fn scalar(out: *mut u32) -> QPeriaptOutput {
    QPeriaptOutput {
        data: out.cast(),
        len: 4,
    }
}
fn endpoint(handle: u64) -> StatusResult<(Arc<transport::Endpoint>, u64)> {
    let (Object::Endpoint(endpoint), parent) = owner_registry().get(handle)? else {
        return Err(Q_PERIAPT_ERR_CLOSED);
    };
    Ok((endpoint, parent))
}
fn with_connection<T>(
    handle: u64,
    operation: impl FnOnce(&mut transport::Connection) -> StatusResult<T>,
) -> StatusResult<T> {
    let Object::Connection(owner) = owner_registry().get(handle)?.0 else {
        return Err(Q_PERIAPT_ERR_CLOSED);
    };
    let mut connection = owner.write().map_err(|_| Q_PERIAPT_ERR_INTERNAL)?;
    let result = operation(&mut connection);
    let closed = connection.is_closed();
    drop(connection);
    if closed {
        // Failed sessions are not retained as dead registry entries. Disposal
        // happens after releasing our borrow, including simultaneous parent close.
        match owner_registry().close(handle) {
            Ok(()) | Err(Q_PERIAPT_ERR_CLOSED) => {}
            Err(error) => return Err(error),
        }
    }
    result
}

unsafe fn endpoint_new(
    handle: u64,
    options: *const QPeriaptConnectionOptions,
    out_endpoint: *mut u64,
    client: bool,
) -> i32 {
    // SAFETY: the public constructor requires the staged readable prefix.
    if let Err(error) =
        unsafe { validate_options_prefix(options.cast(), size_of::<QPeriaptConnectionOptions>()) }
    {
        return error;
    }
    // SAFETY: the caller supplies a complete initialized configuration.
    let config = unsafe { options.read_unaligned() };
    let header = QPeriaptInput {
        data: options.cast(),
        len: size_of::<QPeriaptConnectionOptions>(),
    };
    let output = handle_output(out_endpoint);
    // SAFETY: every option input/output obeys the caller's validity/lifetime contract.
    unsafe {
        execute(
            [
                input(header, header.len, header.len),
                input(config.certificate, 1, transport::MAX_CERTIFICATE_BYTES),
                input(config.private_key, 1, transport::MAX_PRIVATE_KEY_BYTES),
                input(config.peer_certificate, 1, transport::MAX_CERTIFICATE_BYTES),
                input(config.application_context, 0, 65_536),
            ],
            [(output, 8)],
            || {
                let runtime = runtime(handle)?;
                let mut slot = owner_registry().reserve(handle)?;
                let credentials = transport::Credentials {
                    certificate: read(config.certificate)?,
                    private_key: read(config.private_key)?,
                    peer_certificate: read(config.peer_certificate)?,
                };
                let limits = transport::Limits {
                    max_connections: config.max_connections as usize,
                    handshake_ms: config.handshake_ms,
                    request_ms: config.request_ms,
                    idle_ms: config.idle_ms,
                };
                let context = read(config.application_context)?;
                let endpoint = if client {
                    transport::Endpoint::client(runtime, credentials, context, limits)
                } else {
                    transport::Endpoint::server(runtime, credentials, context, limits)
                }
                .map_err(map)?;
                slot.install(Object::Endpoint(Arc::new(endpoint)))?;
                write(output, &slot.id().to_ne_bytes())?;
                slot.publish()
            },
        )
    }
}

/// Construct an explicitly standard-TLS client endpoint under a verified runtime.
/// # Safety
/// Options initially provides four readable immutable bytes (struct_size).
/// Matching size requires the eight-byte size/revision prefix; matching revision
/// requires the complete initialized structure and readable immutable inputs.
/// Unsupported size/revision returns LIMITS with output untouched. out_endpoint
/// is writable for eight bytes and disjoint from every accepted input/options object.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_client_new(
    handle: u64,
    options: *const QPeriaptConnectionOptions,
    out_endpoint: *mut u64,
) -> i32 {
    // SAFETY: this wrapper retains the common constructor's public contract.
    unsafe { endpoint_new(handle, options, out_endpoint, true) }
}
/// Construct a server endpoint requiring the explicit client certificate pin.
/// # Safety
/// Same staged options prefix and disjoint input/output contract as connection_client_new.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_server_new(
    handle: u64,
    options: *const QPeriaptConnectionOptions,
    out_endpoint: *mut u64,
) -> i32 {
    // SAFETY: this wrapper retains the common constructor's public contract.
    unsafe { endpoint_new(handle, options, out_endpoint, false) }
}
/// Start a fresh client TLS engine; server_name is UTF-8 (1..=253 bytes). No socket I/O.
/// # Safety
/// server_name is readable/immutable; out_connection is writable for eight disjoint bytes.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_connect(
    handle: u64,
    server_name: QPeriaptInput,
    out_connection: *mut u64,
) -> i32 {
    let output = handle_output(out_connection);
    // SAFETY: execute validates the disjoint I/O shapes before construction.
    unsafe {
        execute([input(server_name, 1, 253)], [(output, 8)], || {
            let (endpoint, parent) = endpoint(handle)?;
            let mut slot = owner_registry().reserve(parent)?;
            let name = std::str::from_utf8(read(server_name)?).map_err(|_| Q_PERIAPT_ERR_LIMITS)?;
            let connection = endpoint.connect(name).map_err(map)?;
            slot.install(Object::Connection(Arc::new(RwLock::new(connection))))?;
            write(output, &slot.id().to_ne_bytes())?;
            slot.publish()
        })
    }
}
/// Start a fresh server TLS engine; socket accept/read belongs to the adapter.
/// # Safety
/// out_connection is writable for eight bytes.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_accept(
    handle: u64,
    out_connection: *mut u64,
) -> i32 {
    let output = handle_output(out_connection);
    // SAFETY: complete writable output is the caller's contract.
    unsafe {
        execute([], [(output, 8)], || {
            let (endpoint, parent) = endpoint(handle)?;
            let mut slot = owner_registry().reserve(parent)?;
            slot.install(Object::Connection(Arc::new(RwLock::new(
                endpoint.accept().map_err(map)?,
            ))))?;
            write(output, &slot.id().to_ne_bytes())?;
            slot.publish()
        })
    }
}
/// Read progress and enforce deadline/revocation. Fatal sessions release their handle.
/// # Safety
/// output is writable for the complete QPeriaptConnectionProgress structure.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_progress(
    handle: u64,
    output: *mut QPeriaptConnectionProgress,
) -> i32 {
    let span = QPeriaptOutput {
        data: output.cast(),
        len: size_of::<QPeriaptConnectionProgress>(),
    };
    // SAFETY: the caller supplies the complete writable progress output.
    unsafe {
        execute(
            [],
            [(span, size_of::<QPeriaptConnectionProgress>())],
            || {
                with_connection(handle, |connection| {
                    let progress = connection.progress().map_err(map)?;
                    output.write_unaligned(QPeriaptConnectionProgress {
                        phase: progress.phase as u32,
                        wants_write: u32::from(progress.wants_write),
                        remaining_ms: progress.remaining_ms,
                    });
                    Ok(())
                })
            },
        )
    }
}
/// Feed 1..=16384 encrypted bytes; reoffer only an unconsumed suffix on success.
/// # Safety
/// Input is readable/immutable and out_consumed is writable for four disjoint bytes.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_feed(
    handle: u64,
    ciphertext: QPeriaptInput,
    out_consumed: *mut u32,
) -> i32 {
    let output = scalar(out_consumed);
    // SAFETY: validated disjoint inputs/output stay live through this call.
    unsafe {
        execute(
            [input(ciphertext, 1, transport::MAX_TLS_IO_BYTES)],
            [(output, 4)],
            || {
                with_connection(handle, |connection| {
                    let consumed = connection.feed_tls(read(ciphertext)?).map_err(map)?;
                    write(output, &(consumed as u32).to_ne_bytes())
                })
            },
        )
    }
}
/// Drain encrypted bytes into capacity 1..=16384. Unused output bytes are zeroed.
/// # Safety
/// Output and out_written (four bytes) are writable and disjoint for the call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_drain(
    handle: u64,
    output: QPeriaptOutput,
    out_written: *mut u32,
) -> i32 {
    if !(1..=transport::MAX_TLS_IO_BYTES).contains(&output.len) {
        return Q_PERIAPT_ERR_LENGTH;
    }
    let written = scalar(out_written);
    // SAFETY: every output region is writable/disjoint; execute preflights before use.
    unsafe {
        execute([], [(output, output.len), (written, 4)], || {
            with_connection(handle, |connection| {
                let bytes = std::slice::from_raw_parts_mut(output.data, output.len);
                let count = connection.drain_tls(bytes).map_err(map)?;
                write(written, &(count as u32).to_ne_bytes())
            })
        })
    }
}
/// Report transport EOF. Truncation is an error; no empty successful response is fabricated.
#[no_mangle]
pub extern "C" fn q_periapt_sdk_connection_end_input(handle: u64) -> i32 {
    // SAFETY: this entry point has no borrowed buffers.
    unsafe {
        execute([], [], || {
            with_connection(handle, |connection| connection.end_of_input().map_err(map))
        })
    }
}
/// Queue one request (0..=65536 bytes); no retry/durable-execution guarantee.
/// # Safety
/// Payload is readable/immutable; out_request_id is writable for eight disjoint bytes.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_send_request(
    handle: u64,
    payload: QPeriaptInput,
    out_request_id: *mut u64,
) -> i32 {
    let output = handle_output(out_request_id);
    // SAFETY: all borrowed regions obey the public disjoint lifetime contract.
    unsafe {
        execute(
            [input(payload, 0, transport::MAX_PAYLOAD_BYTES)],
            [(output, 8)],
            || {
                with_connection(handle, |connection| {
                    let id = connection.send_request(read(payload)?).map_err(map)?;
                    write(output, &id.to_ne_bytes())
                })
            },
        )
    }
}
/// Query a pending request/response size. This snapshot does not consume it.
/// # Safety
/// out_length is writable for four bytes.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_message_size(
    handle: u64,
    out_length: *mut u32,
) -> i32 {
    let output = scalar(out_length);
    // SAFETY: valid scalar output is supplied by the caller.
    unsafe {
        execute([], [(output, 4)], || {
            with_connection(handle, |connection| {
                write(
                    output,
                    &(connection.pending_message_size().map_err(map)? as u32).to_ne_bytes(),
                )
            })
        })
    }
}
unsafe fn take_message(
    handle: u64,
    output: QPeriaptOutput,
    out_length: *mut u32,
    out_request_id: *mut u64,
    request: bool,
) -> i32 {
    if !(1..=transport::MAX_PAYLOAD_BYTES).contains(&output.len) {
        return Q_PERIAPT_ERR_LENGTH;
    }
    let length = scalar(out_length);
    let id = handle_output(out_request_id);
    // SAFETY: the wrapper's output validity and disjointness contract applies.
    unsafe {
        execute([], [(output, output.len), (length, 4), (id, 8)], || {
            with_connection(handle, |connection| {
                if connection.pending_message_size().map_err(map)? > output.len {
                    return Err(Q_PERIAPT_ERR_LENGTH);
                }
                let message = if request {
                    connection.take_request()
                } else {
                    connection.take_response()
                }
                .map_err(map)?;
                let bytes = std::slice::from_raw_parts_mut(output.data, output.len);
                bytes
                    .get_mut(..message.bytes().len())
                    .ok_or(Q_PERIAPT_ERR_INTERNAL)?
                    .copy_from_slice(message.bytes());
                write(length, &(message.bytes().len() as u32).to_ne_bytes())?;
                write(id, &message.request_id().to_ne_bytes())
            })
        })
    }
}
/// Take a server request into capacity 1..=65536. Too-small capacity retains the message.
/// # Safety
/// Output, out_length (four bytes), out_request_id (eight bytes) are writable/disjoint.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_take_request(
    handle: u64,
    output: QPeriaptOutput,
    out_length: *mut u32,
    out_request_id: *mut u64,
) -> i32 {
    // SAFETY: the same complete output contract is forwarded to take_message.
    unsafe { take_message(handle, output, out_length, out_request_id, true) }
}
/// Take a matching client response; capacity must be at least max(1, message_size).
/// # Safety
/// Output, out_length (four bytes), out_request_id (eight bytes) are writable/disjoint.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_take_response(
    handle: u64,
    output: QPeriaptOutput,
    out_length: *mut u32,
    out_request_id: *mut u64,
) -> i32 {
    // SAFETY: the same complete output contract is forwarded to take_message.
    unsafe { take_message(handle, output, out_length, out_request_id, false) }
}
/// Respond to the single server request using its exact connection-local ID.
/// # Safety
/// Payload is readable and immutable for 0..=65536 bytes throughout the call.
#[no_mangle]
pub unsafe extern "C" fn q_periapt_sdk_connection_send_response(
    handle: u64,
    request_id: u64,
    payload: QPeriaptInput,
) -> i32 {
    // SAFETY: payload validity is the caller's contract.
    unsafe {
        execute(
            [input(payload, 0, transport::MAX_PAYLOAD_BYTES)],
            [],
            || {
                with_connection(handle, |connection| {
                    connection
                        .send_response(request_id, read(payload)?)
                        .map_err(map)
                })
            },
        )
    }
}
/// Queue orderly TLS close after a completed exchange. Drain until Closed, then
/// close the socket. Immediate cancellation instead uses q_periapt_sdk_close.
#[no_mangle]
pub extern "C" fn q_periapt_sdk_connection_shutdown(handle: u64) -> i32 {
    // SAFETY: no borrowed buffers.
    unsafe {
        execute([], [], || {
            with_connection(handle, |connection| connection.shutdown().map_err(map))
        })
    }
}
