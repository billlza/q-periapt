# Explicit TCP reference connection

The native service and independent Python carrier transport the existing
`QPCXCH01` operations over real TCP. Each connection carries a four-byte big-endian
length, one unchanged request frame, then the same framing for its response.
Frames must contain 10 through 32768 bytes. No new cryptographic message or stored
session format is introduced. The original owners authenticate bootstrap,
application messages, consumption acknowledgements and rekey controls.

This explicit carrier exposes public protocol metadata. It provides no TLS server
authentication or traffic confidentiality beyond the inner protocol. It is not
the distinct `QPCNET01` TLS carrier and is never selected as a fallback from TLS.
The reference profile supports Apple Silicon macOS and Linux x86_64.

## Native receiver

```sh
q-periapt-native-session serve /absolute/path/to/service.json
```

Use schema `qperiapt-native-service/1`, a numeric `listen` address such as
`127.0.0.1:8088`, the absolute original `inbox` path, and the same
`device_directory`, `wrapping_key`, `invitation`, `current_root`, `policy_pins`,
`policy_materials`, `witness_endpoint`, `peer_trust` and `bundle` inputs as
[native session exchange](NATIVE_SESSION.md). The device and inbox must already
exist. Startup checks those original inputs; no missing state is created.

The service handles one independently configured peer context. Frame metadata
routes bootstrap or an original session; it cannot select roots, trust settings,
storage paths or policy. Every complete operation reopens and checks the current
configured inputs and uses the SDK's existing owners. It releases the owner after
the operation. Do not rewrite configuration files from incoming requests.

The first stdout JSON line reports `Listening`, `QPCXCH01/TCP`, and the actual
address (port zero selects an ephemeral port). SIGINT cancels outstanding work,
joins its actual workers and emits a `Stopped` line with service counters. A
completed response counter is an I/O observation, not authenticated consumption
by a peer. Errors close that request without fabricating a successful response;
the stop receipt reports operation errors without private payloads.

## Native and independent senders

[Native outgoing operations](NATIVE_OUTGOING.md) accept explicit TCP actions:

```json
{"operation":"rekey_tcp","target":2,"exchanges":4,"address":"127.0.0.1:8088"}
```

Select the original target for the intended rekey. `deliver_tcp` takes `message`
(the exact 32-byte ID returned by `next`), `plaintext`, `associated_data` and
`address`. The same plaintext,
associated-data and explicit-target bounds apply as for file transport. A failed
or missing response leaves the original operation potentially committed. Reopen
that owner and retry the original ID/input or target, without replacing its store.

The independent package exposes `network.TcpTransport((numeric_ip, port))` as the
carrier for `EnrollmentClient.connect`, `Connection.deliver`, `resume` and `rekey`.
It makes one connection attempt per exchange, with no DNS or implicit retry.
Its original absolute deadline and cancellation apply throughout connect and
partial frame I/O. Connection establishment is additionally capped at five seconds.

For incoming traffic, `network_server.Server(address, handler)` invokes
`handler(frame, run)`. Route using `connection_wire.request_route`; this is
unauthenticated metadata only. Open the separately configured original client,
reopen its confirmed connection, and call `serve_message` or `serve_control`
within the supplied `Run`. Close the owner in `finally`. The message consumer must
durably commit its effect and deduplication together, as described in the
[independent client contract](../continuity-openssl-peer/ENROLLMENT_CLIENT.md).

## Admission, shutdown and concurrency

Defaults allow eight incomplete reads, at most two per source IP, a two-second
read deadline, and a thirty-second acceptance-to-response deadline. Oldest
incomplete reads are evicted at capacity; these reads hold no SDK leases.
At most one complete owner operation or response writer executes. Additional
complete requests close as busy; the sender must treat the result as unknown and
reconcile its original operation. Source-IP limits are resource controls, not
identity or protection against sustained authenticated or distributed flooding.

Both servers retain the original acceptance deadline; later work does not obtain
a fresh timeout. The independent server's `close()` requests shutdown and its
`serve()` call joins the worker. The Rust API requires cancelling its token and
awaiting the service future; aborting/dropping that future cannot join a blocking
callback. Host callbacks and filesystem work must bound their own I/O. Neither
runtime can forcibly interrupt arbitrary synchronous host code safely.

The original single-writer owners serialize whole operations, including outgoing
I/O. Simultaneous opposite-direction operations can therefore encounter a busy
owner or an unknown result. Local bidirectional **sequential** operations are
qualified; simultaneous full-duplex operation admission is not established.

## Evidence and open boundaries

The installed qualification runs a fresh real-time bootstrap, an original service
and client reopen, eight idle sockets followed by admitted delivery, actual reply
loss and byte-identical retry in both directions, and one rekey initiated by each
implementation. It retains native process exit receipts, request/response hashes
and transactional effect readback. Separate echo-frame tests check transport
resources, IPv4/IPv6, cancellation and shutdown; those are not cryptographic tests.

These are local TCP process observations under explicit test authority. They do
not establish cross-host installation, TLS deployment, physical power-loss
durability, simultaneous application traffic, expiry recovery of unconfirmed
bootstrap, or the original real account's complete lifecycle.
