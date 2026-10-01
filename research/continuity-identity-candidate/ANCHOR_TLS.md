# Explicit encrypted witness carrier candidate

Status: **native and C implementations under validation, not a frozen product contract**.
Enable `anchor-tls` and use `anchor_tls::AnchorTlsTransport` explicitly. The
existing signed TCP carrier remains a distinct, unencrypted reference path.
Neither transport retries using the other. C/other-language installed interfaces,
independent TLS implementations and deployed-service operation are not yet
qualified for this new carrier.

## Construction and authorization

The carrier uses the SDK's immutable `standard::MutualTlsClient` and
`MutualTlsServer` factories and the already locked rustls 0.23.45. It requires a
full TLS 1.3 handshake with X25519MLKEM768 and ALPN **`q-periapt-anchor/1`**.
TLS 1.2, classic-only key exchange, resumption and early data are disabled.
The driver checks the negotiated version, group, full-handshake status and ALPN
before application bytes. It adds no KDF, signature scheme or alternative witness
state machine. The signed request/reply encodings and `AnchorClient` signature,
challenge, authority and immutable-command checks remain unchanged.

The client independently configures CA roots, server name and exact DER server
leaf pin. The native witness signing identity/public key remain separately pinned
by `AnchorClient`; neither pin is learned from a reply. Those two trusted
configurations must identify the intended witness. The server requires a valid
client certificate and an explicit certificate-to-`AnchorSubject` binding. The
table has 1..256 exact pairs, refuses duplicate pairs and has no wildcard entry.
Each leaf is at most 65,536 bytes and is parsed by the maintained TLS certificate
parser. Operator configuration, not an incoming certificate or request, supplies
the allowed subject. The shared canonical witness decoder checks the incoming
subject against that table before durable image access. The original store then
verifies both device signatures and its original enrollment/state conditions.
TLS membership cannot authorize another enrolled subject, enroll a new journal,
replace a signing key or reset a witness head.

No operational SDK runtime is required for this carrier. That preserves the
ability to contact an independently enrolled witness for reconciliation after SDK
revocation. It creates no application sending or rekey authority. The current
native query test after runtime closure alone is not an installed C cleanup result.
The C consumer now has explicit operational/recovery TLS constructors and a
separate real-process workload: missing key, wrong server name and cross-device
certificate binding refusal; C-to-C bootstrap and message delivery; SDK revocation;
cancelled cleanup; freeze/acknowledgement process exits; and original archive
retirement. Its development execution passed, but the newly extended installed
package collector still requires a fresh source-bound run on both supported Rust
versions. Previous signed-TCP package receipts do not qualify these additions.

## Exact stream and resource contract

Each connection carries one u32 big-endian length plus the 3,674-byte signed
request, followed by the client's TLS `close_notify`. The server requires that
authenticated end marker, with no additional application plaintext, before
accessing the witness store. It responds with one length-prefixed 3,659-byte signed
reply and its own `close_notify`. TLS 1.3 permits this directional closure: receipt
of the peer's end marker does not preclude the remaining response direction.
A missing end marker, truncated frame or additional request is an error; it is
never converted into an empty successful reply. Client admission still verifies
the complete native signed reply.

One caller-selected absolute deadline covers connection, handshake, framing and
reply receipt, with at most 60 seconds remaining at admission. Partial progress
and socket polling do not refresh it. Connected I/O uses at most 25-ms timeouts
and checks the shared one-way cancellation signal between calls. A pending TCP
connect uses the shared nonblocking readiness driver, retaining one socket and
the original deadline. Readiness wakes immediately; waits without events are
limited to 25 ms between cancellation checks, subject to OS scheduling. Each direction admits at most
256 KiB of TLS wire data; rustls outgoing/application buffering is additionally
limited to 16 KiB. These are carrier limits, not a bound on all upstream parser,
certificate/configuration or process memory. The host owns listener admission and
concurrency limits.

Network reads occur without holding the store mutex. Waiting for that mutex polls
cancellation/deadline; a poisoned owner fails rather than exposing its inner state.
Canonical request admission, trusted clock access and native handling run under
the exclusive store owner. Clock, cryptographic and filesystem operations are
synchronous and cannot be preempted. After handling, the mutex is released and
the deadline/cancellation are checked again before writing a response. A failure
after commit withholds acknowledgement but cannot undo the mutation. Clients must
retain the original command and reconcile with a fresh challenge. No arbitrary
global invocation bound or rollback of external effects is promised.

## Security boundaries and validation

TLS hides witness request/reply metadata from an ordinary network observer under
its authentication and confidentiality assumptions. Endpoint addresses, timing and
lengths remain visible; the witness still sees all admitted subject/head metadata.
The witness database format is still authenticated rather than encrypted, and
independent witness-state continuity remains a deployment requirement.

Hybrid key agreement is not post-quantum TLS identity authentication. Certificates
can use classical signatures. Do not claim metadata confidentiality against an
active attacker that can defeat that TLS authentication or holds the pinned TLS
endpoint's credentials. Unchanged dual witness signatures still separately govern
command/reply authenticity; they do not conceal a request already disclosed to a
compromised TLS endpoint. This carrier does not implement an additional PQ channel
authentication protocol, anonymity, padding or traffic-analysis resistance.

The current tests exercise real mutual TLS and native signatures/storage, a
committed advance and exact retry, CA-valid wrong leaf pins, unauthorized client
certificates, another enrolled subject, wrong ALPN, expired/future certificates,
wrong names, a classic-only peer, truncated/pipelined input, host clock failure,
held-handshake and busy-store cancellation/deadlines, and a query after closing
the SDK runtime. A client that disconnects after its authenticated request end
without consuming the committed reply reconciles the exact original advance
with a fresh challenge. A bidirectional TCP relay fragments records and captures ciphertext;
the observed absence of journal tags/subject bytes supplements TLS negotiation
and endpoint checks, not an independent cryptographic secrecy proof.
Certificate renewal, revocation/configuration concurrency, all fault cuts,
installed C/other-language execution, independent endpoints, current-device and
performance evidence remain open. Passing component tests does not close them.

Protocol/library references: [TLS 1.3, including closure alerts](https://www.rfc-editor.org/rfc/rfc8446.html#section-6.1)
and the [pinned rustls connection interface](https://docs.rs/rustls/0.23.45/rustls/enum.Connection.html).
