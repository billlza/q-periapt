# Installed browser and native bidirectional recovery

The installed browser SDK now has a real receiving-side qualification alongside
the retained outgoing path. The same native installation sends through its
existing `q-periapt-native-outgoing` process and TCP carrier. A bounded loopback
HTTP bridge passes the actual ciphertext to the public browser
`serve_session_message` method and returns its actual reply.

The host consumer uses a separate IndexedDB database. A transaction requested
with `durability: strict` commits the business record and its deduplication key
together. The key contains the original session and message identifiers; a
repeated identifier must have identical plaintext. This is a concrete database
effect, not an atomicity claim for arbitrary external actions or power loss.

After the second business record commits, the callback posts an observed cut
and remains unresolved. The parent terminates that Worker and observes the
original storage lease reaching zero. No SDK response exists at this cut. The
native sender receives a real `UnexpectedEof`, exits 1 and retains `Committed`.
A new Worker reopens the original journal and session. The native sender replays
identical request bytes; the consumer is called again, finds the same durable
record and increments only its callback count. The SDK reply then changes the
sender to `Acknowledged`. A subsequent distinct message also succeeds.

The original forward qualification still executes: three browser-to-native
messages, epoch-1 rekey, a real lost ACK, native SIGKILL and a new native service
process, followed by exact recovery. The reverse path adds three native-to-browser
messages and one exact retry. Together the receipt has eight forward exchanges,
four reverse exchanges, 28 ordinary zero-exit runtime commands and one deliberate
transport failure. All 58 command streams, actual request/reply bytes and three
native inbox effects are retained. Three browser business records remain; the
interrupted one records two callback invocations and one application effect.

The complete run passed in 26.737 seconds. Its 270 source inputs, installed package
web payloads, provider files, native binaries and execution tools are hashed
before and after execution. The installed WASM archive is
`06b13752dd172c6629e62c2251b99ff6174043713a2d8966014686d5f1169ed3`.
The native executables are built from the repository and share the session engine
with the browser. Fresh isolated test credentials and the local policy profile
are used. This does not qualify real-user Passkey authorization, required-Witness
operation, an independently implemented session peer, an installed native SDK,
whole-browser-process loss, mobile devices, power loss or multi-epoch PCS.

`CAPTURE.zip` contains 115 files: public receipts and wire captures, the public
test inputs and the exact producer sources needed to inspect this experiment.
It contains no private authority material, installation database or wrapping key.
Its SHA-256 is
`bd99fe191e510b48a83a9a63d9dd3bc24e2930996828ea46ed0f51cccac4fd21`.
`CAPTURE.json` enumerates every file; `READBACK.json` records full byte comparison
and semantic verification. The actual receipt supplies mutation regressions for
fabricated ACKs, replaced requests, duplicate effects, omitted callback retries,
unreleased leases and relabelled transport failure.
