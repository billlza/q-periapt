# Installed browser and native session recovery

The actual installed npm browser SDK completed enrollment, activation, session
establishment, application delivery, one rekey, and original delivery recovery
against the existing native reference service. The final qualifier run took
19.262 seconds, including its cached native build. No product cryptography or
storage contract was changed.

The browser used the public `QPeriaptContinuityDevice` API in a real Chrome Worker
with IndexedDB/OPFS storage. The native peer was built from the repository by the
qualifier. A fresh isolated test issuer used the existing independent Python
reference issuer and cryptography 48.0.1. This does not represent a real account
login or an independent session implementation.

## What actually ran

- Eight actual HTTP-to-TCP protocol exchanges: handshake INITIAL and FINAL,
  epoch-zero application delivery, two rekey exchanges, an epoch-one delivery
  whose real native ACK was withheld, its exact retry, and a new delivery.
- The transport failure closed the browser owner with `PeerTransport`. The
  browser Worker was then terminated and its original storage lease was observed
  released. The native service process was killed with SIGKILL, exit `-9`, and a
  new PID reopened the original native installation, inbox, wrapping key and
  trust configuration.
- A new Worker reopened the original browser journal and session. The retained
  message was `Committed`, not presumed delivered. Retrying its original ID and
  input produced exactly the same request and ACK bytes, then `Acknowledged`.
- Both sending and receiving epochs remained 1. The original native inbox
  returned all three expected application plaintexts. The restarted native
  service completed two real responses without operation errors.
- 267 producer source inputs, 104 provider files, all served installed package
  members, native binaries, and Node/CLI inputs were checked before and after.
  Sixteen ordinary runtime commands exited zero, with all 32 streams retained.
  The native build and both service process streams are also retained.

The npm archive is the exact 716 product, SHA-256
`06b13752dd172c6629e62c2251b99ff6174043713a2d8966014686d5f1169ed3`.
Its source binding is rechecked against the current consumer checkout. The new
qualifier builds the existing native counterpart rather than executing a CI
archive. The final source input hashes are in the report inside `CAPTURE.zip`.

## Reproduce

Build/install the SDK with `artifact/wasm_sdk_package.py`, retain the external npm
installation receipt, and use the pinned Playwright CLI 0.1.22. Install the
hash-pinned provider from `research/continuity-openssl-peer/requirements.txt` into
an isolated directory. Then run the following with explicit local paths:

```sh
sh artifact/python-run.sh artifact/continuity_browser_session.py \
  --receipt /absolute/INSTALLED_CONSUMER.json \
  --output /absolute/fresh-result \
  --native-target /absolute/private-native-build-cache \
  --provider-root /absolute/isolated-provider \
  --node /absolute/node \
  --cli /absolute/playwright-cli.js
```

The issuer's private keys and native installation stay in a fresh private
temporary directory outside served and archived outputs. Only the isolated test
application plaintexts are retained as native effect readback. Original user
devices, accounts and stores are not involved.

`CAPTURE.json` binds every member of the 99-member ZIP. `READBACK.json` records
byte equality and semantic readback. Mutation tests reject replacement journals
or sessions, invented ACK completion, graceful close in place of SIGKILL, altered
wire bytes, missing commands and incorrect native effects. Earlier harness input
and template errors are retained under `controls/` and explained in the manifest.
They are not SDK defects or successful runs.

## Remaining boundaries

This is a local-policy profile and one application direction over explicit
loopback HTTP/TCP. It does not establish required-witness recovery, reverse
application delivery, credential/policy expiry and renewal, revocation, device
replacement, upgrades, physical power loss, mobile execution, deployed TLS, PCS,
formal ABI admission or release readiness. The existing multi-epoch proof and
full 0.2.0 goal remain open. The CI step is prepared locally and has not yet run
on the new source; the active 785 wave predates this qualifier.
