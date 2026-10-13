# Browser activation with a required witness

The shared candidate now offers `AnchorFetchTransport` on WebAssembly. It sends
the existing signed request through Fetch, requires a bounded reply, and leaves
all pin, challenge, command and signature verification to the existing client.
HTTPS is the default admission rule; numeric loopback HTTP has an explicit
diagnostic constructor. Credentials, redirects and automatic retries are disabled.
Cancellation and timeout do not establish non-commit. Dropping a polled Rust
exchange aborts Fetch and detaches its JavaScript callback before freeing it.
Browser scheduling may delay timer delivery; a late reply cannot become success.

The final Chromium run passed eight scenarios with 290 actual witness requests:
normal activation; cancellation before dispatch; a wrong independent witness pin;
a dropped reply, timeout and cancellation after a real witness commit; a damaged
reply signature; and an oversized reply. The last two are refused respectively
as `Anchor(Verification(Authentication))` and transport `InvalidData`. Pre-dispatch
cancellation and the wrong pin sent no request. Each case subsequently reopened
the original journal and its 1,184-byte SDK prekey. Retrying explicit enrollment
with the original genesis preserved the already advanced witness head.

Each scenario generates its device identity in the browser. A fresh native issuer
verifies the actual enrollment request and returns signed credentials and public
trust inputs. A separate persistent native witness authenticates each request;
its owner is closed and reopened for every exchange. The captured authenticated
head readbacks show revisions 1 → 2 → 3 with the same fence, including the three
lost-response cases. Their faults occur after an actual revision commit, not
after a fabricated success or merely a writer-fence change. All later head
readbacks form a continuous chain. The server refuses ambient credentials, and
the browser was given a witness-path cookie as a negative control.

Additional real-browser checks cover ten URL admission cases, HTTP 503 status
preservation, redirect refusal, short and oversized streaming bodies, and dropping
an already polled Rust carrier future without invoking a released callback.
The dropped-future check qualifies resource cleanup; it makes no claim about
whether its aborted request reached the server. Native and WASM Clippy with
warnings denied, Rust formatting, JavaScript syntax, and 13 relevant artifact
tests also passed. The canonical browser staging script includes the new host
module beside the generated glue.

The capture retains the initial failures rather than counting them as acceptance:
the first generated glue imported the Rust type name `Exchange`, which did not
match the JavaScript export; the shared carrier now uses `WitnessExchange`
consistently. One native diagnostic indexed entries by journal ID instead of
their bound subject ID and was corrected to require the unique journal entry.
Two later harness failures were an incorrect expected error-enum name and a
whitespace-sensitive CLI-result check. The final harness parses structured JSON.
These latter three were diagnostic/driver errors, not product recovery failures.

`CAPTURE.zip` has 4,184 members and SHA-256
`2dd8c2ff5de6bfc37b1eaf1cd2f0e90ece4309545d1150dc25c985ef01196068`.
It retains public trust inputs, requests/replies, head readbacks, exact source and
adapter inputs, generated WASM/host modules, commands and reports. Private
authorities, wrapping keys, witness databases and browser secret state are
excluded. `CHECKS.json` identifies the inputs and results. Main's timer rustdoc
was clarified after testing; the carrier implementation is unchanged from the
captured test source. The isolated adapter adds public-input lifecycle exports
and native diagnostic readbacks; it is not the final product browser API.

This qualifies the signed protocol and recovery over loopback HTTP, not deployed
HTTPS, independent-implementation interoperability or installed browser packages.
The browser and native endpoint use the same protocol implementation. Final
product ownership/bindings, complete browser session/root/roster lifecycle,
migrations and full release qualification remain open. These tests also do not
establish resistance to whole-profile rollback, malicious same-origin code,
cryptographic erasure or native power-loss equivalence. The separate installed
Rust/C/Swift producer and hosted CI retain their own source identities and gates.
