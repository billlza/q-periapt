# Independent retained-peer renewal and revocation

The independent owner now retains root-authorized remote credential renewal and
monotonic peer rosters in the original session. The canonical identity parser is
shared by bootstrap and renewal verification. A grant binds the original full
identity/key, predecessor and successor credentials/rosters, exact policy and
caller-retained operation. The target checkpoint is supplied independently.
An identical statement re-signed by the root retains the first committed bytes;
another operation, rollback, fork or observed revoked generation is refused.

New snapshots use `QPREFS05`. An actual archived version-four writer supplies the
original session, outbox and retained plaintext. Explicit metadata-only upgrade
at independent test time 210 succeeds after the remote credential expires,
without granting traffic permission. It still requires current local authority,
policy and normal witness admission. Older readers reject the new format; newer
readers retain formats one through four without implicit rewriting.

Four lifecycle profiles pass: local and required-witness owners each run the
ordinary process-cut scenario and the reentrant observer scenario. The ordinary
profiles use 40 fresh-process operations and four real SIGKILL cuts each; the
observer profiles use 39 operations and three cuts each. They cover two chained
grants, original ciphertext/plaintext and operation identities, actual new send
and rekey computations, semantic retries, committed revocation, cached output
denial, historical status and refused generation reappearance. Each ordinary
profile also passes 31 direct negative controls; each observer profile passes 32.
The witnessed profiles retain 230 and 249 signed attempts respectively, all
publicly reverified. Original local authority remains mandatory.

Two real failures in the new implementation were reproduced before correction:

- A protocol observer committed revocation after a send commit, yet 142 bytes of
  ciphertext were returned. The owner now reloads and checks current durable
  peer authority before releasing the result.
- A witness transport callback committed revocation after obtaining a valid
  current-authority reply, yet 150 bytes were returned. An in-process authority
  generation guard now detects changes during final admission and withholds
  that result. The dedicated repaired test verifies 48 genuine signed witness
  replies and five successive image advances, with no returned ciphertext.

Both failing and passing runs remain preserved. These guards do not claim a
future revocation lease or whole-store rollback protection. The first prototype
green report incorrectly hardcoded four kills; its worker records show three.
Final profile counts are computed from actual worker records and verified by
public readback. That prototype report is diagnostic history only.

All thirteen final runtime lanes pass on exactly the same 63-source closure and
the same ARM64 Mach-O counterpart, SHA-256
`85c20de0d6d97e92b0ae49d8598fe2280ca2e517ad9b3a80768ea1f9b7924277`.
Six public readers pass without diagnostics. They recheck original root grants,
native statement digests, target/operation identities, signatures, original
bootstrap/rekey transcripts, native application outputs, worker PIDs and cuts.
The original witnessed lane still passes: 36 workers, three kills, 265 native
commands, 243 loopback attempts plus one direct control, 242 valid signed replies
and 244 distinct challenges. The other ten regression lanes remain passing.

Release build, strict all-target Clippy, rustfmt, workflow lint and 46 source
contract tests pass. The source census is 725 Rust files; no new full CodeQL
database scan is claimed. The first regression pass caught two test controls
that still used version-four byte offsets. Their exact field positions and
version expectation were corrected without weakening rejection checks. Those
failures, an initial native fixture accessor error and two reader adaptation
errors are retained separately from the final passing results.

`CAPTURE.zip` contains all final public lanes, sources, binary, six readers and
outputs, strict checks, selected diagnostic runs and a verified member manifest:
24,802,162 bytes, 7,965 members, SHA-256
`3c8d5999dffa8456d929acf63a02ee399404ddaee0a2403227f30ec5299da9b2`.
It contains no private image or key. Original interrupted private directories and
other development attempts remain local. Public readers do not rederive private
MAC/AEAD values; direct codec, unchanged-head and no-output checks remain runtime
assertions with the stated input/output scope.

The independent peer uses test times 210/310, while the actual native protocol
counterpart remains at its explicit time 170. This validates independent remote
authorization and retained-session interoperability, not the native peer's local
enrollment renewal. Local joint credential/policy/roster transactions, same-account
coordination, complete installed/cross-host lifecycle and construction-wide
security analysis remain open. Metadata consumes explicit business-record capacity
while retaining control headroom; maximum aggregate peer-metadata adoption is not
qualified by this checkpoint. No physical-erasure, power-loss, PCS or complete
0.2.0 release claim follows. Hosted qualification is pending.
