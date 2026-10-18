# Local lifecycle allocation and full-store renewal

This checkpoint addresses an observed availability failure in the independent
reference: a valid same-key grant could not renew a full business store after
the original credential expired. Version seven charged new identity metadata
against already accepted traffic; ordinary cleanup correctly required current
authority. The [updated contract](../../../continuity-openssl-peer/LOCAL_CREDENTIAL.md)
uses an explicit version-eight allocation without changing those permissions.

`QPREFS08` preserves the existing 2,031,616-byte business cap and 64-KiB control
reservation. It permits at most 213,291 additional bytes exclusively for actual
bounded identity/coordination metadata, for a 2,310,443-byte plaintext image.
Raw journals, required-witness journals and all old schema limits remain. The
same journal transaction engine and cryptographic domains are reused; no second
publication or recovery implementation was introduced.

The before/after probe retains the original private store and native endpoint.
Its 123 outboxes fill all 2,031,616 business bytes. At time 210, the original
credential (ending at 200) denies ordinary output and the old coordinator refuses
the valid renewal. After the repair, fresh independent workers stage and commit
two original root grants in that same store, including three real process cuts.
The earliest and latest original ciphertexts remain unchanged and the native
peer decrypts both. The second Pending head is 2,117,244 bytes, crossing the old
physical image ceiling. No outbox was cleared or assigned a synthetic outcome.

The final capacity regression independently fills another original store to the
same exact limit. All encoded epoch hashes and all 123 outboxes remain identical
across both renewals. An extra business send is refused even with unused lifecycle
space. Its nine direct controls check legacy metadata charging, raw/local journal
bounds, aggregate/file bounds and refusal to relabel a large image as version
seven. This profile uses thirteen worker operations, three SIGKILL cuts and seven
native commands.

An actual archived `73b97e77` writer creates version-seven Pending. Current code
recovers and commits that original operation in seven; the next explicit grant
selects eight. The old reader refuses eight, and the native endpoint accepts the
unchanged original message. This profile uses fourteen worker operations, two
kills, four native commands and one direct refusal. Existing four local renewal
profiles add 148 workers and 29 kills, covering expiry, floors, revocation guards,
combined metadata, cancellation and original send/rekey continuity.

The first capacity entrypoint invocation passed its full-store profile, then
failed in archived-test construction: dataclass equality correctly distinguished
archived and current public-key types. The repair reconstructs pins from the
original bytes and reauthenticates all materials with the archived verifier; it
does not alter equality or weaken identity checks. Only the affected entrypoint
was rerun, and both profiles passed. The original failed private store was also
continued through seven to eight with eight fresh worker operations and unchanged
ciphertext. Its native endpoint had already exited during failed-test cleanup;
that continuation does not claim resumed native decryption or full native restart.

All sixteen final runtime entries and nine public readers pass. The original
failed invocation remains in `QUALIFIED_RUNS.json`; `FINAL_RUNS.json` identifies
the completed replacement execution for the capacity entrypoint. Exact source
provenance covers 78 files. Only `local_budget_controls.py` changed after the
first run, in archived-test construction; its inventory/bound checks and all
other 77 files are identical. The other fifteen entrypoints do not import that
helper and were not rerun. Both executed and final helper hashes are retained.

Python AST and current diff checks pass. Native/provider/workflow bytes are
identical to the committed `73b97e77` qualification, so its strict native
build/Clippy/format and actionlint receipts remain applicable without another run.
The Rust census remains 725. The actual native ARM64 executable SHA-256 remains
`313f303482a37c23a4de278fe408fff19c0e1cce1ebd6a80d6651cdcc9ce8513`.

`CAPTURE.zip` is 32,601,392 bytes with 10,589 members, SHA-256
`d714a79c00d8e9e7e19a033ea349ac02c4b39425b2bf2e62a76e11cbd0f60dd7`.
It retains public transcripts, original failures/continuations, baseline and
final sources, the native executable, nine readers and verified manifest.
Private journals, intents, authority files, signer material and wrapping keys
remain outside the archive. Public readers verify signatures, original IDs,
exact messages, signed rekey and process markers. Private inventory equality,
file lengths, exact target preservation and cancellation remain runtime assertions,
not independent private MAC/AEAD rederivation.

This resolves the tested local-only business-capacity case. Physical disk or
directory quota exhaustion still fails explicitly. Native traffic uses time 170;
independent calls exercise signed expiry at 210/250/310/401. Same-account and full
registration, policy/witness/device replacement, installed/deployed lifecycle,
whole-store rollback, erasure, power loss, resource/energy measurement and full
retained-state PCS/refinement remain open. Hosted qualification of the version-eight
change is pending; this is not full 0.2.0 release admission.
