# Native rekey boundaries under classical signature substitution

Two new native regressions keep an honest message body and its ML-DSA signature
unchanged while generating another valid canonical P-256 signature. The
substituter receives only the classical private key, public verification key
and existing wire; honest protocol endpoints retain their original signing
owners. Both required signature components verify. No protocol implementation,
encoding or acceptance rule is changed.

The tests exercise different rejection boundaries:

- **Offer alias:** the responder authenticates it and constructs a response.
  The proposer rejects that response with `Scope` because its prefix does not
  bind the exact original offer retained locally. The rejecting proposer image
  remains unchanged. The responder refuses the conflicting original offer;
  after both journals reopen, their respective original offer/response retries
  return the exact saved bytes.
- **Response alias:** the proposer accepts its unchanged response body and
  passes KEM/root confirmation. The final then fails at the responder's
  original response-wire binding with `Scope`, without changing its image.
  The proposer refuses substitution of the original response after retaining
  the alias. Reopen preserves its exact final and the responder's original
  response; repeating the mismatched final still refuses without mutation.
- **Original-wire controls:** each scenario completes the full rekey flow
  and carries actual new-epoch application traffic.

Each new test executes a fresh control and substitution case. Both tests pass
in Debug and Release: four test executions, with two controls and two alias
cases per profile. The all-feature/all-target Clippy gate with `-D warnings`
and rustfmt checks also pass. The corrected qualification took 201.426 seconds,
inside its 5,400-second parent ceiling; each command retained the existing
900-second and 16-MiB-per-stream limits. A separate task build directory was
cloned from the earlier cache; original qualification binaries were not replaced.

The first Debug attempt passed the offer case but failed the response case's
positive fixture: after already accepting a response, it called the helper
that starts with `prepare_rekey_offer`. That API correctly returns `Suspended`
for `FinalReady`. The fixture now runs its original-wire control before that
acceptance, so the existing complete-rekey helper follows its proper sequence.
The failed test source, exit 101, parent failure and complete streams remain
retained. No assertion, rejection rule or time bound was weakened. This is a
test-fixture correction, not an old-product/new-product red/green bug claim.

The source base is `eadd07e548c3f884cffa7a2eaa65cc9021871fad` plus the captured
test-only delta: `tests.rs` adds one module and `tests/classical_alias.rs` adds
the two cases. The production source inventory remains identical to the
earlier complete Release cohort; the pre-existing CI workflow changes are
recorded separately. All selected inputs remained unchanged during execution.
The later native-upload ordering repair has its own evidence and was not part
of these Rust commands.

This is a focused native cryptographic/persistence regression. The complete
native aggregate, installed bindings, hosted CI and platform matrix were not
rerun here. Its conclusions do not extend to arbitrary signature substitutions,
whole-state simulation or the complete accepted-prefix proof. The
[body-origin note](../../../../docs/continuity/AUTHENTICATED_BODY_LEMMA_V1.md)
keeps the primitive, collision, identity/context and simulation premises explicit.

`CAPTURE.zip` retains 63 members: initial/corrected sources and command records,
both passing profiles, Clippy/format output, source/tool identities and relevant
protocol implementations. Every member was reread byte-for-byte. Its 429,138
bytes have SHA-256
`fecf2667618e6612bb69c6cec44c293140c8ee081d24ad7ef842a53a43d046b1`.
`FILES.json` binds the bytes and `READBACK.json` records the execution scope.
No private test stores or signing keys are exported.
