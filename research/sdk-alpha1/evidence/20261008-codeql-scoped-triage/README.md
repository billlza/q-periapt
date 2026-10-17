# Scoped Rust CodeQL review

The successful [Rust analysis job](https://github.com/billlza/q-periapt/actions/runs/37703091965/job/113070951972)
produced 780 SARIF results. Analysis, extraction-quality and upload success do
not mean those findings were resolved. This record gives six specific results
manual dispositions and retains one additional result as partially reviewed.
**774 results still have no completed disposition in this record.** No alert
has been remotely dismissed; no query, exclusion or threshold has changed.

`PROVENANCE.json` binds artifact 11522923268 and the SARIF hash to checkout
`d31e67ba573d9b1dcfd7bde112d567b09e82fced`, confirmed by the job's checkout
guard. Its Git tree is exactly the tree of branch head `1ca9ba6b`. All 22
inspected source files remain byte-identical at `5a9f335b`; their hashes are in
`SOURCE_IDENTITY.json`. Selected raw SARIF results, including all related
locations and available data-flow traces, are preserved losslessly. Indices
below are zero-based in that exact SARIF, not GitHub alert identifiers.

| Results | Observation | Disposition |
| --- | --- | --- |
| 530, 531 | `sdk_path_perf.rs:132` allocates two `Vec<u128>` buffers. Both private calls receive `n` only after `main` rejects values outside 100–5000; combined element capacity is at most 160,000 bytes. | Bounded local benchmark input; the reported unbounded allocation is not reachable through its command interface. |
| 680 | `core/src/lib.rs:624` starts a checked length sum at `0usize`, then reserves transcript capacity. The reported bootstrap nonce field is separately filled through `nonce()` and `getrandom`, with failure propagated. | The length accumulator is not a hard-coded nonce. |
| 681 | `sdk/src/purpose.rs:14` is a versioned public HKDF salt. The KEM shared secret is IKM; purpose, policy, root, label and context are bound in expansion info. | Intentional public parameter, not a hard-coded secret. |
| 693 | `sdk/src/lib.rs:315` returns the configuration boolean `is_enabled`. The alleged journal AEAD key is a distinct `JournalKey`, provisioned from entropy or read in full from its protected key file. | The reported boolean-to-secret interpretation does not match the call contract. |
| 696 | `sdk/src/lib.rs:303` initializes 68 public binding bytes. All are overwritten with the 32-byte root digest and 36-byte trusted state before return. The reported nonce/key sinks use separate fields. | Initialization and descriptive metadata are not operational keys or nonces. |
| 695 | `ZeroizingBytes::zeroed` has 23 reported key sinks, but SARIF emits only four traces. Those four lead to signing-owner and traffic keys fully written by HKDF before AEAD. | **Partial/open:** the other 19 named sinks have not all been reviewed here. Four explained traces cannot close the entire result. |

The fixed-salt conclusion is specific to this high-entropy KEM key schedule.
[RFC 5869 §§2.2, 3.1 and 3.2](https://www.rfc-editor.org/rfc/rfc5869.html#section-3.1)
defines HKDF with or without random salt and treats salt as non-secret and
reusable; it also explains benefits of random salt and context binding through
`info`. This is not a claim about password derivation, arbitrary low-entropy
inputs, or complete protocol security. Changing this versioned parameter just
to remove a generic alert would change derived keys without addressing a
demonstrated flaw.

Investigation of path result 187 independently found the scanner's stale
size-check/unbounded-read bug. The [separate repair](../20261008-cli-bounded-read/README.md)
has red/green and actual-process evidence at `5a9f335b`. It does not establish
pathname confinement or automatically resolve that path-injection result.

Remaining path, process, logging and multi-sink cryptographic findings need
their own reachable-input and data-flow review. Test-only location, whole-run
success, or a large count of apparent modeling artifacts is not sufficient to
dismiss them. This is internal source review, not an independent audit or a
0.2.0 release approval.
