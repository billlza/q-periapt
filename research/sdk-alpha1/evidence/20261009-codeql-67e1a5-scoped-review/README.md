# Scoped follow-up to the 67e1a5b0 Rust analysis

This internal source review gives seven specific results dispositions in the
809-result SARIF from job 113515487851, source
`67e1a5b03bf263ab175bc2261e4b70413ce8d79f`. Result indices are zero-based in that
retained SARIF, not GitHub alert IDs. The other **802 results remain without a
completed disposition in this record**. Earlier 780-result analysis counts are
not added to these counts. No remote alert dismissal or query change occurred.

| Results | Concrete observation | Disposition |
| --- | --- | --- |
| 553, 554 | Both calls to private `paired()` receive a parsed count only after `main` rejects values outside 100–5000. The two `Vec<u128>` element capacities together cannot exceed 160,000 bytes. | The reported unbounded command-input allocation is not reachable. |
| 720, 721 | `missing()` returns `false` or `true`, used only to choose signer open/provision. The two named AEAD sinks read a separate opaque `JournalKey`; its production constructors fill all 32 bytes from entropy or an exact protected-file read before returning. | Branch conditions are not operational key values. All two named sinks and four supplied traces per result were checked. |
| 555 | The sole reported expression is `certificates.remove(0)` on a concrete `Vec<Vec<u8>>` of public certificates. | Removing a vector member is not a logging operation. |
| 587, 588 | The formatted expressions use only the result vector's `.len()`, plus process-cut labels, fixture mode, fixed sample/size choices and elapsed time. Neither logs result contents or plaintext bytes. | Explicit test metadata, not the returned cryptographic material. |

`SELECTED_RESULTS.json` retains the selected raw results losslessly, including
every available trace and related location. `SOURCE_IDENTITY.json` binds all 13
inspected files to the analyzed commit and comparison head `b1006eb3`.
Eleven files are byte-identical. The two changed files are retained with their
complete diffs: enrollment adds publication methods; durable storage adds the
publication registry and v22 framing. The inspected boolean use and journal key
construction/material at both AEAD calls remain unchanged. This observation is
limited to those paths, not approval of every new publication operation.

At integration on `dc1e41f7ac611c23d5f06d9aa88296c59f40c838`, the archive
hash, member count and every archived member were checked against the retained
files. All seven raw results exactly match their indices in the original SARIF,
whose hash and total count were also checked. All 13 analyzed files match
`git show` at the analyzed commit, and every current file still matches its
recorded `b1006eb3` comparison hash. This is an integrity/source check, not a new
CodeQL analysis. The archive retains the original review snapshot.

`CAPTURE.json` identifies the archive of source, selected results, dispositions
and diffs. The original full diagnostic archive and analysis identity remain in
the separate 67e1a5b0 inventory. No new runtime test is claimed for this source
review. It does not prove entropy health, arbitrary host key quality, filesystem
confinement, production metadata privacy, full protocol security or physical
erasure. The aggregate security check remains an open release gate.
