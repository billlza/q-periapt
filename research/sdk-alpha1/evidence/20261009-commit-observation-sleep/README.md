# Commit observation interrupted by host sleep

The complete installed Continuity attempt at `a671719e` failed after 3126.574 s
in C Release witnessed-Commit-error public validation. It did not reach Swift or
Kotlin qualification. The Rust harness returned zero and all four case markers,
but the public verifier correctly rejected `tls-expired`: the original signed
policy expired at 1791550033 and the fresh Applied observation occurred at
1791550065, 32 s too late. The other seven predicates in that temporal guard and
the other three cases passed. Native success alone did not establish this
scenario's required ordering.

The existing public observations place the TLS return at 13:45:26 BST and its
fresh observation at 13:47:45. Read-only macOS power events record Maintenance
Sleep at 13:45:24 for 141 s, with DarkWake at exactly 13:47:45. The native harness
reported 22.11 s elapsed despite the 141 s preparation-to-finish wall interval.
The fixture reads `SystemTime`; no clock substitution or global clock change
was used. Host sleep interrupted the intended pre-expiry observation window.
The verifier's refusal is valid and the failed package cannot be called qualified.

The same installed Release harness, client and library were then repeated in
a fresh private directory with their input hashes retained. All four cases
passed the unchanged public verifier, including exact transcript, ownership,
dispatch, expiry and ACK checks. Native elapsed time was 125.347 s. A concurrent
wall/monotonic sampler observed a maximum interval difference of about 16 us.
The repeat driver itself had a postprocessing error after recording native
return code zero (`Popen.check_returncode` does not exist). This was corrected;
the existing native output was independently read back and verified without
rerunning or replacing it. The original driver error is recorded separately.

No policy lifetime, timeout, security predicate or product code was relaxed.
The next complete attempt uses an independent clean `edc673bd` checkout and
`caffeinate -i` for that command's lifetime. This only prevents idle sleep while
the utility runs; it changes no global power preferences or display setting and
does not promise to override forced sleep. That complete attempt remains open.

The archive also retains the completed `edc673bd` preflight: source gate,
44 CodeQL-quality tests and 2668 artifact tests, all passed. Public case files,
clock samples, power transitions, exact binary hashes and source-bound commands
are retained in `CAPTURE.zip`; private database and key files are excluded.
