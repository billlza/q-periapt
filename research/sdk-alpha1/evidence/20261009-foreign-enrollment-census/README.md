# Installed foreign enrollment census repair

The full `f9ae04b9` Rust/C/Swift/Kotlin package producer stops after 5,087.617
seconds with `completed=false`. The C consumer completed. Swift Debug reached
the complete-account reconciliation workload: all three actual tests passed,
with exit zero, in 105.98 seconds. The reader then refused its summary because
it expected 25 filtered tests while the executable reported **26**.

The exact installed native harness lists **29 tests**, including the newly added
registered-publication regression. The next foreign policy and roster readers
also retained the previous 28-test census. A shared `ENROLLMENT_TEST_COUNT=29`
now governs all selections from this same binary, including registration,
publication, renewal, C/foreign independent policy, foreign account/roster and
TLS pre-processing. Other binaries retain their separate counts.

The unchanged real Swift stdout/stderr fails the old reader and passes the
repaired reader, including all nine carrier/interruption scenarios and every
original protocol/dispatch marker. All 23 related reader tests pass. Negative
cases still reject old/higher filtered counts, missing/duplicate/mislabeled
cases, ignored tests, changed executable identities and incomplete scenario
markers. The registration reader now also uses the common strict single-summary
check. No runtime failure, error code or protocol requirement was suppressed.

`QUALIFICATION.json` binds the real test census and selected/filtered counts.
`CAPTURES.zip` retains the failed producer reports and logs, actual Swift
transcript, original binary's test listing, old/new readback, related tests and
exact patch. These readbacks do not re-execute the Swift workload or convert the
failed whole producer into a successful package. A complete producer rerun is
still required; Kotlin had not started when this attempt stopped.
