# Bounded CodeQL evaluator log observations

The Python SARIF from run `42959257074`, artifact `13834424714`, reports three `py/polynomial-redos` results in the evaluator observation parser. Its recorded tree is `0f281a963c2bd0e6f203c025a99d507ae73da9c2`; the affected parser bytes are identical to the SDK integration baseline `56eb5dca95a913539040d0939c733d1f11f89d50`.

## Defect and correction

The old Loaded, eviction and Stage patterns could retry a growing suffix at each repeated marker or numeric position. The retained baseline experiment records approximately quadratic growth, including 1.35 seconds for an 8,029-byte malformed eviction line. The parser admits lines up to 4 MiB, while its old time check ran before the input chunk. It could therefore return a completed observation after the observation deadline.

The parser now uses the first Loaded marker and final suffix, maximal numeric runs followed by a fixed eviction suffix, and the first Stage plus last complete iteration. Each selection retains the old physical-line semantics. Per-line and terminal time checks reject late completion. JVM heap flags must occupy one physical line, preventing cross-line whitespace from assembling a false allocation observation.

The existing query identities, all 39 security queries, evaluation allocation and five-hour evaluator budget are unchanged. This repairs the diagnostics parser; it does not attribute the separate SummaryStats evaluator bottleneck to log parsing.

## Validation

The 146 existing and focused summary-control, query-plan and Rust-profile tests pass. Independent execution compares the actual old/new observation functions on 11 edge cases, 5,000 fixed-seed random logs and 250 valid JVM lines, with identical complete results. Three controlled deadline counterexamples pass incorrectly on the original function and are rejected after the change. The separate cross-line heap counterexample is rejected.

Independent tests also execute eight adversarial shapes at the 4 MiB line bound and three JVM-output shapes at 32 MiB. Raw measurements are retained alongside their precise scope. These local diagnostic measurements are not SDK cryptographic throughput measurements or hosted security-query results.
