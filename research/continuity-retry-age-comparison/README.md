# Native retry-readiness comparison

This experiment isolates application retry readiness in the matched native
service. It uses the same two application budgets (32 and 64), seven schedules,
2,048 directed transmission opportunities, 32-byte requests, native journal,
capture cut and predictor as the retained matched run. Its protocol source is
fixed at `358b921ab3469ce49f166633fc9a762ff6ed7e3d`.

The original matched driver is included with its original bytes as the
`immediate` policy. A separate module changes only the ready predicate for an
unacknowledged application retry and the public timing counters needed by that
predicate. For `sender-turns-4`, a retry becomes ready once its sender has
received four more sending opportunities since that same frame's most recent
emission. Other endpoints' opportunities do not advance this age. A subsequent
retry resets the age. The fair cyclic selection order, new application
admission, control preparation, ACK handling, ciphertext replay, transport,
capture and durable operations retain their original code.

An age is a scheduling parameter. It consumes no hidden transport capacity and
does not release a message key, retire an outbox or change a sending budget.
The retry remains pending until its authenticated ACK or the original protocol
rules remove it. Fresh traffic can use an opportunity during which the pending
retry is not yet ready. Existing control-message retransmission remains
unchanged, so the ablation identifies the effect of the application predicate.

## Motivation and interpretation

In the retained alternating run, budgets 32 and 64 emitted 604 and 579
application retries. Of these, 592 and 572 were emitted after that application
had already reached logical delivery, while its sender was awaiting a
cumulative ACK. This public-trace diagnosis motivates the waiting interval.
The new run determines the actual resulting admissions, delivery, bytes,
reconstruction counts and durable operations; no additional service is
assigned to old trace slots by a counterfactual calculation.

## Execution

The workflow `.github/workflows/continuity-retry-age-comparison.yml` runs on a
pull request that changes this directory or that workflow, and supports manual
dispatch. It compiles one fresh native test executable containing both driver
modules, enumerates and runs each exact test, then validates all 28 traces.
Every matched input is checked against a retained SHA-256 before importing it.
The source derivative changes only the native test module; the before/after
source inventories and executable identity are retained. The original 49-row
matched experiment and its inputs remain unchanged.

```sh
python -m unittest discover -s research/continuity-retry-age-comparison -p 'test_*.py' -v
python research/continuity-retry-age-comparison/run.py run \
  --repository "$PWD" --output "$PWD/target/continuity-retry-age-execution"
```

The public artifact contains the raw traces, original native validation for
each trace, independent retry-age validation, build/run logs, source inventories,
both driver identities, toolchain identity and the single test-executable hash.
Physical persistence values come from the original counting backend. Experiment
elapsed time describes the complete run and is not a per-service timing result.
Each terminal report explicitly identifies whether native execution completed.
