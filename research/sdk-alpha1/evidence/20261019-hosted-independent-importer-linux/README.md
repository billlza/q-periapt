# Hosted installed native counterpart and public importer: Linux

[Run 39181302774](https://github.com/billlza/q-periapt/actions/runs/39181302774),
job 117834428696 succeeded at
`54eda5836d42ed39f01e4957d4bec971cd1e8198`.

Both the native counterpart and public bootstrap importer were built and linted
from the same nine installed product crates, outside the checkout. All nineteen
reference lanes ran, and all twelve readbacks passed on their first execution.
The importer binary matches its installed build receipt and the actual public
bundle import/refusal records. The original complete lockfile retains 118
external packages. Native/source archive identity and signed protocol records
are linked in `CHECKS.json`.

The 54,161,254-byte terminal artifact has SHA-256
`42ae21c54dda012afaaa9650a3ebf1bfdae748b0cc5aeac90f63364174382b48`.
`CAPTURE.zip` and `SOURCE.zip` are disjoint, below 50 MiB each, and covered by
one full manifest inside `CAPTURE.zip`. Uploaded executables were read and
hashed, never executed locally.

The Python reference at this head still runs from source. The later namespace
and wheel work is covered separately by `20261019-independent-python-install`.
Private-state and remote post-build filesystem assertions remain producer
observations. This does not admit deployed account authentication, cross-host
transport, full multidevice lifecycle, PCS or the complete 0.2.0 release.
