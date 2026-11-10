# Installed Python qualification entry point

At `4cf7a202789843df7980ff7c3a9675f13749e62f`, the new CLI inspects a standard
wheel against selected Git sources, installs it with pip outside the checkout,
checks the loaded module paths and runs the existing registration consumer.
It verifies wheel/installation RECORDs and exact pip origin, copies only test
harness inputs, and rechecks the installed files and source inputs afterward.
No source-tree fallback is available. Private states and partial results remain
available on failure.

A complete local invocation from an ordinary checkout finished successfully in
58.8 seconds. The exact wheel, 47 loaded modules, 55 installed files and 111
selected source files are bound to 92 worker operations and 21 real process
kills. Two readbacks verified the installed files and signed public operation
records. The supplied native counterpart retains its earlier installed-package
identity; the provider is the separately pinned prior installation.

Sixteen package-helper tests, workflow lint and diff checks passed. An initial
shellcheck warning was fixed by separating SOURCE_DATE_EPOCH assignment from
export, preserving the Git command's failure status. The CI job limit changes
from 25 to 30 minutes for the additional workload: the earlier Apple Silicon
cohort already took 23 minutes 36 seconds. No existing scenario or assertion was
removed. This record is local verification of the exact new CI entry point;
its hosted execution remains to be observed.

The capture contains public runtime evidence, wheel and installation records,
commands, source snapshots and reader checks. Private images are excluded and
both actual registration wrapping keys were checked absent. This qualifies the
reference consumer boundary, not deployed account authentication, cross-host
transport, multidevice completion, physical erasure, PCS or release admission.
