# Installed independent Python reference

At `39b1e465d098e8041a126089fc805cb0679f1eeb`, the 47 protocol/provider modules
have moved into `qperiapt_continuity_reference` without changing their bytes.
The test harness changes only imports, source inventories and the explicit
package binding for the historical codec. The old archived source paths remain
unchanged. A standard Flit wheel now carries only the reference implementation,
provider loader, licenses and package metadata.

A hash-pinned build backend produced two identical prototype wheels under the
recorded `SOURCE_DATE_EPOCH`. Standard
pip installed the reference and a fresh pinned provider outside the checkout.
The isolated consumer admitted all 47 modules from that installation, with no
source checkout in its import path, no site loading or bytecode, and a private
empty cache prefix. It executed 92 worker operations and 21 real process kills
against the previously installed native counterpart. Registration, original
operation recovery, traffic, rekey, expiry and local/witness credential renewal
passed; the signed public records were separately replayed.

The final committed wheel was rebuilt after adding installation documentation,
installed again and all modules loaded. Only METADATA, RECORD and ZIP timestamps
differ from the registration-tested wheel; all 47 installed module hashes match.
The registration run is linked by those exact module bytes, not described as a
second execution. Six wheel-boundary tests and source/namespace checks passed.

`CAPTURE.zip` retains both wheel versions, the pinned build/provider wheels,
commands, package inspection and installation inventories, consumer provenance,
source snapshots and public runtime records. It excludes private images and
checks both real registration wrapping keys are absent. `CHECKS.json` gives
hashes, actual counters and limitations. The initial metadata readback failure
is retained with the exact one-newline cause; no source check was relaxed.

This remains an unpublished reference implementation at version 0.0.0. The
installed Python platform matrix, complete namespace regression CI, deployed
account authentication, cross-host carrier, full multidevice lifecycle and PCS
analysis remain open. The prior 54eda583 CI run does not test this namespace or
wheel boundary, and this result does not admit the complete 0.2.0 release.

Build format references: [PyPA packaging guide](https://packaging.python.org/en/latest/tutorials/packaging-projects/)
and [Flit configuration](https://flit.pypa.io/en/stable/pyproject_toml.html).
