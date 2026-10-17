# Browser dependency and native package admission

The actual installed-package pipeline at `5f7548fa` stopped before building:
`rust_sdk_profile.classify` required every internal dependency to belong to the
0.2.0 workspace. The private browser entry point now depends on the isolated
Continuity candidate, whose version is 0.0.0 and whose package remains unpublished.
`PACKAGE_BEFORE.json` and `package-before.stderr` retain this terminal failure.

The browser manifest now pins `=0.0.0`. Classification admits only this dependency
from the private `q-periapt-sdk-wasm` crate, at the original repository path, as an
optional normal dependency for `wasm32-unknown` with unchanged features. The
candidate manifest must retain its exact name, version, and `publish = false`.
Other internal dependencies retain their exact 0.2.0 version and publication
ordering checks. The candidate does not join the 12-crate publication cohort or
the 18-member workspace.

The new positive regression fails with the old classifier and passes after the
repair. The negative cases reject alternate paths, version ranges, registry or
renamed dependencies, target/feature changes, product-crate edges, and changes to
the candidate's identity or private publication boundary. Both existing test
modules passed (32 tests):

```sh
QPERIAPT_PYTHON=/opt/homebrew/opt/python@3.14/bin/python3.14 PYTHONPATH=artifact \
  sh artifact/python-run.sh -m unittest -v test_rust_sdk_profile test_continuity_package
```

Actual `cargo metadata --locked --offline --no-deps --format-version 1` from the
repaired workspace also passed classification; its digest and selected edge are
in `CHECKS.json`. This closes the reproduced admission failure. Full current-source
package execution remains a separate requirement and is not claimed here.
