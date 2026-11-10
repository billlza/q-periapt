# Private browser dependency assertions

At `1ce396c4`, hosted `check` job `115181633673` also failed two isolation
assertions. The tests still prohibited every candidate dependency and required
every `q-periapt-*` dependency to use the SDK release version. Both failures
reproduced locally before the assertions changed (`isolation-before.log`).

The revised tests admit exactly the already-authorized optional WASM-target
dependency from the unpublished browser package, pinned to candidate `=0.0.0`.
They invoke the production metadata classifier and its strict dependency
validator, require the exact feature map and path, and retain all other package
version and isolation checks. The candidate remains a separate unpublished
workspace, and its root-lock entry must have neither registry source nor checksum.

The two repaired modules and `test_rust_sdk_profile` pass all 25 tests, including
negative controls for broadened target, feature, identity and publication scope
(`isolation-after.log`). No product dependency or release cohort changed in this
repair. Hosted confirmation remains separate from this local reproduction.
