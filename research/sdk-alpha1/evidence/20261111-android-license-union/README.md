# Android dependency licenses across all shipped ABIs

The fips204 0.5.0 update exposed an invalid assumption in the AAR producer:
the x86_64 production dependency closure had been used as the license inventory
for all four shipped ABIs. The update removes the normal sha2 0.10 dependency,
so x86_64 no longer selects cpufeatures 0.2.17. The aarch64 closure still selects
it through fips204 → sha3 0.10.9 → keccak 0.1.6. This package must remain in the
distributed notices.

## Hosted evidence and cause

| Target | fips204 0.4.6 baseline | fips204 0.5.0 failing package |
| --- | ---: | ---: |
| x86_64-linux-android | 73 | 71 |
| aarch64-linux-android | 72 | 71 |
| armv7-linux-androideabi | 70 | 69 |
| i686-linux-android | 72 | 70 |
| Union | 73 | 72 |

The baseline is [job 130313506309](https://github.com/billlza/q-periapt/actions/runs/42956732871/job/130313506309),
which checked out `fb4b6d3ddf1f0f725cd226bda337c294c291c93a` for SDK head
`56eb5dca95a913539040d0939c733d1f11f89d50`. Its four-target superset check passed.

The failure is [job 130321611627](https://github.com/billlza/q-periapt/actions/runs/42959257196/job/130321611627),
which checked out `834c67183c403fd10d65600252ecbcb950c1af11` for PR #115 head
`3c9df1feeb7857e53ac4d6269788d20c87851459`, complete tree
`0f281a963c2bd0e6f203c025a99d507ae73da9c2`. All four native compilations and the
ELF tree checks passed. At 07:25:28 UTC, the license comparison rejected the
x86_64 reference because it lacked exactly
`cpufeatures 0.2.17 registry+https://github.com/rust-lang/crates.io-index`.
The replay and artifact-upload steps were then skipped.

The 72-package union follows from that hosted comparison: the 71-package
reference lacked exactly one member of the union it computed. It is a result
of the original hosted matrices, not a claim that the repaired producer has
already completed a hosted AAR build. The complete decoded logs are retained
as `hosted-baseline.log.gz` and `hosted-failure.log.gz`. `dependency-edges.json`
records the relevant target and dependency-kind edges from the existing full,
locked Cargo metadata packet.

## Repair

`third_party_licenses.collect_union` independently collects and validates each
requested target's production closure, then publishes their exact union.
Repeated package identities must have identical checksums, license expressions
and license-file hashes. Shared license files are emitted once; every selected
package keeps its real license bytes. Per-package, total-file and total-byte
bounds remain enforced over the final union.

The new inventory schema 2 retains the canonical target list and the exact
package identities selected by each target. Standalone verification checks
that every referenced identity has a package and its license files, that the
union contains no unselected package, and that the expected target set matches
exactly. Duplicate identities, missing targets, conflicting license evidence,
changed license bytes and malformed schemas fail closed.

The Android producer now supplies all four targets to both generation and
verification. The AAR auditor requires this multi-target inventory and binds
the manifest's `covered_targets` to it. The manifest's existing x86_64
reference-target field remains a compatibility field; it no longer supplies
the coverage argument. Other distributions continue to use the existing
single-target schema 1 interface.

## Executed validation

From `artifact/`, freshly executed after recovery:

```text
python -m unittest -v test_third_party_licenses test_android_elf test_android_sdk_profile
Ran 76 tests in 5.780s
OK
```

The retained `focused-tests.log` includes union generation with non-nested
target closures, missing architecture-specific licenses and lock entries,
conflicting shared records, exact target-set verification, omitted package
rejection, deterministic CLI output, aggregate limits, schema admission, and
the existing AAR and SDK-profile checks. `synthetic-union-inventory.json` is
the explicitly synthetic three-package/four-target fixture used to exercise
the new interface; it is not a production dependency inventory.

`bash -n artifact/android-aar.sh`, Python compilation of the four changed
Python modules, and `git diff --check` also passed. An independent source
review found the generation, verification and existing consumer interfaces
consistent with the repair. `validation.json` binds the changed source files
and retained evidence to hashes and records the exact executed commands.

This local environment has no Cargo or rustup executable. The complete
post-fix Android build and fresh target metadata generation are therefore
left to the hosted packaging job; their outcome is separate from the
completed source review and 76 local regressions.

## Recovery provenance

The transient workspace reset after local commit
`0250f73ae3976412a54beabc28f5b7ef67f3410e` and before its publication. The five
source/test changes were reconstructed from the retained patch transcript.
Their `git -c core.abbrev=8 diff` SHA-256 is
`bcea4bbc08ef365ae26778ccad3833eec9ed30d0cb9eaac7648fbb2acc93d3dd`, exactly
matching the independent review record from before the reset. The six
inventory-fix files were recovered directly from the published SDK commit
`1b47a1931cab2a944902316619cdcf479bd64ab0`.

Both complete hosted log strings survived in session storage and were
restored. The original local test-log file did not survive; this packet
contains a new actual execution. The new recovery tree intentionally records
that distinction and is not represented as the lost original tree.
