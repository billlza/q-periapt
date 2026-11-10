# Candidate release identity inventory — 7 November 2026

The real candidate inventory completed the new release-manifest identity check:
**16 package definitions, 46 checked files, 51 SDK C exports and 158 Continuity C
exports**. Its 44 selected source inputs were additionally compared byte-for-byte
with the fixed Git source commit.

| Selected identity | Value |
| --- | --- |
| Source commit | `ee625d7a5501be0f3320511682f0fad95906e516` |
| Source tree | `ae795571ef8607051703c89048469451f86a8292` |
| Manifest SHA-256 | `f6f07c31506a79bbbd2935563793880a6032fc40079c6fe1364829517a96ee46` |
| Specification-lock SHA-256 | `d09cf73b1f8bdec7c9d46327919c28e58c38e1926894cedcdc86d1d770721086` |
| Stage | `candidate`, product target `0.2.0` |
| Python | 3.12.14 |

The selected source adds the exact `=0.0.0` constraint to the reference
application's existing local engine dependency. This matches the engine's actual
current identity. The change is prepared after the Android deadline/diagnostic
repair; the active PR head remains on its original CI wave.

## Recorded inventory

`MANIFEST.json` contains the twelve SDK Cargo crates, the Continuity engine, the
Cargo browser bridge, the reference-service Cargo application and the existing
browser npm package. Cargo and npm retain their shared browser name in separate
ecosystems. The dependency graph follows actual manifests, including exact
internal versions, Cargo aliases and local/workspace paths.

`SPEC_LOCK.json` selects seven primary normative roles and eighteen supporting
contracts. Its package-graph and interface commitments include the actual
definition-file pins. The independent `sdk_c` ABI 2 and `continuity_c`
`qpc-owner/1` declarations retain their existing versions and symbol namespaces.

Native C, Swift, Kotlin and Android have existing installed-consumer qualification;
their formal distribution identity rows and selected artifacts enter the final
manifest during admission. This capture selects no built artifact, assessment
report or separately emitted compiled descriptor. The current candidate freeze
flags remain false. The verification result therefore records identity
consistency with `release_claim_eligible: false` and `publication_performed: false`.

## Receipts and reproduction

- `VERIFICATION.json`: actual successful verifier output.
- `CAPTURE.json`: original capture time, verifier source digest, source identities
  and the 44 exact source-file comparisons.
- `UNIT_TESTS.txt`: 42 passing tests in the final focused run: 31 manifest tests
  and 11 existing contract tests, with exit status zero.

From the repository root, the independently selected pins reproduce the check:

```sh
python3 artifact/continuity_release_manifest.py \
  --root "$PWD" \
  --manifest research/sdk-alpha1/evidence/20261107-release-manifest/MANIFEST.json \
  --manifest-sha256 f6f07c31506a79bbbd2935563793880a6032fc40079c6fe1364829517a96ee46 \
  --source-commit ee625d7a5501be0f3320511682f0fad95906e516 \
  --source-tree ae795571ef8607051703c89048469451f86a8292 \
  --stage candidate
```

The input root must contain the pinned source bytes and these two inventory
documents. The verifier compares independent source selectors; the additional
Git byte comparisons are retained in `CAPTURE.json` rather than inferred from a
checkout's current branch name.

The [manifest contract](../../../../docs/continuity/RELEASE_MANIFEST_V1.md)
defines the schema and checks. The
[admission plan](../../../../docs/continuity/RELEASE_0_2_ADMISSION_PLAN.md)
retains the agreed distribution, construction-review and workload-budget work.
The completed hosted cohort remains attached to its
[original CI receipts](../20261107-ci-release-readback/README.md).
