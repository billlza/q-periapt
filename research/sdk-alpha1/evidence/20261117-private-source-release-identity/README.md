# Private reference-source release identity

The frozen graph deliberately retains `q-periapt-continuity-reference-app`
`0.0.0` and `publish = false`; the executable service distribution is `0.2.0`.
`SERVICE_DISTRIBUTION_0_2.md` specifies this distinction. The release verifier
incorrectly required the private source row to have the outer product version.
The old adopted-graph test checked individual metadata identities without
passing the full graph through the release-stage version rule.

The retained red run executes the real frozen 21-row graph, exact normative
files and real Cargo/npm definitions through the complete release verifier.
Its archive and assessment payloads are explicitly synthetic; it fails at the
product-version rule. The corrected reader has one closed private-source
case: exact name, version, canonical metadata path, no product ABI interface,
and an actual pinned Cargo definition with `publish = false`. Every other
product row retains `0.2.0`. No normative graph or freeze byte was changed.

The green run covers 70 manifest, service-package and SDK GitHub publication
controls with warnings treated as errors. Added negative cases reject a public,
missing or alternate registry publication selection, a changed source name,
version or path, an ABI claim on that private source, and a `0.0.0` service
distribution. The manifest remains an identity check and cannot grant release
admission. Original producer records still name their actual source commits;
final qualification must select the corrected source separately.

Executed through the repository Python launcher:

```text
unittest test_continuity_release_manifest.AdoptedSpecificationTests.test_actual_frozen_graph_accepts_complete_release_identity_inputs
unittest: test_continuity_release_manifest, test_continuity_service_package, test_sdk_github_publication
```
