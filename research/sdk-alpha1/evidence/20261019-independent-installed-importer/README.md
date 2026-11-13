# Installed public bootstrap importer

The clean-checkout CLI at `b89eb724f4f40388ab7546dab9b7d07c80bf607b`
built and linted both the native counterpart and the public importer from the
same nine installed product crates. The original complete Cargo lock and its
118 external packages were unchanged. Release build and Clippy with warnings
as errors passed for both executables; the seven helper tests and workflow lint
also passed.

The final installed importer executed 20 calls with the retained, separately
pinned public vectors: one valid context and nine exact typed refusals for each
of the local and required-witness profiles. No uploaded binary was run. The
native counterpart is byte-identical to the earlier installed registration
binary, so its 92-worker / 21-process-kill evidence is linked by hash rather
than described as a new run.

`CAPTURE.zip` retains command results, final executables, the candidate crate,
public input vectors and outputs, source identities and readback checks.
The SDK archive identity links to the prior installed-counterpart capture.
This is a package boundary result for the reference test consumers. Fixture
trust, installed Python distribution, deployed account authentication, cross-host
transport and full release admission remain distinct requirements. The hosted
44233741 run predates this importer change and is not claimed to test it.
