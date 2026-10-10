# Bounded fuzz execution evidence

The manifest retains the actual local runs, including the missing-cache and Apple-Clang ASan-link failures. Run03 is the first complete three-target run. Run04 repeats only transport after strengthening the 32-bit boundary seed. The final CI configuration remains to be executed on its own commit.

Raw tool text is encoded in JSON with a digest of the decoded bytes; no diagnostics or trailing whitespace were removed. Counts are callback invocations, including early rejection, not completed crypto operations. Source digests and the explicit post-capture differences are recorded in the manifest and per-run results.

The actual workflow statistics parser accepts the real logs and rejects four malformed controls. CodeQL source-census and source-provenance tests ran in a standalone checkout, preserving the requirement for a real `.git` directory.
