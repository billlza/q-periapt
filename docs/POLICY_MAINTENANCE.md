# Offline policy-store maintenance tool

The `q-periapt-policy-maintenance-0.2.0-TARGET.tar.gz` candidate contains a
precompiled `bin/qperiapt`. It requires no Rust installation. Select macOS arm64,
Linux x86_64, or Linux arm64 to match the machine containing the store. Intel Mac
and Windows maintenance are unsupported. Candidate artifacts are not a signed
or notarized public release.

Obtain the archive and its SHA-256 from the same trusted distribution channel.
Verify that digest before extraction. Run the tool as the account that owns the
database; do not use elevated privileges to bypass admission failures.

1. Stop every application/process using this policy store. Retain a recoverable
   backup under the application's backup policy before maintenance.
2. Obtain the original trusted ML-DSA-65 root and the independently retained
   36-byte trusted policy state. Do not derive these trust inputs from the store
   being repaired or substitute a newly generated root.
3. From the extracted package, run:

   ```sh
   ./bin/qperiapt policy-store-upgrade /absolute/private/policy.redb \
     --root /absolute/trusted/root.bin \
     --expected-state /absolute/trusted/state.bin
   ```

A successful JSON result reports `verified-format-3`. The existing database inode,
signed policy, root, signature and exact trusted state are preserved. A retry on
an already-current database verifies that same configuration; it does not prove
that this invocation performed a fresh commit. Restart the application only
after checking the result and using its normal authenticated storage-open path.

The tool supports the original five-field `QPeriapt-Host-Policy-v1` policy store
written with redb format 2. It does not migrate Continuity journals or recovery
enrollment images, create missing databases, replace roots, reset rollback floors,
return an SDK runtime, or choose a backup for you. Ordinary SDK open still refuses
an old format without automatic migration.

On lock, trust, checksum or admission failure, inspect the specific error and
correct its cause. On I/O failure, interruption or an unknown result, stop normal
use and retain the file and diagnostic. Do not delete, reinitialize, rewrite
format bytes, or repeatedly force an upgrade. The original file may contain a
partially completed engine transition. Follow the application's documented
recovery procedure with the original independent trust inputs; successful retry
is not promised for every partial write or power-loss state.

`MANIFEST.json` binds the binary, documentation and notices to their build inputs;
it is an integrity inventory, not a signature or independent builder attestation.
The package qualification records execution on the build host. macOS deployment
metadata does not establish testing on macOS 13, and Linux runtime requirements
are recorded for the producing runner. Physical minimum-OS, signing/notarization
and release approval remain separate gates.
