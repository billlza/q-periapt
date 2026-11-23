# Offline native maintenance tool

The 0.2.0 maintenance archive contains a precompiled `bin/qperiapt`.
Select the archive for your store host from [Apple Silicon](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-policy-maintenance-0.2.0-aarch64-apple-darwin.tar.gz), [Linux x86_64](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-policy-maintenance-0.2.0-x86_64-unknown-linux-gnu.tar.gz), [Linux arm64](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-policy-maintenance-0.2.0-aarch64-unknown-linux-gnu.tar.gz).
On Apple Silicon, run the following commands.

```sh
curl -fLO https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-policy-maintenance-0.2.0-aarch64-apple-darwin.tar.gz
tar -xzf q-periapt-policy-maintenance-0.2.0-aarch64-apple-darwin.tar.gz
```

The package also includes `publication-reclaim` for one bound inactive
v2 publication attempt. Its [separate maintenance contract](PRIVATE_PUBLICATION_MAINTENANCE.md)
specifies the exact control directory, work budgets, refusal conditions and
original-result recovery. This command does not migrate a database and never
follows a formal destination. The procedure below is only for `policy-store-upgrade`.

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
The [0.2.0 package qualification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/package_readback.json)
records execution on the build hosts, and the [verified publication cohort](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/VERIFIED_COHORT.json)
records the released archive bytes. macOS deployment metadata does not establish
testing on macOS 13, and Linux runtime requirements are recorded for the producing
runner. Physical minimum-OS execution and signing/notarization retain their
separate qualification scope.
