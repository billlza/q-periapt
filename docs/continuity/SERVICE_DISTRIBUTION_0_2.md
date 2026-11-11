# Continuity 0.2.0 Linux service distribution

The service distribution is **`q-periapt-continuity-services` `0.2.0`**, delivered
as `q-periapt-continuity-services-0.2.0-<target>.tar.gz`. It contains the existing
directory, witness and two policy authorities, plus the native device command
used to provision the directory's wrapping key. The archive's
`PACKAGE_CONTENTS.json` binds every binary and public document to the selected
source commit/tree and records each binary's Linux runtime requirements.

The source package remains **`q-periapt-continuity-reference-app` `0.0.0`**, with
`publish = false`. The outer distribution version identifies the selected set
of executable files and accompanying contracts. It preserves the existing
command names, cryptographic domains, trust inputs and stored formats; it does
not change the Cargo package's research identity.

## Included commands and retained configuration

| Executable | Operator configuration and storage contract |
| --- | --- |
| `q-periapt-prekey-directory` | Independent directory pin; service, admission and approval JSON schemas `qperiapt-directory-service/1`, `qperiapt-directory-admission/1` and `qperiapt-directory-approval/1`; absolute ledger, signer and wrapping paths; service capacity from 1 through 4096 original allocations. |
| `q-periapt-continuity-witness` | Independently retained witness ID and pin; original host database, `witness-*.wrap`, `witness-*.signer` and `witness-*.redb` files; explicit enrollment approval before the bounded TCP service handles the admitted journal. |
| `q-periapt-policy-publisher` | Original publisher ID and database, protocol signer and wrapping key; four independently supplied SDK policy inputs; existing schema 1 and explicit schema 2 renewal upgrade. |
| `q-periapt-sdk-policy-authority` | Original authority ID and database, dedicated SDK signer and wrapping key; retained operation ID and exact policy TOML; existing SDK policy schema and trusted-state encoding. |
| `q-periapt-native-device` | Existing native device CLI, included so `provision-key` supplies the directory wrapping key through the same protected-file API. |

Detailed operating contracts are included in `docs/DIRECTORY_LEASES.md`,
`docs/SDK_AUTHORITY.md`, `docs/POLICY_PUBLISHER.md`, `docs/NATIVE_DEVICE.md` and
the witness section of `docs/REFERENCE_APPLICATION.md`. Their links select the
archive's source commit. The contents record also retains the original source
document hashes before those links are made portable.

## Install and operate

Select the archive and SHA-256 recorded in the coordinated release manifest,
verify that digest, then extract the archive into an operator-controlled
directory. The producer selects Linux `x86_64-unknown-linux-gnu` or
`aarch64-unknown-linux-gnu` according to its actual build host. Its `bin/` members
have mode `0755`; public documents and licenses have mode `0644`.

Each binary's `needed`, `interpreter` and `symbol_versions` fields specify its
system runtime dependencies. Install those libraries through the host's normal
system provisioning; the archive ships its executables and Rust/ML-KEM notices,
while libc, libgcc and any listed OpenSSL libraries remain host dependencies.
The recorded symbol versions describe the actual build's minimum requirements.

Six selected registry crates omit their license texts from their source
archives. Their original upstream notices are included under the corresponding
dependency names. `LICENSES/UPSTREAM_LICENSE_ORIGINS.json` records the exact
registry archive checksum, embedded VCS revision, upstream license blob and
public source URL for each one. These pins are verified during packaging;
the original Cargo resolution and registry sources stay intact.

Keep service state in a separate private `0700` directory. Retain service IDs
and trust pins independently before first initialization, supply private regular
input files as documented, and use absolute paths. For example:

```text
bin/q-periapt-sdk-policy-authority init /absolute/private/sdk.redb AUTHORITY_ID
bin/q-periapt-continuity-witness init /absolute/private/witness.redb WITNESS_ID
bin/q-periapt-native-device provision-key /absolute/private/directory.wrap
```

After an interrupted operation, reopen the original state with the documented
`prepare`, `result`, `show-key` or `lookup` command. Installing another copy of
the executable does not authorize replacing an existing ledger, signer or
wrapping key. The archive contains public files only; it contains no provisioned
service configuration, private key, database or generated test state.

## Build and retained evidence

From a clean checkout, use the repository's Python launcher and Rust 1.98.1:

```sh
service_cargo_home=$(mktemp -d)
sh artifact/python-run.sh artifact/continuity_service_package.py \
  --toolchain-root "$(rustc +1.98.1 --print sysroot)" \
  --cargo-home "$service_cargo_home" \
  --engine-package-id continuity-engine \
  --output target/continuity-services
```

The producer uses a fresh build directory outside the checkout and the original
locked Cargo graph. Cargo runs there with an explicit source manifest; its cache
and invocation-directory ancestors are checked for configuration overrides.
It selects the five Release executables from Cargo's actual
build records, verifies their ELF architecture and dynamic dependencies, and
collects the production dependency notices. It creates and independently
extracts a deterministic tar archive, verifies every extracted member and its
permissions, then runs new installed processes against fresh private test state.
Those processes exercise SDK policy issue/result byte equality, authority and
witness reopening, directory signer reopening, existing-ledger refusal, and
wrong-identity refusals.

`CONTINUITY_SERVICE_PACKAGE.json` records the build and archive identity.
`CONTINUITY_SERVICE_INSTALLATION.json` records those installed-process checks
under the same source and archive identity. Command logs retain their actual
return codes, including expected refusals. Generated state stays outside the
archive and retained public evidence. The distribution identity and package row
connect these typed receipts to the manifest's `service` role and selected
engine package. Account, directory and cross-client qualification retain their
own original execution receipts; coordinated release admission follows the
[0.2.0 admission plan](RELEASE_0_2_ADMISSION_PLAN.md).
