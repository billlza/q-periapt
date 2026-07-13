#!/bin/sh
# Fail-closed Rust crate publish contract for Q-Periapt.
#
# Default mode is clean-tree only. For an in-progress local diagnostic run, set
# QPERIAPT_ALLOW_DIRTY_PUBLISH_DRY_RUN=1; that proves only a dirty dry-run, never
# release readiness.
set -eu
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

PUBLISHABLE_CRATES="
q-periapt-core
q-periapt-kem
q-periapt-sig
q-periapt-backends
q-periapt-policy
q-periapt-ffi
q-periapt-wasm
q-periapt-rustls
q-periapt-cli
"
PATCHED_DRY_RUN_MODE=${QPERIAPT_RUST_PUBLISH_DRY_RUN_MODE:-patched}
ALLOW_DIRTY=${QPERIAPT_ALLOW_DIRTY_PUBLISH_DRY_RUN:-0}

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need cargo
need cargo-audit
need git
need python3

case "$PATCHED_DRY_RUN_MODE" in
	patched | registry) ;;
	*)
		printf 'error: QPERIAPT_RUST_PUBLISH_DRY_RUN_MODE must be patched or registry, got: %s\n' "$PATCHED_DRY_RUN_MODE" >&2
		exit 2
		;;
esac

if [ -n "${CARGO_REGISTRY_TOKEN:-}" ]; then
	printf 'error: CARGO_REGISTRY_TOKEN must be unset for dry-run proof\n' >&2
	exit 2
fi

dirty_status=$(git status --porcelain=v1)
if [ -n "$dirty_status" ]; then
	if [ "$ALLOW_DIRTY" != "1" ]; then
		printf 'error: Rust publish dry-run requires a clean worktree; set QPERIAPT_ALLOW_DIRTY_PUBLISH_DRY_RUN=1 only for local diagnostics\n' >&2
		exit 2
	fi
	printf 'DIRTY_DRY_RUN_DIAGNOSTIC_ONLY\n'
	printf '%s\n' "$dirty_status"
	ALLOW_DIRTY_ARG=--allow-dirty
else
	ALLOW_DIRTY_ARG=
fi

for license_file in LICENSE LICENSES/Apache-2.0.txt LICENSES/MIT.txt README.md; do
	test -f "$license_file" || {
		printf 'error: required release metadata file missing: %s\n' "$license_file" >&2
		exit 1
	}
done

mkdir -p "$ROOT/target"
metadata_json=$(mktemp "$ROOT/target/qperiapt-cargo-metadata.XXXXXX")
cargo metadata --locked --format-version 1 --no-deps >"$metadata_json"

python3 - "$metadata_json" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
publishable = {
    "q-periapt-core",
    "q-periapt-kem",
    "q-periapt-sig",
    "q-periapt-backends",
    "q-periapt-policy",
    "q-periapt-ffi",
    "q-periapt-wasm",
    "q-periapt-rustls",
    "q-periapt-cli",
}
nonpublishable = {
    "q-periapt-tls-demo",
    "q-periapt-ctstats",
    "q-periapt-continuity-model",
}
packages = {pkg["name"]: pkg for pkg in metadata["packages"]}
workspace_member_ids = set(metadata["workspace_members"])
workspace_q_periapt = {
    pkg["name"]
    for pkg in metadata["packages"]
    if pkg["id"] in workspace_member_ids and pkg["name"].startswith("q-periapt")
}
overlap = sorted(publishable & nonpublishable)
if overlap:
    raise SystemExit(f"error: release plan classifies packages twice: {overlap}")
unclassified = sorted(workspace_q_periapt - publishable - nonpublishable)
if unclassified:
    raise SystemExit(f"error: q-periapt workspace packages lack a release classification: {unclassified}")
not_workspace_packages = sorted((publishable | nonpublishable) - workspace_q_periapt)
if not_workspace_packages:
    raise SystemExit(
        f"error: release plan classifies packages that are not q-periapt workspace members: {not_workspace_packages}"
    )
missing = sorted((publishable | nonpublishable) - set(packages))
if missing:
    raise SystemExit(f"error: release plan references missing packages: {missing}")
workspace_versions = {packages[name]["version"] for name in publishable | nonpublishable}
if len(workspace_versions) != 1:
    raise SystemExit(f"error: workspace package versions diverged: {sorted(workspace_versions)}")
version = workspace_versions.pop()
# Alpha/beta/rc packages must move as one audited set; exact internal
# requirements prevent Cargo from resolving a mixed prerelease graph. Stable
# packages retain the workspace's normal caret-compatible contract.
expected_req = f"={version}" if "-" in version else f"^{version}"
for name in publishable:
    pkg = packages[name]
    if pkg.get("publish") == []:
        raise SystemExit(f"error: publishable crate is marked publish=false: {name}")
    for key in ("license", "repository", "homepage", "readme"):
        if not pkg.get(key):
            raise SystemExit(f"error: publishable crate {name} lacks {key}")
    if pkg.get("license") != "Apache-2.0 OR MIT":
        raise SystemExit(f"error: publishable crate {name} has unexpected license: {pkg.get('license')}")
for name in nonpublishable:
    if packages[name].get("publish") != []:
        raise SystemExit(f"error: nonpublishable crate must set publish=false: {name}")
backends = packages["q-periapt-backends"]
forbidden_backend_dependencies = {
    "pqcrypto-hqc",
    "pqcrypto-internals",
    "pqcrypto-traits",
    "hqc-kem",
}
actual_forbidden_dependencies = sorted(
    dep["name"]
    for dep in backends.get("dependencies", [])
    if dep["name"] in forbidden_backend_dependencies
)
if actual_forbidden_dependencies:
    raise SystemExit(
        "error: publishable q-periapt-backends contains HQC research dependencies: "
        f"{actual_forbidden_dependencies}"
    )
if "hqc" in backends.get("features", {}):
    raise SystemExit("error: publishable q-periapt-backends exposes retired hqc feature")
for pkg in packages.values():
    if not pkg["name"].startswith("q-periapt"):
        continue
    for dep in pkg.get("dependencies", []):
        if dep.get("path") and dep["name"].startswith("q-periapt"):
            if dep.get("req") != expected_req:
                raise SystemExit(
                    f"error: internal dependency {pkg['name']} -> {dep['name']} has req {dep.get('req')}, expected {expected_req}"
                )
print("RUST_PUBLISH_METADATA_PASS")
PY

check_package_list() {
	crate=$1
	list_file=$(mktemp "$ROOT/target/qperiapt-package-$crate.XXXXXX")
	cargo package $ALLOW_DIRTY_ARG --locked -p "$crate" --list >"$list_file"
	python3 - "$crate" "$list_file" <<'PY'
import pathlib
import re
import sys

crate = sys.argv[1]
paths = pathlib.Path(sys.argv[2]).read_text().splitlines()
required = {"Cargo.toml", "Cargo.toml.orig", "README.md"}
missing = sorted(required - set(paths))
if missing:
    raise SystemExit(f"error: package {crate} is missing required files: {missing}")
bad_patterns = [
    re.compile(r"(^|/)target(/|$)"),
    re.compile(r"(^|/)artifact/device-runs(/|$)"),
    re.compile(r"\.xcresult(/|$)"),
    re.compile(r"\.mobileprovision$"),
    re.compile(r"\.(p12|pem|key)$"),
    re.compile(r"(^|/)\.env($|\.)"),
    re.compile(r"(^|/)id_rsa$"),
]
for path in paths:
    if path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
        raise SystemExit(f"error: package {crate} contains non-portable path: {path}")
    for pattern in bad_patterns:
        if pattern.search(path):
            raise SystemExit(f"error: package {crate} contains forbidden path: {path}")
print(f"RUST_PACKAGE_LIST_PASS {crate} files={len(paths)}")
PY
}

for crate in $PUBLISHABLE_CRATES; do
	check_package_list "$crate"
done

run_publish_dry_run() {
	crate=$1
	log=$(mktemp "$ROOT/target/qperiapt-publish-$crate.XXXXXX")
	set +e
	if [ "$PATCHED_DRY_RUN_MODE" = "patched" ]; then
		case "$crate" in
			q-periapt-core | q-periapt-cli)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" >"$log" 2>&1
				rc=$?
				;;
			q-periapt-kem | q-periapt-sig)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" \
					--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
					>"$log" 2>&1
				rc=$?
				;;
			q-periapt-backends)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" \
					--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
					--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
					--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
					>"$log" 2>&1
				rc=$?
				;;
			q-periapt-policy)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" \
					--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
					--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
					--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
					>"$log" 2>&1
				rc=$?
				;;
			q-periapt-ffi)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" \
					--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
					--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
					--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
					--config 'patch.crates-io.q-periapt-policy.path="crates/q-periapt-policy"' \
					--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
					>"$log" 2>&1
				rc=$?
				;;
			q-periapt-wasm)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" \
					--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
					--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
					--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
					--config 'patch.crates-io.q-periapt-policy.path="crates/q-periapt-policy"' \
					--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
					>"$log" 2>&1
				rc=$?
				;;
			q-periapt-rustls)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" \
					--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
					--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
					--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
					--config 'patch.crates-io.q-periapt-policy.path="crates/q-periapt-policy"' \
					>"$log" 2>&1
				rc=$?
				;;
			*)
				printf 'error: no dry-run patch plan for crate: %s\n' "$crate" >&2
				exit 2
				;;
		esac
	else
		cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" >"$log" 2>&1
		rc=$?
	fi
	set -e
	cat "$log"
	if [ "$rc" -ne 0 ]; then
		printf 'error: cargo publish dry-run failed for %s (exit=%s)\n' "$crate" "$rc" >&2
		exit "$rc"
	fi
	python3 - "$crate" "$log" <<'PY'
import pathlib
import sys

crate = sys.argv[1]
lines = pathlib.Path(sys.argv[2]).read_text().splitlines()
for line in lines:
    lower = line.lower()
    if "warning:" in lower and "aborting upload due to dry run" not in lower:
        raise SystemExit(f"error: cargo publish dry-run emitted unexpected warning for {crate}: {line}")
print(f"RUST_PUBLISH_DRY_RUN_PASS {crate}")
PY
}

for crate in $PUBLISHABLE_CRATES; do
	run_publish_dry_run "$crate"
done

PACKAGE_INSPECTION_TARGET=$(mktemp -d /tmp/qperiapt-package-inspection.XXXXXX)
if [ -z "$PACKAGE_INSPECTION_TARGET" ] || [ ! -d "$PACKAGE_INSPECTION_TARGET" ] || [ -L "$PACKAGE_INSPECTION_TARGET" ]; then
	printf 'error: cannot create isolated package-inspection target directory\n' >&2
	exit 1
fi
cleanup_package_inspection() {
	if [ -n "${PACKAGE_INSPECTION_TARGET:-}" ] && [ -d "$PACKAGE_INSPECTION_TARGET" ] && [ ! -L "$PACKAGE_INSPECTION_TARGET" ]; then
		rm -rf -- "$PACKAGE_INSPECTION_TARGET"
	fi
}
trap cleanup_package_inspection 0 1 2 15

# Cargo 1.96 no longer guarantees that `publish --dry-run` retains its archive.
# Produce and verify a fresh archive in an isolated target after all nine
# dry-runs have passed. Verification intentionally leaves Cargo's exact
# normalized package directory available for the independent resolved-graph
# audit below; isolation guarantees there can be only one candidate directory.
package_inspection_log="$PACKAGE_INSPECTION_TARGET/cargo-package.log"
set +e
cargo package $ALLOW_DIRTY_ARG --locked \
	--target-dir "$PACKAGE_INSPECTION_TARGET" \
	--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
	--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
	--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
	-p q-periapt-backends >"$package_inspection_log" 2>&1
package_inspection_rc=$?
set -e
cat "$package_inspection_log"
if [ "$package_inspection_rc" -ne 0 ]; then
	printf 'error: isolated q-periapt-backends package inspection failed (exit=%s)\n' "$package_inspection_rc" >&2
	exit "$package_inspection_rc"
fi
python3 - "$package_inspection_log" <<'PY'
import pathlib
import sys

for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if "warning:" in line.lower():
        raise SystemExit(
            "error: isolated q-periapt-backends package inspection emitted a warning: "
            f"{line}"
        )
print("RUST_BACKENDS_INSPECTION_PACKAGE_PASS")
PY

python3 - "$metadata_json" "$PACKAGE_INSPECTION_TARGET/package" <<'PY'
import json
import pathlib
import sys
import tarfile

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
packages = {pkg["name"]: pkg for pkg in metadata["packages"]}
name = "q-periapt-backends"
version = packages[name]["version"]
archive = pathlib.Path(sys.argv[2]) / f"{name}-{version}.crate"
if not archive.is_file():
    raise SystemExit(f"error: publish dry-run did not produce expected archive: {archive}")
with tarfile.open(archive, mode="r:gz") as packaged:
    names = set(packaged.getnames())
    prefix = f"{name}-{version}/"
    manifest_name = prefix + "Cargo.toml"
    if manifest_name not in names:
        raise SystemExit("error: packaged q-periapt-backends lacks normalized Cargo.toml")
    manifest_file = packaged.extractfile(manifest_name)
    if manifest_file is None:
        raise SystemExit("error: cannot read packaged q-periapt-backends Cargo.toml")
    manifest = manifest_file.read().decode("utf-8")
    forbidden_tokens = (
        "pqcrypto-hqc",
        "pqcrypto-internals",
        "pqcrypto-traits",
        "hqc-kem",
        '[features.hqc]',
        'hqc =',
    )
    present = sorted(token for token in forbidden_tokens if token in manifest)
    if present:
        raise SystemExit(
            "error: normalized q-periapt-backends manifest contains retired/research HQC tokens: "
            f"{present}"
        )
    if prefix + "src/hqc.rs" in names:
        raise SystemExit("error: packaged q-periapt-backends contains retired src/hqc.rs")
print("RUST_BACKENDS_NORMALIZED_MANIFEST_PASS")
PY

# Audit the graph Cargo resolves from the normalized publish manifest, not only
# the workspace lockfile. Local patches stand in for the exact-version
# q-periapt crates until the coordinated prerelease set exists on crates.io.
set -- "$PACKAGE_INSPECTION_TARGET"/package/q-periapt-backends-*/Cargo.toml
if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
	printf 'error: expected exactly one normalized q-periapt-backends package directory\n' >&2
	exit 1
fi
NORMALIZED_BACKENDS_DIR=${1%/Cargo.toml}
cargo generate-lockfile --manifest-path "$NORMALIZED_BACKENDS_DIR/Cargo.toml" \
	--config "patch.crates-io.q-periapt-core.path=\"$ROOT/crates/q-periapt-core\"" \
	--config "patch.crates-io.q-periapt-sig.path=\"$ROOT/crates/q-periapt-sig\"" \
	--config "patch.crates-io.q-periapt-kem.path=\"$ROOT/crates/q-periapt-kem\""
cargo audit --deny warnings --file "$NORMALIZED_BACKENDS_DIR/Cargo.lock"
printf 'RUST_BACKENDS_NORMALIZED_AUDIT_PASS\n'

printf 'RUST_PUBLISH_CONTRACT_PASS mode=%s\n' "$PATCHED_DRY_RUN_MODE"
