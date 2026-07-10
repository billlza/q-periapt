#!/bin/sh
# Fail-closed Rust crate publish contract for Q-Periapt.
#
# Default mode is clean-tree only. For an in-progress local diagnostic run, set
# QPERIAPT_ALLOW_DIRTY_PUBLISH_DRY_RUN=1; that proves only a dirty dry-run, never
# release readiness.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2

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
NONPUBLISHABLE_CRATES="
q-periapt-tls-demo
q-periapt-ctstats
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
nonpublishable = {"q-periapt-tls-demo", "q-periapt-ctstats"}
packages = {pkg["name"]: pkg for pkg in metadata["packages"]}
missing = sorted((publishable | nonpublishable) - set(packages))
if missing:
    raise SystemExit(f"error: release plan references missing packages: {missing}")
workspace_versions = {packages[name]["version"] for name in publishable | nonpublishable}
if len(workspace_versions) != 1:
    raise SystemExit(f"error: workspace package versions diverged: {sorted(workspace_versions)}")
version = workspace_versions.pop()
expected_req = f"^{version}"
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

printf 'RUST_PUBLISH_CONTRACT_PASS mode=%s\n' "$PATCHED_DRY_RUN_MODE"
