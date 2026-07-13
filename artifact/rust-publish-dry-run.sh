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
q-periapt-mlkem-native-sys
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

python3 "$ROOT/crates/q-periapt-mlkem-native-sys/scripts/verify-vendor.py"

mkdir -p "$ROOT/target"
metadata_json=$(mktemp "$ROOT/target/qperiapt-cargo-metadata.XXXXXX")
cargo metadata --locked --format-version 1 >"$metadata_json"

python3 - "$metadata_json" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
publishable = {
    "q-periapt-mlkem-native-sys",
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
    "fips203",
    "hax-lib",
    "hax-lib-macros",
    "libcrux-ml-kem",
    "libcrux-platform",
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
        "error: publishable q-periapt-backends contains retired provider/research dependencies: "
        f"{actual_forbidden_dependencies}"
    )
if "hqc" in backends.get("features", {}):
    raise SystemExit("error: publishable q-periapt-backends exposes retired hqc feature")
mlkem_sys_dependencies = [
    dep
    for dep in backends.get("dependencies", [])
    if dep["name"] == "q-periapt-mlkem-native-sys" and dep.get("kind") is None
]
if len(mlkem_sys_dependencies) != 1:
    raise SystemExit(
        "error: q-periapt-backends must have exactly one normal q-periapt-mlkem-native-sys dependency"
    )
if mlkem_sys_dependencies[0].get("req") != expected_req:
    raise SystemExit(
        "error: q-periapt-backends has an unexpected q-periapt-mlkem-native-sys requirement: "
        f"{mlkem_sys_dependencies[0].get('req')}"
    )
mlkem_reference_dependencies = [
    dep for dep in backends.get("dependencies", []) if dep["name"] == "ml-kem"
]
if len(mlkem_reference_dependencies) != 1:
    raise SystemExit(
        "error: q-periapt-backends must have exactly one RustCrypto ml-kem reference dependency"
    )
mlkem_reference = mlkem_reference_dependencies[0]
expected_mlkem_reference = {
    "source": "registry+https://github.com/rust-lang/crates.io-index",
    "req": "=0.2.3",
    "kind": "dev",
    "rename": None,
    "optional": False,
    "uses_default_features": True,
    "features": ["deterministic", "zeroize"],
    "target": None,
    "registry": None,
}
actual_mlkem_reference = {
    key: (
        sorted(mlkem_reference.get(key, []))
        if key == "features"
        else mlkem_reference.get(key)
    )
    for key in expected_mlkem_reference
}
if actual_mlkem_reference != expected_mlkem_reference:
    raise SystemExit(
        "error: q-periapt-backends RustCrypto ml-kem must be the exact, "
        "unconditional dev-only reference dependency =0.2.3 with only "
        "deterministic and zeroize features: "
        f"{actual_mlkem_reference}"
    )

resolve = metadata.get("resolve")
if not isinstance(resolve, dict):
    raise SystemExit("error: cargo metadata omitted the resolved dependency graph")
packages_by_id = {pkg["id"]: pkg for pkg in metadata["packages"]}
nodes_by_id = {node["id"]: node for node in resolve.get("nodes", [])}
backend_ids = [
    package_id
    for package_id, pkg in packages_by_id.items()
    if pkg["name"] == "q-periapt-backends" and package_id in workspace_member_ids
]
if len(backend_ids) != 1:
    raise SystemExit(
        "error: resolved graph must contain exactly one workspace q-periapt-backends root"
    )
normal_graph_ids: set[str] = set()
pending = backend_ids.copy()
while pending:
    package_id = pending.pop()
    if package_id in normal_graph_ids:
        continue
    if package_id not in packages_by_id or package_id not in nodes_by_id:
        raise SystemExit(f"error: incomplete cargo resolved graph at package id {package_id}")
    normal_graph_ids.add(package_id)
    for dependency in nodes_by_id[package_id].get("deps", []):
        dependency_kinds = dependency.get("dep_kinds")
        if not isinstance(dependency_kinds, list) or not dependency_kinds:
            raise SystemExit(
                "error: cargo resolved graph dependency lacks dependency-kind metadata: "
                f"{package_id} -> {dependency.get('pkg')}"
            )
        # Include normal edges for every target predicate. This is deliberately
        # conservative: a provider hidden behind a target-specific normal edge
        # is still part of the production release surface.
        if any(kind.get("kind") is None for kind in dependency_kinds):
            dependency_id = dependency.get("pkg")
            if dependency_id not in packages_by_id:
                raise SystemExit(
                    "error: cargo resolved graph references an unknown package id: "
                    f"{dependency_id}"
                )
            pending.append(dependency_id)

normal_graph_names = [
    packages_by_id[package_id]["name"] for package_id in normal_graph_ids
]
mlkem_provider_names = {
    "q-periapt-mlkem-native-sys",
    "ml-kem",
    "fips203",
    "libcrux-ml-kem",
}
resolved_mlkem_providers = sorted(
    name for name in normal_graph_names if name in mlkem_provider_names
)
if resolved_mlkem_providers != ["q-periapt-mlkem-native-sys"]:
    raise SystemExit(
        "error: q-periapt-backends production normal graph must resolve only the "
        "q-periapt-mlkem-native-sys ML-KEM provider: "
        f"{resolved_mlkem_providers}"
    )
retired_normal_graph_packages = sorted(
    set(normal_graph_names) & forbidden_backend_dependencies
)
if retired_normal_graph_packages:
    raise SystemExit(
        "error: q-periapt-backends production normal graph contains retired "
        f"provider/research packages: {retired_normal_graph_packages}"
    )
print(
    "RUST_MLKEM_PROVIDER_FENCE_PASS "
    "reference=ml-kem@0.2.3:dev-only normal=q-periapt-mlkem-native-sys"
)
mlkem_sys = packages["q-periapt-mlkem-native-sys"]
normal_sys_dependencies = [
    dep for dep in mlkem_sys.get("dependencies", []) if dep.get("kind") is None
]
if normal_sys_dependencies:
    raise SystemExit(
        "error: q-periapt-mlkem-native-sys must not add Rust runtime dependencies: "
        f"{sorted(dep['name'] for dep in normal_sys_dependencies)}"
    )
sys_build_dependencies = [
    dep for dep in mlkem_sys.get("dependencies", []) if dep.get("kind") == "build"
]
if (
    len(sys_build_dependencies) != 1
    or sys_build_dependencies[0]["name"] != "cc"
    or sys_build_dependencies[0].get("req") != "=1.2.67"
):
    raise SystemExit(
        "error: q-periapt-mlkem-native-sys must pin its sole C build dependency to cc =1.2.67"
    )
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
			q-periapt-mlkem-native-sys | q-periapt-core | q-periapt-cli)
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
					--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"' \
					>"$log" 2>&1
				rc=$?
				;;
			q-periapt-policy)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" \
					--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
					--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
					--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
					--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"' \
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
					--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"' \
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
					--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"' \
					>"$log" 2>&1
				rc=$?
				;;
			q-periapt-rustls)
				cargo publish --dry-run $ALLOW_DIRTY_ARG --locked -p "$crate" \
					--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
					--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
					--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
					--config 'patch.crates-io.q-periapt-policy.path="crates/q-periapt-policy"' \
					--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"' \
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
# Produce and verify fresh sys/backend archives in an isolated target after all
# ten dry-runs have passed. Verification intentionally leaves Cargo's exact
# normalized package directories available for the independent resolved-graph
# audit below; isolation guarantees there can be only one candidate per crate.
sys_package_inspection_log="$PACKAGE_INSPECTION_TARGET/cargo-package-mlkem-native-sys.log"
set +e
cargo package $ALLOW_DIRTY_ARG --locked \
	--target-dir "$PACKAGE_INSPECTION_TARGET" \
	-p q-periapt-mlkem-native-sys >"$sys_package_inspection_log" 2>&1
sys_package_inspection_rc=$?
set -e
cat "$sys_package_inspection_log"
if [ "$sys_package_inspection_rc" -ne 0 ]; then
	printf 'error: isolated q-periapt-mlkem-native-sys package inspection failed (exit=%s)\n' "$sys_package_inspection_rc" >&2
	exit "$sys_package_inspection_rc"
fi
python3 - "$metadata_json" "$PACKAGE_INSPECTION_TARGET/package" "$sys_package_inspection_log" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
import tarfile

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
packages = {pkg["name"]: pkg for pkg in metadata["packages"]}
name = "q-periapt-mlkem-native-sys"
version = packages[name]["version"]
archive = pathlib.Path(sys.argv[2]) / f"{name}-{version}.crate"
log_lines = pathlib.Path(sys.argv[3]).read_text().splitlines()
for line in log_lines:
    if "warning:" in line.lower():
        raise SystemExit(
            "error: isolated q-periapt-mlkem-native-sys package inspection emitted a warning: "
            f"{line}"
        )
if not archive.is_file() or archive.is_symlink():
    raise SystemExit(f"error: expected a regular sys crate archive: {archive}")

prefix = f"{name}-{version}/"
required_files = {
    "Cargo.toml",
    "Cargo.toml.orig",
    "LICENSE",
    "LICENSES/Apache-2.0.txt",
    "LICENSES/MIT.txt",
    "README.md",
    "build.rs",
    "src/mlkem_bridge.c",
    "src/mlkem_config.h",
    "vendor/INVENTORY.sha256",
    "vendor/LICENSE-INVENTORY.md",
    "vendor/LICENSE.mlkem-native",
    "vendor/PROVENANCE.md",
}
bad_path_parts = {
    ".git",
    ".github",
    "artifact",
    "bench",
    "benches",
    "example",
    "examples",
    "fuzz",
    "target",
    "test",
    "tests",
}
bad_suffixes = {
    ".env",
    ".key",
    ".mobileprovision",
    ".p12",
    ".pem",
    ".pyc",
    ".pyo",
    ".xcresult",
}
allowed_vendor_suffixes = {".S", ".c", ".h", ".inc"}

with tarfile.open(archive, mode="r:gz") as packaged:
    members = packaged.getmembers()
    member_names = [member.name for member in members]
    names = set(member_names)
    if len(member_names) != len(names):
        raise SystemExit("error: sys crate archive contains duplicate member names")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"error: sys crate archive contains unsafe path: {member.name}")
        if not member.name.startswith(prefix):
            raise SystemExit(
                f"error: sys crate archive contains an unexpected top-level path: {member.name}"
            )
        if not (member.isfile() or member.isdir()):
            raise SystemExit(
                "error: sys crate archive contains a link or special entry: "
                f"{member.name} type={member.type!r}"
            )
        relative = pathlib.PurePosixPath(*path.parts[1:])
        if member.isfile():
            lower_parts = {part.lower() for part in relative.parts}
            if lower_parts & bad_path_parts:
                raise SystemExit(
                    f"error: sys crate archive contains forbidden path: {relative}"
                )
            if relative.name == "id_rsa" or relative.suffix.lower() in bad_suffixes:
                raise SystemExit(
                    f"error: sys crate archive contains forbidden file: {relative}"
                )

    missing = sorted(path for path in required_files if prefix + path not in names)
    if missing:
        raise SystemExit(f"error: sys crate archive is missing release files: {missing}")

    def read_file(relative: str) -> bytes:
        member = packaged.getmember(prefix + relative)
        if not member.isfile():
            raise SystemExit(f"error: expected regular packaged file: {relative}")
        extracted = packaged.extractfile(member)
        if extracted is None:
            raise SystemExit(f"error: cannot read packaged file: {relative}")
        return extracted.read()

    provenance = read_file("vendor/PROVENANCE.md").decode("utf-8")
    required_provenance_tokens = {
        "https://github.com/pq-code-package/mlkem-native",
        "v1.2.0",
        "0ba906cb14b1c241476134d7403a811b382ca498",
        "f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677",
        "77603845ef1bc00cfed17635d4d6844bbf2019b656a3baea8ab18041daa74396",
    }
    missing_provenance = sorted(
        token for token in required_provenance_tokens if token not in provenance
    )
    if missing_provenance:
        raise SystemExit(
            "error: packaged mlkem-native provenance lacks pinned trust anchors: "
            f"{missing_provenance}"
        )
    if "9206258" in provenance:
        raise SystemExit(
            "error: packaged mlkem-native provenance contains the rejected 9206258 tree hash"
        )

    upstream_license = read_file("vendor/LICENSE.mlkem-native")
    upstream_license_sha256 = hashlib.sha256(upstream_license).hexdigest()
    if upstream_license_sha256 != "6393331d41b9fed47a9e18d21b9b844ae8e76bcad8b6da45604c132ae13f3029":
        raise SystemExit(
            "error: packaged mlkem-native license does not match the pinned v1.2.0 license: "
            f"{upstream_license_sha256}"
        )
    license_inventory = read_file("vendor/LICENSE-INVENTORY.md").decode("utf-8")
    required_license_tokens = {"mlkem-native", "Apache-2.0", "ISC", "MIT"}
    missing_license_tokens = sorted(
        token for token in required_license_tokens if token not in license_inventory
    )
    if missing_license_tokens:
        raise SystemExit(
            "error: packaged vendor license inventory is incomplete: "
            f"{missing_license_tokens}"
        )

    inventory_bytes = read_file("vendor/INVENTORY.sha256")
    inventory_sha256 = hashlib.sha256(inventory_bytes).hexdigest()
    if inventory_sha256 != "83c221011e43ff9d8edfb154ca816e876de955ce2861fe9f686f2fc432138872":
        raise SystemExit(
            "error: packaged mlkem-native inventory does not match the pinned v1.2.0 inventory: "
            f"{inventory_sha256}"
        )
    inventory_lines = inventory_bytes.decode("utf-8").splitlines()
    inventory: dict[str, str] = {}
    inventory_order: list[str] = []
    for line_number, raw_line in enumerate(inventory_lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([0-9a-f]{64})\s+\*?([^\s]+)", line)
        if match is None:
            raise SystemExit(
                "error: invalid vendor inventory line "
                f"{line_number}: {raw_line!r}"
            )
        digest, relative_name = match.groups()
        relative_path = pathlib.PurePosixPath(relative_name)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise SystemExit(
                f"error: vendor inventory contains unsafe/out-of-scope path: {relative_name}"
            )
        if relative_name in inventory:
            raise SystemExit(f"error: duplicate vendor inventory path: {relative_name}")
        inventory[relative_name] = digest
        inventory_order.append(relative_name)
    if not inventory:
        raise SystemExit("error: packaged vendor inventory is empty")
    if inventory_order != sorted(inventory_order):
        raise SystemExit("error: packaged vendor inventory must be path-sorted")

    packaged_vendor_files = {
        member.name.removeprefix(prefix + "vendor/mlkem-native/")
        for member in members
        if member.isfile() and member.name.startswith(prefix + "vendor/mlkem-native/")
    }
    code_suffixes = {".S", ".c", ".h", ".inc"}
    inventory_code_files = {
        path for path in inventory if pathlib.PurePosixPath(path).suffix in code_suffixes
    }
    expected_readmes = {
        "README.md",
        "src/fips202/native/armv81m/README.md",
        "src/native/aarch64/README.md",
        "src/native/ppc64le/README.md",
        "src/native/riscv64/README.md",
        "src/native/x86_64/README.md",
    }
    inventory_non_code = set(inventory) - inventory_code_files
    if inventory_non_code != expected_readmes:
        raise SystemExit(
            "error: vendor inventory non-code set differs from the six pinned upstream READMEs: "
            f"missing={sorted(expected_readmes - inventory_non_code)} "
            f"extra={sorted(inventory_non_code - expected_readmes)}"
        )
    if len(inventory_code_files) != 118:
        raise SystemExit(
            "error: pinned mlkem-native v1.2.0 code inventory must contain 118 files, got "
            f"{len(inventory_code_files)}"
        )
    if packaged_vendor_files != inventory_code_files:
        raise SystemExit(
            "error: packaged vendor code/inventory-subset mismatch: "
            f"missing={sorted(inventory_code_files - packaged_vendor_files)} "
            f"extra={sorted(packaged_vendor_files - inventory_code_files)}"
        )
    for relative_name in sorted(packaged_vendor_files):
        relative_path = pathlib.PurePosixPath(relative_name)
        if relative_path.suffix not in allowed_vendor_suffixes:
            raise SystemExit(
                f"error: packaged vendor tree contains a forbidden file type: {relative_name}"
            )
        lower_parts = {part.lower() for part in relative_path.parts}
        if lower_parts & bad_path_parts:
            raise SystemExit(
                f"error: packaged vendor tree contains a forbidden path: {relative_name}"
            )
        actual = hashlib.sha256(
            read_file(f"vendor/mlkem-native/{relative_name}")
        ).hexdigest()
        if actual != inventory[relative_name]:
            raise SystemExit(
                "error: packaged vendor file hash mismatch: "
                f"{relative_name} expected={inventory[relative_name]} actual={actual}"
            )

    build_rs = read_file("build.rs").decode("utf-8")
    bridge_c = read_file("src/mlkem_bridge.c").decode("utf-8")
    local_config = read_file("src/mlkem_config.h").decode("utf-8")
    build_surface = "\n".join((build_rs, bridge_c, local_config))
    config_selection = re.compile(
        r'\.define\(\s*"MLK_CONFIG_FILE"\s*,\s*'
        r'Some\(\s*"\\"mlkem_config\.h\\""\s*\)\s*\)'
    )
    if config_selection.search(build_rs) is None:
        raise SystemExit(
            "error: portable build does not select the packaged mlkem_config.h"
        )
    source_files = re.findall(r'\.file\(\s*"([^"]+)"', build_rs)
    if source_files != ["src/mlkem_bridge.c"] or re.search(r"\.files\s*\(", build_rs):
        raise SystemExit(
            "error: sys crate must compile exactly the single portable bridge translation unit: "
            f"{source_files}"
        )
    if re.search(r'(?m)^\s*#\s*include\s*"mlkem_native\.c"\s*$', bridge_c) is None:
        raise SystemExit("error: portable bridge does not include pinned mlkem_native.c")
    required_guard_tokens = {
        "MLK_CONFIG_USE_NATIVE_BACKEND_ARITH",
        "MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202",
        "MLK_CONFIG_ARITH_BACKEND_FILE",
        "MLK_CONFIG_FIPS202_BACKEND_FILE",
        "MLK_CONFIG_FIPS202_CUSTOM_HEADER",
        "MLK_CONFIG_FIPS202X4_CUSTOM_HEADER",
    }
    missing_guard_tokens = sorted(
        token for token in required_guard_tokens if token not in local_config
    )
    if missing_guard_tokens or "#error" not in local_config:
        raise SystemExit(
            "error: portable config lacks fail-fast native-backend guards: "
            f"{missing_guard_tokens}"
        )
    native_enable_patterns = {
        "C #define MLK_CONFIG_USE_NATIVE_BACKEND_*": re.compile(
            r"(?m)^\s*#\s*define\s+MLK_CONFIG_USE_NATIVE_BACKEND_(?:ARITH|FIPS202)(?:\s|$)"
        ),
        "cc::Build::define MLK_CONFIG_USE_NATIVE_BACKEND_*": re.compile(
            r"\.define\(\s*\"MLK_CONFIG_USE_NATIVE_BACKEND_(?:ARITH|FIPS202)\""
        ),
        "C #define MLK_CONFIG_*_BACKEND_FILE": re.compile(
            r"(?m)^\s*#\s*define\s+MLK_CONFIG_(?:ARITH|FIPS202)_BACKEND_FILE(?:\s|$)"
        ),
        "cc::Build::define MLK_CONFIG_*_BACKEND_FILE": re.compile(
            r"\.define\(\s*\"MLK_CONFIG_(?:ARITH|FIPS202)_BACKEND_FILE\""
        ),
        "assembly translation unit": re.compile(
            r"(?i)#\s*include\s*[<\"][^>\"]+\.S[>\"]|"
            r"\.files?\([^\n)]*\.S|mlkem_native_asm\.S"
        ),
        "prebuilt object": re.compile(r"\.object\("),
        "native assembly symbol": re.compile(r"(?i)\b[a-z_][a-z0-9_]*_asm\s*\("),
    }
    enabled_native_shapes = sorted(
        label for label, pattern in native_enable_patterns.items() if pattern.search(build_surface)
    )
    if enabled_native_shapes:
        raise SystemExit(
            "error: sys crate release build is not portable-only: "
            f"{enabled_native_shapes}"
        )

print(
    "RUST_MLKEM_NATIVE_SYS_ARCHIVE_PASS "
    f"vendor_files={len(packaged_vendor_files)} "
    "upstream=v1.2.0 commit=0ba906cb14b1c241476134d7403a811b382ca498"
)
PY

package_inspection_log="$PACKAGE_INSPECTION_TARGET/cargo-package.log"
set +e
cargo package $ALLOW_DIRTY_ARG --locked \
	--target-dir "$PACKAGE_INSPECTION_TARGET" \
	--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
	--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
	--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
	--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"' \
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
        "fips203",
        "hax-lib",
        "hax-lib-macros",
        "libcrux-ml-kem",
        "libcrux-platform",
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
    if "q-periapt-mlkem-native-sys" not in manifest:
        raise SystemExit(
            "error: normalized q-periapt-backends manifest lacks q-periapt-mlkem-native-sys"
        )
    if any(name.startswith(prefix + "vendor/mlkem-native/") for name in names):
        raise SystemExit(
            "error: q-periapt-backends duplicates the sys crate's vendored mlkem-native tree"
        )
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
	--config "patch.crates-io.q-periapt-kem.path=\"$ROOT/crates/q-periapt-kem\"" \
	--config "patch.crates-io.q-periapt-mlkem-native-sys.path=\"$ROOT/crates/q-periapt-mlkem-native-sys\""
cargo audit --deny warnings --file "$NORMALIZED_BACKENDS_DIR/Cargo.lock"
printf 'RUST_BACKENDS_NORMALIZED_AUDIT_PASS\n'

if [ "$ALLOW_DIRTY_ARG" = "--allow-dirty" ]; then
	printf 'RUST_PUBLISH_CONTRACT_DIAGNOSTIC_PASS dirty=1 mode=%s\n' "$PATCHED_DRY_RUN_MODE"
else
	printf 'RUST_PUBLISH_CONTRACT_PASS dirty=0 mode=%s\n' "$PATCHED_DRY_RUN_MODE"
fi
