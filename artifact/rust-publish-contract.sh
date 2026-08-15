#!/bin/sh
# Fail-closed Rust crate package and pre-publication contract for Q-Periapt.
#
# Default mode is clean-tree only. For an in-progress local diagnostic run, set
# QPERIAPT_ALLOW_DIRTY_RUST_PACKAGE_CONTRACT=1; that always produces only a
# diagnostic transcript recording the observed dirty state, never release
# readiness or a committed package handoff.
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
ALLOW_DIRTY=${QPERIAPT_ALLOW_DIRTY_RUST_PACKAGE_CONTRACT:-0}
HANDOFF_INNER=${QPERIAPT_RUST_PACKAGE_CONTRACT_INNER:-0}

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

CARGO_AUDIT_BIN=$(command -v cargo-audit)
case "$CARGO_AUDIT_BIN" in
	/*) ;;
	*)
		printf 'error: cargo-audit executable path must be absolute\n' >&2
		exit 2
		;;
esac

run_cargo_captured() {
	label=$1
	stdout_log=$2
	stderr_log=$3
	shift 3
	set +e
	CARGO_TERM_COLOR=never "$@" >"$stdout_log" 2>"$stderr_log"
	rc=$?
	set -e
	cat "$stdout_log"
	if [ "$rc" -ne 0 ]; then
		printf 'error: %s failed (exit=%s)\n' "$label" "$rc" >&2
		exit "$rc"
	fi
	python3 - "$label" "$stdout_log" "$stderr_log" <<'PY'
import pathlib
import sys

from rust_publish_contract import RustPublishContractError, validate_cargo_output

label = sys.argv[1]
streams = []
for raw_path in sys.argv[2:]:
    path = pathlib.Path(raw_path)
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"error: {label} did not produce a safe captured stream: {path}")
    streams.append(path.read_text(encoding="utf-8"))
try:
    validate_cargo_output(label, streams)
except RustPublishContractError as exc:
    raise SystemExit(f"error: {exc}") from exc
print(f"RUST_CARGO_WARNING_FREE_PASS {label}")
PY
}

verify_cargo_package_completion() {
	crate=$1
	stdout_log=$2
	stderr_log=$3
	python3 - "$crate" "$stdout_log" "$stderr_log" <<'PY'
import pathlib
import sys

from rust_publish_contract import (
    RustPublishContractError,
    validate_cargo_package_completion,
)

crate = sys.argv[1]
streams = [pathlib.Path(path).read_text(encoding="utf-8") for path in sys.argv[2:]]
try:
    validate_cargo_package_completion(crate, streams)
except RustPublishContractError as exc:
    raise SystemExit(f"error: {exc}") from exc
print(f"RUST_PACKAGE_COMPLETION_PASS {crate}")
PY
}

create_owned_package_target() {
	owned_target_identity=$(python3 - "$1" <<'PY'
import sys

from rust_publish_contract import RustPublishContractError, create_owned_package_directory

try:
    path, device, inode = create_owned_package_directory(sys.argv[1])
except RustPublishContractError as exc:
    raise SystemExit(f"error: {exc}") from exc
if any(character in str(path) for character in ":\r\n"):
    raise SystemExit("error: owned package directory path is not shell-safe")
print(f"{path}:{device}:{inode}")
PY
	)
	OWNED_PACKAGE_TARGET=${owned_target_identity%%:*}
	owned_target_remainder=${owned_target_identity#*:}
	OWNED_PACKAGE_DEVICE=${owned_target_remainder%%:*}
	OWNED_PACKAGE_INODE=${owned_target_remainder#*:}
	if [ -z "$OWNED_PACKAGE_TARGET" ] || [ "$owned_target_remainder" = "$owned_target_identity" ] || [ "$OWNED_PACKAGE_INODE" = "$owned_target_remainder" ]; then
		printf 'error: owned package directory identity is malformed\n' >&2
		exit 1
	fi
}

cleanup_active_package_target() {
	if [ -z "${ACTIVE_PACKAGE_TARGET:-}" ]; then
		return
	fi
	cleanup_target_path=$ACTIVE_PACKAGE_TARGET
	cleanup_target_device=$ACTIVE_PACKAGE_DEVICE
	cleanup_target_inode=$ACTIVE_PACKAGE_INODE
	cleanup_target_label=$ACTIVE_PACKAGE_LABEL
	ACTIVE_PACKAGE_TARGET=
	ACTIVE_PACKAGE_DEVICE=
	ACTIVE_PACKAGE_INODE=
	ACTIVE_PACKAGE_LABEL=
	python3 - "$cleanup_target_path" "$cleanup_target_device" "$cleanup_target_inode" "$cleanup_target_label" <<'PY'
import pathlib
import sys

from rust_publish_contract import RustPublishContractError, remove_owned_package_directory

try:
    remove_owned_package_directory(
        pathlib.Path(sys.argv[1]),
        int(sys.argv[2]),
        int(sys.argv[3]),
    )
except (RustPublishContractError, ValueError) as exc:
    raise SystemExit(f"error: {exc}") from exc
print(f"RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS {sys.argv[4]}")
PY
}

cleanup_owned_cargo_home() {
	if [ -z "${OWNED_CARGO_HOME:-}" ]; then
		return
	fi
	cargo_home_path=$OWNED_CARGO_HOME
	cargo_home_device=$OWNED_CARGO_HOME_DEVICE
	cargo_home_inode=$OWNED_CARGO_HOME_INODE
	OWNED_CARGO_HOME=
	OWNED_CARGO_HOME_DEVICE=
	OWNED_CARGO_HOME_INODE=
	python3 - "$cargo_home_path" "$cargo_home_device" "$cargo_home_inode" <<'PY'
import pathlib
import sys

from rust_publish_contract import RustPublishContractError, remove_owned_package_directory

try:
    remove_owned_package_directory(
        pathlib.Path(sys.argv[1]),
        int(sys.argv[2]),
        int(sys.argv[3]),
    )
except (RustPublishContractError, ValueError) as exc:
    raise SystemExit(f"error: {exc}") from exc
print("RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS cargo-home")
PY
}

cleanup_contract_state() {
	set +e
	cleanup_active_package_target
	active_cleanup_rc=$?
	cleanup_owned_cargo_home
	cargo_home_cleanup_rc=$?
	set -e
	if [ "$active_cleanup_rc" -ne 0 ]; then
		return "$active_cleanup_rc"
	fi
	return "$cargo_home_cleanup_rc"
}

cleanup_contract_exit() {
	primary_status=$1
	trap - 0 1 2 15
	set +e
	cleanup_contract_state
	cleanup_status=$?
	set -e
	if [ "$primary_status" -ne 0 ]; then
		if [ "$cleanup_status" -ne 0 ]; then
			printf 'error: Rust package contract cleanup also failed (exit=%s)\n' "$cleanup_status" >&2
		fi
		exit "$primary_status"
	fi
	exit "$cleanup_status"
}

cleanup_contract_signal() {
	signal_number=$1
	trap - 0 1 2 15
	set +e
	cleanup_contract_state
	cleanup_status=$?
	set -e
	if [ "$cleanup_status" -ne 0 ]; then
		printf 'error: Rust package contract signal cleanup failed (exit=%s)\n' "$cleanup_status" >&2
	fi
	exit $((128 + signal_number))
}

cleanup_outer_handoff_stage() {
	if [ -z "${OUTER_HANDOFF_STAGE:-}" ]; then
		return
	fi
	stage_path=$OUTER_HANDOFF_STAGE
	stage_device=$OUTER_HANDOFF_STAGE_DEVICE
	stage_inode=$OUTER_HANDOFF_STAGE_INODE
	OUTER_HANDOFF_STAGE=
	OUTER_HANDOFF_STAGE_DEVICE=
	OUTER_HANDOFF_STAGE_INODE=
	python3 - "$stage_path" "$stage_device" "$stage_inode" <<'PY'
import pathlib
import sys

from rust_publish_contract import RustPublishContractError, remove_owned_package_directory

try:
    remove_owned_package_directory(
        pathlib.Path(sys.argv[1]),
        int(sys.argv[2]),
        int(sys.argv[3]),
    )
except (RustPublishContractError, ValueError) as exc:
    del exc
    raise SystemExit("error: Rust package handoff stage cleanup failed") from None
PY
}

cleanup_outer_handoff_exit() {
	primary_status=$1
	trap - 0 1 2 15
	set +e
	cleanup_outer_handoff_stage
	cleanup_status=$?
	set -e
	if [ "$primary_status" -ne 0 ]; then
		if [ "$cleanup_status" -ne 0 ]; then
			printf 'error: Rust package handoff stage cleanup also failed (exit=%s)\n' "$cleanup_status" >&2
		fi
		exit "$primary_status"
	fi
	exit "$cleanup_status"
}

cleanup_outer_handoff_signal() {
	signal_number=$1
	trap - 0 1 2 15
	set +e
	cleanup_outer_handoff_stage
	cleanup_status=$?
	set -e
	if [ "$cleanup_status" -ne 0 ]; then
		printf 'error: Rust package handoff signal cleanup failed (exit=%s)\n' "$cleanup_status" >&2
	fi
	exit $((128 + signal_number))
}

validate_isolated_advisory_database() {
	python3 - "$CARGO_HOME/advisory-db" <<'PY'
import pathlib
import sys

from rust_publish_contract import (
    RUSTSEC_ADVISORY_DB_URL,
    RustPublishContractError,
    validate_rustsec_advisory_database,
)

try:
    commit = validate_rustsec_advisory_database(pathlib.Path(sys.argv[1]))
except RustPublishContractError as exc:
    raise SystemExit(f"error: {exc}") from exc
print(
    "RUST_ADVISORY_DB_PASS "
    f"origin={RUSTSEC_ADVISORY_DB_URL} commit={commit} "
    "clean=1 isolated_cargo_home=1"
)
PY
}

python3 - <<'PY'
import os

from rust_publish_contract import RustPublishContractError, validate_no_registry_credentials

try:
    validate_no_registry_credentials(os.environ)
except RustPublishContractError as exc:
    raise SystemExit(f"error: {exc}") from None
PY

case "$ALLOW_DIRTY" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ALLOW_DIRTY_RUST_PACKAGE_CONTRACT must be 0 or 1\n' >&2
		exit 2
		;;
esac
case "$HANDOFF_INNER" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_RUST_PACKAGE_CONTRACT_INNER must be 0 or 1\n' >&2
		exit 2
		;;
esac

if [ "$HANDOFF_INNER" = "0" ]; then
	if [ -n "${QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE:-}" ] || \
		[ -n "${QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE_DEVICE:-}" ] || \
		[ -n "${QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE_INODE:-}" ]; then
		printf 'error: Rust package handoff inner variables are reserved\n' >&2
		exit 2
	fi
	create_owned_package_target qperiapt-rust-package-handoff-stage.
	OUTER_HANDOFF_STAGE=$OWNED_PACKAGE_TARGET
	OUTER_HANDOFF_STAGE_DEVICE=$OWNED_PACKAGE_DEVICE
	OUTER_HANDOFF_STAGE_INODE=$OWNED_PACKAGE_INODE
	trap 'cleanup_outer_handoff_exit $?' 0
	trap 'cleanup_outer_handoff_signal 1' 1
	trap 'cleanup_outer_handoff_signal 2' 2
	trap 'cleanup_outer_handoff_signal 15' 15
	set +e
	python3 - "$ROOT" "$OUTER_HANDOFF_STAGE" \
		"$OUTER_HANDOFF_STAGE_DEVICE" "$OUTER_HANDOFF_STAGE_INODE" \
		"$ALLOW_DIRTY" <<'PY'
import os
import pathlib
import stat
import sys

from bounded_process import BoundedProcessError, capture_output
from crates_io_publication import (
    CratesIoPublicationError,
    MAX_HANDOFF_STDERR_BYTES,
    MAX_TRANSCRIPT_BYTES,
    persist_rust_package_contract_capture,
    persist_rust_package_diagnostic_capture,
    validated_rust_package_contract_failure_marker,
)
from publication_receipt_io import PublicationReceiptIOError

root = pathlib.Path(sys.argv[1])
stage = pathlib.Path(sys.argv[2])
expected_device = int(sys.argv[3])
expected_inode = int(sys.argv[4])
allow_dirty = sys.argv[5]
if allow_dirty not in {"0", "1"}:
    raise SystemExit("error: invalid bounded Rust package contract mode")
flags = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
descriptor = -1
try:
    descriptor = os.open(stage, flags)
    metadata = os.fstat(descriptor)
    named = stage.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_dev != expected_device
        or metadata.st_ino != expected_inode
        or named.st_dev != expected_device
        or named.st_ino != expected_inode
    ):
        raise BoundedProcessError("output_path", "Rust package handoff stage identity differs")
    environment = dict(os.environ)
    environment["QPERIAPT_RUST_PACKAGE_CONTRACT_INNER"] = "1"
    environment["QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE"] = str(stage)
    environment["QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE_DEVICE"] = sys.argv[3]
    environment["QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE_INODE"] = sys.argv[4]
    result = capture_output(
        ["/bin/sh", str(root / "artifact" / "rust-publish-contract.sh")],
        timeout_seconds=300,
        maximum_stdout_bytes=MAX_TRANSCRIPT_BYTES,
        maximum_stderr_bytes=MAX_HANDOFF_STDERR_BYTES,
        environment=environment,
    )
    if result.returncode != 0:
        marker = validated_rust_package_contract_failure_marker(result)
        written = sys.stderr.buffer.write(marker)
        sys.stderr.buffer.flush()
        if written != len(marker):
            raise OSError("Rust package failure marker replay was incomplete")
        raise SystemExit(1)
    if allow_dirty == "0":
        persist_rust_package_contract_capture(descriptor, result)
    else:
        persist_rust_package_diagnostic_capture(descriptor, result)
except (
    BoundedProcessError,
    CratesIoPublicationError,
    OSError,
    PublicationReceiptIOError,
    ValueError,
) as exc:
    del exc
    print("error: bounded Rust package contract failed", file=sys.stderr)
    raise SystemExit(1) from None
finally:
    if descriptor >= 0:
        os.close(descriptor)
PY
	inner_status=$?
	set -e
	if [ "$inner_status" -ne 0 ]; then
		exit "$inner_status"
	fi
	python3 - "$OUTER_HANDOFF_STAGE/rust-package-contract.log" <<'PY'
import os
import pathlib
import stat
import sys

from evidence_io import EvidenceIOError, read_regular_snapshot

path = pathlib.Path(sys.argv[1])

def validate_transcript_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError(
            "bounded Rust package contract transcript metadata differs"
        )

try:
    snapshot = read_regular_snapshot(
        path,
        maximum=16 * 1024 * 1024,
        label="bounded Rust package contract transcript",
        validate_metadata=validate_transcript_metadata,
    )
    written = sys.stdout.buffer.write(snapshot.data)
    sys.stdout.buffer.flush()
except (BrokenPipeError, EvidenceIOError, OSError) as exc:
    del exc
    print("error: cannot replay bounded Rust package contract transcript", file=sys.stderr)
    raise SystemExit(1) from None
if written != snapshot.size:
    raise SystemExit("error: Rust package contract transcript replay was incomplete")
PY
	if [ "$ALLOW_DIRTY" = "1" ]; then
		cleanup_outer_handoff_stage
		trap - 0 1 2 15
		exit 0
	fi
	# The Python finalizer owns catchable signals from the manifest commit
	# boundary through the sole marker. Do not race it with the shell cleanup
	# handler in that interval.
	trap '' 1 2 15
	set +e
	python3 - "$OUTER_HANDOFF_STAGE" \
		"$OUTER_HANDOFF_STAGE_DEVICE" "$OUTER_HANDOFF_STAGE_INODE" <<'PY'
import pathlib
import sys

from crates_io_publication import (
    CratesIoPublicationError,
    finalize_rust_package_handoff_for_cli,
)
from publication_receipt_io import PublicationReceiptIOError

try:
    finalize_rust_package_handoff_for_cli(
        pathlib.Path(sys.argv[1]),
        staging_device=int(sys.argv[2]),
        staging_inode=int(sys.argv[3]),
    )
except (CratesIoPublicationError, PublicationReceiptIOError, OSError, ValueError) as exc:
    del exc
    print("error: Rust package handoff finalization failed", file=sys.stderr)
    raise SystemExit(1) from None
PY
	handoff_status=$?
	set -e
	if [ ! -e "$OUTER_HANDOFF_STAGE" ] && [ ! -L "$OUTER_HANDOFF_STAGE" ]; then
		OUTER_HANDOFF_STAGE=
		OUTER_HANDOFF_STAGE_DEVICE=
		OUTER_HANDOFF_STAGE_INODE=
	fi
	trap - 1 2 15
	exit "$handoff_status"
fi

if [ -z "${QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE:-}" ] || \
	[ -z "${QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE_DEVICE:-}" ] || \
	[ -z "${QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE_INODE:-}" ]; then
	printf 'error: inner Rust package contract requires an owned handoff stage identity\n' >&2
	exit 2
fi
package_source_state=$(python3 - "$ROOT" "$ALLOW_DIRTY" <<'PY'
import pathlib
import sys

from rust_publish_contract import RustPublishContractError, inspect_package_source

try:
    commit, dirty = inspect_package_source(
        pathlib.Path(sys.argv[1]),
        allow_dirty=sys.argv[2] == "1",
    )
except RustPublishContractError as exc:
    raise SystemExit(f"error: {exc}") from exc
print(f"{commit}:{int(dirty)}")
PY
)
package_source_commit=${package_source_state%:*}
package_source_dirty=${package_source_state##*:}
if [ "$ALLOW_DIRTY" = "1" ]; then
	printf 'DIRTY_RUST_PACKAGE_CONTRACT_DIAGNOSTIC_ONLY\n'
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

create_owned_package_target qperiapt-package-cargo-home.
OWNED_CARGO_HOME=$OWNED_PACKAGE_TARGET
OWNED_CARGO_HOME_DEVICE=$OWNED_PACKAGE_DEVICE
OWNED_CARGO_HOME_INODE=$OWNED_PACKAGE_INODE
trap 'cleanup_contract_exit $?' 0
trap 'cleanup_contract_signal 1' 1
trap 'cleanup_contract_signal 2' 2
trap 'cleanup_contract_signal 15' 15
CARGO_HOME=$OWNED_CARGO_HOME
export CARGO_HOME
printf 'RUST_CARGO_HOME_ISOLATION_PASS mode=0700 ambient_cargo_home_data=unused\n'

rustc_version=$(rustc +1.96.1 --version)
rustc_verbose=$(rustc +1.96.1 -vV)
cargo_version=$(cargo +1.96.1 --version)
cargo_audit_version=$(cargo-audit --version)
rustc_host=$(python3 - "$rustc_verbose" <<'PY'
import re
import sys

host_lines = [line for line in sys.argv[1].splitlines() if line.startswith("host: ")]
if len(host_lines) != 1:
    raise SystemExit(f"error: rustc -vV must report exactly one host target: {host_lines}")
host = host_lines[0].removeprefix("host: ")
if re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", host) is None:
    raise SystemExit(f"error: rustc -vV reported a malformed host target: {host!r}")
print(host)
PY
)
python3 - "$rustc_version" "$cargo_version" "$cargo_audit_version" <<'PY'
import re
import sys

expected = (
    ("rustc", "1.96.1", sys.argv[1]),
    ("cargo", "1.96.1", sys.argv[2]),
    ("cargo-audit", "0.22.2", sys.argv[3]),
)
for tool, version, output in expected:
    if re.fullmatch(
        rf"{re.escape(tool)} {re.escape(version)}(?: \([^\r\n]+\))?",
        output,
    ) is None:
        raise SystemExit(
            f"error: Rust package contract requires {tool} {version}; got {output!r}"
        )
print("RUST_PACKAGE_TOOLCHAIN_PASS rustc=1.96.1 cargo=1.96.1 cargo-audit=0.22.2")
PY

if [ "$ALLOW_DIRTY" = "0" ]; then
	printf 'RUST_PACKAGE_SOURCE_PASS commit=%s clean=1\n' "$package_source_commit"
else
	printf 'RUST_PACKAGE_SOURCE_DIAGNOSTIC commit=%s dirty=%s\n' \
		"$package_source_commit" "$package_source_dirty"
fi

mkdir -p "$ROOT/target"
metadata_json=$(mktemp "$ROOT/target/qperiapt-cargo-metadata.XXXXXX")
metadata_stderr=$(mktemp "$ROOT/target/qperiapt-cargo-metadata-stderr.XXXXXX")
run_cargo_captured "cargo-metadata" "$metadata_json" "$metadata_stderr" \
	cargo +1.96.1 metadata --locked --format-version 1

python3 - "$metadata_json" <<'PY'
import json
import pathlib
import sys

from rust_publish_contract import exact_internal_dependency_requirement

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
    "q-periapt-migration",
    "q-periapt-policy-agent",
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
# Every release channel moves as one audited set. Exact internal requirements
# prevent Cargo from resolving a mixed stable or prerelease package graph.
expected_req = exact_internal_dependency_requirement(version)
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
performance_reference_features = {
    "implementation-improvement",
    "performance-evidence",
    "portable-reference",
    "portable-runtime",
}
exposed_performance_features = sorted(
    performance_reference_features.intersection(backends.get("features", {}))
)
if exposed_performance_features:
    raise SystemExit(
        "error: publishable q-periapt-backends exposes performance-reference features: "
        f"{exposed_performance_features}"
    )
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
print(
    "RUST_PUBLISH_METADATA_PASS publishable=10 nonpublishable=5 "
    "mlkem_provider=q-periapt-mlkem-native-sys "
    "sys_build_dependency=cc@1.2.67"
)
PY

check_package_list() {
	crate=$1
	list_file=$(mktemp "$ROOT/target/qperiapt-package-$crate.XXXXXX")
	list_stderr=$(mktemp "$ROOT/target/qperiapt-package-$crate-stderr.XXXXXX")
	run_cargo_captured "cargo-package-list-$crate" "$list_file" "$list_stderr" \
		cargo +1.96.1 package $ALLOW_DIRTY_ARG --locked --registry crates-io \
		-p "$crate" --list
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

create_owned_package_target qperiapt-package-verification.
PACKAGE_VERIFICATION_TARGET=$OWNED_PACKAGE_TARGET
ACTIVE_PACKAGE_TARGET=$OWNED_PACKAGE_TARGET
ACTIVE_PACKAGE_DEVICE=$OWNED_PACKAGE_DEVICE
ACTIVE_PACKAGE_INODE=$OWNED_PACKAGE_INODE
ACTIVE_PACKAGE_LABEL=package-verification

run_package_verification() {
	crate=$1
	package_stdout=$(mktemp "$ROOT/target/qperiapt-package-verification-$crate-stdout.XXXXXX")
	package_stderr=$(mktemp "$ROOT/target/qperiapt-package-verification-$crate-stderr.XXXXXX")
	set -- cargo +1.96.1 package --locked --registry crates-io \
		--target-dir "$PACKAGE_VERIFICATION_TARGET" -p "$crate"
	if [ -n "$ALLOW_DIRTY_ARG" ]; then
		set -- "$@" "$ALLOW_DIRTY_ARG"
	fi
	case "$crate" in
		q-periapt-mlkem-native-sys | q-periapt-core | q-periapt-cli) ;;
		q-periapt-kem | q-periapt-sig)
			set -- "$@" \
				--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"'
			;;
		q-periapt-backends)
			set -- "$@" \
				--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
				--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
				--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
				--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"'
			;;
		q-periapt-policy)
			set -- "$@" \
				--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
				--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
				--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
				--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"'
			;;
		q-periapt-ffi | q-periapt-wasm)
			set -- "$@" \
				--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
				--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
				--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
				--config 'patch.crates-io.q-periapt-policy.path="crates/q-periapt-policy"' \
				--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
				--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"'
			;;
		q-periapt-rustls)
			set -- "$@" \
				--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
				--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
				--config 'patch.crates-io.q-periapt-backends.path="crates/q-periapt-backends"' \
				--config 'patch.crates-io.q-periapt-policy.path="crates/q-periapt-policy"' \
				--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"'
			;;
		*)
			printf 'error: no package-verification patch plan for crate: %s\n' "$crate" >&2
			exit 2
			;;
	esac
	run_cargo_captured "cargo-package-verification-$crate" \
		"$package_stdout" "$package_stderr" env RUSTFLAGS='-D warnings' "$@"
	verify_cargo_package_completion "$crate" "$package_stdout" "$package_stderr"
	set -- "$PACKAGE_VERIFICATION_TARGET/package/$crate-"*.crate
	if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
		printf 'error: cargo package verification did not produce exactly one regular archive for %s\n' "$crate" >&2
		exit 1
	fi
	printf 'RUST_PACKAGE_VERIFICATION_PASS %s registry=crates-io upload=not-attempted\n' "$crate"
}

for crate in $PUBLISHABLE_CRATES; do
	run_package_verification "$crate"
done
if [ "$ALLOW_DIRTY" = "0" ]; then
	python3 - "$PACKAGE_VERIFICATION_TARGET" \
		"$ACTIVE_PACKAGE_DEVICE" "$ACTIVE_PACKAGE_INODE" \
		"$QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE" \
		"$QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE_DEVICE" \
		"$QPERIAPT_RUST_PACKAGE_HANDOFF_STAGE_INODE" <<'PY'
import pathlib
import sys

from crates_io_publication import CratesIoPublicationError, stage_verified_crate_handoff
from publication_receipt_io import PublicationReceiptCommittedError, PublicationReceiptIOError

try:
    stage_verified_crate_handoff(
        pathlib.Path(sys.argv[1]),
        pathlib.Path(sys.argv[4]),
        package_device=int(sys.argv[2]),
        package_inode=int(sys.argv[3]),
        staging_device=int(sys.argv[5]),
        staging_inode=int(sys.argv[6]),
    )
except PublicationReceiptCommittedError as exc:
    del exc
    print(
        "RUST_PACKAGE_CONTRACT_FAILURE "
        "stage=handoff-staging category=committed",
        file=sys.stderr,
    )
    raise SystemExit(125) from None
except CratesIoPublicationError as exc:
    del exc
    print(
        "RUST_PACKAGE_CONTRACT_FAILURE "
        "stage=handoff-staging category=contract",
        file=sys.stderr,
    )
    raise SystemExit(1) from None
except PublicationReceiptIOError as exc:
    del exc
    print(
        "RUST_PACKAGE_CONTRACT_FAILURE "
        "stage=handoff-staging category=publication-io",
        file=sys.stderr,
    )
    raise SystemExit(1) from None
except OSError as exc:
    del exc
    print(
        "RUST_PACKAGE_CONTRACT_FAILURE "
        "stage=handoff-staging category=filesystem",
        file=sys.stderr,
    )
    raise SystemExit(1) from None
except ValueError as exc:
    del exc
    print(
        "RUST_PACKAGE_CONTRACT_FAILURE "
        "stage=handoff-staging category=input",
        file=sys.stderr,
    )
    raise SystemExit(1) from None
PY
fi
cleanup_active_package_target

create_owned_package_target qperiapt-package-inspection.
PACKAGE_INSPECTION_TARGET=$OWNED_PACKAGE_TARGET
ACTIVE_PACKAGE_TARGET=$OWNED_PACKAGE_TARGET
ACTIVE_PACKAGE_DEVICE=$OWNED_PACKAGE_DEVICE
ACTIVE_PACKAGE_INODE=$OWNED_PACKAGE_INODE
ACTIVE_PACKAGE_LABEL=package-inspection

# Produce and verify fresh sys/backend archives in an isolated target after all
# ten registry-bound package verifications have passed. Verification intentionally
# leaves Cargo's exact
# normalized package directories available for the independent resolved-graph
# audit below; isolation guarantees there can be only one candidate per crate.
sys_package_stdout="$PACKAGE_INSPECTION_TARGET/cargo-package-mlkem-native-sys.stdout"
sys_package_stderr="$PACKAGE_INSPECTION_TARGET/cargo-package-mlkem-native-sys.stderr"
run_cargo_captured "cargo-package-inspection-q-periapt-mlkem-native-sys" \
	"$sys_package_stdout" "$sys_package_stderr" env RUSTFLAGS='-D warnings' \
	cargo +1.96.1 package $ALLOW_DIRTY_ARG --locked --registry crates-io \
	--target-dir "$PACKAGE_INSPECTION_TARGET" -p q-periapt-mlkem-native-sys
verify_cargo_package_completion q-periapt-mlkem-native-sys \
	"$sys_package_stdout" "$sys_package_stderr"
python3 - "$metadata_json" "$PACKAGE_INSPECTION_TARGET/package" \
	"$PACKAGE_INSPECTION_TARGET" "$rustc_host" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile

from bounded_process import BoundedProcessError, capture_stdout
from evidence_io import EvidenceIOError, read_regular_snapshot
from rust_publish_contract import (
    RustPublishContractError,
    parse_mlkem_archive_defined_symbols,
    validate_mlkem_native_build_surface,
    validate_mlkem_native_archive_contract,
    validate_packaged_mlkem_native_local_source_digests,
    validate_packaged_mlkem_native_local_sources,
)

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
packages = {pkg["name"]: pkg for pkg in metadata["packages"]}
name = "q-periapt-mlkem-native-sys"
version = packages[name]["version"]
archive = pathlib.Path(sys.argv[2]) / f"{name}-{version}.crate"
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
    "src/build_support.rs",
    "src/build_support_tests.rs",
    "src/lib.rs",
    "src/mlkem_bridge.c",
    "src/mlkem_bridge_asm.S",
    "src/mlkem_bridge.h",
    "src/mlkem_bridge_native.c",
    "src/mlkem_bridge_portable.c",
    "src/mlkem_config.h",
    "src/mlkem_fips202_aarch64.h",
    "src/raw.rs",
    "src/tests.rs",
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
maximum_packaged_member_bytes = 8 * 1024 * 1024

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

    packaged_local_sources = {
        member.name.removeprefix(prefix)
        for member in members
        if member.isfile() and member.name.startswith(prefix + "src/")
    }
    try:
        validate_packaged_mlkem_native_local_sources(packaged_local_sources)
    except RustPublishContractError as source:
        raise SystemExit(f"error: {source}") from source

    def read_file(relative: str) -> bytes:
        member = packaged.getmember(prefix + relative)
        if not member.isfile():
            raise SystemExit(f"error: expected regular packaged file: {relative}")
        if member.size < 0 or member.size > maximum_packaged_member_bytes:
            raise SystemExit(
                f"error: packaged file exceeds the inspection limit: {relative} "
                f"size={member.size}"
            )
        extracted = packaged.extractfile(member)
        if extracted is None:
            raise SystemExit(f"error: cannot read packaged file: {relative}")
        data = extracted.read(maximum_packaged_member_bytes + 1)
        if len(data) != member.size:
            raise SystemExit(
                f"error: packaged file size changed while reading: {relative} "
                f"declared={member.size} actual={len(data)}"
            )
        return data

    try:
        validate_packaged_mlkem_native_local_source_digests(
            {
                relative: read_file(relative)
                for relative in sorted({"build.rs"} | packaged_local_sources)
            }
        )
    except RustPublishContractError as source:
        raise SystemExit(f"error: {source}") from source

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
    build_support = read_file("src/build_support.rs").decode("utf-8")
    bridge_c = read_file("src/mlkem_bridge.c").decode("utf-8")
    bridge_native_c = read_file("src/mlkem_bridge_native.c").decode("utf-8")
    bridge_portable_c = read_file("src/mlkem_bridge_portable.c").decode("utf-8")
    bridge_asm = read_file("src/mlkem_bridge_asm.S").decode("utf-8")
    bridge_h = read_file("src/mlkem_bridge.h").decode("utf-8")
    local_config = read_file("src/mlkem_config.h").decode("utf-8")
    aarch64_fips202 = read_file("src/mlkem_fips202_aarch64.h").decode("utf-8")
    try:
        validate_mlkem_native_build_surface(
            build_rs=build_rs,
            build_support=build_support,
            bridge_c=bridge_c,
            bridge_native_c=bridge_native_c,
            bridge_portable_c=bridge_portable_c,
            bridge_asm=bridge_asm,
            bridge_h=bridge_h,
            local_config=local_config,
            aarch64_fips202=aarch64_fips202,
        )
    except RustPublishContractError as source:
        raise SystemExit(f"error: {source}") from source


def required_tool(name: str) -> str:
    tool = shutil.which(name)
    if tool is None:
        raise SystemExit(f"error: required archive inspection tool not found: {name}")
    path = pathlib.Path(tool)
    try:
        resolved = path.resolve(strict=True)
    except OSError as source:
        raise SystemExit(
            f"error: archive inspection tool cannot be resolved: {tool}: {source}"
        ) from source
    if not path.is_absolute() or not resolved.is_file():
        raise SystemExit(
            f"error: archive inspection tool must be an absolute regular file: {tool}"
        )
    if not os.access(resolved, os.X_OK):
        raise SystemExit(f"error: archive inspection tool is not executable: {tool}")
    return str(resolved)


def run_tool(label: str, arguments: list[str]) -> str:
    try:
        completed = capture_stdout(
            arguments,
            timeout_seconds=30,
            maximum_bytes=256 * 1024,
            stderr=subprocess.STDOUT,
            environment={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except BoundedProcessError as source:
        raise SystemExit(
            f"error: {label} failed at its {source.kind} boundary: {source}"
        ) from source
    if completed.returncode != 0:
        raise SystemExit(
            f"error: {label} failed with exit {completed.returncode}: "
            f"{completed.stdout.decode('utf-8', errors='replace')!r}"
        )
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as source:
        raise SystemExit(f"error: {label} emitted non-UTF-8 output") from source


build_root = pathlib.Path(sys.argv[3])
built_archives = sorted(
    build_root.glob(
        "debug/build/q-periapt-mlkem-native-sys-*/out/libq_periapt_mlkem_native.a"
    )
)
if (
    len(built_archives) != 1
    or not built_archives[0].is_file()
    or built_archives[0].is_symlink()
):
    raise SystemExit(
        "error: packaged sys verification must produce exactly one regular C archive: "
        f"{built_archives}"
    )
built_archive = built_archives[0]
build_output_path = built_archive.parent.parent / "output"
if not build_output_path.is_file() or build_output_path.is_symlink():
    raise SystemExit(
        f"error: packaged sys verification lacks a regular build output: {build_output_path}"
    )
archive_members = run_tool(
    "ar member inspection",
    [required_tool("ar"), "-t", str(built_archive)],
).splitlines()
nm = required_tool("nm")
if sys.platform == "darwin":
    nm_arguments = [nm, "-gUj", str(built_archive)]
    leading_underscore = True
elif sys.platform.startswith("linux"):
    nm_arguments = [nm, "-g", "--defined-only", "-j", str(built_archive)]
    leading_underscore = False
else:
    raise SystemExit(
        f"error: packaged sys archive inspection is unsupported on {sys.platform!r}"
    )
try:
    build_output = read_regular_snapshot(
        build_output_path,
        maximum=1024 * 1024,
        label="packaged sys build output",
    ).data.decode("utf-8")
    defined_symbols = parse_mlkem_archive_defined_symbols(
        run_tool("nm defined-symbol inspection", nm_arguments),
        leading_underscore=leading_underscore,
    )
    archive_receipt = validate_mlkem_native_archive_contract(
        target=sys.argv[4],
        archive_members=archive_members,
        defined_symbols=defined_symbols,
        build_output=build_output,
    )
except (EvidenceIOError, RustPublishContractError, UnicodeDecodeError) as source:
    raise SystemExit(f"error: {source}") from source

print(
    "RUST_MLKEM_NATIVE_SYS_ARCHIVE_BINARY_PASS "
    f"target={sys.argv[4]} "
    f"implementation={archive_receipt.implementation} "
    f"implementation_id={archive_receipt.implementation_id} "
    f"objects={archive_receipt.object_count} "
    f"symbols={archive_receipt.symbol_count} reserved_dynamic_abi=none"
)
print(
    "RUST_MLKEM_NATIVE_SYS_ARCHIVE_PASS "
    f"vendor_files={len(packaged_vendor_files)} "
    "upstream=v1.2.0 commit=0ba906cb14b1c241476134d7403a811b382ca498"
)
PY

package_inspection_stdout="$PACKAGE_INSPECTION_TARGET/cargo-package-backends.stdout"
package_inspection_stderr="$PACKAGE_INSPECTION_TARGET/cargo-package-backends.stderr"
run_cargo_captured "cargo-package-inspection-q-periapt-backends" \
	"$package_inspection_stdout" "$package_inspection_stderr" \
	env RUSTFLAGS='-D warnings' cargo +1.96.1 package $ALLOW_DIRTY_ARG --locked \
	--registry crates-io \
	--target-dir "$PACKAGE_INSPECTION_TARGET" \
	--config 'patch.crates-io.q-periapt-core.path="crates/q-periapt-core"' \
	--config 'patch.crates-io.q-periapt-sig.path="crates/q-periapt-sig"' \
	--config 'patch.crates-io.q-periapt-kem.path="crates/q-periapt-kem"' \
	--config 'patch.crates-io.q-periapt-mlkem-native-sys.path="crates/q-periapt-mlkem-native-sys"' \
	-p q-periapt-backends
verify_cargo_package_completion q-periapt-backends \
	"$package_inspection_stdout" "$package_inspection_stderr"
printf '%s\n' 'RUST_BACKENDS_INSPECTION_PACKAGE_PASS package=q-periapt-backends normalized_archive=present'

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
    raise SystemExit(f"error: package verification did not produce expected archive: {archive}")
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
    forbidden_performance_manifest_tokens = (
        "implementation-improvement",
        "performance-evidence",
        "portable-reference",
        "portable-runtime",
    )
    present_performance_tokens = sorted(
        token for token in forbidden_performance_manifest_tokens if token in manifest
    )
    if present_performance_tokens:
        raise SystemExit(
            "error: normalized q-periapt-backends manifest exposes the evidence-only "
            f"performance reference: {present_performance_tokens}"
        )
    shipping_source_tokens = (
        "qperiapt_performance_evidence",
        "evidence_only_non_product_reference",
        "mlkem-native-1.2.0/portable-c/evidence-only-reference",
    )
    for packaged_name in sorted(names):
        if not packaged_name.startswith(prefix + "src/") or not packaged_name.endswith(".rs"):
            continue
        source_file = packaged.extractfile(packaged_name)
        if source_file is None:
            raise SystemExit(f"error: cannot read packaged Rust source: {packaged_name}")
        source = source_file.read().decode("utf-8")
        present_source_tokens = sorted(
            token for token in shipping_source_tokens if token in source
        )
        if present_source_tokens:
            raise SystemExit(
                "error: q-periapt-backends shipping source exposes the evidence-only "
                f"performance reference in {packaged_name}: {present_source_tokens}"
            )
    if any(name.startswith(prefix + "vendor/mlkem-native/") for name in names):
        raise SystemExit(
            "error: q-periapt-backends duplicates the sys crate's vendored mlkem-native tree"
        )
print(
    "RUST_BACKENDS_NORMALIZED_MANIFEST_PASS package=q-periapt-backends "
    "mlkem_provider=q-periapt-mlkem-native-sys retired=none vendored_mlkem=none "
    "performance_reference_api=absent"
)
PY

# Audit the graph Cargo resolves from the normalized publish manifest, not only
# the workspace lockfile. Local patches stand in for the exact-version
# q-periapt crates until the coordinated stable set exists on crates.io.
set -- "$PACKAGE_INSPECTION_TARGET"/package/q-periapt-backends-*/Cargo.toml
if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
	printf 'error: expected exactly one normalized q-periapt-backends package directory\n' >&2
	exit 1
fi
NORMALIZED_BACKENDS_DIR=${1%/Cargo.toml}
lockfile_stdout="$PACKAGE_INSPECTION_TARGET/cargo-generate-lockfile.stdout"
lockfile_stderr="$PACKAGE_INSPECTION_TARGET/cargo-generate-lockfile.stderr"
run_cargo_captured "cargo-generate-normalized-backends-lockfile" \
	"$lockfile_stdout" "$lockfile_stderr" cargo +1.96.1 generate-lockfile \
	--manifest-path "$NORMALIZED_BACKENDS_DIR/Cargo.toml" \
	--config "patch.crates-io.q-periapt-core.path=\"$ROOT/crates/q-periapt-core\"" \
	--config "patch.crates-io.q-periapt-sig.path=\"$ROOT/crates/q-periapt-sig\"" \
	--config "patch.crates-io.q-periapt-kem.path=\"$ROOT/crates/q-periapt-kem\"" \
	--config "patch.crates-io.q-periapt-mlkem-native-sys.path=\"$ROOT/crates/q-periapt-mlkem-native-sys\""
if [ ! -f "$NORMALIZED_BACKENDS_DIR/Cargo.lock" ] || [ -L "$NORMALIZED_BACKENDS_DIR/Cargo.lock" ]; then
	printf 'error: normalized backend lockfile generation did not produce a regular Cargo.lock\n' >&2
	exit 1
fi
normalized_lock_state=$(python3 - "$NORMALIZED_BACKENDS_DIR/Cargo.lock" <<'PY'
import pathlib
import sys

from evidence_io import EvidenceIOError, read_regular_snapshot
from rust_publish_contract import (
    RUST_SPARSE_LOCK_MAX_BYTES,
    RustPublishContractError,
    validate_crates_io_sparse_yanked,
)

try:
    lock_snapshot = read_regular_snapshot(
        pathlib.Path(sys.argv[1]),
        maximum=RUST_SPARSE_LOCK_MAX_BYTES,
        label="normalized q-periapt-backends Cargo.lock",
    )
    registry_packages = validate_crates_io_sparse_yanked(lock_snapshot.data)
except (EvidenceIOError, RustPublishContractError) as exc:
    raise SystemExit(f"error: {exc}") from exc
print(f"{lock_snapshot.sha256}:{lock_snapshot.size}:{registry_packages}")
PY
)
normalized_lock_sha256=${normalized_lock_state%%:*}
normalized_lock_remainder=${normalized_lock_state#*:}
normalized_lock_size=${normalized_lock_remainder%%:*}
normalized_lock_registry_packages=${normalized_lock_remainder##*:}
python3 - "$normalized_lock_sha256" "$normalized_lock_size" "$normalized_lock_registry_packages" <<'PY'
import re
import sys

if re.fullmatch(r"[0-9a-f]{64}", sys.argv[1]) is None:
    raise SystemExit("error: normalized Cargo.lock SHA-256 state is malformed")
if re.fullmatch(r"[1-9][0-9]*", sys.argv[2]) is None:
    raise SystemExit("error: normalized Cargo.lock size state is malformed")
if re.fullmatch(r"[1-9][0-9]*", sys.argv[3]) is None or int(sys.argv[3]) > 256:
    raise SystemExit("error: normalized Cargo.lock registry package state is malformed")
PY
printf 'RUST_CRATES_IO_LOCK_VERIFY_PASS registry_packages=%s index=sparse-https checksums=exact yanked=0 normalized_lock_sha256=%s\n' \
	"$normalized_lock_registry_packages" "$normalized_lock_sha256"
audit_stdout="$PACKAGE_INSPECTION_TARGET/cargo-audit.stdout"
audit_stderr="$PACKAGE_INSPECTION_TARGET/cargo-audit.stderr"
if [ -e "$CARGO_HOME/advisory-db" ] || [ -L "$CARGO_HOME/advisory-db" ]; then
	printf 'error: isolated Cargo home unexpectedly contains a preexisting advisory database\n' >&2
	exit 1
fi
run_cargo_captured "cargo-audit-normalized-backends" \
	"$audit_stdout" "$audit_stderr" env -i \
	PATH=/usr/bin:/bin HOME="$CARGO_HOME" CARGO_HOME="$CARGO_HOME" \
	CARGO_TERM_COLOR=never TERM=dumb "$CARGO_AUDIT_BIN" audit --deny warnings \
	--no-yanked \
	--db "$CARGO_HOME/advisory-db" \
	--file "$NORMALIZED_BACKENDS_DIR/Cargo.lock"
printf 'RUST_BACKENDS_NORMALIZED_AUDIT_PASS\n'
validate_isolated_advisory_database
python3 - "$NORMALIZED_BACKENDS_DIR/Cargo.lock" "$normalized_lock_sha256" "$normalized_lock_size" <<'PY'
import pathlib
import sys

from evidence_io import EvidenceIOError, read_regular_snapshot
from rust_publish_contract import RUST_SPARSE_LOCK_MAX_BYTES

try:
    snapshot = read_regular_snapshot(
        pathlib.Path(sys.argv[1]),
        maximum=RUST_SPARSE_LOCK_MAX_BYTES,
        label="post-audit normalized q-periapt-backends Cargo.lock",
    )
    expected_size = int(sys.argv[3])
except (EvidenceIOError, ValueError) as exc:
    raise SystemExit(f"error: {exc}") from exc
if snapshot.sha256 != sys.argv[2] or snapshot.size != expected_size:
    raise SystemExit("error: normalized Cargo.lock changed during registry and advisory verification")
print("RUST_NORMALIZED_LOCK_STABILITY_PASS sha256=" + snapshot.sha256)
PY

cleanup_contract_state
trap - 0 1 2 15

final_package_source_state=$(python3 - "$ROOT" "$ALLOW_DIRTY" <<'PY'
import pathlib
import sys

from rust_publish_contract import RustPublishContractError, inspect_package_source

try:
    commit, dirty = inspect_package_source(
        pathlib.Path(sys.argv[1]),
        allow_dirty=sys.argv[2] == "1",
    )
except RustPublishContractError as exc:
    raise SystemExit(f"error: {exc}") from exc
print(f"{commit}:{int(dirty)}")
PY
)
if [ "$final_package_source_state" != "$package_source_state" ]; then
	printf 'error: Rust package source provenance changed during the contract run\n' >&2
	exit 1
fi

if [ "$ALLOW_DIRTY" = "1" ]; then
	completed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	printf 'RUST_PACKAGE_CONTRACT_DIAGNOSTIC_PASS dirty=%s registry=crates-io upload=not-attempted completed_at=%s\n' \
		"$package_source_dirty" "$completed_at"
else
	completed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	printf 'RUST_PACKAGE_CONTRACT_PASS dirty=0 registry=crates-io upload=not-attempted completed_at=%s\n' "$completed_at"
fi
