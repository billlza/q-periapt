#!/bin/sh
# Build and verify a host C-ABI release archive for downstream consumers.
# Public archive verification is selected by QPERIAPT_C_PACKAGE_VERIFY_ARCHIVE
# and additionally requires EXPECTED_SHA256, EXPECTED_TARGET, EXPECTED_VERSION,
# EXPECTED_MANIFEST_SHA256, and EXPECTED_CONTRACT_SHA256 with the same prefix.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

if [ -n "${QPERIAPT_C_PACKAGE_VERIFY_ARCHIVE:-}" ]; then
	VERIFY_ONLY=1
else
	VERIFY_ONLY=0
fi

need cc
need cmake
need ctest
need pkg-config
need python3
need rustc
need shasum
need nm
if [ "$VERIFY_ONLY" = "0" ]; then
	need cargo
	need cbindgen
	need git
fi

if [ "${QPERIAPT_C_PACKAGE_SKIP_VERIFY:-0}" = "1" ]; then
	printf 'error: QPERIAPT_C_PACKAGE_SKIP_VERIFY is not supported by the release archive proof gate\n' >&2
	exit 2
fi

case "${QPERIAPT_ALLOW_DIRTY_C_PACKAGE:-0}" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ALLOW_DIRTY_C_PACKAGE must be 0 or 1\n' >&2
		exit 2
		;;
esac

if [ "$VERIFY_ONLY" = "0" ]; then
	SOURCE_PROVENANCE=$(python3 - "$ROOT" <<'PY'
import pathlib
import sys

from git_provenance import GitProvenanceError, inspect_worktree, run_git_text

root = pathlib.Path(sys.argv[1])
try:
    inspection = inspect_worktree(root)
    commit_epoch = run_git_text(root, ["show", "-s", "--format=%ct", "HEAD"])
except GitProvenanceError as exc:
    raise SystemExit(f"error: cannot establish C package source provenance: {exc}") from exc
if not commit_epoch.isascii() or not commit_epoch.isdigit():
    raise SystemExit("error: source commit timestamp is malformed")
print(inspection.commit, 1 if inspection.dirty else 0, commit_epoch)
PY
	)
	IFS=' ' read -r SOURCE_COMMIT SOURCE_DIRTY SOURCE_COMMIT_EPOCH SOURCE_EXTRA <<EOF
$SOURCE_PROVENANCE
EOF
	if [ -n "$SOURCE_EXTRA" ]; then
		printf 'error: C package source provenance output is malformed\n' >&2
		exit 2
	fi
	case "$SOURCE_COMMIT" in
		'' | *[!0-9a-f]*)
			printf 'error: C package source provenance output is malformed\n' >&2
			exit 2
			;;
	esac
	EXPECTED_GIT_COMMIT=${QPERIAPT_EXPECTED_GIT_COMMIT:-}
	if [ -n "$EXPECTED_GIT_COMMIT" ]; then
		case "$EXPECTED_GIT_COMMIT" in
			*[!0-9a-f]*)
				printf 'error: QPERIAPT_EXPECTED_GIT_COMMIT must be exactly 40 lowercase hexadecimal characters\n' >&2
				exit 2
				;;
		esac
		if [ "${#EXPECTED_GIT_COMMIT}" -ne 40 ]; then
			printf 'error: QPERIAPT_EXPECTED_GIT_COMMIT must be exactly 40 lowercase hexadecimal characters\n' >&2
			exit 2
		fi
		if [ "$SOURCE_COMMIT" != "$EXPECTED_GIT_COMMIT" ]; then
			printf 'error: C package source commit differs from QPERIAPT_EXPECTED_GIT_COMMIT\n' >&2
			exit 2
		fi
	fi
	case "$SOURCE_DIRTY" in
		0 | 1) ;;
		*)
			printf 'error: C package source dirty provenance is malformed\n' >&2
			exit 2
			;;
	esac
	case "$SOURCE_COMMIT_EPOCH" in
		'' | *[!0-9]*)
			printf 'error: C package source timestamp is malformed\n' >&2
			exit 2
			;;
	esac
	if [ "$SOURCE_DIRTY" = "1" ] && [ "${QPERIAPT_ALLOW_DIRTY_C_PACKAGE:-0}" != "1" ]; then
		printf 'error: C package release gate requires a clean worktree; set QPERIAPT_ALLOW_DIRTY_C_PACKAGE=1 only for local diagnostics\n' >&2
		exit 2
	fi
	if [ "$SOURCE_DIRTY" = "1" ]; then
		printf 'DIRTY_C_PACKAGE_DIAGNOSTIC_ONLY\n'
	fi
	SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$SOURCE_COMMIT_EPOCH}
	case "$SOURCE_DATE_EPOCH" in
		'' | *[!0-9]*)
			printf 'error: SOURCE_DATE_EPOCH must be an unsigned decimal integer\n' >&2
			exit 2
			;;
	esac
	if [ "$SOURCE_DATE_EPOCH" -gt 4294967295 ]; then
		printf 'error: SOURCE_DATE_EPOCH exceeds deterministic archive range\n' >&2
		exit 2
	fi
	export SOURCE_DATE_EPOCH
else
	if [ -n "${QPERIAPT_EXPECTED_GIT_COMMIT:-}" ]; then
		printf 'error: QPERIAPT_EXPECTED_GIT_COMMIT is not accepted in verify-only mode; use the expected archive, manifest, and contract digests\n' >&2
		exit 2
	fi
	SOURCE_COMMIT=verify-only
	SOURCE_DIRTY=0
	SOURCE_COMMIT_EPOCH=0
	SOURCE_DATE_EPOCH=0
fi

assert_source_snapshot() {
	if [ "$VERIFY_ONLY" = "1" ]; then
		return 0
	fi
	python3 - "$ROOT" "$SOURCE_COMMIT" "$SOURCE_DIRTY" <<'PY'
import pathlib
import sys

from git_provenance import GitProvenanceError, inspect_worktree

root = pathlib.Path(sys.argv[1])
expected_commit = sys.argv[2]
expected_dirty = sys.argv[3] == "1"
try:
    inspection = inspect_worktree(root)
except GitProvenanceError as exc:
    raise SystemExit(f"error: cannot revalidate C package source provenance: {exc}") from exc
if inspection.commit != expected_commit:
    raise SystemExit("error: C package source commit changed during the build")
if inspection.dirty is not expected_dirty:
    raise SystemExit("error: C package source dirty state changed during the build")
if not expected_dirty and inspection.reasons:
    raise SystemExit("error: clean C package source acquired dirty provenance")
PY
}

assert_source_snapshot

mkdir -p "$ROOT/target"
CARGO_TARGET_DIR="$ROOT/target"
export CARGO_TARGET_DIR

if [ "$VERIFY_ONLY" = "0" ]; then
	if [ -z "${HOME:-}" ]; then
		printf 'error: HOME is required to remap private paths from C package binaries\n' >&2
		exit 2
	fi
	BUILD_HOME=$(python3 - "$HOME" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.is_absolute():
    raise SystemExit("error: HOME must be an absolute path")
text = str(path.resolve(strict=True))
if text == "/" or "=" in text or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in text):
    raise SystemExit("error: HOME is not a supported build path")
if not pathlib.Path(text).is_dir():
    raise SystemExit("error: HOME is not a directory")
print(text)
PY
	)
	rustflags_separator=$(printf '\037')
	CARGO_ENCODED_RUSTFLAGS="-Dwarnings${rustflags_separator}-Cstrip=debuginfo${rustflags_separator}--remap-path-prefix=$BUILD_HOME=/__qperiapt__/build-home"
	CFLAGS="-ffile-prefix-map=$BUILD_HOME=/__qperiapt__/build-home -fdebug-prefix-map=$BUILD_HOME=/__qperiapt__/build-home -fmacro-prefix-map=$BUILD_HOME=/__qperiapt__/build-home"
	CC_SHELL_ESCAPED_FLAGS=1
	CARGO_INCREMENTAL=0
	unset RUSTFLAGS
	export CARGO_ENCODED_RUSTFLAGS CFLAGS CC_SHELL_ESCAPED_FLAGS CARGO_INCREMENTAL
else
	# Public archive verification must not inherit caller compiler/linker flags
	# that could redirect the native consumer away from the extracted SDK.
	CFLAGS=
	CPPFLAGS=
	LDFLAGS=
	CC=cc
	PKG_CONFIG_SYSROOT_DIR=
	PKG_CONFIG_SYSTEM_INCLUDE_PATH=
	PKG_CONFIG_SYSTEM_LIBRARY_PATH=
	unset CARGO_ENCODED_RUSTFLAGS RUSTFLAGS CXX CMAKE_TOOLCHAIN_FILE \
		CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH COMPILER_PATH \
		GCC_EXEC_PREFIX PKG_CONFIG_PATH PKG_CONFIG_LIBDIR CMAKE_PREFIX_PATH
	export CFLAGS CPPFLAGS LDFLAGS CC PKG_CONFIG_SYSROOT_DIR \
		PKG_CONFIG_SYSTEM_INCLUDE_PATH PKG_CONFIG_SYSTEM_LIBRARY_PATH
fi

static_libs_log=
tmp_cbom=
tmp_sbom=
tmp_header=
path_log=
cleanup() {
	for temporary_file in "$tmp_header" "$path_log" "$static_libs_log" "$tmp_cbom" "$tmp_sbom"; do
		[ -z "$temporary_file" ] || rm -f "$temporary_file"
	done
}
trap cleanup EXIT INT TERM

static_libs_log=$(mktemp "$ROOT/target/qperiapt-c-package-static-libs.log.XXXXXX")
tmp_cbom=$(mktemp "$ROOT/target/qperiapt-cbom.json.XXXXXX")
tmp_sbom=$(mktemp "$ROOT/target/qperiapt-sbom.json.XXXXXX")
ABI_MAJOR=2
ABI_COMPAT_VERSION=2.0.0
LINUX_GLIBC_POLICY_MAX=2.35
CONTRACT_SOURCE="$ROOT/crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
HEADER_SOURCE="$ROOT/crates/q-periapt-ffi/include/q_periapt.h"
FIXTURE_SOURCE="$ROOT/bindings/c/signed_policy_fixture.h"
VENDOR_ROOT="$ROOT/crates/q-periapt-mlkem-native-sys/vendor"
HOST=$(rustc -vV | awk '/^host: / { print $2 }')
if [ "$VERIFY_ONLY" = "0" ]; then
	VERSION=$(cargo metadata --locked --format-version 1 | python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
for package in metadata["packages"]:
    if package["name"] == "q-periapt-ffi":
        print(package["version"])
        break
else:
    raise SystemExit("error: q-periapt-ffi package not found in cargo metadata")
')
	EXPECTED_MANIFEST_SHA256=
	EXPECTED_CONTRACT_SHA256=
else
	VERSION=${QPERIAPT_C_PACKAGE_EXPECTED_VERSION:-}
	EXPECTED_MANIFEST_SHA256=${QPERIAPT_C_PACKAGE_EXPECTED_MANIFEST_SHA256:-}
	EXPECTED_CONTRACT_SHA256=${QPERIAPT_C_PACKAGE_EXPECTED_CONTRACT_SHA256:-}
	ARCHIVE=$(python3 - \
		"$QPERIAPT_C_PACKAGE_VERIFY_ARCHIVE" \
		"${QPERIAPT_C_PACKAGE_EXPECTED_SHA256:-}" \
		"${QPERIAPT_C_PACKAGE_EXPECTED_TARGET:-}" \
		"$VERSION" \
		"$EXPECTED_MANIFEST_SHA256" \
		"$EXPECTED_CONTRACT_SHA256" \
		"$HOST" <<'PY'
import pathlib
import re
import sys

from evidence_io import EvidenceIOError, read_regular_snapshot

archive = pathlib.Path(sys.argv[1])
archive_sha256, target, version, manifest_sha256, contract_sha256, host = sys.argv[2:]
if not archive.is_absolute():
    raise SystemExit("error: QPERIAPT_C_PACKAGE_VERIFY_ARCHIVE must be absolute")
if target != host:
    raise SystemExit(
        f"error: verify-only C package target must equal native host: {target!r} != {host!r}"
    )
numeric_identifier = r"(?:0|[1-9][0-9]*)"
prerelease_identifier = rf"(?:{numeric_identifier}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
semver = re.compile(
    rf"{numeric_identifier}\.{numeric_identifier}\.{numeric_identifier}"
    rf"(?:-{prerelease_identifier}(?:\.{prerelease_identifier})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
if semver.fullmatch(version) is None:
    raise SystemExit("error: QPERIAPT_C_PACKAGE_EXPECTED_VERSION is not strict SemVer")
for label, digest in (
    ("QPERIAPT_C_PACKAGE_EXPECTED_SHA256", archive_sha256),
    ("QPERIAPT_C_PACKAGE_EXPECTED_MANIFEST_SHA256", manifest_sha256),
    ("QPERIAPT_C_PACKAGE_EXPECTED_CONTRACT_SHA256", contract_sha256),
):
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SystemExit(f"error: {label} must be one lowercase SHA-256 digest")
try:
    snapshot = read_regular_snapshot(
        archive,
        maximum=128 * 1024 * 1024,
        label="public C package archive",
    )
except EvidenceIOError as exc:
    raise SystemExit(f"error: {exc}") from exc
if snapshot.sha256 != archive_sha256:
    raise SystemExit(
        "error: public C package archive SHA-256 differs: "
        f"{snapshot.sha256} != {archive_sha256}"
    )
print(snapshot.path)
PY
	)
fi
RUST_SYSROOT=$(rustc --print sysroot)
LLVM_NM="$RUST_SYSROOT/lib/rustlib/$HOST/bin/llvm-nm"
if [ ! -f "$LLVM_NM" ] || [ -L "$LLVM_NM" ] || [ ! -x "$LLVM_NM" ]; then
	printf 'error: matching Rust llvm-nm is unavailable; install the llvm-tools component: %s\n' \
		"$LLVM_NM" >&2
	exit 2
fi
LLVM_STRIP="$RUST_SYSROOT/lib/rustlib/$HOST/bin/llvm-strip"
if [ "$VERIFY_ONLY" = "0" ] && { [ ! -f "$LLVM_STRIP" ] || [ -L "$LLVM_STRIP" ] || [ ! -x "$LLVM_STRIP" ]; }; then
	printf 'error: matching Rust llvm-strip is unavailable; install the llvm-tools component: %s\n' \
		"$LLVM_STRIP" >&2
	exit 2
fi
PACKAGE_NAME="q-periapt-c-abi2-$VERSION-$HOST"
if [ "$VERIFY_ONLY" = "0" ]; then
	OUT_ROOT=${QPERIAPT_C_PACKAGE_OUT_DIR:-"$ROOT/target/qperiapt-c-abi2"}
else
	OUT_ROOT=${QPERIAPT_C_PACKAGE_OUT_DIR:-"$ROOT/target/qperiapt-c-abi2-verify"}
fi
PACKAGE_DIR="$OUT_ROOT/$PACKAGE_NAME"
if [ "$VERIFY_ONLY" = "0" ]; then
	ARCHIVE="$OUT_ROOT/$PACKAGE_NAME.tar.gz"
fi
VERIFY_ROOT="$OUT_ROOT/verify-$PACKAGE_NAME"
tmp_header=$(mktemp "$ROOT/target/qperiapt-c-package-header.h.XXXXXX")
path_log=$(mktemp "$ROOT/target/qperiapt-c-package-paths.log.XXXXXX")

case "$(uname -s)" in
	Darwin)
		PLATFORM="macos"
		BUILD_SHARED_LIB="libq_periapt_ffi_abi2.dylib"
		SHARED_LIB="libq_periapt_ffi.2.dylib"
		RPATH_FLAG="-Wl,-rpath,"
		need otool
		;;
	Linux)
		PLATFORM="linux"
		BUILD_SHARED_LIB="libq_periapt_ffi_abi2.so"
		SHARED_LIB="libq_periapt_ffi.so.2"
		RPATH_FLAG="-Wl,-rpath,"
		need ldd
		need readelf
		;;
	*)
		printf 'error: C package script currently supports Darwin/Linux hosts, got %s\n' "$(uname -s)" >&2
	exit 2
		;;
esac
case "$PLATFORM:$HOST" in
	macos:aarch64-apple-darwin | macos:x86_64-apple-darwin | \
		linux:x86_64-unknown-linux-gnu | linux:aarch64-unknown-linux-gnu) ;;
	*)
		printf 'error: unsupported native public C package target: %s\n' "$HOST" >&2
		exit 2
		;;
esac
STATIC_LIB="libq_periapt_ffi_abi2.a"

inspect_dynamic_linkage() {
	binary=$1
	label=$2
	linkage="$VERIFY_ROOT/$label-linkage.txt"
	case "$(uname -s)" in
		Darwin)
			otool -L "$binary" >"$linkage"
			if ! grep -F "@rpath/$SHARED_LIB" "$linkage" >/dev/null 2>&1; then
				cat "$linkage" >&2
				printf 'error: dynamic consumer is not linked through @rpath/%s\n' "$SHARED_LIB" >&2
				exit 1
			fi
			otool -l "$binary" >"$linkage-rpaths"
			python3 - "$linkage-rpaths" "$EXTRACTED/lib" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
expected = pathlib.Path(sys.argv[2]).resolve(strict=True)
rpaths = re.findall(r"^\s*path (.+?) \(offset [0-9]+\)\s*$", text, re.MULTILINE)
try:
    resolved = [pathlib.Path(value).resolve(strict=True) for value in rpaths]
except OSError as exc:
    raise SystemExit(f"error: dynamic consumer LC_RPATH cannot be resolved: {exc}") from exc
if resolved != [expected]:
    raise SystemExit(
        f"error: dynamic consumer LC_RPATH differs: {resolved} != {[expected]}"
    )
PY
			;;
		Linux)
			if LANG=C LC_ALL=C ldd "$binary" >"$linkage" 2>&1; then
				:
			else
				ldd_status=$?
				cat "$linkage" >&2
				printf 'error: ldd failed for dynamic consumer (exit %s)\n' \
					"$ldd_status" >&2
				exit 1
			fi
			python3 artifact/c_package_manifest.py verify-ldd \
				--ldd-output "$linkage" \
				--package-root "$EXTRACTED" \
				--shared-filename "$SHARED_LIB"
			;;
	esac
	if grep -F "$ROOT/target/release" "$linkage" >/dev/null 2>&1; then
		cat "$linkage" >&2
		printf 'error: dynamic consumer linkage references source-tree target/release\n' >&2
		exit 1
	fi
}

inspect_static_linkage() {
	binary=$1
	label=$2
	linkage="$VERIFY_ROOT/$label-linkage.txt"
	case "$(uname -s)" in
		Darwin)
			otool -L "$binary" >"$linkage"
			;;
		Linux)
			if LANG=C LC_ALL=C ldd "$binary" >"$linkage" 2>&1; then
				:
			else
				ldd_status=$?
				if [ "$ldd_status" -ne 1 ] || ! grep -Eq 'not a dynamic executable|statically linked' "$linkage"; then
					cat "$linkage" >&2
					printf 'error: ldd failed unexpectedly for static consumer (exit %s)\n' "$ldd_status" >&2
					exit 1
				fi
			fi
			;;
	esac
	if grep -F "$SHARED_LIB" "$linkage" >/dev/null 2>&1; then
		cat "$linkage" >&2
		printf 'error: static consumer unexpectedly links to %s\n' "$SHARED_LIB" >&2
		exit 1
	fi
	if grep -F "$ROOT/target/release" "$linkage" >/dev/null 2>&1; then
		cat "$linkage" >&2
		printf 'error: static consumer linkage references source-tree target/release\n' >&2
		exit 1
	fi
}

audit_linux_shared_library() {
	library=$1
	python3 - "$library" "$HOST" "$LINUX_GLIBC_POLICY_MAX" <<'PY'
import os
import pathlib
import re
import subprocess
import sys

library = pathlib.Path(sys.argv[1])
host = sys.argv[2]
policy_max = sys.argv[3]

expected_machines = {
    "x86_64-unknown-linux-gnu": "Advanced Micro Devices X86-64",
    "aarch64-unknown-linux-gnu": "AArch64",
}
expected_machine = expected_machines.get(host)
if expected_machine is None:
    raise SystemExit(f"error: unsupported public Linux C package host: {host}")

def run(*args: str) -> str:
    environment = dict(os.environ)
    environment.update({"LANG": "C", "LC_ALL": "C"})
    try:
        return subprocess.check_output(
            ["readelf", *args, str(library)],
            text=True,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else ""
        suffix = f": {detail}" if detail else ""
        raise SystemExit(f"error: readelf {' '.join(args)} failed for {library}{suffix}") from exc

header = run("-hW")
machine_rows = re.findall(r"^\s*Machine:\s*(.+?)\s*$", header, re.MULTILINE)
class_rows = re.findall(r"^\s*Class:\s*(.+?)\s*$", header, re.MULTILINE)
type_rows = re.findall(r"^\s*Type:\s*(\S+)", header, re.MULTILINE)
if machine_rows != [expected_machine]:
    raise SystemExit(
        f"error: Linux ELF machine differs for {host}: {machine_rows} != {[expected_machine]}"
    )
if class_rows != ["ELF64"] or type_rows != ["DYN"]:
    raise SystemExit(
        f"error: Linux shared library must be one ELF64 DYN object: class={class_rows} type={type_rows}"
    )

program_headers = run("-lW")
relro_rows = [line for line in program_headers.splitlines() if "GNU_RELRO" in line]
stack_rows = [line for line in program_headers.splitlines() if "GNU_STACK" in line]
if len(relro_rows) != 1:
    raise SystemExit("error: Linux shared library must contain exactly one GNU_RELRO segment")
if len(stack_rows) != 1:
    raise SystemExit("error: Linux shared library must contain exactly one GNU_STACK segment")
stack_tokens = stack_rows[0].split()
try:
    stack_index = stack_tokens.index("GNU_STACK")
except ValueError as exc:
    raise SystemExit("error: cannot parse Linux GNU_STACK program header") from exc
stack_tail = stack_tokens[stack_index + 1 :]
if "RWE" in stack_tail or "E" in stack_tail or "RW" not in stack_tail:
    raise SystemExit(
        f"error: Linux shared library stack is executable or malformed: {stack_rows[0].strip()}"
    )

dynamic = run("-dW")
dynamic_flag_rows = re.findall(
    r"^\s*\S+\s+\((FLAGS(?:_1)?)\)\s+(.+?)\s*$",
    dynamic,
    re.MULTILINE,
)
has_bind_now = any(
    (tag == "FLAGS" and re.search(r"\bBIND_NOW\b", value) is not None)
    or (tag == "FLAGS_1" and re.search(r"\bNOW\b", value) is not None)
    for tag, value in dynamic_flag_rows
)
if not has_bind_now:
    raise SystemExit("error: Linux shared library lacks immediate binding (NOW)")
for forbidden in ("(TEXTREL)", "(RPATH)", "(RUNPATH)"):
    if forbidden in dynamic:
        raise SystemExit(f"error: Linux shared library contains forbidden dynamic tag {forbidden}")
if re.search(r"\(FLAGS\).*\bTEXTREL\b", dynamic):
    raise SystemExit("error: Linux shared library contains TEXTREL dynamic flags")

sections = run("-SW")
debug_sections = sorted(
    set(
        re.findall(
            r"\.(?:z?debug(?:_[A-Za-z0-9_.-]+)?|gnu_debuglink|gnu_debugaltlink|"
            r"gnu_debugdata|gdb_index|dwo|BTF(?:\.ext)?|ctf)\b",
            sections,
        )
    )
)
if debug_sections:
    raise SystemExit(
        f"error: Linux shared library contains debug sections: {debug_sections}"
    )

versions = run("--version-info", "-W")
glibc_requirements = set()
in_version_needs = False
for line in versions.splitlines():
    heading = line.lstrip()
    if heading.startswith("Version needs section"):
        in_version_needs = True
        continue
    if heading.startswith("Version "):
        in_version_needs = False
    if in_version_needs:
        glibc_requirements.update(re.findall(r"\bName:\s*(GLIBC_[A-Za-z0-9_.]+)\b", line))
if not glibc_requirements:
    raise SystemExit("error: Linux GNU shared library declares no GLIBC version requirements")
unknown_glibc = sorted(
    requirement
    for requirement in glibc_requirements
    if re.fullmatch(r"GLIBC_[0-9]+(?:\.[0-9]+)+", requirement) is None
)
if unknown_glibc:
    raise SystemExit(
        f"error: Linux shared library has non-numeric GLIBC requirements: {unknown_glibc}"
    )
glibc_names = {requirement.removeprefix("GLIBC_") for requirement in glibc_requirements}
maximum = max(
    glibc_names,
    key=lambda value: tuple(int(part) for part in value.split(".")),
)
def version_tuple(value: str) -> tuple[int, ...]:
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", value) is None:
        raise SystemExit(f"error: malformed Linux GLIBC policy maximum: {value}")
    return tuple(int(part) for part in value.split("."))

if version_tuple(maximum) > version_tuple(policy_max):
    raise SystemExit(
        f"error: Linux shared library GLIBC requirement {maximum} exceeds policy {policy_max}"
    )
print(maximum)
PY
}

audit_linux_needed_libraries() {
	library=$1
	python3 - "$library" "$HOST" <<'PY'
import os
import pathlib
import re
import subprocess
import sys

library = pathlib.Path(sys.argv[1])
host = sys.argv[2]
loader_by_host = {
    "x86_64-unknown-linux-gnu": "ld-linux-x86-64.so.2",
    "aarch64-unknown-linux-gnu": "ld-linux-aarch64.so.1",
}
loader = loader_by_host.get(host)
if loader is None:
    raise SystemExit(f"error: unsupported public Linux C package host: {host}")
environment = dict(os.environ)
environment.update({"LANG": "C", "LC_ALL": "C"})
try:
    dynamic = subprocess.check_output(
        ["readelf", "-dW", str(library)],
        text=True,
        stderr=subprocess.PIPE,
        env=environment,
    )
except (OSError, subprocess.CalledProcessError) as exc:
    detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else ""
    suffix = f": {detail}" if detail else ""
    raise SystemExit(f"error: readelf -dW failed for {library}{suffix}") from exc
needed = re.findall(
    r"^\s*\S+\s+\(NEEDED\)\s+Shared library: \[([^\]]+)\]\s*$",
    dynamic,
    re.MULTILINE,
)
if len(needed) != dynamic.count("(NEEDED)"):
    raise SystemExit("error: Linux shared library DT_NEEDED entries are malformed")
if not needed or "libc.so.6" not in needed:
    raise SystemExit("error: Linux shared library lacks its expected libc.so.6 dependency")
if len(needed) != len(set(needed)):
    raise SystemExit(f"error: Linux shared library has duplicate DT_NEEDED entries: {needed}")
for name in needed:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name) is None:
        raise SystemExit(f"error: Linux shared library has unsafe DT_NEEDED name: {name!r}")
allowed = {
    "libc.so.6",
    "libdl.so.2",
    "libgcc_s.so.1",
    "libm.so.6",
    "libpthread.so.0",
    "libresolv.so.2",
    "librt.so.1",
    "libutil.so.1",
    loader,
}
unexpected = sorted(set(needed) - allowed)
if unexpected:
    raise SystemExit(
        f"error: Linux shared library has unexpected DT_NEEDED libraries: {unexpected}"
    )
print(",".join(sorted(needed)))
PY
}

scan_release_tree() {
	package_root=$1
	python3 - "$ROOT" "$package_root" <<'PY'
import pathlib
import sys

from release_binary_scan import ReleaseBinaryScanError, scan_release_file

repository_root = pathlib.Path(sys.argv[1]).resolve()
package_root = pathlib.Path(sys.argv[2]).resolve()
files = sorted(path for path in package_root.rglob("*") if path.is_file())
if not files:
    raise SystemExit("error: C package release scan found no files")
for path in files:
    if path.is_symlink():
        raise SystemExit(f"error: C package release scan rejects symlink: {path}")
    try:
        scan_release_file(path, forbidden_text=[str(repository_root)])
    except ReleaseBinaryScanError as exc:
        raise SystemExit(f"error: {exc}") from exc
print(f"C_ABI_PACKAGE_BINARY_SCAN_PASS files={len(files)}")
PY
}

validate_license_and_boms() {
	package_root=$1
	python3 - "$ROOT" "$package_root" "$VERIFY_ONLY" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
package_root = pathlib.Path(sys.argv[2]).resolve()
verify_only = sys.argv[3] == "1"

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")

def read_text(rel: str) -> str:
    path = package_root / rel
    require(path.is_file(), f"missing package file: {rel}")
    return path.read_text(encoding="utf-8")

def load_json(rel: str):
    path = package_root / rel
    require(path.is_file(), f"missing package file: {rel}")
    return json.loads(path.read_text(encoding="utf-8"))

license_text = read_text("LICENSE")
apache_text = read_text("LICENSES/Apache-2.0.txt")
mit_text = read_text("LICENSES/MIT.txt")
require("Apache-2.0 OR MIT" in license_text, "LICENSE does not match workspace license expression")
require("Apache License" in apache_text and "Version 2.0, January 2004" in apache_text, "Apache license text is incomplete")
require("MIT License" in mit_text and "Permission is hereby granted" in mit_text, "MIT license text is incomplete")

vendor_files = {
    "LICENSES/mlkem-native/LICENSE.mlkem-native": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE.mlkem-native",
    "LICENSES/mlkem-native/LICENSE-INVENTORY.md": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE-INVENTORY.md",
    "LICENSES/mlkem-native/PROVENANCE.md": "crates/q-periapt-mlkem-native-sys/vendor/PROVENANCE.md",
    "LICENSES/mlkem-native/INVENTORY.sha256": "crates/q-periapt-mlkem-native-sys/vendor/INVENTORY.sha256",
}
for packaged, source in vendor_files.items():
    packaged_path = package_root / packaged
    require(packaged_path.is_file() and not packaged_path.is_symlink(), f"missing packaged vendor record: {packaged}")
    if not verify_only:
        source_path = root / source
        require(source_path.is_file() and not source_path.is_symlink(), f"missing source vendor record: {source}")
        require(packaged_path.read_bytes() == source_path.read_bytes(), f"packaged vendor record differs from source: {packaged}")
vendor_license = read_text("LICENSES/mlkem-native/LICENSE.mlkem-native")
vendor_inventory = read_text("LICENSES/mlkem-native/LICENSE-INVENTORY.md")
vendor_provenance = read_text("LICENSES/mlkem-native/PROVENANCE.md")
require(
    all(token in vendor_license for token in ("Apache-2.0 license", "ISC license", "MIT license")),
    "mlkem-native license choices are incomplete",
)
require("118 vendored" in vendor_inventory and "CC-BY-4.0" in vendor_inventory, "mlkem-native license inventory is incomplete")
require("0ba906cb14b1c241476134d7403a811b382ca498" in vendor_provenance, "mlkem-native provenance commit is missing")
require("f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677" in vendor_provenance, "mlkem-native provenance archive hash is missing")

bad_value = re.compile(
    r"(/Users/|/home/|/private/|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16}|(?:api|auth|access|secret)[_-]?token\s*[:=]|password\s*[:=])",
    re.IGNORECASE,
)
bad_keys = {"timestamp", "generated_at", "serialNumber"}

def walk(value, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            require(key not in bad_keys, f"non-reproducible BOM key at {path}/{key}")
            walk(child, f"{path}/{key}")
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            walk(child, f"{path}/{idx}")
    elif isinstance(value, str):
        require(not bad_value.search(value), f"sensitive or nonportable BOM value at {path}: {value[:120]}")

def validate_cyclonedx(data, rel: str):
    require(data.get("bomFormat") == "CycloneDX", f"{rel} is not CycloneDX")
    require(data.get("specVersion") == "1.6", f"{rel} is not CycloneDX 1.6")
    require(isinstance(data.get("version"), int) and data["version"] > 0, f"{rel} version must be a positive integer")
    metadata = data.get("metadata")
    require(isinstance(metadata, dict), f"{rel} metadata missing")
    component = metadata.get("component")
    require(isinstance(component, dict) and component.get("name") == "q-periapt-hybrid-suite", f"{rel} component metadata mismatch")
    components = data.get("components")
    require(isinstance(components, list) and components, f"{rel} components missing")
    refs = [component.get("bom-ref") for component in components if isinstance(component, dict) and "bom-ref" in component]
    require(len(refs) == len(set(refs)), f"{rel} duplicate bom-ref")
    walk(data, rel)
    return components

cbom = load_json("share/q-periapt/bom/cbom.cdx.json")
sbom = load_json("share/q-periapt/bom/sbom.cdx.json")
cbom_components = validate_cyclonedx(cbom, "share/q-periapt/bom/cbom.cdx.json")
sbom_components = validate_cyclonedx(sbom, "share/q-periapt/bom/sbom.cdx.json")

expected_crypto = {
    "ML-KEM-768",
    "ML-KEM-1024",
    "X25519",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-256s",
    "SHA3-256",
    "SHAKE-256",
}
seen_crypto = set()
for component in cbom_components:
    require(component.get("type") == "cryptographic-asset", "CBOM component is not a cryptographic asset")
    name = component.get("name")
    seen_crypto.add(name)
    crypto = component.get("cryptoProperties")
    require(isinstance(crypto, dict) and crypto.get("assetType") == "algorithm", f"CBOM cryptoProperties missing for {name}")
    algo = crypto.get("algorithmProperties")
    require(isinstance(algo, dict), f"CBOM algorithmProperties missing for {name}")
    require(isinstance(algo.get("primitive"), str) and algo["primitive"], f"CBOM primitive missing for {name}")
    require(algo.get("parameterSetIdentifier") == name, f"CBOM parameterSetIdentifier mismatch for {name}")
    require(isinstance(algo.get("cryptoFunctions"), list) and algo["cryptoFunctions"], f"CBOM cryptoFunctions missing for {name}")
    require(isinstance(algo.get("nistQuantumSecurityLevel"), int), f"CBOM NIST level missing for {name}")
require(
    seen_crypto == expected_crypto,
    "CBOM asset inventory mismatch: "
    f"missing={sorted(expected_crypto - seen_crypto)} "
    f"unexpected={sorted(seen_crypto - expected_crypto)}",
)

actual_sbom = set()
for component in sbom_components:
    require(component.get("type") == "library", "SBOM component is not a library")
    name = component.get("name")
    version = component.get("version")
    purl = component.get("purl")
    bom_ref = component.get("bom-ref")
    require(isinstance(name, str) and name, "SBOM component name missing")
    require(isinstance(version, str) and version, f"SBOM component version missing for {name}")
    require(purl == f"pkg:cargo/{name}@{version}", f"SBOM purl mismatch for {name}")
    require(bom_ref == purl, f"SBOM bom-ref mismatch for {name}")
    actual_sbom.add((name, version, purl))
require(len(actual_sbom) == len(sbom_components), "SBOM contains duplicate package identities")
if not verify_only:
    lock_components = []
    name = version = None
    in_package = False
    for raw in (root / "Cargo.lock").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line == "[[package]]":
            if name and version:
                lock_components.append((name, version))
            name = version = None
            in_package = True
        elif in_package and line.startswith("name = "):
            name = line.removeprefix("name = ").strip('"')
        elif in_package and line.startswith("version = "):
            version = line.removeprefix("version = ").strip('"')
    if name and version:
        lock_components.append((name, version))
    expected_sbom = {
        (name, version, f"pkg:cargo/{name}@{version}")
        for name, version in lock_components
    }
    require(actual_sbom == expected_sbom, "SBOM components do not match Cargo.lock package set")
PY
}

python3 - "$ROOT" "$OUT_ROOT" "$PACKAGE_DIR" "$VERIFY_ROOT" \
	"$VERIFY_ONLY" "$ARCHIVE" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
target = (root / "target").resolve()
for raw, label in ((sys.argv[2], "QPERIAPT_C_PACKAGE_OUT_DIR"), (sys.argv[3], "package dir"), (sys.argv[4], "verify dir")):
    path = pathlib.Path(raw).resolve()
    try:
        path.relative_to(target)
    except ValueError as exc:
        raise SystemExit(f"error: {label} must be under {target}: {path}") from exc
    if path == target:
        raise SystemExit(f"error: {label} must not be the target root itself: {path}")
if not re.fullmatch(r"q-periapt-c-abi2-[0-9A-Za-z._+-]+-[0-9A-Za-z._+-]+", pathlib.Path(sys.argv[3]).name):
    raise SystemExit(f"error: unsafe package directory name: {pathlib.Path(sys.argv[3]).name}")
if sys.argv[5] == "1":
    archive = pathlib.Path(sys.argv[6]).resolve(strict=True)
    verify_root = pathlib.Path(sys.argv[4]).resolve()
    if archive == verify_root or archive.is_relative_to(verify_root):
        raise SystemExit("error: verify-only archive must be outside its disposable extraction root")
PY

if [ "$VERIFY_ONLY" = "0" ]; then
printf 'Q-Periapt C ABI package\n'
printf 'version : %s\n' "$VERSION"
printf 'host    : %s\n' "$HOST"
printf 'out     : %s\n' "$OUT_ROOT"

printf '\n=== Frozen ABI 2 contract and generated header freshness ===\n'
test -f "$CONTRACT_SOURCE" || {
	printf 'error: missing ABI contract: %s\n' "$CONTRACT_SOURCE" >&2
	exit 1
}
test -f "$FIXTURE_SOURCE" || {
	printf 'error: missing signed-policy fixture: %s\n' "$FIXTURE_SOURCE" >&2
	exit 1
}
python3 artifact/c_abi_contract.py \
	--contract "$CONTRACT_SOURCE" \
	--header "$HEADER_SOURCE"
cbindgen --config crates/q-periapt-ffi/cbindgen.toml \
	--crate q-periapt-ffi \
	--output "$tmp_header"
cmp "$tmp_header" "$HEADER_SOURCE"
cmp "$HEADER_SOURCE" bindings/swift/Sources/CQPeriapt/q_periapt.h
CONTRACT_VERSION=$(python3 - "$CONTRACT_SOURCE" <<'PY'
import json
import pathlib
import sys

print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["package"]["semver"])
PY
)
if [ "$VERSION" != "$CONTRACT_VERSION" ]; then
	printf 'error: Cargo package version %s differs from frozen ABI contract version %s\n' \
		"$VERSION" "$CONTRACT_VERSION" >&2
	exit 1
fi
printf 'PASS: ABI 2 source contract and generated header freshness\n'

printf '\n=== Build release C ABI ===\n'
cargo build -p q-periapt-ffi --release --locked
test -f "$ROOT/target/release/$STATIC_LIB" || {
	printf 'error: missing static library: %s\n' "$ROOT/target/release/$STATIC_LIB" >&2
	exit 1
}
test -f "$ROOT/target/release/$BUILD_SHARED_LIB" || {
	printf 'error: missing shared library: %s\n' "$ROOT/target/release/$BUILD_SHARED_LIB" >&2
	exit 1
}
if ! CARGO_TERM_COLOR=never cargo rustc -p q-periapt-ffi --release --locked --crate-type staticlib -- --print native-static-libs >"$static_libs_log" 2>&1; then
	cat "$static_libs_log" >&2
	printf 'error: failed to obtain q-periapt-ffi native static link libraries\n' >&2
	exit 1
fi
NATIVE_STATIC_LIBS=$(python3 - "$static_libs_log" "$(uname -s)" <<'PY'
import pathlib
import re
import shlex
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
platform = sys.argv[2]
# GitHub runners can force colored Cargo diagnostics even when output is redirected.
# Strip only well-formed ANSI CSI sequences, then reject any remaining escape byte;
# the native linker tokens below still pass through the strict allowlist.
ansi_csi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
text = ansi_csi.sub("", text)
if "\x1b" in text:
    raise SystemExit("error: unsupported terminal escape in rustc native-static-libs output")
matches = re.findall(r"native-static-libs:\s*(.*)", text)
if not matches:
    raise SystemExit("error: rustc did not print native-static-libs for q-periapt-ffi")
tokens = shlex.split(matches[-1])
allowed_value_after = {"-framework", "-weak_framework"}
expect_value = False
for token in tokens:
    if expect_value:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.+-]*", token):
            raise SystemExit(f"error: unsafe native static library token: {token}")
        expect_value = False
        continue
    if token in allowed_value_after:
        expect_value = True
        continue
    if not re.fullmatch(r"-l[A-Za-z0-9_.+-]+|-Wl,[A-Za-z0-9_.,@%+/=:-]+", token):
        raise SystemExit(f"error: unsafe native static library token: {token}")
if expect_value:
    raise SystemExit("error: native static library option missing value")

if platform == "Darwin":
    # AppleClang injects libSystem (which provides libc and libm) itself;
    # spelling any alias again makes ld warn in every static consumer proof.
    # Preserve every other token, including ordering and duplication: rustc's
    # native-static-libs contract warns that both can be significant.
    tokens = [token for token in tokens if token not in {"-lSystem", "-lc", "-lm"}]
print(" ".join(tokens))
PY
)
CMAKE_NATIVE_STATIC_LIBS=$(python3 - "$NATIVE_STATIC_LIBS" <<'PY'
import sys

tokens = sys.argv[1].split()
print(" ".join('"' + token.replace("\\", "\\\\").replace('"', '\\"') + '"' for token in tokens))
PY
)
printf 'native static libs: %s\n' "$NATIVE_STATIC_LIBS"

if [ "$PLATFORM" = "macos" ]; then
	# Mach-O compatibility/current versions cannot be set by install_name_tool.
	# Write all three ABI-major identity fields at link time, then have the
	# independent contract verifier read LC_ID_DYLIB from the packaged copy.
	cargo rustc -p q-periapt-ffi --release --locked --crate-type cdylib -- \
		-C "link-arg=-Wl,-install_name,@rpath/$SHARED_LIB" \
		-C "link-arg=-Wl,-compatibility_version,$ABI_COMPAT_VERSION" \
		-C "link-arg=-Wl,-current_version,$ABI_COMPAT_VERSION"
elif [ "$PLATFORM" = "linux" ]; then
	# Cargo has no stable manifest key for an ELF SONAME. Re-link this single
	# cdylib target with the frozen ABI-major SONAME and verify it below; merely
	# renaming an unversioned ELF file would create a false runtime identity.
	cargo rustc -p q-periapt-ffi --release --locked --crate-type cdylib -- \
		-C "link-arg=-Wl,-soname,$SHARED_LIB" \
		-C "link-arg=-Wl,-z,relro" \
		-C "link-arg=-Wl,-z,now" \
		-C "link-arg=-Wl,-z,noexecstack" \
		-C strip=debuginfo
fi

for required_file in LICENSE LICENSES/Apache-2.0.txt LICENSES/MIT.txt; do
	test -f "$ROOT/$required_file" || {
		printf 'error: required license file missing: %s\n' "$required_file" >&2
		exit 1
	}
done
for required_vendor_file in LICENSE.mlkem-native LICENSE-INVENTORY.md PROVENANCE.md INVENTORY.sha256; do
	test -f "$VENDOR_ROOT/$required_vendor_file" && test ! -L "$VENDOR_ROOT/$required_vendor_file" || {
		printf 'error: required mlkem-native vendor record missing or unsafe: %s\n' "$required_vendor_file" >&2
		exit 1
	}
done
python3 "$ROOT/crates/q-periapt-mlkem-native-sys/scripts/verify-vendor.py"

rm -rf "$PACKAGE_DIR" "$VERIFY_ROOT" "$ARCHIVE" "$ARCHIVE.sha256"
mkdir -p "$PACKAGE_DIR/include/qperiapt/abi2" \
	"$PACKAGE_DIR/lib/pkgconfig" \
	"$PACKAGE_DIR/lib/cmake/QPeriaptABI2" \
	"$PACKAGE_DIR/share/q-periapt/abi" \
	"$PACKAGE_DIR/share/q-periapt/bom" \
	"$PACKAGE_DIR/LICENSES/mlkem-native"
cp "$HEADER_SOURCE" "$PACKAGE_DIR/include/qperiapt/abi2/q_periapt.h"
cp "$FIXTURE_SOURCE" "$PACKAGE_DIR/include/qperiapt/abi2/signed_policy_fixture.h"
cp "$CONTRACT_SOURCE" "$PACKAGE_DIR/share/q-periapt/abi/q-periapt-c-abi-v2.json"
cp "$ROOT/target/release/$STATIC_LIB" "$PACKAGE_DIR/lib/$STATIC_LIB"
cp "$ROOT/target/release/$BUILD_SHARED_LIB" "$PACKAGE_DIR/lib/$SHARED_LIB"
"$LLVM_STRIP" --strip-debug --enable-deterministic-archives "$PACKAGE_DIR/lib/$STATIC_LIB"
cp "$ROOT/bindings/c/smoke.c" "$PACKAGE_DIR/share/q-periapt/smoke.c"
cp "$ROOT/LICENSE" "$PACKAGE_DIR/LICENSE"
cp "$ROOT/LICENSES/Apache-2.0.txt" "$PACKAGE_DIR/LICENSES/Apache-2.0.txt"
cp "$ROOT/LICENSES/MIT.txt" "$PACKAGE_DIR/LICENSES/MIT.txt"
cp "$VENDOR_ROOT/LICENSE.mlkem-native" "$PACKAGE_DIR/LICENSES/mlkem-native/LICENSE.mlkem-native"
cp "$VENDOR_ROOT/LICENSE-INVENTORY.md" "$PACKAGE_DIR/LICENSES/mlkem-native/LICENSE-INVENTORY.md"
cp "$VENDOR_ROOT/PROVENANCE.md" "$PACKAGE_DIR/LICENSES/mlkem-native/PROVENANCE.md"
cp "$VENDOR_ROOT/INVENTORY.sha256" "$PACKAGE_DIR/LICENSES/mlkem-native/INVENTORY.sha256"
python3 artifact/third_party_licenses.py create \
	--root "$ROOT" \
	--package-root "$PACKAGE_DIR" \
	--target "$HOST"
python3 artifact/c_abi_contract.py \
	--contract "$PACKAGE_DIR/share/q-periapt/abi/q-periapt-c-abi-v2.json" \
	--header "$PACKAGE_DIR/include/qperiapt/abi2/q_periapt.h" \
	--library "$PACKAGE_DIR/lib/$SHARED_LIB" \
	--static-library "$PACKAGE_DIR/lib/$STATIC_LIB" \
	--llvm-nm "$LLVM_NM" \
	--platform "$PLATFORM"

LINUX_MAX_GLIBC_VERSION=not-applicable
LINUX_NEEDED_LIBRARIES=not-applicable
if [ "$PLATFORM" = "linux" ]; then
	LINUX_MAX_GLIBC_VERSION=$(audit_linux_shared_library "$PACKAGE_DIR/lib/$SHARED_LIB")
	LINUX_NEEDED_LIBRARIES=$(audit_linux_needed_libraries "$PACKAGE_DIR/lib/$SHARED_LIB")
	printf 'Linux maximum required GLIBC version: %s\n' "$LINUX_MAX_GLIBC_VERSION"
	printf 'Linux DT_NEEDED libraries: %s\n' "$LINUX_NEEDED_LIBRARIES"
fi

cargo run --locked --quiet -p q-periapt-cli --bin qperiapt -- cbom >"$tmp_cbom"
cargo run --locked --quiet -p q-periapt-cli --bin qperiapt -- sbom --lock Cargo.lock >"$tmp_sbom"
cp "$tmp_cbom" "$PACKAGE_DIR/share/q-periapt/bom/cbom.cdx.json"
cp "$tmp_sbom" "$PACKAGE_DIR/share/q-periapt/bom/sbom.cdx.json"
validate_license_and_boms "$PACKAGE_DIR"

cat > "$PACKAGE_DIR/lib/pkgconfig/qperiapt-abi2.pc" <<EOF
prefix=\${pcfiledir}/../..
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include/qperiapt/abi2

Name: qperiapt-abi2
Description: Q-Periapt policy-gated C ABI 2 (ML-KEM-768 + X25519)
Version: $VERSION
Cflags: -I\${includedir}
Libs: \${libdir}/$SHARED_LIB ${RPATH_FLAG}\${libdir}
EOF

cat > "$PACKAGE_DIR/lib/pkgconfig/qperiapt-abi2-static.pc" <<EOF
prefix=\${pcfiledir}/../..
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include/qperiapt/abi2

Name: qperiapt-abi2-static
Description: Q-Periapt policy-gated C ABI 2 static library (ML-KEM-768 + X25519)
Version: $VERSION
Cflags: -I\${includedir}
Libs: \${libdir}/$STATIC_LIB
Libs.private: $NATIVE_STATIC_LIBS
EOF

cat > "$PACKAGE_DIR/lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake" <<EOF
include_guard(GLOBAL)

if(NOT DEFINED QPeriaptABI2_FIND_VERSION OR
   NOT QPeriaptABI2_FIND_VERSION VERSION_EQUAL "$ABI_COMPAT_VERSION" OR
   NOT QPeriaptABI2_FIND_VERSION_EXACT)
  message(FATAL_ERROR
    "QPeriaptABI2 must be requested as find_package(QPeriaptABI2 $ABI_COMPAT_VERSION EXACT CONFIG REQUIRED)")
endif()

get_filename_component(_QPERIAPT_ABI2_PREFIX "\${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(QPeriaptABI2_VERSION "$ABI_COMPAT_VERSION")
set(QPeriaptABI2_ABI_MAJOR "$ABI_MAJOR")
set(QPeriaptABI2_RELEASE_VERSION "$VERSION")
set(QPeriaptABI2_INCLUDE_DIR "\${_QPERIAPT_ABI2_PREFIX}/include/qperiapt/abi2")
set(QPeriaptABI2_LIBRARY "\${_QPERIAPT_ABI2_PREFIX}/lib/$SHARED_LIB")
set(QPeriaptABI2_STATIC_LIBRARY "\${_QPERIAPT_ABI2_PREFIX}/lib/$STATIC_LIB")
set(_QPERIAPT_ABI2_STATIC_NATIVE_LIBS $CMAKE_NATIVE_STATIC_LIBS)

if(NOT EXISTS "\${QPeriaptABI2_INCLUDE_DIR}/q_periapt.h")
  message(FATAL_ERROR "QPeriapt ABI 2 header not found: \${QPeriaptABI2_INCLUDE_DIR}/q_periapt.h")
endif()
if(NOT EXISTS "\${QPeriaptABI2_LIBRARY}")
  message(FATAL_ERROR "QPeriapt ABI 2 shared library not found: \${QPeriaptABI2_LIBRARY}")
endif()
if(NOT EXISTS "\${QPeriaptABI2_STATIC_LIBRARY}")
  message(FATAL_ERROR "QPeriapt ABI 2 static library not found: \${QPeriaptABI2_STATIC_LIBRARY}")
endif()

if(NOT TARGET QPeriaptABI2::qperiapt)
  add_library(QPeriaptABI2::qperiapt UNKNOWN IMPORTED)
  set_target_properties(QPeriaptABI2::qperiapt PROPERTIES
    IMPORTED_LOCATION "\${QPeriaptABI2_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "\${QPeriaptABI2_INCLUDE_DIR}"
  )
endif()

if(NOT TARGET QPeriaptABI2::qperiapt_static)
  add_library(QPeriaptABI2::qperiapt_static STATIC IMPORTED)
  set_target_properties(QPeriaptABI2::qperiapt_static PROPERTIES
    IMPORTED_LOCATION "\${QPeriaptABI2_STATIC_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "\${QPeriaptABI2_INCLUDE_DIR}"
  )
  if(_QPERIAPT_ABI2_STATIC_NATIVE_LIBS)
    set_property(TARGET QPeriaptABI2::qperiapt_static APPEND PROPERTY
      INTERFACE_LINK_LIBRARIES \${_QPERIAPT_ABI2_STATIC_NATIVE_LIBS})
  endif()
endif()
EOF

cat > "$PACKAGE_DIR/lib/cmake/QPeriaptABI2/QPeriaptABI2ConfigVersion.cmake" <<EOF
set(PACKAGE_VERSION "$ABI_COMPAT_VERSION")

if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)
  set(PACKAGE_VERSION_EXACT TRUE)
  set(PACKAGE_VERSION_COMPATIBLE TRUE)
else()
  set(PACKAGE_VERSION_COMPATIBLE FALSE)
  set(PACKAGE_VERSION_UNSUITABLE TRUE)
endif()
EOF

cat > "$PACKAGE_DIR/README.md" <<EOF
# Q-Periapt C ABI 2 — $VERSION ($HOST)

This archive contains the policy-gated Q-Periapt C ABI 2 for ML-KEM-768 + X25519.
The CMake ABI compatibility version is \`$ABI_COMPAT_VERSION\`; the full release
version is exposed as \`QPeriaptABI2_RELEASE_VERSION=$VERSION\`.

Contents:

- \`include/qperiapt/abi2/q_periapt.h\`
- \`include/qperiapt/abi2/signed_policy_fixture.h\` (public smoke-test material)
- \`lib/$STATIC_LIB\`
- \`lib/$SHARED_LIB\`
- \`lib/pkgconfig/qperiapt-abi2.pc\`
- \`lib/pkgconfig/qperiapt-abi2-static.pc\`
- \`lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake\`
- \`lib/cmake/QPeriaptABI2/QPeriaptABI2ConfigVersion.cmake\`
- \`share/q-periapt/abi/q-periapt-c-abi-v2.json\`
- \`share/q-periapt/smoke.c\`
- \`share/q-periapt/bom/cbom.cdx.json\`
- \`share/q-periapt/bom/sbom.cdx.json\`
- \`LICENSE\`
- \`LICENSES/Apache-2.0.txt\`
- \`LICENSES/MIT.txt\`
- \`LICENSES/mlkem-native/LICENSE.mlkem-native\`
- \`LICENSES/mlkem-native/LICENSE-INVENTORY.md\`
- \`LICENSES/mlkem-native/PROVENANCE.md\`
- \`LICENSES/mlkem-native/INVENTORY.sha256\`
- \`THIRD_PARTY/rust/INVENTORY.json\` and its exact dependency license texts
- \`MANIFEST.json\` and \`SHA256SUMS\`

Verify checksums:

\`\`\`sh
shasum -a 256 -c SHA256SUMS
\`\`\`

Compile the bundled smoke with pkg-config:

\`\`\`sh
PKG_CONFIG_PATH="\$PWD/lib/pkgconfig" PKG_CONFIG_LIBDIR="\$PWD/lib/pkgconfig" \\
  pkg-config --cflags --libs qperiapt-abi2 > qperiapt-abi2.flags
cc -std=c11 -Wall -Wextra -Wpedantic -Werror share/q-periapt/smoke.c \\
  @qperiapt-abi2.flags \\
  -o c_smoke
./c_smoke
\`\`\`

Compile the bundled smoke with the static archive:

\`\`\`sh
PKG_CONFIG_PATH="\$PWD/lib/pkgconfig" PKG_CONFIG_LIBDIR="\$PWD/lib/pkgconfig" \\
  pkg-config --cflags --libs --static qperiapt-abi2-static > qperiapt-abi2-static.flags
cc -std=c11 -Wall -Wextra -Wpedantic -Werror share/q-periapt/smoke.c \\
  @qperiapt-abi2-static.flags \\
  -o c_static_smoke
./c_static_smoke
\`\`\`
EOF

if grep -R -n -F "$ROOT" \
		"$PACKAGE_DIR/lib/pkgconfig" \
		"$PACKAGE_DIR/lib/cmake" \
		"$PACKAGE_DIR/share/q-periapt" \
		"$PACKAGE_DIR/LICENSE" \
		"$PACKAGE_DIR/LICENSES" \
		"$PACKAGE_DIR/THIRD_PARTY" \
		"$PACKAGE_DIR/README.md" >"$path_log" 2>&1; then
	cat "$path_log" >&2
	printf 'error: package metadata contains source-tree path\n' >&2
	exit 1
fi
if grep -R -n -F "target/release" \
		"$PACKAGE_DIR/lib/pkgconfig" \
		"$PACKAGE_DIR/lib/cmake" \
		"$PACKAGE_DIR/share/q-periapt" \
		"$PACKAGE_DIR/THIRD_PARTY" \
		"$PACKAGE_DIR/README.md" >"$path_log" 2>&1; then
	cat "$path_log" >&2
	printf 'error: package metadata references target/release\n' >&2
	exit 1
fi

python3 - "$ROOT" "$PACKAGE_DIR" "$PACKAGE_NAME" "$VERSION" "$HOST" \
	"$PLATFORM" "$SHARED_LIB" "$STATIC_LIB" "$SOURCE_COMMIT" "$SOURCE_DIRTY" \
	"$SOURCE_DATE_EPOCH" "$LINUX_MAX_GLIBC_VERSION" \
	"$LINUX_GLIBC_POLICY_MAX" "$LINUX_NEEDED_LIBRARIES" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
package_dir = pathlib.Path(sys.argv[2]).resolve()
package_name = sys.argv[3]
version = sys.argv[4]
host = sys.argv[5]
platform = sys.argv[6]
shared_filename = sys.argv[7]
static_filename = sys.argv[8]
source_commit = sys.argv[9]
source_dirty = sys.argv[10] == "1"
source_date_epoch = int(sys.argv[11])
linux_max_glibc_version = sys.argv[12]
linux_glibc_policy_max = sys.argv[13]
linux_needed_libraries = sys.argv[14]

def sha256(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def run(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, cwd=root, text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else ""
        raise SystemExit(f"error: command failed for package manifest: {' '.join(args)} {stderr}") from exc

entries = []
for path in sorted(p for p in package_dir.rglob("*") if p.is_file() and p.name not in {"MANIFEST.json", "SHA256SUMS"}):
    rel = path.relative_to(package_dir).as_posix()
    st = path.stat()
    entries.append({
        "path": rel,
        "type": "file",
        "mode": "0o644",
        "sha256": sha256(path),
        "bytes": st.st_size,
    })

def tree_hash(rels: tuple[str, ...]) -> str:
    hasher = hashlib.sha256()
    seen = False
    for rel in rels:
        base = root / rel
        if base.is_file():
            candidates = [base]
        elif base.is_dir():
            candidates = sorted(p for p in base.rglob("*") if p.is_file())
        else:
            raise SystemExit(f"error: source input missing: {base}")
        for candidate in candidates:
            seen = True
            rel_name = candidate.resolve().relative_to(root).as_posix()
            hasher.update(rel_name.encode("utf-8"))
            hasher.update(b"\0")
            hasher.update(hashlib.sha256(candidate.read_bytes()).digest())
            hasher.update(b"\0")
    if not seen:
        raise SystemExit("error: source tree hash had no inputs")
    return hasher.hexdigest()

source_contract_rel = "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
embedded_contract_rel = "share/q-periapt/abi/q-periapt-c-abi-v2.json"
source_contract_path = root / source_contract_rel
embedded_contract_path = package_dir / embedded_contract_rel
if sha256(source_contract_path) != sha256(embedded_contract_path):
    raise SystemExit("error: embedded ABI contract differs from repository trust root")
contract = json.loads(embedded_contract_path.read_text(encoding="utf-8"))
exports = sorted(item["name"] for item in contract["abi"]["exports"])
if len(exports) != 9 or len(exports) != len(set(exports)):
    raise SystemExit(f"error: ABI contract export count differs from frozen value: {len(exports)}")
# ABI export-set digest encoding: UTF-8 of sorted exact names, one per line,
# including the final LF. This is stable across JSON formatting and platforms.
exports_sha256 = hashlib.sha256(("\n".join(exports) + "\n").encode("utf-8")).hexdigest()
runtime_identity = contract["package"]["platforms"][platform]
if runtime_identity["shared_filename"] != shared_filename:
    raise SystemExit("error: packaged shared filename differs from ABI contract")
if runtime_identity["static_filename"] != static_filename:
    raise SystemExit("error: packaged static filename differs from ABI contract")

platform_compatibility = {"target": host}
if platform == "linux":
    if host not in {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}:
        raise SystemExit(f"error: unsupported public Linux target: {host}")
    if not linux_max_glibc_version or linux_max_glibc_version == "not-applicable":
        raise SystemExit("error: Linux maximum GLIBC requirement is missing")
    platform_compatibility.update(
        {
            "elf_class": "ELF64",
            "elf_machine": {
                "x86_64-unknown-linux-gnu": "Advanced Micro Devices X86-64",
                "aarch64-unknown-linux-gnu": "AArch64",
            }[host],
            "needed_libraries": linux_needed_libraries.split(","),
            "max_glibc_version": linux_max_glibc_version,
            "glibc_policy_max": linux_glibc_policy_max,
            "hardening": {
                "bind_now": True,
                "debug_sections_absent": True,
                "gnu_relro": True,
                "nx_stack": True,
                "rpath_runpath_absent": True,
                "textrel_absent": True,
            },
        }
    )
elif linux_max_glibc_version != "not-applicable":
    raise SystemExit("error: non-Linux package unexpectedly carries a GLIBC requirement")
elif linux_needed_libraries != "not-applicable":
    raise SystemExit("error: non-Linux package unexpectedly carries DT_NEEDED libraries")

manifest = {
    "schema_version": 2,
    "package": package_name,
    "version": version,
    "host": host,
    "generated_at": dt.datetime.fromtimestamp(source_date_epoch, dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "source_date_epoch": source_date_epoch,
    "git_commit": source_commit,
    "git_dirty": source_dirty,
    "diagnostic_only": source_dirty,
    "rustc": run(["rustc", "--version"]),
    "cargo": run(["cargo", "--version"]),
    "platform_compatibility": platform_compatibility,
    "abi": {
        "major": 2,
        "contract_path": source_contract_rel,
        "embedded_contract_path": embedded_contract_rel,
        "contract_sha256": sha256(embedded_contract_path),
        "exports_sha256": exports_sha256,
        "export_count": len(exports),
        "platform": platform,
        "runtime_identity": runtime_identity,
        "shared_filename": shared_filename,
        "static_filename": static_filename,
    },
    "source_inputs_sha256": {
        "cargo_lock": sha256(root / "Cargo.lock"),
        "c_package_script": sha256(root / "artifact" / "c-package.sh"),
        "c_package_manifest_verifier": sha256(root / "artifact" / "c_package_manifest.py"),
        "c_abi_contract_script": sha256(root / "artifact" / "c_abi_contract.py"),
        "deterministic_archive_script": sha256(root / "artifact" / "deterministic_archive.py"),
        "release_binary_scan_script": sha256(root / "artifact" / "release_binary_scan.py"),
        "third_party_licenses_script": sha256(root / "artifact" / "third_party_licenses.py"),
        "third_party_rust_license_inventory": sha256(package_dir / "THIRD_PARTY" / "rust" / "INVENTORY.json"),
        "c_abi_contract": sha256(root / "crates" / "q-periapt-ffi" / "abi" / "q-periapt-c-abi-v2.json"),
        "c_smoke": sha256(root / "bindings" / "c" / "smoke.c"),
        "c_signed_policy_fixture": sha256(root / "bindings" / "c" / "signed_policy_fixture.h"),
        "license": sha256(root / "LICENSE"),
        "license_apache": sha256(root / "LICENSES" / "Apache-2.0.txt"),
        "license_mit": sha256(root / "LICENSES" / "MIT.txt"),
        "mlkem_native_license": sha256(root / "crates" / "q-periapt-mlkem-native-sys" / "vendor" / "LICENSE.mlkem-native"),
        "mlkem_native_license_inventory": sha256(root / "crates" / "q-periapt-mlkem-native-sys" / "vendor" / "LICENSE-INVENTORY.md"),
        "mlkem_native_provenance": sha256(root / "crates" / "q-periapt-mlkem-native-sys" / "vendor" / "PROVENANCE.md"),
        "mlkem_native_inventory": sha256(root / "crates" / "q-periapt-mlkem-native-sys" / "vendor" / "INVENTORY.sha256"),
        "qperiapt_cli_cargo": sha256(root / "crates" / "q-periapt-cli" / "Cargo.toml"),
        "qperiapt_cli_lib": sha256(root / "crates" / "q-periapt-cli" / "src" / "lib.rs"),
        "qperiapt_cli_main": sha256(root / "crates" / "q-periapt-cli" / "src" / "main.rs"),
        "ffi_header": sha256(root / "crates" / "q-periapt-ffi" / "include" / "q_periapt.h"),
        "rust_workspace_build_inputs": tree_hash(("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates")),
    },
    "files": entries,
}
manifest_path = package_dir / "MANIFEST.json"
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
entries.append({"path": "MANIFEST.json", "sha256": sha256(manifest_path), "bytes": manifest_path.stat().st_size})

with (package_dir / "SHA256SUMS").open("w", encoding="utf-8") as handle:
    for entry in sorted(entries, key=lambda item: item["path"]):
        handle.write(f"{entry['sha256']}  {entry['path']}\n")
PY

scan_release_tree "$PACKAGE_DIR"
assert_source_snapshot

printf '\n=== Archive package ===\n'
mkdir -p "$OUT_ROOT"
python3 artifact/deterministic_archive.py create-tar-gz \
	--source "$PACKAGE_DIR" \
	--output "$ARCHIVE" \
	--root "$PACKAGE_NAME" \
	--mtime "$SOURCE_DATE_EPOCH"
ARCHIVE_BASENAME=${ARCHIVE##*/}
(cd "$OUT_ROOT" && shasum -a 256 "$ARCHIVE_BASENAME" > "$ARCHIVE_BASENAME.sha256")
printf 'C_ABI_PACKAGE_ARCHIVE=%s\n' "$ARCHIVE"
else
	printf 'Q-Periapt public C ABI archive verification\n'
	printf 'version : %s\n' "$VERSION"
	printf 'host    : %s\n' "$HOST"
	printf 'archive : %s\n' "$ARCHIVE"
	mkdir -p "$OUT_ROOT"
	rm -rf "$VERIFY_ROOT"
fi

printf '\n=== Verify extracted package ===\n'
if [ "$VERIFY_ONLY" = "0" ]; then
	(cd "$OUT_ROOT" && shasum -a 256 -c "$ARCHIVE_BASENAME.sha256")
	python3 artifact/deterministic_archive.py extract-tar-gz \
		--archive "$ARCHIVE" \
		--destination "$VERIFY_ROOT" \
		--root "$PACKAGE_NAME" \
		--mtime "$SOURCE_DATE_EPOCH"
else
	python3 artifact/deterministic_archive.py extract-tar-gz \
		--archive "$ARCHIVE" \
		--destination "$VERIFY_ROOT" \
		--root "$PACKAGE_NAME" \
		--sha256 "$QPERIAPT_C_PACKAGE_EXPECTED_SHA256"
fi
EXTRACTED="$VERIFY_ROOT/$PACKAGE_NAME"
test -d "$EXTRACTED" || {
	printf 'error: extracted package missing: %s\n' "$EXTRACTED" >&2
	exit 1
}
validate_license_and_boms "$EXTRACTED"
python3 artifact/third_party_licenses.py verify \
	--package-root "$EXTRACTED" \
	--expected-target "$HOST"
scan_release_tree "$EXTRACTED"
if [ "$VERIFY_ONLY" = "1" ]; then
	LINUX_MAX_GLIBC_VERSION=not-applicable
	LINUX_NEEDED_LIBRARIES=not-applicable
	if [ "$PLATFORM" = "linux" ]; then
		LINUX_MAX_GLIBC_VERSION=$(audit_linux_shared_library "$EXTRACTED/lib/$SHARED_LIB")
		LINUX_NEEDED_LIBRARIES=$(audit_linux_needed_libraries "$EXTRACTED/lib/$SHARED_LIB")
	fi
fi
python3 - "$ROOT" "$EXTRACTED" "$SOURCE_COMMIT" "$SOURCE_DIRTY" \
	"$SOURCE_DATE_EPOCH" "$LINUX_MAX_GLIBC_VERSION" "$HOST" \
	"$VERIFY_ONLY" "$EXPECTED_MANIFEST_SHA256" "$EXPECTED_CONTRACT_SHA256" \
	"$VERSION" "$PACKAGE_NAME" "$LINUX_GLIBC_POLICY_MAX" \
	"$LINUX_NEEDED_LIBRARIES" <<'PY'
import datetime as dt
import hashlib
import json
import pathlib
import re
import stat
import sys

repo_root = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(sys.argv[2]).resolve()
expected_commit = sys.argv[3]
expected_dirty = sys.argv[4] == "1"
expected_epoch = int(sys.argv[5])
expected_glibc = sys.argv[6]
expected_host = sys.argv[7]
verify_only = sys.argv[8] == "1"
expected_manifest_sha256 = sys.argv[9]
expected_contract_sha256 = sys.argv[10]
expected_version = sys.argv[11]
expected_package = sys.argv[12]
expected_glibc_policy_max = sys.argv[13]
expected_needed_libraries = sys.argv[14]

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")

manifest_path = root / "MANIFEST.json"
sums_path = root / "SHA256SUMS"
require(manifest_path.is_file(), "MANIFEST.json missing after extraction")
require(sums_path.is_file(), "SHA256SUMS missing after extraction")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
require(manifest.get("schema_version") == 2, "unsupported MANIFEST schema")
require(manifest.get("host") == expected_host, "MANIFEST host differs")
require(manifest.get("version") == expected_version, "MANIFEST version differs")
require(manifest.get("package") == expected_package, "MANIFEST package root differs")
if verify_only:
    expected_commit = manifest.get("git_commit")
    expected_dirty = manifest.get("git_dirty")
    expected_epoch = manifest.get("source_date_epoch")
    require(
        isinstance(expected_commit, str)
        and re.fullmatch(r"[0-9a-f]{40,64}", expected_commit) is not None,
        "MANIFEST source commit is malformed",
    )
    require(type(expected_dirty) is bool, "MANIFEST dirty provenance is malformed")
    require(not expected_dirty, "public archive was produced from a dirty source tree")
    require(
        type(expected_epoch) is int and 0 <= expected_epoch <= 0xFFFFFFFF,
        "MANIFEST source epoch is malformed",
    )
else:
    require(manifest.get("git_commit") == expected_commit, "MANIFEST source commit differs")
    require(manifest.get("git_dirty") is expected_dirty, "MANIFEST dirty provenance differs")
    require(manifest.get("source_date_epoch") == expected_epoch, "MANIFEST source epoch differs")
require(manifest.get("diagnostic_only") is expected_dirty, "MANIFEST diagnostic boundary differs")
expected_generated_at = dt.datetime.fromtimestamp(expected_epoch, dt.timezone.utc).isoformat().replace("+00:00", "Z")
require(manifest.get("generated_at") == expected_generated_at, "MANIFEST generated_at is not the source epoch")
expected_mtime_ns = expected_epoch * 1_000_000_000
for extracted_path in (root, *root.rglob("*")):
    metadata = extracted_path.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode),
        f"archive contains an unsupported extracted file type: {extracted_path.relative_to(root)}",
    )
    require(
        metadata.st_mtime_ns == expected_mtime_ns,
        f"archive member mtime differs from MANIFEST source_date_epoch: {extracted_path.relative_to(root)}",
    )
files = manifest.get("files")
require(isinstance(files, list) and files, "MANIFEST files list missing")
source_inputs = manifest.get("source_inputs_sha256")
require(isinstance(source_inputs, dict), "MANIFEST source_inputs_sha256 missing")
abi = manifest.get("abi")
require(isinstance(abi, dict), "MANIFEST abi object missing")
require(set(abi) == {
    "major",
    "contract_path",
    "embedded_contract_path",
    "contract_sha256",
    "exports_sha256",
    "export_count",
    "platform",
    "runtime_identity",
    "shared_filename",
    "static_filename",
}, "MANIFEST abi keys differ from schema 2")
require(abi["major"] == 2, "MANIFEST ABI major is not 2")
require(abi["export_count"] == 9, "MANIFEST ABI export count is not 9")
expected_platform = {
    "aarch64-apple-darwin": "macos",
    "x86_64-apple-darwin": "macos",
    "aarch64-unknown-linux-gnu": "linux",
    "x86_64-unknown-linux-gnu": "linux",
}.get(expected_host)
require(expected_platform is not None, "MANIFEST host is unsupported")
require(abi["platform"] == expected_platform, "MANIFEST ABI platform differs from host")
require(abi["contract_path"] == "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json", "MANIFEST repository contract path differs")
require(abi["embedded_contract_path"] == "share/q-periapt/abi/q-periapt-c-abi-v2.json", "MANIFEST embedded contract path differs")
require(re.fullmatch(r"[0-9a-f]{64}", abi["contract_sha256"] or "") is not None, "MANIFEST ABI contract hash is malformed")
require(re.fullmatch(r"[0-9a-f]{64}", abi["exports_sha256"] or "") is not None, "MANIFEST ABI exports hash is malformed")
require(isinstance(abi["runtime_identity"], dict), "MANIFEST runtime identity is not an object")
compatibility = manifest.get("platform_compatibility")
require(isinstance(compatibility, dict), "MANIFEST platform_compatibility is missing")
require(compatibility.get("target") == manifest.get("host"), "MANIFEST target differs from host")
if abi["platform"] == "linux":
    expected_machine = {
        "x86_64-unknown-linux-gnu": "Advanced Micro Devices X86-64",
        "aarch64-unknown-linux-gnu": "AArch64",
    }.get(expected_host)
    require(expected_machine is not None, "MANIFEST Linux host is unsupported")
    require(
        set(compatibility) == {
            "target",
            "elf_class",
            "elf_machine",
            "needed_libraries",
            "max_glibc_version",
            "glibc_policy_max",
            "hardening",
        },
        "MANIFEST Linux compatibility keys differ",
    )
    require(compatibility.get("elf_class") == "ELF64", "MANIFEST Linux ELF class differs")
    require(compatibility.get("elf_machine") == expected_machine, "MANIFEST Linux ELF machine differs")
    require(
        compatibility.get("needed_libraries") == expected_needed_libraries.split(","),
        "MANIFEST Linux DT_NEEDED libraries differ",
    )
    require(compatibility.get("max_glibc_version") == expected_glibc, "MANIFEST GLIBC maximum differs")
    require(
        compatibility.get("glibc_policy_max") == expected_glibc_policy_max,
        "MANIFEST GLIBC policy maximum differs",
    )
    require(
        compatibility.get("hardening") == {
            "bind_now": True,
            "debug_sections_absent": True,
            "gnu_relro": True,
            "nx_stack": True,
            "rpath_runpath_absent": True,
            "textrel_absent": True,
        },
        "MANIFEST Linux hardening evidence differs",
    )
else:
    require(expected_glibc == "not-applicable", "non-Linux package carries a GLIBC maximum")
    require(expected_needed_libraries == "not-applicable", "non-Linux package carries DT_NEEDED libraries")
    require(compatibility == {"target": expected_host}, "non-Linux compatibility metadata differs")

manifest_hashes = {}
for entry in files:
    require(isinstance(entry, dict), "MANIFEST file entry is not an object")
    require(set(entry) == {"path", "type", "mode", "sha256", "bytes"}, "MANIFEST file entry keys differ")
    rel = entry.get("path")
    digest = entry.get("sha256")
    require(entry.get("type") == "file" and entry.get("mode") == "0o644", f"MANIFEST file metadata differs for {rel}")
    require(type(entry.get("bytes")) is int and entry["bytes"] >= 0, f"MANIFEST file byte count invalid for {rel}")
    require(isinstance(rel, str) and rel, "MANIFEST path missing")
    require(re.fullmatch(r"[0-9a-f]{64}", digest or ""), f"MANIFEST sha256 invalid for {rel}")
    require(not pathlib.PurePosixPath(rel).is_absolute(), f"MANIFEST absolute path: {rel}")
    require(".." not in pathlib.PurePosixPath(rel).parts, f"MANIFEST parent traversal path: {rel}")
    require(not any(part.startswith("._") for part in pathlib.PurePosixPath(rel).parts), f"MANIFEST AppleDouble path: {rel}")
    require(rel not in manifest_hashes, f"duplicate MANIFEST path: {rel}")
    manifest_hashes[rel] = digest

sum_hashes = {}
for line in sums_path.read_text(encoding="utf-8").splitlines():
    if not line:
        continue
    parts = line.split("  ", 1)
    require(len(parts) == 2, f"malformed SHA256SUMS line: {line}")
    digest, rel = parts
    require(re.fullmatch(r"[0-9a-f]{64}", digest), f"invalid SHA256SUMS digest for {rel}")
    require(rel not in sum_hashes, f"duplicate SHA256SUMS path: {rel}")
    sum_hashes[rel] = digest

actual_files = {
    path.relative_to(root).as_posix()
    for path in root.rglob("*")
    if path.is_file()
}
expected_actual = set(manifest_hashes) | {"MANIFEST.json", "SHA256SUMS"}
require(actual_files == expected_actual, f"archive file set mismatch extra={sorted(actual_files - expected_actual)} missing={sorted(expected_actual - actual_files)}")
expected_sums = set(manifest_hashes) | {"MANIFEST.json"}
require(set(sum_hashes) == expected_sums, f"SHA256SUMS path set mismatch extra={sorted(set(sum_hashes) - expected_sums)} missing={sorted(expected_sums - set(sum_hashes))}")

def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

for rel, digest in manifest_hashes.items():
    require(sum_hashes[rel] == digest, f"MANIFEST/SHA256SUMS hash mismatch for {rel}")
    require(sha256(root / rel) == digest, f"file hash mismatch for {rel}")
    entry = next(item for item in files if item["path"] == rel)
    require((root / rel).stat().st_size == entry["bytes"], f"file byte count mismatch for {rel}")
    require(stat.S_IMODE((root / rel).stat().st_mode) == 0o644, f"file mode mismatch for {rel}")
require(sha256(manifest_path) == sum_hashes["MANIFEST.json"], "MANIFEST.json hash mismatch")
if verify_only:
    require(
        sha256(manifest_path) == expected_manifest_sha256,
        "public MANIFEST.json SHA-256 differs from the expected digest",
    )
embedded_contract_path = root / abi["embedded_contract_path"]
require(embedded_contract_path.is_file(), "embedded ABI contract is missing")
require(sha256(embedded_contract_path) == abi["contract_sha256"], "embedded ABI contract hash mismatch")
if verify_only:
    require(
        abi["contract_sha256"] == expected_contract_sha256,
        "public ABI contract SHA-256 differs from the expected digest",
    )
else:
    source_contract_path = repo_root / abi["contract_path"]
    require(source_contract_path.is_file(), "repository ABI contract is missing")
    require(sha256(source_contract_path) == abi["contract_sha256"], "repository/embedded ABI contract hash mismatch")
contract = json.loads(embedded_contract_path.read_text(encoding="utf-8"))
require(contract["abi"]["major"] == 2, "embedded ABI contract major differs")
require(contract["package"]["semver"] == manifest.get("version"), "manifest version differs from ABI contract")
require(abi["runtime_identity"] == contract["package"]["platforms"][abi["platform"]], "MANIFEST runtime identity differs from ABI contract")
require(abi["shared_filename"] == abi["runtime_identity"]["shared_filename"], "MANIFEST shared filename differs from runtime identity")
require(abi["static_filename"] == abi["runtime_identity"]["static_filename"], "MANIFEST static filename differs from runtime identity")
exports = sorted(item["name"] for item in contract["abi"]["exports"])
require(len(exports) == 9 and len(exports) == len(set(exports)), "embedded ABI contract export count differs")
# Encoding is UTF-8 of sorted exact export names, one name per line, with a final LF.
exports_sha256 = hashlib.sha256(("\n".join(exports) + "\n").encode("utf-8")).hexdigest()
require(exports_sha256 == abi["exports_sha256"], "MANIFEST ABI export-set hash mismatch")
require((root / "lib" / abi["shared_filename"]).is_file(), "MANIFEST shared library is missing")
require((root / "lib" / abi["static_filename"]).is_file(), "MANIFEST static library is missing")
require((root / "include/qperiapt/abi2/q_periapt.h").is_file(), "ABI-major header path is missing")
require((root / "include/qperiapt/abi2/signed_policy_fixture.h").is_file(), "signed-policy fixture is missing")
for legacy in (
    "include/q_periapt.h",
    "lib/libq_periapt_ffi.dylib",
    "lib/libq_periapt_ffi.so",
    "lib/libq_periapt_ffi.a",
    "lib/libq_periapt_ffi_abi2.dylib",
    "lib/libq_periapt_ffi_abi2.so",
    "lib/pkgconfig/qperiapt.pc",
    "lib/pkgconfig/qperiapt-static.pc",
    "lib/cmake/QPeriapt/QPeriaptConfig.cmake",
):
    require(not (root / legacy).exists(), f"legacy/unversioned package path is present: {legacy}")
expected_source_files = {
    "cargo_lock": "Cargo.lock",
    "c_package_script": "artifact/c-package.sh",
    "c_package_manifest_verifier": "artifact/c_package_manifest.py",
    "c_abi_contract_script": "artifact/c_abi_contract.py",
    "deterministic_archive_script": "artifact/deterministic_archive.py",
    "release_binary_scan_script": "artifact/release_binary_scan.py",
    "third_party_licenses_script": "artifact/third_party_licenses.py",
    "c_abi_contract": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
    "c_smoke": "bindings/c/smoke.c",
    "c_signed_policy_fixture": "bindings/c/signed_policy_fixture.h",
    "ffi_header": "crates/q-periapt-ffi/include/q_periapt.h",
    "license": "LICENSE",
    "license_apache": "LICENSES/Apache-2.0.txt",
    "license_mit": "LICENSES/MIT.txt",
    "mlkem_native_license": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE.mlkem-native",
    "mlkem_native_license_inventory": "crates/q-periapt-mlkem-native-sys/vendor/LICENSE-INVENTORY.md",
    "mlkem_native_provenance": "crates/q-periapt-mlkem-native-sys/vendor/PROVENANCE.md",
    "mlkem_native_inventory": "crates/q-periapt-mlkem-native-sys/vendor/INVENTORY.sha256",
    "qperiapt_cli_cargo": "crates/q-periapt-cli/Cargo.toml",
    "qperiapt_cli_lib": "crates/q-periapt-cli/src/lib.rs",
    "qperiapt_cli_main": "crates/q-periapt-cli/src/main.rs",
}
require(
    set(source_inputs)
    == set(expected_source_files)
    | {"rust_workspace_build_inputs", "third_party_rust_license_inventory"},
    "MANIFEST source input key set differs",
)
for key, digest in source_inputs.items():
    require(
        isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
        f"MANIFEST source input hash is malformed: {key}",
    )
for key, rel in expected_source_files.items():
    if not verify_only:
        require(source_inputs[key] == sha256(repo_root / rel), f"MANIFEST source input hash mismatch for {rel}")
require(
    source_inputs["third_party_rust_license_inventory"]
    == sha256(root / "THIRD_PARTY/rust/INVENTORY.json"),
    "MANIFEST third-party Rust license inventory hash mismatch",
)
PY

# The Python verifier above first proves the checksum file's exact path set and
# canonical relative names; only then may a generic checksum consumer open them.
(cd "$EXTRACTED" && shasum -a 256 -c SHA256SUMS)

python3 artifact/c_abi_contract.py \
	--contract "$EXTRACTED/share/q-periapt/abi/q-periapt-c-abi-v2.json" \
	--header "$EXTRACTED/include/qperiapt/abi2/q_periapt.h" \
	--library "$EXTRACTED/lib/$SHARED_LIB" \
	--static-library "$EXTRACTED/lib/$STATIC_LIB" \
	--llvm-nm "$LLVM_NM" \
	--platform "$PLATFORM"

if [ "$PLATFORM" = "linux" ]; then
	EXTRACTED_MAX_GLIBC_VERSION=$(audit_linux_shared_library "$EXTRACTED/lib/$SHARED_LIB")
	EXTRACTED_NEEDED_LIBRARIES=$(audit_linux_needed_libraries "$EXTRACTED/lib/$SHARED_LIB")
	if [ "$EXTRACTED_MAX_GLIBC_VERSION" != "$LINUX_MAX_GLIBC_VERSION" ]; then
		printf 'error: extracted Linux GLIBC maximum differs: %s != %s\n' \
			"$EXTRACTED_MAX_GLIBC_VERSION" "$LINUX_MAX_GLIBC_VERSION" >&2
		exit 1
	fi
	if [ "$EXTRACTED_NEEDED_LIBRARIES" != "$LINUX_NEEDED_LIBRARIES" ]; then
		printf 'error: extracted Linux DT_NEEDED libraries differ: %s != %s\n' \
			"$EXTRACTED_NEEDED_LIBRARIES" "$LINUX_NEEDED_LIBRARIES" >&2
		exit 1
	fi
fi

unset LD_LIBRARY_PATH LD_PRELOAD DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH \
	DYLD_INSERT_LIBRARIES

printf '\n=== Legacy package-name negative controls ===\n'
for legacy_module in qperiapt qperiapt-static; do
	if PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
		PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
		pkg-config --exists "$legacy_module"; then
		printf 'error: legacy pkg-config module unexpectedly resolves: %s\n' "$legacy_module" >&2
		exit 1
	fi
done
printf 'PASS: legacy pkg-config modules do not resolve\n'

printf '\n=== pkg-config extracted consumer ===\n'
PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
	PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
	pkg-config --cflags --libs qperiapt-abi2 > "$VERIFY_ROOT/pkgconfig-dynamic.flags"
PKG_DYNAMIC_VERSION=$(PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
	PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
	pkg-config --modversion qperiapt-abi2)
if [ "$PKG_DYNAMIC_VERSION" != "$VERSION" ]; then
	printf 'error: dynamic pkg-config release version differs: %s\n' "$PKG_DYNAMIC_VERSION" >&2
	exit 1
fi
cc -std=c11 -Wall -Wextra -Wpedantic -Werror "$EXTRACTED/share/q-periapt/smoke.c" \
	@"$VERIFY_ROOT/pkgconfig-dynamic.flags" \
	-o "$VERIFY_ROOT/pkgconfig-smoke"
"$VERIFY_ROOT/pkgconfig-smoke"
inspect_dynamic_linkage "$VERIFY_ROOT/pkgconfig-smoke" "pkgconfig-smoke"

printf '\n=== pkg-config static extracted consumer ===\n'
PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
	PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
	pkg-config --cflags --libs --static qperiapt-abi2-static > "$VERIFY_ROOT/pkgconfig-static.flags"
PKG_STATIC_VERSION=$(PKG_CONFIG_PATH="$EXTRACTED/lib/pkgconfig" \
	PKG_CONFIG_LIBDIR="$EXTRACTED/lib/pkgconfig" \
	pkg-config --modversion qperiapt-abi2-static)
if [ "$PKG_STATIC_VERSION" != "$VERSION" ]; then
	printf 'error: static pkg-config release version differs: %s\n' "$PKG_STATIC_VERSION" >&2
	exit 1
fi
cc -std=c11 -Wall -Wextra -Wpedantic -Werror "$EXTRACTED/share/q-periapt/smoke.c" \
	@"$VERIFY_ROOT/pkgconfig-static.flags" \
	-o "$VERIFY_ROOT/pkgconfig-static-smoke"
"$VERIFY_ROOT/pkgconfig-static-smoke"
inspect_static_linkage "$VERIFY_ROOT/pkgconfig-static-smoke" "pkgconfig-static-smoke"

printf '\n=== CMake extracted consumer ===\n'
CMAKE_SRC="$VERIFY_ROOT/cmake-consumer-src"
CMAKE_BUILD="$VERIFY_ROOT/cmake-consumer-build"
mkdir -p "$CMAKE_SRC"
cp "$EXTRACTED/share/q-periapt/smoke.c" "$CMAKE_SRC/smoke.c"
cat > "$CMAKE_SRC/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.20)
project(QPeriaptCConsumer C)
find_package(QPeriaptABI2 2.0.0 EXACT REQUIRED CONFIG NO_DEFAULT_PATH)
if(NOT QPeriaptABI2_RELEASE_VERSION STREQUAL EXPECTED_QPERIAPT_RELEASE_VERSION)
  message(FATAL_ERROR
    "QPeriapt ABI 2 release version mismatch: ${QPeriaptABI2_RELEASE_VERSION}")
endif()
add_executable(cmake-smoke smoke.c)
target_compile_features(cmake-smoke PRIVATE c_std_11)
target_compile_options(cmake-smoke PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(cmake-smoke PRIVATE QPeriaptABI2::qperiapt)
add_executable(cmake-static-smoke smoke.c)
target_compile_features(cmake-static-smoke PRIVATE c_std_11)
target_compile_options(cmake-static-smoke PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(cmake-static-smoke PRIVATE QPeriaptABI2::qperiapt_static)
enable_testing()
add_test(NAME qperiapt-cmake-smoke COMMAND cmake-smoke)
add_test(NAME qperiapt-cmake-static-smoke COMMAND cmake-static-smoke)
EOF
cmake -S "$CMAKE_SRC" -B "$CMAKE_BUILD" -DCMAKE_PREFIX_PATH="$EXTRACTED" \
	-DQPeriaptABI2_DIR="$EXTRACTED/lib/cmake/QPeriaptABI2" \
	-DEXPECTED_QPERIAPT_RELEASE_VERSION="$VERSION" \
	-DCMAKE_BUILD_TYPE=Release -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
	-DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON \
	-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF \
	-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF
cmake --build "$CMAKE_BUILD"
ctest_list=$(ctest --test-dir "$CMAKE_BUILD" -N)
printf '%s\n' "$ctest_list"
if ! printf '%s\n' "$ctest_list" | grep -q 'Total Tests: 2'; then
	printf 'error: expected exactly two CMake smoke tests\n' >&2
	exit 1
fi
ctest --test-dir "$CMAKE_BUILD" --output-on-failure
inspect_dynamic_linkage "$CMAKE_BUILD/cmake-smoke" "cmake-smoke"
inspect_static_linkage "$CMAKE_BUILD/cmake-static-smoke" "cmake-static-smoke"

printf '\n=== Legacy CMake package negative control ===\n'
LEGACY_CMAKE_SRC="$VERIFY_ROOT/cmake-legacy-negative-src"
LEGACY_CMAKE_BUILD="$VERIFY_ROOT/cmake-legacy-negative-build"
mkdir -p "$LEGACY_CMAKE_SRC"
cat > "$LEGACY_CMAKE_SRC/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.20)
project(QPeriaptLegacyNegative NONE)
find_package(QPeriapt CONFIG QUIET PATHS "${QPERIAPT_TEST_PREFIX}" NO_DEFAULT_PATH)
if(QPeriapt_FOUND)
  message(FATAL_ERROR "legacy QPeriapt CMake package unexpectedly resolved")
endif()
find_package(QPeriaptABI2 2.0.1 EXACT CONFIG QUIET
  PATHS "${QPERIAPT_TEST_PREFIX}" NO_DEFAULT_PATH)
if(QPeriaptABI2_FOUND)
  message(FATAL_ERROR "wrong QPeriaptABI2 compatibility version unexpectedly resolved")
endif()
EOF
cmake -S "$LEGACY_CMAKE_SRC" -B "$LEGACY_CMAKE_BUILD" \
	-DQPERIAPT_TEST_PREFIX="$EXTRACTED" \
	-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF \
	-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF
printf 'PASS: legacy CMake package and wrong ABI compatibility version do not resolve\n'

assert_source_snapshot
if [ "$VERIFY_ONLY" = "1" ]; then
	printf 'C_ABI_PUBLIC_ARCHIVE_VERIFY_PASS archive_sha256=%s manifest_sha256=%s contract_sha256=%s\n' \
		"$QPERIAPT_C_PACKAGE_EXPECTED_SHA256" \
		"$EXPECTED_MANIFEST_SHA256" \
		"$EXPECTED_CONTRACT_SHA256"
fi
printf '\nC_ABI_PACKAGE_VERIFY_PASS\n'
