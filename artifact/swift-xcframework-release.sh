#!/bin/sh
# Build, Developer ID-sign, and verify the public static SwiftPM XCFramework.
#
# This is the only supported entry point for credentialed Apple distribution.
# The ordinary swift-xcframework.sh path remains network-free and unsigned for CI.
set -eu

unset CDPATH
if [ "${GIT_DIR+x}" = "x" ] || \
	[ "${GIT_WORK_TREE+x}" = "x" ] || \
	[ "${GIT_COMMON_DIR+x}" = "x" ] || \
	[ "${GIT_INDEX_FILE+x}" = "x" ] || \
	[ "${GIT_OBJECT_DIRECTORY+x}" = "x" ] || \
	[ "${GIT_ALTERNATE_OBJECT_DIRECTORIES+x}" = "x" ] || \
	[ "${GIT_SHALLOW_FILE+x}" = "x" ] || \
	[ "${GIT_NAMESPACE+x}" = "x" ] || \
	[ "${GIT_REPLACE_REF_BASE+x}" = "x" ] || \
	[ "${GIT_CONFIG_SYSTEM+x}" = "x" ] || \
	[ "${GIT_CONFIG_GLOBAL+x}" = "x" ] || \
	[ "${GIT_CONFIG_NOSYSTEM+x}" = "x" ] || \
	[ "${GIT_CONFIG_COUNT+x}" = "x" ] || \
	[ "${GIT_CONFIG_PARAMETERS+x}" = "x" ] || \
	[ "${GIT_CEILING_DIRECTORIES+x}" = "x" ] || \
	[ "${GIT_DISCOVERY_ACROSS_FILESYSTEM+x}" = "x" ]; then
	printf 'error: Apple release tooling rejects Git repository/configuration environment overrides\n' >&2
	exit 2
fi
ROOT=$(cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

release_git_command() {
	/usr/bin/env -i \
		PATH=/usr/bin:/bin \
		LC_ALL=C \
		LANG=C \
		GIT_CONFIG_NOSYSTEM=1 \
		GIT_CONFIG_GLOBAL=/dev/null \
		GIT_CONFIG_SYSTEM=/dev/null \
		GIT_NO_REPLACE_OBJECTS=1 \
		GIT_OPTIONAL_LOCKS=0 \
		/usr/bin/git \
		-c core.fsmonitor=false \
		-c core.hooksPath=/dev/null \
		-c core.attributesFile=/dev/null \
		-c core.excludesFile=/dev/null \
		"$@"
}

release_main_git() {
	release_git_command \
		--git-dir="$ROOT/.git" \
		--work-tree="$ROOT" \
		-c "safe.directory=$ROOT" \
		"$@"
}

release_worktree_git() {
	release_git_command \
		-c "safe.directory=$WORKTREE_ROOT" \
		-C "$WORKTREE_ROOT" \
		"$@"
}

release_worktree_python() {
	sh "$WORKTREE_ROOT/artifact/python-run.sh" "$@"
}

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required Apple release tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need ditto
need cmp
need codesign
need git
need python3
need security
need shasum

if [ "$#" -ne 0 ]; then
	printf 'error: swift-xcframework-release.sh accepts no positional arguments\n' >&2
	exit 2
fi

PRODUCT_VERSION="0.1.0-alpha.2"
RELEASE_REVISION="r1"
RELEASE_TAG="v$PRODUCT_VERSION-$RELEASE_REVISION"
EXPECTED_TEAM_ID="YKUPL7Z869"
EXPECTED_IDENTITY_SHA1="2DA7764ED42B213AE04925B6261238B24C758FE1"
EXPECTED_CERTIFICATE_SHA256="806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D"

if [ "${QPERIAPT_APPLE_RELEASE_CONFIRM:-}" != "$RELEASE_TAG" ]; then
	printf 'error: set QPERIAPT_APPLE_RELEASE_CONFIRM=%s to authorize this signed release\n' "$RELEASE_TAG" >&2
	exit 2
fi
if [ "${QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK:-0}" != "0" ]; then
	printf 'error: credentialed Apple distribution never permits a dirty worktree\n' >&2
	exit 2
fi
if ! SOURCE_STATUS=$(release_main_git status --porcelain=v1); then
	printf 'error: unable to inspect the credentialed Apple source worktree\n' >&2
	exit 2
fi
if [ -n "$SOURCE_STATUS" ]; then
	printf 'error: credentialed Apple distribution requires a clean worktree\n' >&2
	exit 2
fi
if ! SOURCE_COMMIT=$(release_main_git rev-parse HEAD); then
	printf 'error: unable to resolve the credentialed Apple source commit\n' >&2
	exit 2
fi
case "$SOURCE_COMMIT" in
	*[!0-9a-f]*|'')
		printf 'error: Apple release source is not a canonical Git commit\n' >&2
		exit 2
		;;
esac
if [ "${#SOURCE_COMMIT}" -ne 40 ]; then
	printf 'error: Apple release source commit must contain 40 hexadecimal digits\n' >&2
	exit 2
fi
AUTHORIZED_SOURCE_COMMIT=${QPERIAPT_APPLE_RELEASE_SOURCE_COMMIT:-}
case "$AUTHORIZED_SOURCE_COMMIT" in
	*[!0-9a-f]*|'')
		printf 'error: QPERIAPT_APPLE_RELEASE_SOURCE_COMMIT must be a canonical Git commit\n' >&2
		exit 2
		;;
esac
if [ "${#AUTHORIZED_SOURCE_COMMIT}" -ne 40 ] || \
		[ "$AUTHORIZED_SOURCE_COMMIT" != "$SOURCE_COMMIT" ]; then
	printf 'error: authorized Apple release source commit differs from clean HEAD\n' >&2
	exit 2
fi

identities=$(security find-identity -v -p codesigning)
identity_count=$(printf '%s\n' "$identities" | awk -v identity="$EXPECTED_IDENTITY_SHA1" '
$2 == identity { count += 1 }
END { print count + 0 }
')
identity_line=$(printf '%s\n' "$identities" | awk -v identity="$EXPECTED_IDENTITY_SHA1" '$2 == identity { print }')
if [ "$identity_count" -ne 1 ]; then
	printf 'error: pinned Developer ID signing identity must be available exactly once\n' >&2
	exit 2
fi
case "$identity_line" in
	*"Developer ID Application:"*"($EXPECTED_TEAM_ID)"*) ;;
	*)
		printf 'error: pinned identity is not the expected Developer ID Application Team\n' >&2
		exit 2
		;;
esac

RELEASES_ROOT="$ROOT/target/qperiapt-apple-release-worktrees"
RELEASE_ROOT="$RELEASES_ROOT/$SOURCE_COMMIT"
WORKTREE_ROOT="$RELEASE_ROOT/source"
SOURCE_OUT="$WORKTREE_ROOT/target/qperiapt-swift-xcframework"
if [ -e "$RELEASE_ROOT" ] || [ -L "$RELEASE_ROOT" ]; then
	printf 'error: refusing to repeat or replace Apple release state for this source commit\n' >&2
	exit 1
fi
mkdir -p "$RELEASES_ROOT"
mkdir "$RELEASE_ROOT"
chmod 700 "$RELEASE_ROOT"
WORKTREE_CREATED=0
RELEASE_COMPLETED=0
WORKTREE_GIT_DIR=
WORKTREE_ADMIN_NAME=

cleanup_owned_release_worktree() {
	if [ "$WORKTREE_CREATED" != "1" ]; then
		return 0
	fi
	if ! cleanup_commit=$(release_worktree_git rev-parse HEAD) || \
		! cleanup_toplevel=$(release_worktree_git rev-parse --show-toplevel) || \
		! cleanup_common=$(release_worktree_git rev-parse --path-format=absolute --git-common-dir) || \
		! cleanup_git_dir=$(release_worktree_git rev-parse --absolute-git-dir); then
		printf 'error: cannot safely identify the wrapper-owned Apple release worktree during cleanup\n' >&2
		return 1
	fi
	case "$cleanup_git_dir" in
		"$ROOT/.git/worktrees/"?*) cleanup_admin=${cleanup_git_dir#"$ROOT/.git/worktrees/"} ;;
		*)
			printf 'error: wrapper-owned Apple release worktree has an unsafe Git admin path\n' >&2
			return 1
			;;
	esac
	case "$cleanup_admin" in
		*/*|'')
			printf 'error: wrapper-owned Apple release worktree admin name is invalid\n' >&2
			return 1
			;;
	esac
	if [ "$cleanup_commit" != "$SOURCE_COMMIT" ] || \
		[ "$cleanup_toplevel" != "$WORKTREE_ROOT" ] || \
		[ "$cleanup_common" != "$ROOT/.git" ] || \
		{ [ -n "$WORKTREE_GIT_DIR" ] && [ "$cleanup_git_dir" != "$WORKTREE_GIT_DIR" ]; } || \
		{ [ -n "$WORKTREE_ADMIN_NAME" ] && [ "$cleanup_admin" != "$WORKTREE_ADMIN_NAME" ]; }; then
		printf 'error: wrapper-owned Apple release worktree identity changed before cleanup\n' >&2
		return 1
	fi
	if ! cleanup_worktree_status=$(release_worktree_git status --porcelain=v1 --untracked-files=normal); then
		printf 'error: cannot inspect the wrapper-owned Apple release worktree during cleanup\n' >&2
		return 1
	fi
	if [ -n "$cleanup_worktree_status" ]; then
		printf 'error: refusing to force-remove a changed wrapper-owned Apple release worktree\n' >&2
		return 1
	fi
	if ! release_main_git worktree remove --force "$WORKTREE_ROOT"; then
		printf 'error: cannot remove the wrapper-owned Apple release worktree\n' >&2
		return 1
	fi
	if [ -e "$WORKTREE_ROOT" ] || [ -L "$WORKTREE_ROOT" ] || \
		[ -e "$ROOT/.git/worktrees/$cleanup_admin" ] || \
		[ -L "$ROOT/.git/worktrees/$cleanup_admin" ]; then
		printf 'error: wrapper-owned Apple release worktree cleanup was incomplete\n' >&2
		return 1
	fi
	if release_main_git worktree list --porcelain | grep -Fx "worktree $WORKTREE_ROOT" >/dev/null 2>&1; then
		printf 'error: wrapper-owned Apple release worktree remains registered after cleanup\n' >&2
		return 1
	fi
	WORKTREE_CREATED=0
}

cleanup_release_exit() {
	exit_status=$?
	trap - EXIT INT TERM
	cleanup_status=0
	cleanup_owned_release_worktree || cleanup_status=1
	if [ "$RELEASE_COMPLETED" != "1" ] && \
		{ [ -e "$RELEASE_ROOT" ] || [ -L "$RELEASE_ROOT" ]; }; then
		if [ -d "$RELEASE_ROOT" ] && [ ! -L "$RELEASE_ROOT" ] && rmdir "$RELEASE_ROOT"; then
			:
		else
			printf 'error: incomplete private Apple release root could not be cleaned\n' >&2
			cleanup_status=1
		fi
	fi
	if [ "$cleanup_status" -ne 0 ] && [ "$exit_status" -eq 0 ]; then
		exit_status=1
	fi
	exit "$exit_status"
}
trap cleanup_release_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

release_main_git worktree add --detach "$WORKTREE_ROOT" "$SOURCE_COMMIT"
WORKTREE_CREATED=1
python3 - "$RELEASE_ROOT" <<'PY'
import os
import pathlib
import stat
import sys

release_root = pathlib.Path(sys.argv[1])
state = os.lstat(release_root)
if (
    not stat.S_ISDIR(state.st_mode)
    or state.st_uid != os.geteuid()
    or stat.S_IMODE(state.st_mode) != 0o700
):
    raise SystemExit(
        f"error: private Apple release root must be a current-user 0700 directory: {release_root}"
    )
PY
if ! WORKTREE_COMMIT=$(release_worktree_git rev-parse HEAD) || \
	! WORKTREE_TOPLEVEL=$(release_worktree_git rev-parse --show-toplevel) || \
	! WORKTREE_COMMON_GIT_DIR=$(release_worktree_git rev-parse --path-format=absolute --git-common-dir) || \
	! WORKTREE_GIT_DIR=$(release_worktree_git rev-parse --absolute-git-dir) || \
	! WORKTREE_STATUS=$(release_worktree_git status --porcelain=v1 --untracked-files=normal); then
	printf 'error: unable to inspect the detached Apple release worktree\n' >&2
	exit 1
fi
case "$WORKTREE_GIT_DIR" in
	"$ROOT/.git/worktrees/"?*)
		WORKTREE_ADMIN_NAME=${WORKTREE_GIT_DIR#"$ROOT/.git/worktrees/"}
		case "$WORKTREE_ADMIN_NAME" in
			*/*)
				printf 'error: detached Apple release worktree Git admin name is not one path component\n' >&2
				exit 1
				;;
		esac
		;;
	*)
		printf 'error: detached Apple release worktree has an unexpected Git admin directory\n' >&2
		exit 1
		;;
esac
if [ "$WORKTREE_COMMIT" != "$SOURCE_COMMIT" ] || \
	[ "$WORKTREE_TOPLEVEL" != "$WORKTREE_ROOT" ] || \
	[ "$WORKTREE_COMMON_GIT_DIR" != "$ROOT/.git" ] || \
	[ -n "$WORKTREE_STATUS" ]; then
	printf 'error: detached Apple release worktree is not the exact clean source commit\n' >&2
	exit 1
fi

QPERIAPT_INTERNAL_APPLE_RELEASE_ENTRYPOINT="swift-xcframework-release-v1" \
QPERIAPT_INTERNAL_APPLE_RELEASE_MODE="1" \
QPERIAPT_INTERNAL_APPLE_EXPECTED_TEAM_ID="$EXPECTED_TEAM_ID" \
QPERIAPT_INTERNAL_APPLE_IDENTITY_SHA1="$EXPECTED_IDENTITY_SHA1" \
QPERIAPT_INTERNAL_APPLE_CERTIFICATE_SHA256="$EXPECTED_CERTIFICATE_SHA256" \
QPERIAPT_INTERNAL_APPLE_DURABILITY_ROOT="$ROOT" \
QPERIAPT_INTERNAL_APPLE_SOURCE_COMMIT="$SOURCE_COMMIT" \
QPERIAPT_INTERNAL_APPLE_RELEASE_TAG="$RELEASE_TAG" \
QPERIAPT_SWIFT_XCFRAMEWORK_OUT_DIR="$SOURCE_OUT" \
sh "$WORKTREE_ROOT/artifact/swift-xcframework.sh"

SOURCE_DIST="$SOURCE_OUT/q-periapt-swift-$PRODUCT_VERSION"
PUBLIC_OUT="$ROOT/target/qperiapt-swift-xcframework"
PUBLIC_DIST="$PUBLIC_OUT/q-periapt-swift-$PRODUCT_VERSION"
if [ ! -d "$SOURCE_DIST" ]; then
	printf 'error: detached release completed without its public distribution directory\n' >&2
	exit 1
fi
for release_file in CQPeriapt.xcframework.zip APPLE_DISTRIBUTION.json MANIFEST.json SHA256SUMS; do
	if [ ! -f "$SOURCE_DIST/$release_file" ] || [ -L "$SOURCE_DIST/$release_file" ]; then
		printf 'error: detached release lacks required regular public file: %s\n' "$release_file" >&2
		exit 1
	fi
done
if [ ! -d "$SOURCE_DIST/CQPeriapt.xcframework" ] || [ -L "$SOURCE_DIST/CQPeriapt.xcframework" ]; then
	printf 'error: detached release lacks its signed XCFramework directory\n' >&2
	exit 1
fi
(
	cd "$SOURCE_DIST"
	if [ "$(wc -l <SHA256SUMS | tr -d '[:space:]')" -ne 3 ]; then
		printf 'error: detached release checksum manifest must contain exactly three entries\n' >&2
		exit 1
	fi
	for release_file in CQPeriapt.xcframework.zip APPLE_DISTRIBUTION.json MANIFEST.json; do
		if [ "$(awk -v name="$release_file" '$2 == name { count += 1 } END { print count + 0 }' SHA256SUMS)" -ne 1 ]; then
			printf 'error: detached release checksum manifest lacks exactly one %s entry\n' "$release_file" >&2
			exit 1
		fi
	done
	shasum -c SHA256SUMS
)
codesign --verify --strict --verbose=4 "$SOURCE_DIST/CQPeriapt.xcframework"
rm -rf "$PUBLIC_OUT"
mkdir -p "$PUBLIC_OUT"
ditto "$SOURCE_DIST" "$PUBLIC_DIST"
for release_file in CQPeriapt.xcframework.zip APPLE_DISTRIBUTION.json MANIFEST.json SHA256SUMS; do
	cmp "$SOURCE_DIST/$release_file" "$PUBLIC_DIST/$release_file"
done
(
	cd "$PUBLIC_DIST"
	shasum -c SHA256SUMS
)
codesign --verify --strict --verbose=4 "$PUBLIC_DIST/CQPeriapt.xcframework"
release_worktree_python \
	"$WORKTREE_ROOT/artifact/apple_distribution.py" validate-zip \
	--artifact "$PUBLIC_DIST/CQPeriapt.xcframework.zip" --require-signature
if ! FINAL_WORKTREE_COMMIT=$(release_worktree_git rev-parse HEAD) || \
	! FINAL_WORKTREE_TOPLEVEL=$(release_worktree_git rev-parse --show-toplevel) || \
	! FINAL_WORKTREE_COMMON_GIT_DIR=$(release_worktree_git rev-parse --path-format=absolute --git-common-dir) || \
	! FINAL_WORKTREE_GIT_DIR=$(release_worktree_git rev-parse --absolute-git-dir) || \
	! FINAL_WORKTREE_STATUS=$(release_worktree_git status --porcelain=v1 --untracked-files=normal); then
	printf 'error: unable to revalidate the detached release worktree before cleanup\n' >&2
	exit 1
fi
if [ "$FINAL_WORKTREE_COMMIT" != "$SOURCE_COMMIT" ] || \
	[ "$FINAL_WORKTREE_TOPLEVEL" != "$WORKTREE_ROOT" ] || \
	[ "$FINAL_WORKTREE_COMMON_GIT_DIR" != "$ROOT/.git" ] || \
	[ "$FINAL_WORKTREE_GIT_DIR" != "$WORKTREE_GIT_DIR" ] || \
	[ "$FINAL_WORKTREE_GIT_DIR" != "$ROOT/.git/worktrees/$WORKTREE_ADMIN_NAME" ] || \
	[ -n "$FINAL_WORKTREE_STATUS" ]; then
	printf 'error: detached release worktree identity changed before cleanup\n' >&2
	exit 1
fi
COMPLETION_PENDING="$RELEASE_ROOT/completed.json.pending"
COMPLETION_LEDGER="$RELEASE_ROOT/completed.json"
python3 - "$COMPLETION_PENDING" "$SOURCE_COMMIT" "$PUBLIC_DIST" "$PRODUCT_VERSION" "$RELEASE_REVISION" "$RELEASE_TAG" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

ledger_path = pathlib.Path(sys.argv[1])
source_commit = sys.argv[2]
public_dist = pathlib.Path(sys.argv[3])
product_version = sys.argv[4]
release_revision = sys.argv[5]
release_tag = sys.argv[6]
names = (
    "CQPeriapt.xcframework.zip",
    "APPLE_DISTRIBUTION.json",
    "MANIFEST.json",
    "SHA256SUMS",
)
document = {
    "schema_version": 2,
    "kind": "qperiapt.apple_static_xcframework_release_completion",
    "source_commit": source_commit,
    "release_identity": {
        "product_version": product_version,
        "revision": release_revision,
        "tag": release_tag,
    },
    "public_assets_sha256": {
        name: hashlib.sha256((public_dist / name).read_bytes()).hexdigest()
        for name in names
    },
}
payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
descriptor = os.open(
    ledger_path,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
    0o600,
)
with os.fdopen(descriptor, "wb") as stream:
    stream.write(payload)
    stream.flush()
    os.fsync(stream.fileno())
directory = os.open(
    ledger_path.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
cleanup_owned_release_worktree
python3 - "$COMPLETION_PENDING" "$COMPLETION_LEDGER" <<'PY'
import os
import pathlib
import sys

pending = pathlib.Path(sys.argv[1])
completed = pathlib.Path(sys.argv[2])
if not pending.is_file() or pending.is_symlink() or os.path.lexists(completed):
    raise SystemExit("error: Apple release completion ledger state is invalid")
os.rename(pending, completed)
directory = os.open(
    completed.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
RELEASE_COMPLETED=1
printf 'APPLE_RELEASE_PUBLIC_COPY_PASS source_commit=%s path=%s source_worktree_cleaned=true completion_ledger=true\n' \
	"$SOURCE_COMMIT" "$PUBLIC_DIST"
