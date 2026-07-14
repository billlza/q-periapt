#!/bin/sh
# Build, Developer ID-sign, notarize, and verify the public SwiftPM XCFramework.
#
# This is the only supported entry point for credentialed Apple distribution.
# The ordinary swift-xcframework.sh path remains network-free and unsigned for CI.
set -eu

unset CDPATH
# Capture the selected Keychain profile before any external command runs.  Unset
# the destination first because POSIX shells preserve a variable's export
# attribute across a plain assignment when the caller exported that name.
unset NOTARY_KEYCHAIN_PROFILE
NOTARY_KEYCHAIN_PROFILE=${QPERIAPT_NOTARY_KEYCHAIN_PROFILE:-}
unset QPERIAPT_NOTARY_KEYCHAIN_PROFILE
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
need xcrun

if [ "$#" -ne 0 ]; then
	printf 'error: swift-xcframework-release.sh accepts no positional arguments\n' >&2
	exit 2
fi

VERSION="0.1.0-alpha.2"
EXPECTED_TEAM_ID="YKUPL7Z869"
EXPECTED_IDENTITY_SHA1="2DA7764ED42B213AE04925B6261238B24C758FE1"
EXPECTED_CERTIFICATE_SHA256="806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D"

if [ "${QPERIAPT_APPLE_RELEASE_CONFIRM:-}" != "$VERSION" ]; then
	printf 'error: set QPERIAPT_APPLE_RELEASE_CONFIRM=%s to authorize this release submission\n' "$VERSION" >&2
	exit 2
fi
if [ -z "$NOTARY_KEYCHAIN_PROFILE" ]; then
	printf 'error: QPERIAPT_NOTARY_KEYCHAIN_PROFILE must name one pre-validated Keychain profile\n' >&2
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

# Validate only the explicitly selected profile. Never enumerate Keychain items or
# try another profile after authentication fails.
xcrun notarytool history \
	--keychain-profile "$NOTARY_KEYCHAIN_PROFILE" \
	--output-format json >/dev/null

RELEASES_ROOT="$ROOT/target/qperiapt-apple-release-worktrees"
RELEASE_ROOT="$RELEASES_ROOT/$SOURCE_COMMIT"
WORKTREE_ROOT="$RELEASE_ROOT/source"
NOTARY_STATE_ROOT="$WORKTREE_ROOT/target/qperiapt-apple-notary-state"
SOURCE_OUT="$WORKTREE_ROOT/target/qperiapt-swift-xcframework"
RESUME_SUBMISSION_ID=${QPERIAPT_NOTARY_SUBMISSION_ID:-}
if [ -n "$RESUME_SUBMISSION_ID" ]; then
	if [ ! -e "$RELEASE_ROOT" ] || [ -L "$RELEASE_ROOT" ]; then
		printf 'error: notary resume requires its real private Apple release root\n' >&2
		exit 1
	fi
	if [ ! -d "$WORKTREE_ROOT" ] || [ ! -d "$NOTARY_STATE_ROOT" ]; then
		printf 'error: notary resume requires the preserved detached worktree and durable state ledger\n' >&2
		exit 1
	fi
else
	if [ -e "$RELEASE_ROOT" ] || [ -L "$RELEASE_ROOT" ]; then
		printf 'error: refusing a new notary attempt because this source already has a preserved worktree or state ledger\n' >&2
		exit 1
	fi
	mkdir -p "$RELEASES_ROOT"
	mkdir "$RELEASE_ROOT"
	chmod 700 "$RELEASE_ROOT"
	release_main_git worktree add --detach "$WORKTREE_ROOT" "$SOURCE_COMMIT"
fi
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
QPERIAPT_INTERNAL_NOTARY_KEYCHAIN_PROFILE="$NOTARY_KEYCHAIN_PROFILE" \
QPERIAPT_INTERNAL_NOTARY_STATE_DIR="$NOTARY_STATE_ROOT" \
QPERIAPT_INTERNAL_NOTARY_SUBMISSION_ID="$RESUME_SUBMISSION_ID" \
QPERIAPT_SWIFT_XCFRAMEWORK_OUT_DIR="$SOURCE_OUT" \
sh "$WORKTREE_ROOT/artifact/swift-xcframework.sh"

SOURCE_DIST="$SOURCE_OUT/q-periapt-swift-$VERSION"
PUBLIC_OUT="$ROOT/target/qperiapt-swift-xcframework"
PUBLIC_DIST="$PUBLIC_OUT/q-periapt-swift-$VERSION"
if [ ! -d "$SOURCE_DIST" ]; then
	printf 'error: detached release completed without its public distribution directory\n' >&2
	exit 1
fi
for release_file in CQPeriapt.xcframework.zip NOTARIZATION.json MANIFEST.json SHA256SUMS; do
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
	for release_file in CQPeriapt.xcframework.zip NOTARIZATION.json MANIFEST.json; do
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
for release_file in CQPeriapt.xcframework.zip NOTARIZATION.json MANIFEST.json SHA256SUMS; do
	cmp "$SOURCE_DIST/$release_file" "$PUBLIC_DIST/$release_file"
done
(
	cd "$PUBLIC_DIST"
	shasum -c SHA256SUMS
)
codesign --verify --strict --verbose=4 "$PUBLIC_DIST/CQPeriapt.xcframework"
if [ -f "$SOURCE_OUT/swift-binary-consumer.log" ]; then
	cp "$SOURCE_OUT/swift-binary-consumer.log" "$PUBLIC_OUT/swift-binary-consumer.log"
fi
printf 'APPLE_RELEASE_PUBLIC_COPY_PASS source_commit=%s path=%s\n' "$SOURCE_COMMIT" "$PUBLIC_DIST"
