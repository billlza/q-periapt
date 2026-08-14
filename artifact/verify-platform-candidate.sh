#!/bin/sh
# Verify the exact attested CI candidate set before platform distribution assembly.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

if [ "$#" -ne 3 ]; then
	printf 'usage: %s CANDIDATE_DIRECTORY EXPECTED_TAG_COMMIT PROJECTION_OUTPUT\n' "$0" >&2
	exit 2
fi

CANDIDATE_DIR=$1
EXPECTED_COMMIT=$2
PROJECTION_OUTPUT=$3
REPOSITORY=billlza/q-periapt
SIGNER_WORKFLOW=billlza/q-periapt/.github/workflows/abi2-platform-candidate.yml

case "$CANDIDATE_DIR" in
	/*) ;;
	*)
		printf 'error: candidate directory must be an absolute path\n' >&2
		exit 2
		;;
esac
case "$PROJECTION_OUTPUT" in
	/*) ;;
	*)
		printf 'error: candidate projection output must be an absolute path\n' >&2
		exit 2
		;;
esac
case "$EXPECTED_COMMIT" in
	????????????????????????????????????????) ;;
	*)
		printf 'error: expected tag commit must contain exactly 40 lowercase hexadecimal characters\n' >&2
		exit 2
		;;
esac
case "$EXPECTED_COMMIT" in
	*[!0-9a-f]*)
		printf 'error: expected tag commit must contain exactly 40 lowercase hexadecimal characters\n' >&2
		exit 2
		;;
esac

for tool in gh git python3; do
	command -v "$tool" >/dev/null 2>&1 || {
		printf 'error: required candidate verification tool is unavailable: %s\n' "$tool" >&2
		exit 2
	}
done

RELEASE_TAG=$(sh artifact/python-run.sh artifact/platform_candidate_attestation.py release-tag)
case "$RELEASE_TAG" in
	'' | *[!A-Za-z0-9._+-]*)
		printf 'error: current candidate release tag contract is unsafe\n' >&2
		exit 1
		;;
	*) ;;
esac
RELEASE_REF=refs/tags/$RELEASE_TAG

test "$(git cat-file -t "$RELEASE_REF")" = tag || {
	printf 'error: platform release tag is not annotated: %s\n' "$RELEASE_TAG" >&2
	exit 1
}
test "$(git rev-parse --verify "$RELEASE_REF^{commit}")" = "$EXPECTED_COMMIT" || {
	printf 'error: platform release tag commit differs from the trusted candidate commit\n' >&2
	exit 1
}
test "$(git rev-parse --verify 'HEAD^{commit}')" = "$EXPECTED_COMMIT" || {
	printf 'error: candidate verification checkout differs from the release tag commit\n' >&2
	exit 1
}
test "$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')" = "$EXPECTED_COMMIT" || {
	printf 'error: candidate verification commit differs from origin/main\n' >&2
	exit 1
}
test -z "$(git status --porcelain=v1 --untracked-files=all)" || {
	printf 'error: candidate verification requires a clean worktree\n' >&2
	exit 1
}

PRIVATE_PARENT=$ROOT/target
if [ -e "$PRIVATE_PARENT" ]; then
	test -d "$PRIVATE_PARENT" && test ! -L "$PRIVATE_PARENT" || {
		printf 'error: candidate attestation parent must be a non-symlink directory\n' >&2
		exit 1
	}
else
	(umask 077 && mkdir "$PRIVATE_PARENT") || {
		printf 'error: cannot create candidate attestation parent\n' >&2
		exit 1
	}
fi
ATTESTATION_DIR=$(
	umask 077
	mktemp -d "$PRIVATE_PARENT/abi2-platform-candidate-attestations.XXXXXXXX"
) || {
	printf 'error: cannot create private candidate attestation directory\n' >&2
	exit 1
}
chmod 0700 "$ATTESTATION_DIR"
SNAPSHOT_OUTPUT=$ATTESTATION_DIR/candidate-snapshot.json

# This validates the explicit O_EXCL projection target and records the sole
# preflight byte snapshot before any network-backed verification starts.
sh artifact/python-run.sh artifact/platform_candidate_attestation.py snapshot \
	"$CANDIDATE_DIR" "$SNAPSHOT_OUTPUT" "$PROJECTION_OUTPUT"

gh auth status >/dev/null 2>&1
SUBJECT_NAMES=$(sh artifact/python-run.sh \
	artifact/platform_candidate_attestation.py subject-names)
for asset in $SUBJECT_NAMES; do
	output=$ATTESTATION_DIR/$asset.json
	error_output=$ATTESTATION_DIR/$asset.stderr
	if ! (umask 077 && gh attestation verify "$CANDIDATE_DIR/$asset" \
		--repo "$REPOSITORY" \
		--signer-workflow "$SIGNER_WORKFLOW" \
		--signer-digest "$EXPECTED_COMMIT" \
		--source-ref "$RELEASE_REF" \
		--source-digest "$EXPECTED_COMMIT" \
		--deny-self-hosted-runners \
		--format json >"$output" 2>"$error_output"); then
		chmod 0600 "$output" "$error_output"
		printf 'error: GitHub rejected candidate attestation for %s\n' "$asset" >&2
		exit 1
	fi
	chmod 0600 "$output" "$error_output"
done

# Re-sample with the same parser, require an identical snapshot, then parse all
# six raw VRs as one exact transaction and O_EXCL-publish the safe projection.
sh artifact/python-run.sh artifact/platform_candidate_attestation.py verify \
	"$CANDIDATE_DIR" "$EXPECTED_COMMIT" "$PROJECTION_OUTPUT" \
	"$ATTESTATION_DIR" "$SNAPSHOT_OUTPUT"
