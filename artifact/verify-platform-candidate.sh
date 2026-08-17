#!/bin/sh
# Verify the exact attested CI candidate set before platform distribution assembly.
set -eu

ROOT=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

if [ "$#" -ne 3 ]; then
	printf 'usage: %s CANDIDATE_DIRECTORY EXPECTED_TAG_COMMIT PROJECTION_OUTPUT\n' "$0" >&2
	exit 2
fi

CANDIDATE_DIR=$1
EXPECTED_COMMIT=$2
PROJECTION_OUTPUT=$3

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

# Reject every caller-controlled filesystem path before invoking Git or GitHub.
/bin/sh artifact/python-run.sh artifact/platform_candidate_attestation.py preflight \
	"$CANDIDATE_DIR" "$PROJECTION_OUTPUT" "$EXPECTED_COMMIT"

TARGET_ROOT=$ROOT/target
VERIFICATION_ROOT=$TARGET_ROOT/abi2-platform-candidate-verification
PRIVATE_PARENT=$VERIFICATION_ROOT/raw
for private_root in "$TARGET_ROOT" "$VERIFICATION_ROOT" "$PRIVATE_PARENT"; do
	if [ -e "$private_root" ]; then
		test -d "$private_root" && test ! -L "$private_root" || {
			printf 'error: candidate verification root must be a non-symlink directory: %s\n' "$private_root" >&2
			exit 1
		}
	else
		(umask 077 && /bin/mkdir "$private_root") || {
			printf 'error: cannot create candidate verification root: %s\n' "$private_root" >&2
			exit 1
		}
	fi
done
/bin/sh artifact/python-run.sh artifact/platform_candidate_attestation.py validate-raw-root
/bin/sh artifact/python-run.sh artifact/platform_candidate_attestation.py checkout-verify \
	"$EXPECTED_COMMIT"

ATTESTATION_DIR=$(
	umask 077
	/usr/bin/mktemp -d "$PRIVATE_PARENT/transaction.XXXXXXXX"
) || {
	printf 'error: cannot create private candidate attestation directory\n' >&2
	exit 1
}
/bin/chmod 0700 "$ATTESTATION_DIR"
SNAPSHOT_OUTPUT=$ATTESTATION_DIR/candidate-snapshot.json

# This validates the explicit O_EXCL projection target and records the sole
# preflight byte snapshot before any network-backed verification starts.
/bin/sh artifact/python-run.sh artifact/platform_candidate_attestation.py snapshot \
	"$CANDIDATE_DIR" "$SNAPSHOT_OUTPUT" "$PROJECTION_OUTPUT" "$EXPECTED_COMMIT"

/bin/sh artifact/python-run.sh artifact/platform_candidate_attestation.py github-verify \
	"$CANDIDATE_DIR" "$EXPECTED_COMMIT" "$ATTESTATION_DIR"

# Re-sample with the same parser, require an identical snapshot, then parse all
# six raw VRs as one exact transaction and O_EXCL-publish the safe projection.
/bin/sh artifact/python-run.sh artifact/platform_candidate_attestation.py verify \
	"$CANDIDATE_DIR" "$EXPECTED_COMMIT" "$PROJECTION_OUTPUT" \
	"$ATTESTATION_DIR" "$SNAPSHOT_OUTPUT"
