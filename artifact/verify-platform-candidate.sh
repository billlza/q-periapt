#!/bin/sh
# Verify the exact attested CI candidate set before platform distribution assembly.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

if [ "$#" -ne 2 ]; then
	printf 'usage: %s CANDIDATE_DIRECTORY EXPECTED_TAG_COMMIT\n' "$0" >&2
	exit 2
fi

CANDIDATE_DIR=$1
EXPECTED_COMMIT=$2
RELEASE_TAG=abi2-platforms-v0.1.0-alpha.2-r2
RELEASE_REF=refs/tags/$RELEASE_TAG
REPOSITORY=billlza/q-periapt
SIGNER_WORKFLOW=billlza/q-periapt/.github/workflows/abi2-platform-candidate.yml

case "$CANDIDATE_DIR" in
	/*) ;;
	*)
		printf 'error: candidate directory must be an absolute path\n' >&2
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

PYTHONPATH=artifact python3 - "$CANDIDATE_DIR" <<'PY'
import hashlib
import pathlib
import re
import stat
import sys

from evidence_io import EvidenceIOError, read_regular_snapshot

root = pathlib.Path(sys.argv[1])
try:
    metadata = root.lstat()
    root = root.resolve(strict=True)
except OSError as exc:
    raise SystemExit(f"error: cannot inspect candidate directory: {exc}") from exc
if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
    raise SystemExit("error: candidate directory must be a non-symlink directory")

assets = {
    "q-periapt-android-0.1.0-alpha.2.aar",
    "q-periapt-android-0.1.0-alpha.2-MANIFEST.json",
    "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz",
    "q-periapt-c-abi2-0.1.0-alpha.2-aarch64-unknown-linux-gnu.tar.gz",
    "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc.zip",
}
expected = assets | {"CANDIDATE_SHA256SUMS"}
actual = set()
for path in root.rglob("*"):
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        if stat.S_ISDIR(info.st_mode) and not path.is_symlink():
            continue
        raise SystemExit(f"error: candidate tree contains an unsafe entry: {path}")
    relative = path.relative_to(root).as_posix()
    if "/" in relative:
        raise SystemExit(f"error: candidate asset must be at the directory root: {relative}")
    actual.add(relative)
if actual != expected:
    raise SystemExit(
        "error: candidate asset set differs: "
        f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
    )

try:
    sums = read_regular_snapshot(
        root / "CANDIDATE_SHA256SUMS",
        maximum=1024 * 1024,
        label="candidate SHA256SUMS",
    ).data.decode("ascii")
except (EvidenceIOError, UnicodeDecodeError) as exc:
    raise SystemExit(f"error: cannot read candidate checksums: {exc}") from exc
if not sums.endswith("\n"):
    raise SystemExit("error: candidate SHA256SUMS must end with a newline")
parsed = {}
for line in sums.splitlines():
    parts = line.split("  ", 1)
    if len(parts) != 2:
        raise SystemExit(f"error: malformed candidate checksum line: {line!r}")
    digest, name = parts
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None or name not in assets or name in parsed:
        raise SystemExit(f"error: invalid candidate checksum entry: {name!r}")
    parsed[name] = digest
if list(parsed) != sorted(parsed) or set(parsed) != assets:
    raise SystemExit("error: candidate checksum paths are incomplete or not canonically sorted")
for name, expected_digest in parsed.items():
    try:
        data = read_regular_snapshot(
            root / name,
            maximum=512 * 1024 * 1024,
            label=f"candidate asset {name}",
        ).data
    except EvidenceIOError as exc:
        raise SystemExit(f"error: {exc}") from exc
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise SystemExit(f"error: candidate checksum mismatch: {name}")
PY

gh auth status >/dev/null 2>&1
ATTESTATION_DIR=$ROOT/target/abi2-platform-candidate-attestations
rm -rf "$ATTESTATION_DIR"
mkdir -p "$ATTESTATION_DIR"

for asset in \
	q-periapt-android-0.1.0-alpha.2.aar \
	q-periapt-android-0.1.0-alpha.2-MANIFEST.json \
	q-periapt-c-abi2-0.1.0-alpha.2-aarch64-unknown-linux-gnu.tar.gz \
	q-periapt-c-abi2-0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz \
	q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc.zip \
	CANDIDATE_SHA256SUMS
do
	output=$ATTESTATION_DIR/$asset.json
	gh attestation verify "$CANDIDATE_DIR/$asset" \
		--repo "$REPOSITORY" \
		--signer-workflow "$SIGNER_WORKFLOW" \
		--signer-digest "$EXPECTED_COMMIT" \
		--source-ref "$RELEASE_REF" \
		--source-digest "$EXPECTED_COMMIT" \
		--deny-self-hosted-runners \
		--format json >"$output"
	PYTHONPATH=artifact python3 - "$output" "$asset" <<'PY'
import pathlib
import sys

from evidence_io import EvidenceIOError, parse_strict_json_bytes, read_regular_snapshot

path = pathlib.Path(sys.argv[1])
asset = sys.argv[2]
try:
    snapshot = read_regular_snapshot(
        path,
        maximum=16 * 1024 * 1024,
        label=f"attestation verification result for {asset}",
    )
    result = parse_strict_json_bytes(snapshot.data, label=f"attestation verification result for {asset}")
except EvidenceIOError as exc:
    raise SystemExit(f"error: {exc}") from exc
if not isinstance(result, list) or not result:
    raise SystemExit(f"error: no verified build provenance attestation was returned for {asset}")
PY
done

printf 'ABI2_PLATFORM_CANDIDATE_ATTESTATION_VERIFY_PASS assets=6 commit=%s\n' "$EXPECTED_COMMIT"
