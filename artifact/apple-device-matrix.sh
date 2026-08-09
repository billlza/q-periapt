#!/bin/sh
# Physical iPhone+iPad matrix proof for the Apple Swift/C ABI face.
set -eu
umask 077

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd) || exit 2
cd "$ROOT" || exit 2
. "$ROOT/artifact/python-env.sh"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'error: required tool not found: %s\n' "$1" >&2
		exit 2
	fi
}

need date
need python3
need xcrun

MATRIX_SPEC=${QPERIAPT_IOS_DEVICE_MATRIX:-}
DEVICE_PROOF_MAX_AGE_SECONDS=${QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS:-86400}
ALLOW_DIRTY_APPLE_DEVICE=${QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE:-0}
RUN_LABEL=$(date -u +%Y%m%dT%H%M%SZ)-$(python3 -c 'import secrets; print(secrets.token_hex(4))')
MATRIX_RESULT_DIR=${QPERIAPT_DEVICE_RESULT_DIR:-"$ROOT/artifact/device-runs/apple-matrix-$RUN_LABEL"}
DERIVED_BASE=${QPERIAPT_DERIVED_DATA:-"$ROOT/target/apple-device-derived-matrix-$RUN_LABEL"}
MATRIX_PROOF="$MATRIX_RESULT_DIR/apple-device-matrix-proof.json"

if [ "${QPERIAPT_REQUIRED_DEVICE_TYPES+x}" = x ]; then
	printf 'error: QPERIAPT_REQUIRED_DEVICE_TYPES was removed; the release matrix always requires iPad and iPhone\n' >&2
	exit 2
fi

case "$ALLOW_DIRTY_APPLE_DEVICE" in
	0 | 1) ;;
	*)
		printf 'error: QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE must be 0 or 1\n' >&2
		exit 2
		;;
esac
SOURCE_TREE_DIRTY=$(PYTHONPATH=artifact python3 - "$ROOT" <<'PY'
import pathlib
import sys

from git_provenance import source_tree_dirty

print(int(source_tree_dirty(pathlib.Path(sys.argv[1]))))
PY
)
if [ "$SOURCE_TREE_DIRTY" = "1" ]; then
	if [ "$ALLOW_DIRTY_APPLE_DEVICE" != "1" ]; then
		printf 'error: Apple device matrix proof requires a clean source tree; set QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1 for local diagnostics only\n' >&2
		exit 2
	fi
	printf 'note: QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1 records diagnostic-only dirty-source Apple matrix proof\n'
fi

python3 - "$ROOT" "$MATRIX_RESULT_DIR" "$MATRIX_PROOF" "$DERIVED_BASE" "$DEVICE_PROOF_MAX_AGE_SECONDS" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
matrix_dir = pathlib.Path(sys.argv[2]).resolve()
matrix_proof = pathlib.Path(sys.argv[3]).resolve()
derived_base = pathlib.Path(sys.argv[4]).resolve()
max_age = int(sys.argv[5])
runs_base = root / "artifact" / "device-runs"
target_base = root / "target"
limit = 7 * 24 * 60 * 60

def require_under(path, base, label):
    try:
        path.relative_to(base.resolve())
    except ValueError:
        raise SystemExit(f"error: {label} must be under {base}: {path}")

require_under(matrix_dir, runs_base, "QPERIAPT_DEVICE_RESULT_DIR")
require_under(matrix_proof, matrix_dir, "matrix proof")
require_under(derived_base, target_base, "QPERIAPT_DERIVED_DATA")
if not 0 < max_age <= limit:
    raise SystemExit(f"error: QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS must be between 1 and {limit}: {max_age}")
PY

if [ -z "$MATRIX_SPEC" ]; then
	printf 'error: QPERIAPT_IOS_DEVICE_MATRIX is required; automatic device selection is forbidden for the physical matrix lane\n' >&2
	exit 2
fi

mkdir -p "$MATRIX_RESULT_DIR" "$DERIVED_BASE"
chmod 700 "$MATRIX_RESULT_DIR" "$DERIVED_BASE"

PYTHONPATH=artifact python3 - "$MATRIX_SPEC" <<'PY'
import re
import sys

from apple_device_proof import load_device_metadata

matrix_spec = sys.argv[1]
label_to_type = {"ipad": "iPad", "iphone": "iPhone"}
label_to_transport = {"ipad": "wired", "iphone": "localNetwork"}
entries = []
seen_labels = set()
seen_ids = set()
for raw in matrix_spec.split(","):
    if ":" not in raw:
        raise SystemExit(f"error: QPERIAPT_IOS_DEVICE_MATRIX entries must be label:device-id, got: {raw}")
    label, device_id = raw.split(":", 1)
    if label not in label_to_type:
        raise SystemExit(f"error: unsupported matrix label: {label}")
    if not re.fullmatch(r"[A-Za-z0-9-]{8,128}", device_id):
        raise SystemExit(f"error: invalid matrix device id for {label}: {device_id}")
    if label in seen_labels:
        raise SystemExit(f"error: duplicate matrix label: {label}")
    if device_id in seen_ids:
        raise SystemExit(f"error: duplicate matrix device id for label {label}")
    seen_labels.add(label)
    seen_ids.add(device_id)
    entries.append((label, device_id, label_to_type[label]))
missing_labels = set(label_to_type) - seen_labels
if missing_labels:
    raise SystemExit(f"error: matrix missing required labels: {sorted(missing_labels)}")
seen_types = set()
for label, device_id, expected_type in entries:
    metadata = load_device_metadata(
        device_id,
        expected_type,
        label_to_transport[label],
    )
    seen_types.add(metadata["type"])
if seen_types != {"iPad", "iPhone"}:
    raise SystemExit(f"error: matrix must contain iPad and iPhone, got: {sorted(seen_types)}")
PY

MATRIX_SPEC_DISPLAY=$(python3 - "$MATRIX_SPEC" <<'PY'
import hashlib
import sys

items = []
for raw in sys.argv[1].split(","):
    label, device_id = raw.split(":", 1)
    digest = hashlib.sha256(device_id.encode("utf-8")).hexdigest()[:12]
    items.append(f"{label}:sha256:{digest}")
print(",".join(items))
PY
)

printf 'Q-Periapt Apple device matrix smoke\n'
printf 'matrix : %s\n' "$MATRIX_SPEC_DISPLAY"
printf 'result : %s\n' "$MATRIX_RESULT_DIR"
printf 'derived: %s\n' "$DERIVED_BASE"

set --
SEEN_LABELS=
SEEN_DEVICE_IDS=
OLD_IFS=$IFS
IFS=,
for raw_entry in $MATRIX_SPEC; do
	IFS=$OLD_IFS
	label=${raw_entry%%:*}
	device_id=${raw_entry#*:}
	if [ "$label" = "$raw_entry" ] || [ -z "$label" ] || [ -z "$device_id" ]; then
		printf 'error: QPERIAPT_IOS_DEVICE_MATRIX entries must be label:device-id, got: %s\n' "$raw_entry" >&2
		exit 2
	fi
	case "$label" in
		ipad) expected_type=iPad; expected_transport=wired ;;
		iphone) expected_type=iPhone; expected_transport=localNetwork ;;
		*)
			printf 'error: unsupported matrix label: %s (expected ipad or iphone)\n' "$label" >&2
			exit 2
			;;
	esac
	case " $SEEN_LABELS " in
		*" $label "*)
			printf 'error: duplicate matrix label: %s\n' "$label" >&2
			exit 2
			;;
	esac
	case " $SEEN_DEVICE_IDS " in
		*" $device_id "*)
			printf 'error: duplicate matrix device id for label %s\n' "$label" >&2
			exit 2
			;;
	esac
	SEEN_LABELS="$SEEN_LABELS $label"
	SEEN_DEVICE_IDS="$SEEN_DEVICE_IDS $device_id"

	device_result_dir="$MATRIX_RESULT_DIR/$label"
	device_derived="$DERIVED_BASE/$label"
	mkdir -p "$device_result_dir"
	printf '\n=== Matrix device: %s (%s) ===\n' "$label" "$expected_type"
	python3 artifact/apple_device_proof.py inspect-device \
		--device-id "$device_id" \
		--expected-device-type "$expected_type" \
		--expected-transport "$expected_transport" >/dev/null
	QPERIAPT_IOS_DEVICE_ID="$device_id" \
	QPERIAPT_DEVICE_LABEL="$label" \
	QPERIAPT_DEVICE_ARTIFACT_PREFIX="$label" \
	QPERIAPT_EXPECT_DEVICE_TYPE="$expected_type" \
	QPERIAPT_EXPECT_DEVICE_TRANSPORT="$expected_transport" \
	QPERIAPT_DEVICE_RESULT_DIR="$device_result_dir" \
	QPERIAPT_DERIVED_DATA="$device_derived" \
	sh artifact/apple-device-smoke.sh
	set -- "$@" --entry "$label:$label:$device_result_dir"
	IFS=,
done
IFS=$OLD_IFS

case " $SEEN_LABELS " in
	*" ipad "*) ;;
	*)
		printf 'error: matrix missing ipad entry\n' >&2
		exit 2
		;;
esac
case " $SEEN_LABELS " in
	*" iphone "*) ;;
	*)
		printf 'error: matrix missing iphone entry\n' >&2
		exit 2
		;;
esac

if [ "$ALLOW_DIRTY_APPLE_DEVICE" = "1" ]; then
	python3 artifact/apple_device_proof.py emit-matrix \
		--root "$ROOT" \
		--matrix-root "$MATRIX_RESULT_DIR" \
		--output "$MATRIX_PROOF" \
		--max-age-seconds "$DEVICE_PROOF_MAX_AGE_SECONDS" \
		--allow-dirty-proof \
		"$@"
	python3 artifact/apple_device_proof.py verify-matrix \
		--root "$ROOT" \
		--matrix-root "$MATRIX_RESULT_DIR" \
		--matrix-proof "$MATRIX_PROOF" \
		--max-age-seconds "$DEVICE_PROOF_MAX_AGE_SECONDS" \
		--allow-dirty-proof
else
	python3 artifact/apple_device_proof.py emit-matrix \
		--root "$ROOT" \
		--matrix-root "$MATRIX_RESULT_DIR" \
		--output "$MATRIX_PROOF" \
		--max-age-seconds "$DEVICE_PROOF_MAX_AGE_SECONDS" \
		"$@"
	python3 artifact/apple_device_proof.py verify-matrix \
		--root "$ROOT" \
		--matrix-root "$MATRIX_RESULT_DIR" \
		--matrix-proof "$MATRIX_PROOF" \
		--max-age-seconds "$DEVICE_PROOF_MAX_AGE_SECONDS"
fi

printf '\nALL PASS: wired physical iPad + localNetwork physical iPhone Apple-device matrix smoke\n'
