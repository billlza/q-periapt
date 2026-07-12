#!/bin/sh
# Physical iPhone+iPad matrix proof for the Apple Swift/C ABI face.
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
	MATRIX_SPEC=$(xcrun devicectl list devices --json-output - 2>/dev/null | PYTHONPATH=artifact python3 -c '
import sys
from evidence_io import parse_strict_json_bytes

raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
if len(raw) > 8 * 1024 * 1024:
    raise SystemExit("error: devicectl device list JSON exceeds 8 MiB")
data = parse_strict_json_bytes(raw, label="devicectl device list")
if not isinstance(data, dict):
    raise SystemExit("error: devicectl device list root is not an object")
matches = {"ipad": [], "iphone": []}
for dev in data.get("result", {}).get("devices", []):
    props = dev.get("properties", {})
    hardware = props.get("hardware", {})
    state = props.get("state", {})
    connection = props.get("connection", {})
    if hardware.get("platform") != "iOS" or hardware.get("reality") != "physical":
        continue
    if state.get("bootState") != "booted" or connection.get("state") != "connected":
        continue
    udid = hardware.get("udid")
    if hardware.get("deviceType") == "iPad" and udid:
        matches["ipad"].append(udid)
    if hardware.get("deviceType") == "iPhone" and udid:
        matches["iphone"].append(udid)
if len(matches["ipad"]) != 1 or len(matches["iphone"]) != 1:
    missing = [label for label, values in matches.items() if len(values) != 1]
    raise SystemExit("error: auto-detect requires exactly one connected physical iPad and one connected physical iPhone; set QPERIAPT_IOS_DEVICE_MATRIX explicitly. missing_or_ambiguous=" + ",".join(missing))
print("ipad:{},iphone:{}".format(matches["ipad"][0], matches["iphone"][0]))
')
fi

mkdir -p "$MATRIX_RESULT_DIR" "$DERIVED_BASE"

PYTHONPATH=artifact python3 - "$MATRIX_SPEC" <<'PY'
import re
import subprocess
import sys

from evidence_io import parse_strict_json_bytes

matrix_spec = sys.argv[1]
label_to_type = {"ipad": "iPad", "iphone": "iPhone"}
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
    raw_json = subprocess.check_output(
        ["xcrun", "devicectl", "device", "info", "details", "--device", device_id, "--json-output", "-"],
        stderr=subprocess.DEVNULL,
    )
    if len(raw_json) > 8 * 1024 * 1024:
        raise SystemExit(f"error: devicectl detail JSON exceeds 8 MiB for {label}")
    document = parse_strict_json_bytes(raw_json, label=f"devicectl detail for {label}")
    if not isinstance(document, dict):
        raise SystemExit(f"error: devicectl detail root is not an object for {label}")
    result = document.get("result", {})
    props = result.get("properties", {})
    hardware = props.get("hardware", {})
    state = props.get("state", {})
    connection = props.get("connection", {})
    if hardware.get("udid") != device_id:
        raise SystemExit(f"error: devicectl returned the wrong device for {label}")
    actual_type = hardware.get("deviceType")
    if hardware.get("platform") != "iOS" or hardware.get("reality") != "physical":
        raise SystemExit(f"error: matrix device {label} is not a physical iOS device")
    if actual_type != expected_type:
        raise SystemExit(f"error: matrix label {label} expected {expected_type}, got {actual_type}")
    if state.get("bootState") != "booted" or connection.get("state") != "connected" or connection.get("pairingState") != "paired":
        raise SystemExit(
            f"error: matrix device {label} must be booted/connected/paired; "
            f"boot={state.get('bootState')} connection={connection.get('state')} "
            f"pairing={connection.get('pairingState')} transport={connection.get('transportType')}; "
            "devicectl available/paired but disconnected devices are not accepted as runnable proof"
        )
    seen_types.add(actual_type)
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
		ipad) expected_type=iPad ;;
		iphone) expected_type=iPhone ;;
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
		--expected-device-type "$expected_type" >/dev/null
	QPERIAPT_IOS_DEVICE_ID="$device_id" \
	QPERIAPT_DEVICE_LABEL="$label" \
	QPERIAPT_DEVICE_ARTIFACT_PREFIX="$label" \
	QPERIAPT_EXPECT_DEVICE_TYPE="$expected_type" \
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

printf '\nALL PASS: physical iPad + iPhone Apple-device matrix smoke\n'
