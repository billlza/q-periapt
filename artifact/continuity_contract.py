#!/usr/bin/env python3
"""Compare a compiled candidate's shared contract with the reviewed wire budgets."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from bounded_process import capture_output
from evidence_io import parse_strict_json_bytes, read_regular_snapshot

ROOT = Path(__file__).resolve().parent.parent
BUDGETS = ROOT / "docs/continuity/BUDGETS_V1.json"
FIELDS = {"schema_version", "frozen_product_contract", "signature_context", "rekey_profile",
          "rekey_profile_sha3_256", "message_domain", "maximums"}
LIMITS = {
    "signed_body_bytes", "bootstrap_bundle_bytes", "bootstrap_field_bytes", "plaintext_bytes",
    "associated_data_bytes", "skipped_keys_per_direction_epoch", "outstanding_messages_per_direction_epoch",
    "retained_traffic_epochs", "control_body_bytes", "connection_frame_bytes", "session_operation_records",
    "prekey_records", "account_roster_records", "device_history_per_account", "journal_image_bytes",
    "network_exchanges", "run_timeout_seconds", "connect_timeout_seconds", "roster_devices", "manifest_prekeys",
}


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def validate(value: object) -> dict:
    require(type(value) is dict and set(value) == FIELDS, "contract fields differ")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1,
            "contract schema differs")
    require(value["frozen_product_contract"] is False, "candidate cannot claim a product freeze")
    for name in ("signature_context", "rekey_profile", "rekey_profile_sha3_256", "message_domain"):
        text = value[name]
        require(type(text) is str and 0 < len(text) <= 512 and all(0x21 <= ord(c) <= 0x7e for c in text),
                "contract domain/profile encoding is invalid")
    bounds = value["maximums"]
    require(type(bounds) is dict and set(bounds) == LIMITS, "contract limit fields differ")
    require(all(type(n) is int and 0 < n <= 2**32-1 for n in bounds.values()),
            "contract limit is not a positive bounded integer")
    domain = b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/offer-profile"
    body = value["rekey_profile"].encode("ascii")
    digest = hashlib.sha3_256(len(domain).to_bytes(8, "big") + domain
                            + len(body).to_bytes(8, "big") + body).hexdigest()
    require(value["rekey_profile_sha3_256"] == digest, "profile commitment differs")
    return value


def compare(expected: object, actual: object) -> dict:
    expected = validate(expected)
    actual = validate(actual)
    require(actual == expected, "compiled contract differs from reviewed wire budgets")
    return actual


def snapshot(path: Path, maximum: int = 65536):
    return read_regular_snapshot(path, maximum=maximum, label="Continuity contract input")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    expected = snapshot(BUDGETS)
    executable = snapshot(args.consumer, 256 * 1024**2)
    output = args.output.absolute()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {"kind": "qperiapt.continuity_wire_contract", "completed": False,
              "release_claim_eligible": False, "budgets_sha256": expected.sha256,
              "consumer_sha256": executable.sha256, "consumer": str(executable.path)}
    try:
        argv = [str(executable.path)]
        result = capture_output(argv, timeout_seconds=30, maximum_stdout_bytes=65536,
                                maximum_stderr_bytes=65536)
        (output / "consumer.stdout").write_bytes(result.stdout)
        (output / "consumer.stderr").write_bytes(result.stderr)
        report.update(argv=argv, returncode=result.returncode)
        require(result.returncode == 0 and result.stderr == b"", "compiled contract command failed or emitted diagnostics")
        actual = compare(parse_strict_json_bytes(expected.data, label="reviewed wire budgets"),
                         parse_strict_json_bytes(result.stdout, label="compiled wire contract"))
        require(snapshot(BUDGETS).sha256 == expected.sha256
                and snapshot(args.consumer, 256 * 1024**2).sha256 == executable.sha256,
                "contract inputs changed during verification")
        report.update(completed=True, contract=actual)
    except Exception as error:
        report["failure"] = str(error)
        raise
    finally:
        with (output / "CONTRACT.json").open("x") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
