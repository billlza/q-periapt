#!/usr/bin/env python3
"""Replay the reviewed single-exchange recovery certificates, without proof search.

Byte pins bind the editable model to the reviewed observer projection and complete
queries. A model/certificate change needs a new reviewed checkpoint and pins;
passing a different theorem is not a compatible update. This gate does not prove
computational security, multi-epoch recovery or correspondence with the SDK.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
import zipfile

from bounded_process import BoundedProcessError, capture_output
from evidence_io import EvidenceIOError, fresh_output_directory, read_regular_snapshot
from formal_toolchain_contract import FormalToolchainContractError, verify_installed


ROOT = Path(__file__).resolve().parents[1]
MODEL = "research/continuity-recovery-symbolic/protected-state.spthy"
MODEL_SHA256 = "7802d0a937cd3f1afd75cb256c4cadc17b714f042f4894f4d471b3ea3d7bf902"
ARCHIVE = "research/sdk-alpha1/evidence/20261015-recovery-positive-symbolic/CAPTURE.zip"
ARCHIVE_SHA256 = "e207e57e480608b408823bff1c3ce28a805214df24e651a599b02150684dcea9"
MAIN = "clean_reservation_recovers_symbolic_message_secrecy"
WITNESSES = (
    "recovery_is_executable",
    "pre_cut_generation_reservation_remains_exposed",
    "later_storage_access_defeats_fresh_reservations",
)
DEPENDENCIES = (
    "traffic_key_derivation_requires_prior_root",
    "message_derivation_requires_prior_traffic_key",
    "response_confirmation_has_origin_or_prior_root",
    "computed_root_identifies_session",
    "accepted_root_has_origin_or_prior_derivation",
    "signing_secret_derivation_origin",
    "generation_secret_derivation_origin",
    "signing_secret_origin",
    "generation_secret_origin",
    "encapsulation_uses_authenticated_generation",
    "encapsulation_derivation_requires_session_leak",
    "accepted_root_has_authenticated_origin",
    "message_root_has_authenticated_origin",
    "root_constructor_requires_prior_coins_or_snapshot",
    "computed_root_derivation_requires_session_leak",
    "message_derivation_requires_session_leak",
    "retained_record_has_saved_origin",
    "stored_records_follow_fresh_reservations",
    "encapsulation_secret_requires_session_leak",
)
# (archive member, reviewed certificate digest, GHC heap limit)
CERTIFICATES = {
    "positive": (
        "proof/final-positive-53-proof.spthy",
        "91dd31801ee8c208d295a5a02efc1721c794fc8dd32bb1430d303fcb18199707", "12G",
    ),
    "witnesses": (
        "prior/original-witnesses-export-36.spthy",
        "3e217d9c6d535739826799f46078137328dda6bbc23d984ca88556095eacb8d2", "2G",
    ),
}
MAXIMUM_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 900
_ROW = re.compile(
    r"  (\w+) \((all-traces|exists-trace)\): "
    r"(verified|analysis incomplete|falsified - found trace) \(([1-9][0-9]*) steps\)"
)


class RecoveryProofError(ValueError):
    """The pinned proof contract or its actual terminal result was not satisfied."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryProofError(message)


def checked_bytes(data: bytes, expected: str, label: str) -> bytes:
    require(hashlib.sha256(data).hexdigest() == expected, f"{label} differs from reviewed bytes")
    return data


def load_inputs(root: Path) -> dict[str, bytes]:
    """Read bounded snapshots; never extract arbitrary archive paths."""
    model = read_regular_snapshot(root / MODEL, maximum=MAXIMUM_BYTES, label="recovery model")
    checked_bytes(model.data, MODEL_SHA256, "recovery model")
    archive = read_regular_snapshot(root / ARCHIVE, maximum=MAXIMUM_BYTES, label="recovery archive")
    checked_bytes(archive.data, ARCHIVE_SHA256, "recovery archive")
    inputs = {}
    with zipfile.ZipFile(io.BytesIO(archive.data)) as zipped:
        names = zipped.namelist()
        require(len(names) == len(set(names)), "duplicate recovery archive members")
        for label, (member, digest, _heap) in CERTIFICATES.items():
            require(member in names, f"missing {label} certificate")
            require(zipped.getinfo(member).file_size <= MAXIMUM_BYTES, "oversized certificate")
            inputs[label] = checked_bytes(zipped.read(member), digest, label)
    return inputs


def expected_results(label: str) -> dict[str, tuple[str, str]]:
    if label == "positive":
        return {
            **{name: ("all-traces", "verified") for name in (*DEPENDENCIES, MAIN)},
            **{name: ("exists-trace", "analysis incomplete") for name in WITNESSES},
        }
    require(label == "witnesses", "unknown recovery proof group")
    return {
        **{name: ("exists-trace", "verified") for name in WITNESSES},
        **{name: ("all-traces", "analysis incomplete") for name in ("generation_secret_origin", MAIN)},
    }


def verify_summary(stdout: bytes, label: str, source: Path, output: Path) -> dict[str, int]:
    """Accept exactly one terminal inventory, including its non-premise placeholders."""
    text = stdout.decode("utf-8", errors="strict")
    separator = "=" * 78
    lines = [line for line in text.splitlines() if line.strip()]
    require(len(lines) >= 7, "missing recovery proof summary")
    require(lines[:3] == [separator, "summary of summaries:", f"analyzed: {source}"],
            "unexpected recovery summary header or analyzed input")
    require(lines[3] == f"  output:          {output}", "unexpected recovery certificate output")
    require(re.fullmatch(r"  processing time: [0-9]+(?:\.[0-9]+)?s", lines[4]) is not None,
            "missing recovery processing time")
    require(lines[-1] == separator, "unterminated recovery summary")
    actual = {}
    steps = {}
    for line in lines[5:-1]:
        row = _ROW.fullmatch(line)
        if row is None:
            raise RecoveryProofError("malformed recovery lemma result")
        name, mode, status, count = row.groups()
        require(name not in actual, "duplicate recovery lemma result")
        actual[name] = (mode, status)
        steps[name] = int(count)
    require(actual == expected_results(label), "recovery proof inventory or status differs")
    return {name: steps[name] for name, (_mode, status) in actual.items() if status == "verified"}


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def prover_environment() -> dict[str, str]:
    # Exported Tamarin certificates contain Unicode quantifiers and proof arrows.
    # Linux GHC decodes handles using the locale: LC_ALL=C rejects these bytes.
    # macOS provides en_US.UTF-8; glibc provides the portable C.UTF-8 locale.
    require(sys.platform in ("darwin", "linux"), "recovery replay requires macOS or Linux")
    encoding_locale = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
    return {"PATH": os.environ["PATH"], "LANG": encoding_locale, "LC_ALL": encoding_locale}


def replay(label: str, data: bytes, directory: Path, environment: dict[str, str]) -> dict:
    source = directory / f"{label}-input.spthy"
    output = directory / f"{label}-checked.spthy"
    with source.open("xb") as stream:
        stream.write(data)
    argv = [
        "tamarin-prover", str(source), "--heuristic=s", "--derivcheck-timeout=60",
        "--quit-on-warning", "--output=" + str(output),
        "+RTS", "-N2", "-M" + CERTIFICATES[label][2], "-s", "-RTS",
    ]
    write_json(directory / f"{label}-started.json", {
        "argv": argv, "timeout_seconds": TIMEOUT_SECONDS,
        "input_sha256": hashlib.sha256(data).hexdigest(),
    })
    started = time.monotonic()
    result = capture_output(argv, timeout_seconds=TIMEOUT_SECONDS,
                            maximum_stdout_bytes=MAXIMUM_BYTES,
                            maximum_stderr_bytes=MAXIMUM_BYTES, environment=environment)
    for suffix, content in (("stdout", result.stdout), ("stderr", result.stderr)):
        with (directory / f"{label}.{suffix}").open("xb") as stream:
            stream.write(content)
    require(result.returncode == 0, f"{label} prover exited {result.returncode}")
    stderr = result.stderr.decode("utf-8", errors="strict")
    require(re.search(r"(?im)^\s*(?:warning|error|fatal)\b", stderr) is None,
            f"{label} emitted a diagnostic")
    verified = verify_summary(result.stdout, label, source, output)
    checked = read_regular_snapshot(output, maximum=MAXIMUM_BYTES, label="checked certificate")
    require(checked.size > 0, "empty checked certificate")
    source_after = read_regular_snapshot(source, maximum=MAXIMUM_BYTES, label="replayed input")
    checked_bytes(source_after.data, CERTIFICATES[label][1], "replayed input")
    return {"verified": verified, "elapsed_seconds": time.monotonic() - started,
            "returncode": result.returncode, "certificate_sha256": checked.sha256}


def run(root: Path, destination: Path) -> None:
    inputs = load_inputs(root)
    directory = fresh_output_directory(destination, within=root / "target", label="recovery replay")
    directory.mkdir(parents=True, mode=0o700)
    receipt = {"accepted": False, "release_claim_eligible": False, "groups": {},
               "model_sha256": MODEL_SHA256, "archive_sha256": ARCHIVE_SHA256,
               "gate_sha256": read_regular_snapshot(Path(__file__), maximum=MAXIMUM_BYTES,
                                                     label="recovery gate").sha256}
    try:
        # Share the repository's version authority, and remove ambient RTS overrides.
        verify_installed("tamarin")
        environment = prover_environment()
        for label, data in inputs.items():
            print(f"Replaying recovery {label} certificate (deadline {TIMEOUT_SECONDS}s)", flush=True)
            receipt["groups"][label] = replay(label, data, directory, environment)
        require(load_inputs(root) == inputs, "recovery inputs changed during replay")
        receipt["accepted"] = True
    except (RecoveryProofError, BoundedProcessError, FormalToolchainContractError,
            EvidenceIOError, OSError, UnicodeError, zipfile.BadZipFile) as exc:
        receipt["error"] = str(exc)
        write_json(directory / "RESULT.json", receipt)
        raise
    write_json(directory / "RESULT.json", receipt)
    print("CONTINUITY_RECOVERY_PROOF_PASS properties=20 witnesses=3 release_claim_eligible=false")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        run(ROOT, args.output)
        return 0
    except (RecoveryProofError, BoundedProcessError, FormalToolchainContractError,
            EvidenceIOError, OSError, UnicodeError, zipfile.BadZipFile) as exc:
        print(f"error: continuity recovery proof: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
