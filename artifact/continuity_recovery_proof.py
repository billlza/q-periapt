#!/usr/bin/env python3
"""Replay the reviewed single-exchange recovery certificates, without proof search.

Byte pins bind the editable model to the reviewed observer projection and complete
queries. A model/certificate change needs a new reviewed checkpoint and pins;
passing a different theorem is not a compatible update. This gate does not prove
computational security, multi-epoch recovery or correspondence with the SDK.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
import zipfile

import continuity_recovery_profiles as profiles
import continuity_recovery_composition as composition
from bounded_process import BoundedProcessError, capture_output
from evidence_io import EvidenceIOError, fresh_output_directory, read_regular_snapshot
from formal_toolchain_contract import FormalToolchainContractError, verify_installed


ROOT = Path(__file__).resolve().parents[1]
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


def select_profile(name: str) -> profiles.RecoveryProfile:
    require(name in profiles.PROFILES, "unknown recovery proof profile")
    return profiles.PROFILES[name]


def certificate(label: str, profile: str) -> profiles.Certificate:
    spec = select_profile(profile)
    require(label in spec.cases, "unknown recovery proof group")
    return spec.cases[label]


def load_inputs(root: Path, profile: str = "independent") -> dict[str, bytes]:
    """Read bounded snapshots; never extract arbitrary archive paths."""
    spec = select_profile(profile)
    model = read_regular_snapshot(root / spec.model, maximum=MAXIMUM_BYTES, label="recovery model")
    checked_bytes(model.data, spec.model_sha256, "recovery model")
    archive = read_regular_snapshot(root / spec.archive, maximum=spec.archive_maximum_bytes,
                                    label="recovery archive")
    checked_bytes(archive.data, spec.archive_sha256, "recovery archive")
    inputs = {}
    with zipfile.ZipFile(io.BytesIO(archive.data)) as zipped:
        names = zipped.namelist()
        require(len(names) == len(set(names)), "duplicate recovery archive members")
        for label, case in spec.cases.items():
            require(case.member in names, f"missing {label} certificate")
            require(zipped.getinfo(case.member).file_size <= MAXIMUM_BYTES, "oversized certificate")
            inputs[label] = checked_bytes(zipped.read(case.member), case.sha256, label)
    return inputs


def _verify_summary(stdout: bytes, source: Path, output: Path,
                    expected: dict[str, tuple[str, str]]) -> dict[str, int]:
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
    require(actual == expected, "recovery proof inventory or status differs")
    return {name: steps[name] for name, (_mode, status) in actual.items() if status == "verified"}


def verify_summary(stdout: bytes, label: str, source: Path, output: Path,
                   profile: str = "independent") -> dict[str, int]:
    return _verify_summary(stdout, source, output, certificate(label, profile).expected_results())


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


def _replay_once(label: str, data: bytes, directory: Path, environment: dict[str, str],
                 case: profiles.Certificate) -> dict:
    source = directory / f"{label}-input.spthy"
    output = directory / f"{label}-checked.spthy"
    with source.open("xb") as stream:
        stream.write(data)
    argv = [
        "tamarin-prover", str(source), "--heuristic=s", "--derivcheck-timeout=60",
        "--quit-on-warning", "--output=" + str(output),
        "+RTS", f"-N{case.threads}", f"-M{case.heap_gib}G", "-s", "-RTS",
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
    verified = _verify_summary(result.stdout, source, output, case.expected_results())
    checked = read_regular_snapshot(output, maximum=MAXIMUM_BYTES, label="checked certificate")
    require(checked.size > 0, "empty checked certificate")
    source_after = read_regular_snapshot(source, maximum=MAXIMUM_BYTES, label="replayed input")
    checked_bytes(source_after.data, case.sha256, "replayed input")
    return {"verified": verified, "elapsed_seconds": time.monotonic() - started,
            "returncode": result.returncode, "certificate_sha256": checked.sha256}


def replay(label: str, data: bytes, directory: Path, environment: dict[str, str],
           profile: str = "independent") -> dict:
    case = certificate(label, profile)
    if not case.compose_proofs:
        return _replay_once(label, data, directory, environment, case)
    nodes = composition.plan(data, case)
    parts = directory / label
    parts.mkdir(mode=0o700)
    started = time.monotonic()
    records = {}
    for index, node in enumerate(nodes):
        part_label = f"node-{index:02d}"
        print(f"Replaying {label} property {index + 1}/{len(nodes)}: {node.name}", flush=True)
        conditional = replace(case, sha256=node.sha256, verified=(node.name,), compose_proofs=False)
        result = _replay_once(part_label, node.data, parts, environment, conditional)
        record = {"source_certificate_sha256": case.sha256, "input_sha256": node.sha256,
                  "dependencies": list(node.dependencies), "result": result}
        write_json(parts / f"{part_label}-result.json", record)
        records[node.name] = record
    verified = composition.combine(data, records, case)
    # Recheck earlier parts too, after the last subprocess has completed.
    for index, node in enumerate(nodes):
        for suffix, expected in (("input", node.sha256),
                                 ("checked", records[node.name]["result"]["certificate_sha256"])):
            snapshot = read_regular_snapshot(parts / f"node-{index:02d}-{suffix}.spthy",
                                             maximum=MAXIMUM_BYTES, label="composition part")
            checked_bytes(snapshot.data, expected, "composition part")
    manifest = parts / "COMPOSITION.json"
    write_json(manifest, {"source_certificate_sha256": case.sha256,
                          "verified": verified, "nodes": records})
    return {"verified": verified, "elapsed_seconds": time.monotonic() - started,
            "returncode": 0, "verification_mode": "acyclic-composition",
            "composition_sha256": read_regular_snapshot(manifest, maximum=MAXIMUM_BYTES,
                                                          label="composition manifest").sha256}


def source_digests() -> dict[str, str]:
    return {
        name: read_regular_snapshot(path, maximum=MAXIMUM_BYTES, label=name).sha256
        for name, path in (("gate_sha256", Path(__file__)),
                           ("profile_catalog_sha256", Path(profiles.__file__)),
                           ("composition_checker_sha256", Path(composition.__file__)))
    }


def run(root: Path, destination: Path, profile: str = "independent") -> None:
    spec = select_profile(profile)
    inputs = load_inputs(root, profile)
    directory = fresh_output_directory(destination, within=root / "target", label="recovery replay")
    directory.mkdir(parents=True, mode=0o700)
    sources = source_digests()
    receipt = {"accepted": False, "release_claim_eligible": False, "groups": {},
               "profile": profile, "main_theorem": spec.main,
               "model_sha256": spec.model_sha256, "archive_sha256": spec.archive_sha256,
               **sources}
    try:
        # Share the repository's version authority, and remove ambient RTS overrides.
        verify_installed("tamarin")
        environment = prover_environment()
        for label, data in inputs.items():
            print(f"Replaying recovery {profile}/{label} certificate (per-process deadline {TIMEOUT_SECONDS}s)", flush=True)
            receipt["groups"][label] = replay(label, data, directory, environment, profile)
        require(load_inputs(root, profile) == inputs, "recovery inputs changed during replay")
        require(source_digests() == sources, "recovery checker changed during replay")
        receipt["accepted"] = True
    except (RecoveryProofError, composition.CompositionError, BoundedProcessError, FormalToolchainContractError,
            EvidenceIOError, OSError, UnicodeError, zipfile.BadZipFile) as exc:
        receipt["error"] = str(exc)
        write_json(directory / "RESULT.json", receipt)
        raise
    write_json(directory / "RESULT.json", receipt)
    universals = {name for case in spec.cases.values() for name in case.verified if name in case.all_traces}
    witnesses = {name for case in spec.cases.values() for name in case.verified if name in case.exists_traces}
    print(f"CONTINUITY_RECOVERY_PROOF_PASS profile={profile} properties={len(universals)} "
          f"witnesses={len(witnesses)} release_claim_eligible=false")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", choices=tuple(profiles.PROFILES), default="independent")
    args = parser.parse_args(argv)
    try:
        run(ROOT, args.output, args.profile)
        return 0
    except (RecoveryProofError, composition.CompositionError, BoundedProcessError, FormalToolchainContractError,
            EvidenceIOError, OSError, UnicodeError, zipfile.BadZipFile) as exc:
        print(f"error: continuity recovery proof: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
