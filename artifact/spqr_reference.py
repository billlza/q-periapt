"""Verify pinned SPQR public traces and packet accounting, independently of its codec.

Key agreement is asserted by the Rust driver against actual upstream outputs.
This verifier does not reconstruct secret keys or claim a protocol security proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib
import platform
from artifact.bounded_process import capture_output

REVISION = "f2589fef855c10f39d72634dab3d14654dd410bf"
TREE = "7286f31638620152a770f6c4d2e86ac6862a0319"
UPSTREAM_LOCK = "e130211d61c7875cf5d94e606487a1da51845446e118633b6099e1f2d0303688"
SCENARIOS = ("ping_pong", "lossy", "reordered", "duplicates", "asymmetric", "offline_then_exchange", "one_way")
MESSAGES = 2048
SEED = 0x5143505153524546
ROOT = Path(__file__).resolve().parents[1]


class ReferenceError(ValueError):
    """Reference evidence is incomplete or contradicts its declared contract."""


def require(value: bool, detail: str) -> None:
    if not value:
        raise ReferenceError(detail)


def integer(value, low: int, high: int, label: str) -> int:
    require(type(value) is int and low <= value <= high, f"invalid {label}")
    return value


def identical(first, second) -> bool:
    return json.dumps(first, sort_keys=True, allow_nan=False) == json.dumps(second, sort_keys=True, allow_nan=False)


def decode_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def constant(_):
        raise ReferenceError("non-finite JSON value")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def wire_header(wire: bytes) -> tuple[int, int, int]:
    require(4 <= len(wire) <= 52 and wire[0] == 1, "wrong wire size/version")
    at = 1

    def varint(maximum: int) -> int:
        nonlocal at
        value = 0
        for shift in range(0, 70, 7):
            require(at < len(wire), "truncated varint")
            byte = wire[at]
            at += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                require(shift == 0 or byte != 0, "noncanonical varint")
                require(value <= maximum, "varint overflow")
                return value
        raise ReferenceError("unterminated varint")

    epoch = varint((1 << 64) - 1)
    index = varint((1 << 32) - 1)
    require(epoch > 0 and index > 0 and at < len(wire), "zero epoch/index or missing type")
    kind = wire[at]
    at += 1
    require(kind in range(7), "unknown message type")
    if kind in (0, 4):
        require(at == len(wire), "unexpected payload")
    else:
        varint(65535)
        require(len(wire) - at == 32, "wrong chunk length")
    return epoch, index, kind


def metadata(value: dict) -> dict:
    require(isinstance(value, dict) and set(value) == {"epoch", "send_epoch", "bytes"}, "state metadata fields")
    integer(value["epoch"], 0, (1 << 64) - 1, "epoch")
    integer(value["send_epoch"], 0, value["epoch"], "send epoch")
    integer(value["bytes"], 1, 16 * 1024 * 1024, "state byte size")
    return value


def snapshot(path: Path, maximum: int) -> bytes:
    require(path.is_file() and not path.is_symlink(), "missing or symlink evidence file")
    before = path.stat()
    require(0 < before.st_size <= maximum, "evidence size bound")
    data = path.read_bytes()
    after = path.stat()
    require((before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns), "evidence changed during read")
    return data


def schedule(name: str) -> list[tuple[str, int]]:
    result, pending = [], []
    for sequence in range(MESSAGES):
        result.append(("send", sequence))
        if name == "lossy" and sequence % 10 == 4:
            result.append(("drop", sequence))
        elif name == "reordered":
            pending.append(sequence)
            if sequence % 7 == 6:
                result.extend(("receive", n) for n in reversed(pending))
                pending.clear()
        elif name == "offline_then_exchange" and sequence < 256:
            pending.append(sequence)
        else:
            if name == "offline_then_exchange" and sequence == 256:
                result.extend(("receive", n) for n in pending)
                pending.clear()
            result.append(("receive", sequence))
            if name == "duplicates" and sequence % 13 == 0:
                result.append(("duplicate", sequence))
    result.extend(("receive", n) for n in pending)
    return result


def verify_trace(path: Path, name: str) -> tuple[dict, str]:
    data = snapshot(path, 4 * 1024 * 1024)
    rows = [decode_json(line) for line in data.splitlines()]
    config = {"event": "configuration", "schema": 1, "upstream": REVISION, "scenario": name,
              "seed": SEED, "messages": MESSAGES, "version": 1, "minimum_version": 1,
              "max_jump": 25000, "max_out_of_order": 2000, "chunk_bytes": 32}
    require(rows and identical(rows[0], config), "configuration differs")
    require([(row.get("event"), row.get("sequence")) for row in rows[1:-1]] == schedule(name), "transport schedule differs")
    packets, statuses, indices = {}, {}, {}
    states = [None, None]
    total_bytes = peak_wire = peak_state = delivered = dropped = duplicates = 0
    for row in rows[1:-1]:
        sequence = integer(row["sequence"], 0, MESSAGES - 1, "sequence")
        kind = row["event"]
        if kind == "send":
            sender = (0 if name == "one_way" or (name == "offline_then_exchange" and sequence < 256)
                      else int(sequence % 10 == 9) if name == "asymmetric" else sequence % 2)
            require(integer(row["sender"], 0, 1, "sender") == sender and sequence not in packets, "sender/sequence differs")
            require(isinstance(row["wire"], str) and re.fullmatch(r"[0-9a-f]{8,104}", row["wire"]) is not None, "wire hex")
            wire = bytes.fromhex(row["wire"])
            epoch, index, _ = wire_header(wire)
            expected = indices.get((sender, epoch), 0) + 1
            require(index == expected, "message index skipped or reused")
            indices[(sender, epoch)] = index
            state = metadata(row["state"])
            require(state["send_epoch"] == epoch - 1, "wire/key epoch differs")
            packets[sequence] = (sender, epoch)
            total_bytes += len(wire)
            peak_wire = max(peak_wire, len(wire))
            who = sender
        elif kind == "receive":
            require(sequence in packets and sequence not in statuses, "receive did not consume one pending packet")
            sender, epoch = packets[sequence]
            who = 1 - sender
            require(integer(row["receiver"], 0, 1, "receiver") == who and row.get("key_matches") is True, "agreement failed or wrong receiver")
            state = metadata(row["state"])
            require(state["epoch"] >= epoch - 1, "received key epoch not available")
            statuses[sequence] = "received"
            delivered += 1
        elif kind == "drop":
            require(sequence in packets and sequence not in statuses, "invalid drop")
            statuses[sequence] = "dropped"
            dropped += 1
            continue
        elif kind == "duplicate":
            require(statuses.get(sequence) == "received" and row["receiver"] == 1 - packets[sequence][0]
                    and row["outcome"] == "KeyAlreadyRequested", "duplicate was not rejected")
            duplicates += 1
            continue
        else:
            raise ReferenceError("unknown event")
        previous = states[who]
        require(previous is None or (state["epoch"] >= previous["epoch"] and state["send_epoch"] >= previous["send_epoch"]), "state epoch moved backwards")
        states[who] = state
        peak_state = max(peak_state, state["bytes"])
    require(len(packets) == len(statuses) == MESSAGES, "incomplete packet accounting")
    require(all(state is not None for state in states), "missing endpoint state")
    for state in states:
        require(state["epoch"] == 0 if name == "one_way" else state["epoch"] >= 3, "unexpected progress boundary")
    expected = {"event": "summary", "scenario": name, "sent": MESSAGES, "delivered": delivered,
                "dropped": dropped, "duplicates_rejected": duplicates, "unique_message_keys": MESSAGES,
                "wire_bytes": total_bytes, "peak_wire_bytes": peak_wire, "peak_serialized_state_bytes": peak_state,
                "final_a": states[0], "final_b": states[1]}
    require(identical(rows[-1], expected), "summary differs from raw events")
    return expected, hashlib.sha256(data).hexdigest()


def verify(directory: Path) -> dict:
    report = decode_json(snapshot(directory / "report.json", 4 * 1024 * 1024))
    require(integer(report["schema"], 1, 1, "schema") == 1 and report["upstream_revision"] == REVISION
            and report["driver"] == "public_api_v1" and report["production_claim_eligible"] is False, "report identity/claim differs")
    require(identical(report["controls"], {"downgrade":"MinimumVersion", "unknown_version":"ignored_without_key_or_state_change",
            "wrong_auth_provisional_key_mismatches":2, "wrong_auth_mac_rejected_at":2,
            "outer_message_authentication_required_before_state_commit":True}), "negative controls differ")
    require(len(report["runs"]) == len(SCENARIOS), "scenario count")
    results = []
    for name, recorded in zip(SCENARIOS, report["runs"], strict=True):
        summary, digest = verify_trace(directory / f"{name}.jsonl", name)
        require(identical(recorded["summary"], summary) and recorded["trace_sha256"] == digest, "report/raw trace mismatch")
        for operation, count in (("send", MESSAGES), ("receive", summary["delivered"])):
            timing = recorded[operation]
            raw = timing["raw_ns"]
            require(timing["samples"] == count and len(raw) == count, "timing coverage differs")
            for value in raw:
                integer(value, 0, 60_000_000_000, "operation nanoseconds")
            ordered = sorted(raw)
            for field, quantile in (("p50_ns",50),("p95_ns",95),("p99_ns",99)):
                require(timing[field] == ordered[((count - 1) * quantile) // 100], "timing quantile differs")
            require(timing["max_ns"] == ordered[-1], "timing maximum differs")
        results.append({"scenario":name,"trace_sha256":digest,"summary":summary})
    return {"schema":1,"upstream_revision":REVISION,"verified_public_traces":results,
            "key_agreement_evidence":"upstream outputs compared inside the pinned driver",
            "production_claim_eligible":False}


def check_lock(upstream: Path, reference: Path) -> dict:
    old = snapshot(upstream, 1024 * 1024)
    require(hashlib.sha256(old).hexdigest() == UPSTREAM_LOCK, "upstream dependency lock changed")
    def packages(data):
        return {(p["name"],p["version"],p.get("checksum")) for p in tomllib.loads(data.decode())["package"]
                if p.get("source", "").startswith("registry+")}
    selected = packages(snapshot(reference, 1024 * 1024))
    require(selected <= packages(old), "reference dependencies differ from upstream lock")
    lock = tomllib.loads(snapshot(reference, 1024 * 1024).decode())
    spqr = [p for p in lock["package"] if p["name"] == "spqr"]
    require(len(spqr) == 1 and spqr[0]["version"] == "1.5.1" and spqr[0]["source"] ==
            f"git+https://github.com/signalapp/SparsePostQuantumRatchet?rev={REVISION}#{REVISION}", "upstream source pin differs")
    return {"upstream_lock_sha256":UPSTREAM_LOCK,"registry_packages":len(selected)}


def command(argv: list[str]) -> str:
    result = capture_output(argv, timeout_seconds=120, maximum_stdout_bytes=4*1024*1024,
                            maximum_stderr_bytes=1024*1024)
    require(result.returncode == 0, "source command failed: " + result.stderr.decode(errors="replace"))
    return result.stdout.decode().strip()


def upstream_manifest() -> Path:
    data = decode_json(command(["cargo","metadata","--manifest-path",
        str(ROOT/"research/continuity-spqr-reference/Cargo.toml"),"--locked","--format-version","1"]))
    packages = [p for p in data["packages"] if p["name"] == "spqr"]
    require(len(packages) == 1 and packages[0]["source"] ==
            f"git+https://github.com/signalapp/SparsePostQuantumRatchet?rev={REVISION}#{REVISION}", "metadata source differs")
    return Path(packages[0]["manifest_path"])


def source_receipt(binary: Path) -> dict:
    upstream = upstream_manifest().parent
    for checkout in (ROOT, upstream):
        require(not command(["git","-C",str(checkout),"status","--porcelain","--untracked-files=no"]), "tracked source differs")
    require(command(["git","-C",str(upstream),"rev-parse","HEAD"]) == REVISION, "upstream checkout differs")
    require(command(["git","-C",str(upstream),"rev-parse","HEAD^{tree}"]) == TREE, "upstream tree differs")
    return {"source_commit":command(["git","-C",str(ROOT),"rev-parse","HEAD"]),
            "source_tree":command(["git","-C",str(ROOT),"rev-parse","HEAD^{tree}"]),
            "upstream_commit":REVISION,"upstream_tree":TREE,
            "reference_lock_sha256":hashlib.sha256(snapshot(ROOT/"research/continuity-spqr-reference/Cargo.lock",1024*1024)).hexdigest(),
            "upstream_license":"AGPL-3.0-only",
            "upstream_license_sha256":hashlib.sha256(snapshot(upstream/"LICENSE",128*1024)).hexdigest(),
            "binary_sha256":hashlib.sha256(snapshot(binary,128*1024*1024)).hexdigest(),
            "rustc":command(["rustc","-vV"]),"protoc":command(["protoc","--version"]),
            "system":platform.system(),"machine":platform.machine(),"os_release":platform.release(),
            "measurement_scope":"reference component CPU calls; no AEAD, network, disk durability or energy"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--upstream-lock", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--reference-lock", type=Path, default=Path("research/continuity-spqr-reference/Cargo.lock"))
    args = parser.parse_args()
    result = verify(args.directory)
    corpus = decode_json(snapshot(ROOT/"research/continuity-spqr-reference/TRACE_CORPUS.json",1024*1024))
    require(corpus["upstream_revision"] == REVISION and identical(corpus["traces"],result["verified_public_traces"]), "locked corpus differs")
    result["dependencies"] = check_lock(args.upstream_lock or upstream_manifest().with_name("Cargo.lock"), args.reference_lock)
    if args.compare:
        require(verify(args.compare) == verify(args.directory), "repeated public trace differs")
        result["repeat_public_bytes_equal"] = True
    if args.binary:
        result["source_receipt"] = source_receipt(args.binary)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
