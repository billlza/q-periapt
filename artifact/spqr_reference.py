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
from artifact.evidence_io import EvidenceIOError, parse_strict_json_bytes, read_regular_snapshot

REVISION = "f2589fef855c10f39d72634dab3d14654dd410bf"
TREE = "7286f31638620152a770f6c4d2e86ac6862a0319"
UPSTREAM_LOCK = "e130211d61c7875cf5d94e606487a1da51845446e118633b6099e1f2d0303688"
SCENARIOS = ("ping_pong", "lossy", "reordered", "duplicates", "asymmetric", "offline_then_exchange", "one_way")
MESSAGES = 2048
SEED = 0x5143505153524546
CUTS = (0, 1, 7, 63, 255, 1023)
SNAPSHOT_THREAT = "one endpoint state snapshot; passive full public transcript; no future private state or RNG"
SNAPSHOT_INTERPRETATION = "retrospective key derivation, not a security proof or recovery claim"
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
    try:
        return parse_strict_json_bytes(
            data.encode("utf-8") if isinstance(data, str) else data,
            label="SPQR reference JSON",
        )
    except EvidenceIOError as exc:
        raise ReferenceError(str(exc)) from exc


def wire_fields(wire: bytes, *, chunk_bytes: int = 32) -> tuple[int, int, int, int | None]:
    require(type(chunk_bytes) is int and chunk_bytes in (32, 64), "unsupported reference chunk profile")
    require(4 <= len(wire) <= chunk_bytes + 20 and wire[0] == 1, "wrong wire size/version")
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
    chunk_index = None
    if kind in (0, 4):
        require(at == len(wire), "unexpected payload")
    else:
        chunk_index = varint(65535)
        require(len(wire) - at == chunk_bytes, "wrong chunk length")
    return epoch, index, kind, chunk_index


def wire_header(wire: bytes, *, chunk_bytes: int = 32) -> tuple[int, int, int]:
    epoch, index, kind, _ = wire_fields(wire, chunk_bytes=chunk_bytes)
    return epoch, index, kind


def metadata(value: dict) -> dict:
    require(isinstance(value, dict) and set(value) == {"epoch", "send_epoch", "bytes"}, "state metadata fields")
    integer(value["epoch"], 0, (1 << 64) - 1, "epoch")
    integer(value["send_epoch"], 0, value["epoch"], "send epoch")
    integer(value["bytes"], 1, 16 * 1024 * 1024, "state byte size")
    return value


def snapshot(path: Path, maximum: int) -> bytes:
    try:
        data = read_regular_snapshot(path, maximum=maximum, label="SPQR reference evidence").data
    except EvidenceIOError as exc:
        raise ReferenceError(str(exc)) from exc
    require(bool(data), "empty SPQR reference evidence")
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


def verify_trace(path: Path, name: str, *, chunk_bytes: int = 32) -> tuple[dict, str]:
    require(type(chunk_bytes) is int and chunk_bytes in (32, 64), "unsupported reference chunk profile")
    data = snapshot(path, 4 * 1024 * 1024)
    rows = [decode_json(line) for line in data.splitlines()]
    config = {"event": "configuration", "schema": 1, "upstream": REVISION, "scenario": name,
              "seed": SEED, "messages": MESSAGES, "version": 1, "minimum_version": 1,
              "max_jump": 25000, "max_out_of_order": 2000, "chunk_bytes": chunk_bytes}
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
            require(isinstance(row["wire"], str) and re.fullmatch(rf"[0-9a-f]{{8,{2*(chunk_bytes+20)}}}", row["wire"]) is not None, "wire hex")
            wire = bytes.fromhex(row["wire"])
            epoch, index, _ = wire_header(wire, chunk_bytes=chunk_bytes)
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


def verify_compromise(data: bytes, trace: bytes, name: str, *, chunk_bytes: int = 32) -> dict:
    """Check the public projection, never turn absent derivation into a security proof."""
    require(type(chunk_bytes) is int and chunk_bytes in (32, 64), "unsupported reference chunk profile")
    report = decode_json(data)
    require(isinstance(report, dict) and set(report) == {"schema", "scenario", "upstream_revision", "public_test_entropy", "threat", "interpretation", "cases"}, "snapshot report fields")
    require(type(report["schema"]) is int and report["schema"] == 1 and report["scenario"] == name
            and report["upstream_revision"] == REVISION and report["threat"] == SNAPSHOT_THREAT
            and report["interpretation"] == SNAPSHOT_INTERPRETATION and report["public_test_entropy"] is True, "snapshot identity or interpretation")
    states = [0, 0]
    at_cut, packets, ciphertext, complete = {}, {}, {}, {}
    for row in (decode_json(line) for line in trace.splitlines()):
        event = row["event"]
        if event == "send":
            sequence, sender = row["sequence"], row["sender"]
            if sequence in CUTS:
                at_cut[sequence] = tuple(states)
            epoch, _, kind, chunk_index = wire_fields(bytes.fromhex(row["wire"]), chunk_bytes=chunk_bytes)
            packets[sequence] = (sender, epoch - 1)
            if kind in (5, 6):
                parts = ciphertext.setdefault((sender, epoch), {5: set(), 6: set()})
                parts[kind].add(chunk_index)
                if len(parts[5]) >= (960+chunk_bytes-1)//chunk_bytes and len(parts[6]) >= (160+chunk_bytes-1)//chunk_bytes:
                    complete.setdefault((sender, epoch), sequence)
            states[sender] = row["state"]["epoch"]
        elif event == "receive":
            states[row["receiver"]] = row["state"]["epoch"]
    require(set(packets) == set(range(MESSAGES)) and set(at_cut) == set(CUTS), "snapshot trace coverage")
    require(isinstance(report["cases"], list) and len(report["cases"]) == len(CUTS)*2, "snapshot case coverage")
    kinds = {"KeysUnsampled", "KeysSampled", "HeaderSent", "Ct1Received", "EkSentCt1Received",
             "NoHeaderReceived", "HeaderReceived", "Ct1Sampled", "EkReceivedCt1Sampled", "Ct1Acknowledged", "Ct2Sampled"}
    dk_kinds = {"KeysSampled", "HeaderSent", "Ct1Received", "EkSentCt1Received"}
    summaries = []
    for case, (cut, owner) in zip(report["cases"], ((cut, owner) for cut in CUTS for owner in (0, 1)), strict=True):
        require(isinstance(case, dict) and set(case) == {"cut_before_send", "owner", "snapshot_chain_epoch", "snapshot_braid_state",
                "stolen_pending_dk_epoch", "recovered_pending_epoch", "predicted_sequences", "not_derived_sequences", "wrong_key_control_mismatch_at"}, "snapshot case fields")
        require(integer(case["cut_before_send"], 0, MESSAGES-1, "snapshot cut") == cut
                and integer(case["owner"], 0, 1, "snapshot owner") == owner, "snapshot case order")
        current = integer(case["snapshot_chain_epoch"], 0, MESSAGES, "snapshot epoch")
        require(current == at_cut[cut][owner] and case["snapshot_braid_state"] in kinds, "snapshot public state projection")
        pending = current + 1 if case["snapshot_braid_state"] in dk_kinds else None
        require(identical(case["stolen_pending_dk_epoch"], pending), "snapshot pending KEM classification")
        recovered = ({"epoch": pending, "public_ciphertext_complete_at": complete[(1-owner, pending)]}
                     if pending is not None and (1-owner, pending) in complete else None)
        require(identical(case["recovered_pending_epoch"], recovered), "snapshot public ciphertext completion")
        known = pending if recovered is not None else current
        predicted = [sequence for sequence, (_, epoch) in packets.items() if sequence >= cut and epoch <= known]
        unknown = [sequence for sequence, (_, epoch) in packets.items() if sequence >= cut and epoch > known]
        require(predicted and identical(case["predicted_sequences"], predicted)
                and identical(case["not_derived_sequences"], unknown), "snapshot key derivation coverage")
        require(integer(case["wrong_key_control_mismatch_at"], cut, MESSAGES-1, "wrong key control") == predicted[0], "snapshot negative control")
        require(not unknown if name == "one_way" else bool(unknown), "snapshot one-way/duplex boundary")
        future_predictions = sum(packets[sequence][1] > current for sequence in predicted)
        require(future_predictions > 0 if recovered is not None else future_predictions == 0, "pending secret contribution")
        summaries.append({"cut_before_send": cut, "owner": owner, "predicted": len(predicted),
                          "not_derived": len(unknown), "predicted_from_pending_epoch": future_predictions})
    return {"scenario": name, "sha256": hashlib.sha256(data).hexdigest(), "cases": summaries}


def verify(directory: Path, *, chunk_bytes: int = 32) -> dict:
    require(type(chunk_bytes) is int and chunk_bytes in (32, 64), "unsupported reference chunk profile")
    driver = "public_api_v1" if chunk_bytes == 32 else "experimental_chunk64"
    provisional = (96+chunk_bytes-1)//chunk_bytes - 1
    report = decode_json(snapshot(directory / "report.json", 4 * 1024 * 1024))
    require(integer(report["schema"], 1, 1, "schema") == 1 and report["upstream_revision"] == REVISION
            and report["driver"] == driver and report["production_claim_eligible"] is False, "report identity/claim differs")
    require(identical(report["controls"], {"downgrade":"MinimumVersion", "unknown_version":"ignored_without_key_or_state_change",
            "wrong_auth_provisional_key_mismatches":provisional, "wrong_auth_mac_rejected_at":provisional,
            "outer_message_authentication_required_before_state_commit":True}), "negative controls differ")
    require(len(report["runs"]) == len(SCENARIOS), "scenario count")
    results, compromises = [], []
    for name, recorded in zip(SCENARIOS, report["runs"], strict=True):
        summary, digest = verify_trace(directory / f"{name}.jsonl", name, chunk_bytes=chunk_bytes)
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
        trace = snapshot(directory / f"{name}.jsonl", 4 * 1024 * 1024)
        require(hashlib.sha256(trace).hexdigest() == digest, "trace changed before snapshot validation")
        compromises.append(verify_compromise(snapshot(directory / f"{name}.compromise.json", 4 * 1024 * 1024), trace, name, chunk_bytes=chunk_bytes))
    return {"schema":1,"upstream_revision":REVISION,"verified_public_traces":results,
            "verified_snapshot_experiments":compromises,
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
    compromise = decode_json(snapshot(ROOT/"research/continuity-spqr-reference/COMPROMISE_CORPUS.json",1024*1024))
    require(compromise["upstream_revision"] == REVISION and identical(compromise["traces"],result["verified_snapshot_experiments"]), "locked snapshot corpus differs")
    result["dependencies"] = check_lock(args.upstream_lock or upstream_manifest().with_name("Cargo.lock"), args.reference_lock)
    if args.compare:
        require(verify(args.compare) == verify(args.directory), "repeated public trace differs")
        result["repeat_public_bytes_equal"] = True
    if args.binary:
        result["source_receipt"] = source_receipt(args.binary)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
