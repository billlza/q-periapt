"""Prepare and verify the isolated, explicitly modified 64-byte SPQR experiment."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import tomllib

from artifact import spqr_reference as ref

PROFILE = "experimental_chunk64"
VARIANTS = ref.ROOT / "research/continuity-spqr-reference/variants"
DRIVER = ref.ROOT / "research/continuity-spqr-reference"
DRIVER_FILES = ("Cargo.toml", "Cargo.lock", "LICENSE", "src/main.rs", "src/compromise.rs")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clean_source() -> dict:
    upstream = ref.upstream_manifest().parent
    for checkout in (ref.ROOT, upstream):
        ref.require(not ref.command(["git", "-C", str(checkout), "status", "--porcelain", "--untracked-files=no"]), "source has tracked edits")
    ref.require(ref.command(["git", "-C", str(upstream), "rev-parse", "HEAD"]) == ref.REVISION, "upstream revision")
    ref.require(ref.command(["git", "-C", str(upstream), "rev-parse", "HEAD^{tree}"]) == ref.TREE, "upstream tree")
    for name in ("chunk64.patch", "chunk64-driver.patch"):
        ref.command(["git", "-C", str(ref.ROOT), "ls-files", "--error-unmatch", str(VARIANTS/name)])
    return {"source_commit":ref.command(["git", "-C", str(ref.ROOT), "rev-parse", "HEAD"]),
            "source_tree":ref.command(["git", "-C", str(ref.ROOT), "rev-parse", "HEAD^{tree}"]),
            "upstream_revision":ref.REVISION, "upstream_tree":ref.TREE,
            "upstream_patch_sha256":digest(ref.snapshot(VARIANTS/"chunk64.patch", 1024*1024)),
            "driver_patch_sha256":digest(ref.snapshot(VARIANTS/"chunk64-driver.patch", 1024*1024))}


def inventory(directory: Path) -> list[dict]:
    records, total = [], 0
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if ".git" in relative.parts:
            continue
        ref.require(not path.is_symlink(), "variant source symlink")
        if path.is_dir():
            continue
        data = ref.snapshot(path, 16*1024*1024)
        total += len(data)
        ref.require(total <= 64*1024*1024 and len(records) < 2048, "variant source bounds")
        records.append({"path":relative.as_posix(), "size":len(data), "sha256":digest(data)})
    ref.require(bool(records), "empty variant source")
    return records


def write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def prepare(directory: Path) -> dict:
    identity = clean_source()
    upstream = ref.upstream_manifest().parent
    ref.require(".." not in directory.parts and directory.name not in ("", "."), "variant output path")
    directory = directory.parent.resolve(strict=True)/directory.name
    directory.mkdir()
    target = directory/"upstream"
    target.mkdir()
    names = ref.command(["git", "-C", str(upstream), "ls-files", "-z"]).split("\0")
    for name in filter(None, names):
        relative = Path(name)
        ref.require(not relative.is_absolute() and ".." not in relative.parts, "upstream source path")
        write_new(target/relative, ref.snapshot(upstream/relative, 16*1024*1024))
    driver = directory/"driver"
    for name in DRIVER_FILES:
        write_new(driver/name, ref.snapshot(DRIVER/name, 16*1024*1024))
    for checkout, patch in ((target, "chunk64.patch"), (driver, "chunk64-driver.patch")):
        ref.command(["git", "-C", str(checkout), "init", "--quiet", "--initial-branch=reference"])
        ref.command(["git", "-C", str(checkout), "apply", "--unidiff-zero", "--check", str(VARIANTS/patch)])
        ref.command(["git", "-C", str(checkout), "apply", "--unidiff-zero", str(VARIANTS/patch)])
    records = {"upstream":inventory(target), "driver":inventory(driver)}
    check_dependencies(directory)
    ref.require(clean_source() == identity, "source changed during preparation")
    result = {"schema":1, "profile":PROFILE, "identity":identity, "files":records,
              "component_conformance_claim":False, "inherited_formal_proof_claim":False}
    write_new(directory/"preparation.json", (json.dumps(result, sort_keys=True, indent=2)+"\n").encode())
    return result


def check_dependencies(directory: Path) -> None:
    upstream = ref.snapshot(directory/"upstream/Cargo.lock", 1024*1024)
    ref.require(digest(upstream) == ref.UPSTREAM_LOCK, "variant upstream dependency lock")
    baseline = tomllib.loads(ref.snapshot(DRIVER/"Cargo.lock", 1024*1024).decode())
    modified = tomllib.loads(ref.snapshot(directory/"driver/Cargo.lock", 1024*1024).decode())
    expected = ref.decode_json(json.dumps(baseline))
    packages = [p for p in expected["package"] if p["name"] == "spqr"]
    ref.require(len(packages) == 1 and packages[0]["source"] ==
                f"git+https://github.com/signalapp/SparsePostQuantumRatchet?rev={ref.REVISION}#{ref.REVISION}", "baseline source pin")
    del packages[0]["source"]
    ref.require(ref.identical(expected, modified), "variant changed dependency selection")


def verify_preparation(directory: Path) -> dict:
    receipt = ref.decode_json(ref.snapshot(directory/"preparation.json", 4*1024*1024))
    ref.require(isinstance(receipt, dict) and set(receipt) == {"schema", "profile", "identity", "files", "component_conformance_claim", "inherited_formal_proof_claim"}, "preparation fields")
    ref.require(type(receipt["schema"]) is int and receipt["schema"] == 1 and receipt["profile"] == PROFILE
                and receipt["component_conformance_claim"] is False and receipt["inherited_formal_proof_claim"] is False, "variant interpretation")
    ref.require(ref.identical(receipt["identity"], clean_source()), "variant source identity changed")
    ref.require(ref.identical(receipt["files"], {"upstream":inventory(directory/"upstream"), "driver":inventory(directory/"driver")}), "variant sources changed after preparation")
    check_dependencies(directory)
    return receipt


def verify(directory: Path, first: Path, repeated: Path, baseline: Path, binary: Path, fixtures: Path) -> dict:
    preparation = verify_preparation(directory)
    result = ref.verify(first, chunk_bytes=64)
    ref.require(ref.identical(result, ref.verify(repeated, chunk_bytes=64)), "variant repeated corpus differs")
    locked = ref.decode_json(ref.snapshot(VARIANTS/"CHUNK64_CORPUS.json", 1024*1024))
    ref.require(locked["profile"] == PROFILE and ref.identical(locked["result"], result), "variant locked corpus differs")
    original = ref.verify(baseline)
    original_lock = ref.decode_json(ref.snapshot(DRIVER/"TRACE_CORPUS.json", 1024*1024))
    compromise_lock = ref.decode_json(ref.snapshot(DRIVER/"COMPROMISE_CORPUS.json", 1024*1024))
    ref.require(ref.identical(original["verified_public_traces"], original_lock["traces"])
                and ref.identical(original["verified_snapshot_experiments"], compromise_lock["traces"]), "baseline corpus differs")
    for name in ("issue1275_chunk64_a_state.in", "issue1275_chunk64_b_state.in"):
        ref.require(ref.snapshot(fixtures/name, 1024*1024) == ref.snapshot(directory/"upstream/src"/name, 1024*1024), "regenerated endian regression fixture differs")
    comparisons = []
    for index, (old, new) in enumerate(zip(original["verified_public_traces"], result["verified_public_traces"], strict=True)):
        entry = {"scenario":old["scenario"]}
        for label, item, snapshots in (("chunk32", old, original["verified_snapshot_experiments"]), ("chunk64", new, result["verified_snapshot_experiments"])):
            summary = item["summary"]
            exposure = next(c for c in snapshots[index]["cases"] if c["cut_before_send"] == 1 and c["owner"] == 0)
            entry[label] = {"wire_bytes":summary["wire_bytes"], "bytes_per_send":summary["wire_bytes"]/ref.MESSAGES,
                            "peak_wire_bytes":summary["peak_wire_bytes"], "peak_state_bytes":summary["peak_serialized_state_bytes"],
                            "final_epochs":[summary["final_a"]["epoch"], summary["final_b"]["epoch"]],
                            "snapshot_a_after_first_send":exposure}
        comparisons.append(entry)
    receipt = {"preparation":preparation["identity"], "binary_sha256":digest(ref.snapshot(binary, 128*1024*1024)),
               "rustc":ref.command(["rustc", "-vV"]), "protoc":ref.command(["protoc", "--version"]),
               "system":platform.system(), "machine":platform.machine()}
    ref.require(verify_preparation(directory) == preparation, "variant source changed during verification")
    return {"schema":1, "profile":PROFILE, "source_receipt":receipt, "repeat_public_bytes_equal":True,
            "upstream_endian_fixtures_reproduced":True, "comparisons":comparisons,
            "component_conformance_claim":False, "inherited_formal_proof_claim":False,
            "product_performance_claim":False, "production_claim_eligible":False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("prepare")
    init.add_argument("directory", type=Path)
    check = sub.add_parser("verify")
    for name in ("directory", "first", "repeated", "baseline", "binary", "fixtures"):
        check.add_argument("--"+name, required=True, type=Path)
    args = parser.parse_args()
    if args.action == "prepare":
        result = prepare(args.directory)
    else:
        result = verify(args.directory, args.first, args.repeated, args.baseline, args.binary, args.fixtures)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
