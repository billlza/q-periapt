"""Install and recheck one source-bound experimental SummaryStats query plan.

The capsule changes the full summary query's compiler join mode to ``all``.
Its single QLX and fifteen referenced stages are fixed bytes, shared by both
allocation arms. Query sources and the other 38 compiled queries stay pinned by
the allocation controller. No compilation or download occurs during installation.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from evidence_io import parse_strict_json_bytes, read_regular_snapshot


CAPSULE = Path(__file__).with_name("codeql-summary-dynamic-plan.zip")
MANIFEST = Path(__file__).with_name("codeql_summary_dynamic_plan.json")
CAPSULE_BYTES = 620068
CAPSULE_SHA256 = "ce21381b3bec721aab246b26b84c00834959871235e1e82354addca8a40dcef7"
MANIFEST_SHA256 = "308a36a957741fdfa8a58f40fb81ffae6e863759527b516ca93816c75057c1f7"
COMPILED_INVENTORY_SHA256 = "97e028e1cd833859981f356342d79d5ab2172991cb50726fa51891842063ae66"
SOURCE_SHA256 = "7278d53373afb4f8069122e287c9c036a959ba0d167c152d67cd0de885881d67"
BUNDLED_PLAN_SHA256 = "bc65daf746a13e0d162f0853b3a21eda41ff2d573774e6862983a916c06244a6"
PLAN_SHA256 = "bb7a4ea7ec0910b62f34efc0e9e25a3e23e7f57d3dadde9799069ed1e824875f"
COMPILER_INPUTS_DIGEST = "209f28c6b9e8d5465a3f8417573e42d6"
PLAN_PATH = "queries/summary/SummaryStats.qlx"
STAGES = 15
MAX_MEMBER_BYTES = 2 * 1024**2


class PlanError(ValueError):
    """The candidate capsule or its effective files differ from the fixed plan."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanError(message)


def manifest() -> dict:
    snapshot = read_regular_snapshot(MANIFEST, maximum=64 * 1024, label="summary plan manifest")
    require(snapshot.sha256 == MANIFEST_SHA256, "summary plan manifest digest differs")
    value = parse_strict_json_bytes(snapshot.data, label="summary plan manifest")
    require(isinstance(value, dict) and value.get("mode") == "all"
            and value.get("capsule_bytes") == CAPSULE_BYTES
            and value.get("capsule_sha256") == CAPSULE_SHA256
            and value.get("compiler_inputs_digest") == COMPILER_INPUTS_DIGEST
            and value.get("query_source_sha256") == SOURCE_SHA256
            and value.get("plan_path") == PLAN_PATH and value.get("stage_count") == STAGES,
            "summary plan manifest identity differs")
    files = value.get("files", {})
    require(len(files) == STAGES + 1 and PLAN_PATH in files
            and files[PLAN_PATH]["sha256"] == PLAN_SHA256, "summary plan member census differs")
    require(all(name == PLAN_PATH or re.fullmatch(
        r"\.codeql/precompiled/[a-z0-9]+\.bytes\.qlx", name) for name in files),
        "summary plan member path differs")
    return value


def expected_identity() -> dict:
    value = manifest()
    return {"mode": "all", "capsule_sha256": CAPSULE_SHA256, "capsule_bytes": CAPSULE_BYTES,
            "manifest_sha256": MANIFEST_SHA256, "compiler_inputs_digest": COMPILER_INPUTS_DIGEST,
            "source_sha256": SOURCE_SHA256, "bundled_plan_sha256": BUNDLED_PLAN_SHA256,
            "effective_plan_sha256": PLAN_SHA256, "stage_count": STAGES,
            "files": value["files"]}


def member_path(pack: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and ".." not in relative.parts,
            "summary plan member escapes the pack")
    require(pack.is_dir() and not pack.is_symlink(), "summary plan pack is not a regular directory")
    parent = pack
    for part in relative.parts[:-1]:
        parent = parent / part
        require(parent.is_dir() and not parent.is_symlink(), "summary plan parent is not a regular directory")
    return pack / relative


def admit_header(data: bytes, files: dict, *, compiler_inputs_digest: str | None = None) -> None:
    expected_key = COMPILER_INPUTS_DIGEST if compiler_inputs_digest is None else compiler_inputs_digest
    header, separator, _ = data.partition(b"\n...\n")
    require(bool(separator) and len(header) <= 16 * 1024, "summary plan header boundary differs")
    text = header.decode("utf-8")
    require(re.findall(r"^inputsDigest: ([a-z0-9]+)$", text, re.MULTILINE)
            == [expected_key], "summary plan compiler input key differs")
    names = re.findall(r"^- filename: ([a-z0-9]+\.bytes\.qlx)$", text, re.MULTILINE)
    require(len(names) == len(set(names)) == STAGES
            and {".codeql/precompiled/" + name for name in names} == set(files) - {PLAN_PATH},
            "summary plan referenced stage closure differs")


def validate_members(pack: Path, files: dict, *, compiler_inputs_digest: str) -> None:
    """Recheck the complete closure selected by a separately pinned manifest."""
    for name, expected in files.items():
        snapshot = read_regular_snapshot(member_path(pack, name), maximum=MAX_MEMBER_BYTES,
                                         label="effective summary plan member")
        require(snapshot.size == expected["bytes"] and snapshot.sha256 == expected["sha256"],
                "effective summary plan member differs: " + name)
        if name == PLAN_PATH:
            admit_header(snapshot.data, files, compiler_inputs_digest=compiler_inputs_digest)


def validate(pack: Path) -> dict:
    """Hash the effective source, QLX and every referenced stage without compiling."""
    value = manifest()
    source = read_regular_snapshot(member_path(pack, PLAN_PATH).with_suffix(".ql"),
                                   maximum=64 * 1024, label="full summary query source")
    require(source.sha256 == SOURCE_SHA256, "full summary query source changed")
    validate_members(pack, value["files"], compiler_inputs_digest=COMPILER_INPUTS_DIGEST)
    return expected_identity()


def write_exclusive(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as stream:
        require(stream.write(data) == len(data), "summary plan write was incomplete")


def read_capsule(pack: Path, path: Path, *, size: int, digest: str, files: dict,
                 compiler_inputs_digest: str) -> dict[str, bytes]:
    """Admit all fixed capsule bytes before the caller mutates the query pack."""
    capsule = read_regular_snapshot(path, maximum=size, label="summary plan capsule")
    require(capsule.size == size and capsule.sha256 == digest,
            "summary plan capsule digest or size differs")
    payloads = {}
    with zipfile.ZipFile(io.BytesIO(capsule.data)) as archive:
        members = archive.infolist()
        require(len(members) == len({member.filename for member in members}) == STAGES + 1
                and {member.filename for member in members} == set(files),
                "summary plan capsule member census differs")
        for member in members:
            expected = files[member.filename]
            require(stat.S_IFMT(member.external_attr >> 16) == stat.S_IFREG
                    and member.file_size == expected["bytes"] <= MAX_MEMBER_BYTES,
                    "summary plan capsule member type or size differs")
            data = archive.read(member)
            require(hashlib.sha256(data).hexdigest() == expected["sha256"],
                    "summary plan capsule member digest differs")
            member_path(pack, member.filename)
            payloads[member.filename] = data
    admit_header(payloads[PLAN_PATH], files, compiler_inputs_digest=compiler_inputs_digest)
    return payloads


def install(pack: Path, evidence: Path) -> dict:
    """Install the admitted fixed capsule only over the original bundled plan."""
    value = manifest()
    original = read_regular_snapshot(member_path(pack, PLAN_PATH), maximum=MAX_MEMBER_BYTES,
                                     label="original bundled summary plan")
    require(original.sha256 == BUNDLED_PLAN_SHA256, "original bundled summary plan differs")
    source = read_regular_snapshot(member_path(pack, PLAN_PATH).with_suffix(".ql"),
                                   maximum=64 * 1024, label="full summary query source")
    require(source.sha256 == SOURCE_SHA256, "full summary query source changed")
    payloads = read_capsule(pack, CAPSULE, size=CAPSULE_BYTES, digest=CAPSULE_SHA256,
                            files=value["files"], compiler_inputs_digest=COMPILER_INPUTS_DIGEST)
    # Admit the entire capsule before any pack mutation. New stage files are
    # exclusive creations, and the QLX is atomically replaced only after them.
    for name in payloads:
        if name != PLAN_PATH:
            path = member_path(pack, name)
            require(not path.exists() and not path.is_symlink(), "candidate stage already exists")
    write_exclusive(evidence / "SUMMARY_PLAN_ORIGINAL.qlx", original.data)
    for name, data in payloads.items():
        if name != PLAN_PATH:
            write_exclusive(member_path(pack, name), data)
    plan = member_path(pack, PLAN_PATH)
    incoming = plan.with_name(".SummaryStats.qlx.incoming")
    write_exclusive(incoming, payloads[PLAN_PATH])
    incoming.replace(plan)
    identity = validate(pack)
    write_exclusive(evidence / "SUMMARY_PLAN.json", (json.dumps(identity, indent=2, sort_keys=True) + "\n").encode())
    return identity
