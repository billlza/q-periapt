"""Produce and independently reopen the formal Continuity arm64 AAR/Maven capsule.

Native and Java compilation are separate, independently pinned inputs. This
module performs static package verification and never claims ART/device execution.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import tempfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile

import android_elf as elf
import continuity_c_abi as c_abi
from bounded_process import capture_output
from claim_ledger import canonical_tree_digest, repository_paths
from continuity_android_classes import verify_classes
from evidence_io import fresh_output_directory, parse_strict_json_bytes, read_regular_snapshot
from git_provenance import inspect_worktree, run_git_text
from release_binary_scan import scan_release_file
from third_party_licenses import verify as verify_licenses

ROOT = Path(__file__).resolve().parent.parent
NAME, VERSION = "q-periapt-continuity-android", "0.2.0"
COORDINATE = f"dev.qperiapt:{NAME}:{VERSION}"
PREFIX = f"{NAME}-{VERSION}"
MAVEN = f"maven/dev/qperiapt/{NAME}/{VERSION}"
TARGET, ABI, NDK = "aarch64-linux-android", "qpc-owner/1", "29.0.14206865"
C_LIBRARY = "libq_periapt_continuity_c_consumer.so"
JNI_LIBRARY = "libqperiapt_continuity_jni.so"
ADAPTER = "bindings/android/ContinuityPackageConsumer"
CONSUMER = "bindings/c/ContinuityPackageConsumer"
MAX_BYTES, MAX_ENTRY, MAX_MEMBERS = 128 * 1024**2, 64 * 1024**2, 2048
INPUT_KIND = "qperiapt.continuity_android_distribution_inputs"
METADATA = "META-INF/qperiapt/distribution.json"
MANIFEST = (b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            b'package="dev.qperiapt.continuity.android" android:versionName="0.2.0">'
            b'<uses-sdk android:minSdkVersion="23"/></manifest>\n')
AAR_METADATA = b"aarFormatVersion=1.0\naarMetadataVersion=1.0\nminCompileSdk=23\n"
POM = (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
       f'<groupId>dev.qperiapt</groupId><artifactId>{NAME}</artifactId><version>{VERSION}</version>'
       '<packaging>aar</packaging></project>\n').encode()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reference(path: str, data: bytes) -> dict:
    return {"path": path, "bytes": len(data), "sha256": sha(data)}


def safe_path(value: object) -> str:
    require(type(value) is str and 0 < len(value) <= 1024, "input path is not bounded text")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and 0 < len(path.parts) <= 32
            and all(re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", p) and p not in {".", ".."} for p in path.parts),
            "input path is not canonical relative text")
    return value


def read_pin(root: Path, ref: dict, *, maximum: int = MAX_ENTRY) -> bytes:
    require(type(ref) is dict and set(ref) == {"path", "bytes", "sha256"}, "file pin fields differ")
    path = safe_path(ref["path"])
    require(type(ref["bytes"]) is int and 0 < ref["bytes"] <= maximum
            and type(ref["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]),
            "file pin size or digest differs")
    observed = read_regular_snapshot(root / path, maximum=maximum, label="Continuity Android input")
    require((observed.size, observed.sha256) == (ref["bytes"], ref["sha256"]), "selected input bytes differ")
    return observed.data


def zip_entries(data: bytes, *, canonical_aar: bool = False) -> dict[str, bytes]:
    require(0 < len(data) <= MAX_BYTES, "archive size exceeds bounds")
    if canonical_aar:
        elf._verify_canonical_aar_zip_framing(data)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.infolist()) <= MAX_MEMBERS, "archive member count exceeds bounds")
        return elf._read_zip_entries(archive, label="Continuity Android archive",
            max_total_bytes=MAX_BYTES, max_entry_bytes=MAX_ENTRY)


def zip_bytes(files: dict[str, bytes]) -> bytes:
    require(0 < len(files) <= MAX_MEMBERS and sum(map(len, files.values())) <= MAX_BYTES,
            "archive inventory exceeds bounds")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            elf._validate_zip_name(name, label="Continuity Android output")
            entry = zipfile.ZipInfo(name, elf.AAR_CANONICAL_DATE_TIME)
            entry.create_system, entry.create_version, entry.extract_version = 3, 20, 20
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, data)
    encoded = output.getvalue()
    require(len(encoded) <= MAX_BYTES, "encoded archive exceeds bounds")
    return encoded


def source_identity(*, paths: list[str], pinned_files: dict | None = None) -> dict:
    worktree = inspect_worktree(ROOT)
    require(not worktree.dirty, "formal Android source checkout is modified")
    require(repository_paths(ROOT) == paths, "selected source path inventory changed")
    tree = run_git_text(ROOT, ["rev-parse", "--verify", worktree.commit + "^{tree}"])
    require(re.fullmatch(r"[0-9a-f]{40}", tree) is not None, "selected Git tree identity is malformed")
    return {"commit": worktree.commit, "tree": tree,
            "tree_sha256": canonical_tree_digest(ROOT, paths, pinned_files=pinned_files)}


def source_contract(paths: list[str]) -> dict:
    pinned = {}
    def source(relative: str, maximum: int) -> bytes:
        data = read_regular_snapshot(ROOT / relative, maximum=maximum, label="Continuity source contract").data
        require(relative not in pinned, "source contract was read twice")
        pinned[relative] = data
        return data
    engine = tomllib.loads(source("research/continuity-identity-candidate/Cargo.toml", 65536).decode())
    require(engine["package"]["name"] == "q-periapt-continuity" and engine["package"]["version"] == VERSION
            and engine["package"]["publish"] is False, "formal engine package identity differs")
    with tempfile.TemporaryDirectory(prefix="continuity-abi-snapshot-") as temp:
        private = Path(temp)
        for relative, maximum in (("qpc_owner.h", 128 * 1024), (c_abi.CONTRACT, 256 * 1024)):
            path = private / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source(CONSUMER + "/" + relative, maximum))
        abi = c_abi.load(private)
    require(len(abi["functions"]) == 158, "Continuity owner export inventory differs")
    sources = {}
    prefix = ADAPTER + "/src/main/java/"
    for relative in paths:
        if relative.startswith(prefix) and relative.endswith(".java"):
            sources[relative.removeprefix(prefix)] = source(relative, 1024**2)
    require(sources, "Continuity Java sources are absent")
    rules = source(ADAPTER + "/consumer-rules.pro", 65536)
    require(rules == b"# RegisterNatives and the native error callback depend on these exact names.\n"
                     b"-keep class dev.qperiapt.continuity.android.Native { *; }\n", "JNI keep rule contract differs")
    bridge = source(ADAPTER + "/jni/continuity_jni.c", 65536).decode()
    licenses = {"META-INF/licenses/" + name: source("LICENSES/" + name, MAX_ENTRY)
        for name in ("Apache-2.0.txt", "MIT.txt", "Rust-1.98.1-library.html")}
    # This locally installed SDK crate carries vendored C implementation
    # notices; registry-only Rust dependency collection does not cover them.
    licenses.update({"META-INF/licenses/mlkem-native/" + name:
        source("crates/q-periapt-mlkem-native-sys/vendor/" + name, MAX_ENTRY)
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md")})
    return {"exports": set(abi["functions"]), "java": sources, "rules": rules, "bridge": bridge,
            "licenses": licenses, "pinned": pinned}


def validate_selection(data: bytes, input_root: Path, *, expected_sha256: str, source: dict) -> tuple[dict, dict]:
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None and sha(data) == expected_sha256,
            "independent input-selection digest differs")
    selection = parse_strict_json_bytes(data, label="Continuity Android input selection")
    require(type(selection) is dict and set(selection) == {"schema_version", "kind", "name", "version", "abi", "target",
            "source", "native_package_id", "native", "classes", "licenses", "native_receipt", "classes_receipt"}, "input-selection fields differ")
    require(type(selection["schema_version"]) is int and selection["schema_version"] == 1
            and selection["kind"] == INPUT_KIND and selection["name"] == NAME and selection["version"] == VERSION
            and selection["abi"] == ABI and selection["target"] == TARGET and selection["source"] == source,
            "input-selection source or formal identity differs")
    require(type(source) is dict and set(source) == {"commit", "tree", "tree_sha256"}
            and type(source["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", source["commit"])
            and type(source["tree"]) is str and re.fullmatch(r"[0-9a-f]{40}", source["tree"])
            and type(source["tree_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", source["tree_sha256"]),
            "selected source identity is malformed")
    require(type(selection["native_package_id"]) is str
            and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", selection["native_package_id"]), "native dependency row ID differs")
    require(type(selection["native"]) is dict and set(selection["native"]) == {"c", "jni"}, "native input inventory differs")
    refs = {**selection["native"], **{key: selection[key] for key in
            ("classes", "licenses", "native_receipt", "classes_receipt")}}
    require(len({ref.get("path") for ref in refs.values() if type(ref) is dict}) == len(refs), "input paths alias")
    contents = {key: read_pin(input_root, ref) for key, ref in refs.items()}
    for key, kind, artifacts, package, toolchain in (
        ("native_receipt", "qperiapt.continuity_android_native_build", {**selection["native"], "licenses": selection["licenses"]},
         "q-periapt-continuity", {"rust": "1.98.1", "ndk": NDK, "target": TARGET}),
        ("classes_receipt", "qperiapt.continuity_android_classes_build", {"classes": selection["classes"]},
         NAME, {"java_major": 25, "release": 11}),
    ):
        report = parse_strict_json_bytes(contents[key], label=key)
        require(type(report) is dict and report.get("schema_version") == 1 and type(report.get("schema_version")) is int
                and report.get("kind") == kind and report.get("completed") is True and "failure" not in report
                and report.get("source") == source and report.get("package") == {"name": package, "version": VERSION}
                and report.get("artifacts") == artifacts and report.get("toolchain") == toolchain,
                "compilation receipt source, package, artifact or toolchain binding differs")
    return selection, contents


def android_note(data: bytes) -> dict:
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "Android note requires ELF64 little endian")
    offset, size, count, names_index = struct.unpack_from("<Q", data, 40)[0], *struct.unpack_from("<HHH", data, 58)
    require(size == 64 and 0 < count <= 4096 and 0 < names_index < count and offset + size * count <= len(data),
            "ELF section table exceeds bounds")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset + size * n) for n in range(count)]
    names = sections[names_index]
    require(names[4] + names[5] <= len(data), "ELF section-name table exceeds bounds")
    strings = data[names[4]:names[4] + names[5]]
    matches = []
    for section in sections:
        require(section[0] < len(strings), "ELF section-name index exceeds bounds")
        end = strings.find(b"\0", section[0])
        require(end >= 0, "unterminated ELF section name")
        if strings[section[0]:end] == b".note.android.ident":
            require(section[1] == 7 and section[5] == 152 and section[4] + section[5] <= len(data),
                    "Android identity note framing differs")
            note = data[section[4]:section[4] + section[5]]
            require(struct.unpack_from("<III", note) == (8, 132, 1) and note[12:20] == b"Android\0",
                    "Android note type or owner differs")
            require(struct.unpack_from("<I", note, 20)[0] == 23
                    and note[24:88] == b"r29" + b"\0" * 61
                    and note[88:152] == b"14206865" + b"\0" * 56, "Android compile API or NDK identity differs")
            matches.append(note)
    require(len(matches) == 1, "Android identity note is missing or duplicated")
    return {"compile_api": 23, "ndk": NDK}


def load_segments(data: bytes) -> int:
    """Check ELF64 LOAD geometry as well as the tool's displayed alignment."""
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "LOAD geometry requires ELF64 little endian")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    require(size == 56 and 0 < count <= 256 and offset + size * count <= len(data),
            "ELF program-header table exceeds bounds")
    loads = 0
    for index in range(count):
        kind, _, file_offset, address, _, file_size, memory_size, alignment = struct.unpack_from(
            "<IIQQQQQQ", data, offset + size * index)
        if kind == 1:
            require(alignment >= 16384 and alignment & (alignment - 1) == 0
                    and file_offset % alignment == address % alignment,
                    "LOAD alignment or address congruence differs")
            require(file_size <= memory_size and file_offset + file_size <= len(data)
                    and address + memory_size <= 2**64, "LOAD file or memory range exceeds bounds")
            loads += 1
    require(loads > 0, "ELF has no LOAD segment")
    return loads


def native_tools(ndk: Path) -> dict:
    require(elf.verify_ndk_r29(ndk) == NDK, "Continuity Android requires the selected NDK revision")
    directory = elf.find_ndk_toolchain(ndk)
    return {name: (directory / "bin" / name).resolve(strict=True) for name in ("llvm-nm", "llvm-readelf")}


def verify_native(path: Path, *, role: str, tools: dict, exports: set[str]) -> dict:
    selected = read_regular_snapshot(path, maximum=MAX_ENTRY, label="Continuity native library")
    elf.parse_elf_header(path, "arm64-v8a")
    load_segments(selected.data)
    name = C_LIBRARY if role == "c" else JNI_LIBRARY
    require(path.name == name and role in {"c", "jni"}, "native library identity differs")
    def run(tool, arguments):
        result = capture_output([str(tools[tool]), *arguments, str(path)], timeout_seconds=60,
            maximum_stdout_bytes=8 * 1024**2, maximum_stderr_bytes=65536,
            environment={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        require(result.returncode == 0 and result.stderr == b"", "native verifier tool failed or emitted diagnostics")
        return result.stdout.decode()
    found = elf.parse_nm_exports(run("llvm-nm", ["-D", "--defined-only", "--format=posix"]), path)
    require(found == (exports if role == "c" else {"JNI_OnLoad"}), "native export set differs")
    # Canonical NDK paths can resolve the readelf alias to llvm-readobj, whose
    # default is LLVM format. Bind the GNU format required by these parsers.
    result = run("llvm-readelf", ["--elf-output-style=GNU", "-h", "-l", "-d", "-S", "-W"])
    elf.verify_program_headers(result, path); elf.verify_release_sections(result, path)
    soname, needed, tags, values = elf.parse_dynamic_entries(result, path)
    expected = {"libc.so", "libdl.so"} | ({C_LIBRARY} if role == "jni" else set())
    require(soname == name and needed == expected and not tags & {"TEXTREL", "RPATH", "RUNPATH"}
            and ("BIND_NOW" in values.get("FLAGS", "") or re.search(r"(?:^|\s)NOW(?:\s|$)", values.get("FLAGS_1", ""))),
            "native SONAME, dependency or immediate-binding contract differs")
    note = android_note(selected.data)
    scan_release_file(path, forbidden_text=(str(ROOT),))
    final = read_regular_snapshot(path, maximum=MAX_ENTRY, label="Continuity native reread")
    require(final.sha256 == selected.sha256, "native library changed during static verification")
    return {"sha256": selected.sha256, "bytes": selected.size, "exports": len(found), "needed": sorted(needed), **note}


def verify_contents(entries: dict[str, bytes], selection: dict, inputs: dict, contract: dict, tools: dict) -> dict:
    licenses = zip_entries(inputs["licenses"])
    require(all(name.startswith("THIRD_PARTY/rust/") for name in licenses), "license archive namespace differs")
    expected = {"AndroidManifest.xml": MANIFEST, "R.txt": b"", "classes.jar": inputs["classes"],
        "proguard.txt": contract["rules"], "META-INF/com/android/build/gradle/aar-metadata.properties": AAR_METADATA,
        METADATA: canonical(selection), f"jni/arm64-v8a/{C_LIBRARY}": inputs["c"],
        f"jni/arm64-v8a/{JNI_LIBRARY}": inputs["jni"], **contract["licenses"],
        **{"META-INF/" + name: data for name, data in licenses.items()}}
    require(entries == expected, "AAR exact member inventory or bytes differ")
    classes = verify_classes(zip_entries(entries["classes.jar"]), set(contract["java"]), contract["bridge"])
    with tempfile.TemporaryDirectory(prefix="continuity-aar-readback-") as temp:
        private = Path(temp).resolve()
        for name, data in licenses.items():
            path = private / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        inventory = verify_licenses(private, expected_target=TARGET, root_package="q-periapt-continuity-c-consumer")
        native = {}
        for role, name in (("c", C_LIBRARY), ("jni", JNI_LIBRARY)):
            path = private / name; path.write_bytes(inputs[role])
            native[role] = verify_native(path, role=role, tools=tools, exports=contract["exports"])
    return {"classes": classes, "native": native, "license_packages": len(inventory["packages"])}


def maven_files(aar: bytes, contract: dict) -> dict[str, bytes]:
    sources = {**contract["java"], **{name: data for name, data in contract["licenses"].items()
                                      if not name.endswith(".html")}, "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n\r\n"}
    files = {f"{PREFIX}.aar": aar, f"{PREFIX}.pom": POM, f"{PREFIX}-sources.jar": zip_bytes(sources)}
    for name, data in tuple(files.items()):
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            files[name + "." + algorithm] = (hashlib.new(algorithm, data).hexdigest() + "\n").encode()
    return {MAVEN + "/" + name: data for name, data in files.items()}


def verify_maven(files: dict[str, bytes], aar: bytes, contract: dict) -> None:
    primary = {f"{MAVEN}/{PREFIX}{suffix}" for suffix in (".aar", ".pom", "-sources.jar")}
    expected = primary | {name + "." + algorithm for name in primary
                          for algorithm in ("md5", "sha1", "sha256", "sha512")}
    require(set(files) == expected, "Maven exact file inventory differs")
    require(files[f"{MAVEN}/{PREFIX}.aar"] == aar, "Maven AAR bytes differ")
    for name in primary:
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            require(files[name + "." + algorithm] == (hashlib.new(algorithm, files[name]).hexdigest() + "\n").encode(),
                    "Maven checksum differs")
    pom_data = files[f"{MAVEN}/{PREFIX}.pom"]
    require(pom_data == POM, "Maven POM metadata differs")
    pom = ET.fromstring(pom_data)
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    require([pom.findtext("m:" + name, namespaces=namespace) for name in ("groupId", "artifactId", "version", "packaging")]
            == ["dev.qperiapt", NAME, VERSION, "aar"], "Maven coordinate differs")
    sources = zip_entries(files[f"{MAVEN}/{PREFIX}-sources.jar"], canonical_aar=True)
    expected_sources = {**contract["java"], "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n\r\n",
                        **{name: data for name, data in contract["licenses"].items() if not name.endswith(".html")}}
    require(sources == expected_sources, "Maven source archive inventory or bytes differ")


def distribution_identity(selection: dict, files: dict[str, bytes]) -> dict:
    """The existing release-manifest identity schema; not an assessment report."""
    return {"schema_version": 1, "kind": "qperiapt.continuity_distribution_identity", "name": NAME, "version": VERSION,
            "source": {key: selection["source"][key] for key in ("commit", "tree")},
            "dependencies": [selection["native_package_id"]], "interfaces": ["continuity_c"],
            "artifacts": [reference(f"{MAVEN}/{PREFIX}{suffix}", files[f"{MAVEN}/{PREFIX}{suffix}"])
                          for suffix in (".aar", ".pom", "-sources.jar")]}


def read_capsule(root: Path, expected_sha256: str) -> tuple[dict, dict[str, bytes]]:
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None, "capsule receipt digest is malformed")
    data = read_regular_snapshot(root / "DISTRIBUTION.json", maximum=1024**2, label="distribution receipt").data
    require(sha(data) == expected_sha256, "independently selected distribution receipt digest differs")
    record = parse_strict_json_bytes(data, label="distribution receipt")
    require(type(record) is dict and type(record.get("files")) is dict, "distribution receipt inventory is missing")
    primary = {f"{MAVEN}/{PREFIX}{suffix}" for suffix in (".aar", ".pom", "-sources.jar")}
    expected = primary | {name + "." + algorithm for name in primary
                          for algorithm in ("md5", "sha1", "sha256", "sha512")}
    expected |= {"INPUT_SELECTION.json", "native-build.json", "classes-build.json", "PACKAGE_IDENTITY.json"}
    require(set(record["files"]) == expected, "distribution receipt file inventory differs")
    expected_directories = {parent.as_posix() for name in expected
                            for parent in PurePosixPath(name).parents if parent.as_posix() != "."}
    actual = set()
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            path = Path(directory) / name
            require(not path.is_symlink() and path.relative_to(root).as_posix() in expected_directories,
                    "unexpected or linked capsule directory")
        for name in files:
            relative = (Path(directory) / name).relative_to(root).as_posix()
            require(relative in expected | {"DISTRIBUTION.json"}, "unexpected capsule file")
            actual.add(relative)
    require(actual == expected | {"DISTRIBUTION.json"}, "capsule file inventory differs")
    contents = {}
    for name, ref in record["files"].items():
        require(type(ref) is dict and ref.get("path") == name, "capsule file pin path differs")
        contents[name] = read_pin(root, ref, maximum=MAX_BYTES)
    require(read_regular_snapshot(root / "DISTRIBUTION.json", maximum=1024**2,
                                 label="distribution receipt reread").data == data, "distribution receipt changed")
    return record, contents


def verify_capsule_record(record: dict, files: dict, *, result: dict, selection_data: bytes,
                          inputs: dict, contract: dict) -> None:
    expected = {**result, "files": {name: reference(name, data) for name, data in sorted(files.items())}}
    # A separate verifier can use the same selected NDK on another host. Its
    # binaries have their own pins; the retained producer pins remain recorded.
    producer_tools = record.get("tool_sha256")
    require(type(producer_tools) is dict and set(producer_tools) == {"llvm-nm", "llvm-readelf"}
            and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in producer_tools.values()),
            "producer tool pins differ")
    expected["tool_sha256"] = producer_tools
    require(canonical(record) == canonical(expected), "distribution receipt fields or verification claims differ")
    require(files["INPUT_SELECTION.json"] == selection_data
            and files["native-build.json"] == inputs["native_receipt"]
            and files["classes-build.json"] == inputs["classes_receipt"], "capsule input receipts differ")
    selection = parse_strict_json_bytes(selection_data, label="selected distribution input")
    require(files["PACKAGE_IDENTITY.json"] == canonical(distribution_identity(selection, files)),
            "release-manifest distribution identity differs")
    verify_maven({name: data for name, data in files.items() if name.startswith("maven/")},
                 files[f"{MAVEN}/{PREFIX}.aar"], contract)


def write_capsule(output: Path, result: dict, files: dict, *, selection_data: bytes,
                  inputs: dict, contract: dict) -> None:
    # The caller owns this workspace. Exclusive creation establishes ownership;
    # a failure removes only the newly created output, never retained evidence.
    output.mkdir(parents=True, mode=0o700)
    try:
        for name, data in files.items():
            path = output / name; path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)
        for name, expected in files.items():
            require(read_regular_snapshot(output / name, maximum=MAX_BYTES, label="AAR output reread").data == expected,
                    "produced capsule changed")
        with (output / "DISTRIBUTION.json").open("xb") as stream:
            stream.write(canonical(result))
        record, produced = read_capsule(output, sha(canonical(result)))
        verify_capsule_record(record, produced, result={key: value for key, value in result.items() if key != "files"},
                              selection_data=selection_data, inputs=inputs, contract=contract)
    except BaseException:
        shutil.rmtree(output)
        raise


def make_aar(selection: dict, inputs: dict, contract: dict) -> bytes:
    licenses = zip_entries(inputs["licenses"])
    files = {"AndroidManifest.xml": MANIFEST, "R.txt": b"", "classes.jar": inputs["classes"],
        "proguard.txt": contract["rules"], "META-INF/com/android/build/gradle/aar-metadata.properties": AAR_METADATA,
        METADATA: canonical(selection), f"jni/arm64-v8a/{C_LIBRARY}": inputs["c"],
        f"jni/arm64-v8a/{JNI_LIBRARY}": inputs["jni"], **contract["licenses"],
        **{"META-INF/" + name: data for name, data in licenses.items()}}
    return zip_bytes(files)


def execute(args) -> dict:
    output = fresh_output_directory(args.output, within=ROOT / "target", label="Continuity Android output") if args.command == "produce" else None
    paths = repository_paths(ROOT)
    source = source_identity(paths=paths)
    require(source["commit"] == args.source_commit and source["tree"] == args.source_tree
            and source["tree_sha256"] == args.source_tree_sha256,
            "independently selected checkout identity differs")
    input_root = args.inputs.resolve(strict=True)
    require(args.inputs.absolute() == input_root and not args.inputs.is_symlink(), "input root must be canonical")
    safe_path(args.selection)
    selection_data = read_regular_snapshot(input_root / args.selection, maximum=1024**2, label="AAR input selection").data
    selection, inputs = validate_selection(selection_data, input_root, expected_sha256=args.selection_sha256, source=source)
    contract, tools = source_contract(paths), native_tools(args.ndk.resolve(strict=True))
    tool_pins = {key: read_regular_snapshot(path, maximum=256 * 1024**2, label="native inspection tool").sha256 for key, path in tools.items()}
    if args.command == "produce":
        aar = make_aar(selection, inputs, contract)
    else:
        require(args.capsule.absolute() == args.capsule.resolve(strict=True), "capsule path must be canonical")
        capsule_record, capsule_files = read_capsule(args.capsule, args.distribution_sha256)
        aar = capsule_files[f"{MAVEN}/{PREFIX}.aar"]
    verified = verify_contents(zip_entries(aar, canonical_aar=True), selection, inputs, contract, tools)
    require(source_identity(paths=paths, pinned_files=contract["pinned"]) == source,
            "consumed source bytes differ from the selected checkout")
    require(validate_selection(selection_data, input_root, expected_sha256=args.selection_sha256, source=source)[1] == inputs,
            "selected inputs changed during AAR verification")
    require(read_regular_snapshot(input_root / args.selection, maximum=1024**2, label="selection reread").data == selection_data,
            "input selection changed during AAR verification")
    require({key: read_regular_snapshot(path, maximum=256 * 1024**2, label="native tool reread").sha256 for key, path in tools.items()} == tool_pins,
            "native inspection tools changed")
    result = {"schema_version": 1, "kind": "qperiapt.continuity_android_distribution", "completed": True,
        "coordinate": COORDINATE, "abi": ABI, "target": TARGET, "source": source,
        "input_selection_sha256": args.selection_sha256, "aar": reference(f"{MAVEN}/{PREFIX}.aar", aar),
        "tool_sha256": tool_pins, "verification": verified, "native_compilation_executed": False,
        "java_compilation_executed": False, "art_executed": False, "physical_device_executed": False,
        "release_claim_eligible": False, "publication_performed": False}
    if output is not None:
        files = maven_files(aar, contract)
        verify_maven(files, aar, contract)
        files["PACKAGE_IDENTITY.json"] = canonical(distribution_identity(selection, files))
        files.update({"INPUT_SELECTION.json": selection_data, "native-build.json": inputs["native_receipt"],
                      "classes-build.json": inputs["classes_receipt"]})
        result["files"] = {name: reference(name, data) for name, data in sorted(files.items())}
        write_capsule(output, result, files, selection_data=selection_data, inputs=inputs, contract=contract)
    else:
        verify_capsule_record(capsule_record, capsule_files, result=result, selection_data=selection_data,
                              inputs=inputs, contract=contract)
        require(read_capsule(args.capsule, args.distribution_sha256) == (capsule_record, capsule_files),
                "capsule changed during verification")
        result["distribution_receipt_sha256"] = args.distribution_sha256
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("produce", "verify"))
    for name in ("inputs", "ndk"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("selection", "selection-sha256", "source-commit", "source-tree", "source-tree-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output", type=Path); parser.add_argument("--capsule", type=Path)
    parser.add_argument("--distribution-sha256")
    args = parser.parse_args()
    if args.command == "produce":
        if args.output is None or args.capsule is not None or args.distribution_sha256 is not None:
            parser.error("produce requires --output and no existing capsule input")
    else:
        if args.output is not None or args.capsule is None or args.distribution_sha256 is None:
            parser.error("verify requires --capsule and --distribution-sha256, with no --output")
    print(json.dumps(execute(args), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
