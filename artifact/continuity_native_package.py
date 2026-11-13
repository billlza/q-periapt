"""Package the already executed Linux C owner as a versioned native companion.

The producer retains the qualified Release library unchanged. The archive is
reopened independently and a fresh C process loads that installed copy. The
receipt retains its source and C execution identity for coordinated admission.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import struct

import continuity_c_abi as abi
import continuity_c_consumer as c
import continuity_package as package
import continuity_profiles as profiles
import rust_sdk_profile as sdk
import third_party_licenses as licenses
from deterministic_archive import ArchiveLimits, create_zip, extract_zip
from evidence_io import parse_strict_json_bytes
from git_provenance import run_git_text

NAME, VERSION, ABI = "q-periapt-continuity-native", "0.2.0", "qpc-owner/1"
LIBRARY = "libq_periapt_continuity_c_consumer.so"
CONTENTS = "PACKAGE_CONTENTS.json"
TARGETS = {"x86_64": ("x86_64-unknown-linux-gnu", 62, "ld-linux-x86-64.so.2"),
           "aarch64": ("aarch64-unknown-linux-gnu", 183, "ld-linux-aarch64.so.1")}
MTIME = 1767225600
LIMITS = ArchiveLimits(maximum_archive_bytes=256 * 1024**2,
                       maximum_member_bytes=128 * 1024**2, maximum_total_bytes=256 * 1024**2)
REPORT = "CONTINUITY_NATIVE_PACKAGE.json"
IDENTITY = "CONTINUITY_NATIVE_DISTRIBUTION.json"
ROW = "CONTINUITY_NATIVE_PACKAGE_ROW.json"


def canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def inventory(root: Path) -> dict[str, str]:
    sdk.require(root.is_dir() and not root.is_symlink(), "native package root is not a plain directory")
    result = {}
    for path in sorted(root.rglob("*")):
        sdk.require(not path.is_symlink(), "native package contains a symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes).sha256
        else:
            sdk.require(path.is_dir(), "native package contains a special file")
    return result


def elf_target(data: bytes, target: str) -> None:
    entry = next((row for row in TARGETS.values() if row[0] == target), None)
    sdk.require(entry is not None, "unsupported native package target")
    sdk.require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
                and data[7] in (0, 3) and data[8:16] == bytes(8), "native library is not Linux ELF64")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    sdk.require((kind, machine, version) == (3, entry[1], 1), "native library type or architecture differs")
    sdk.require(struct.unpack_from("<H", data, 52)[0] == 64, "native ELF header size differs")


def dynamic_contract(text: str, target: str) -> dict:
    entry = next((row for row in TARGETS.values() if row[0] == target), None)
    sdk.require(entry is not None, "unsupported native package target")
    sonames = re.findall(r"\(SONAME\)\s+Library soname: \[([^\]]+)\]", text)
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", text)
    allowed = {"libc.so.6", "libgcc_s.so.1", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1", entry[2]}
    sdk.require(sonames == [LIBRARY] and len(needed) == len(set(needed)) and "libc.so.6" in needed
                and set(needed) <= allowed, "native SONAME or runtime dependency inventory differs")
    sdk.require(re.search(r"\((?:RPATH|RUNPATH|TEXTREL|FILTER|AUXILIARY|AUDIT|DEPAUDIT)\)", text) is None,
                "native library has an unapproved loader path or dynamic dependency")
    versions = re.findall(r"\bName: ([A-Za-z0-9_.]+)", text)
    sdk.require(versions and all(re.fullmatch(r"(?:GLIBC|GCC)_[0-9]+(?:\.[0-9]+)*", value)
                                for value in versions), "native runtime symbol-version requirement differs")
    return {"soname": LIBRARY, "needed": sorted(needed), "symbol_versions": sorted(set(versions)),
            "loader_search_path": None}


def verify_native(path: Path, target: str, run) -> dict:
    before = sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes)
    elf_target(before.data, target)
    symbols = run(["/usr/bin/nm", "-D", "--defined-only", "--format=posix", str(path)], "exports").decode()
    rows = [line.split() for line in symbols.splitlines() if line.strip()]
    names = [row[0] for row in rows]
    sdk.require(all(len(row) >= 3 and row[1] == "T" for row in rows)
                and len(names) == len(set(names)) and set(names) == c.EXPORTS,
                "native exported functions differ from qpc-owner/1")
    result = dynamic_contract(run(["/usr/bin/readelf", "-d", "--version-info", "-W", str(path)],
                                  "dynamic").decode(), target)
    sdk.require(sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes).sha256 == before.sha256,
                "native library changed during verification")
    return {"sha256": before.sha256, "bytes": before.size, "owner_exports": len(names), **result}


def verify_package(root: Path, expected: dict) -> None:
    actual = parse_strict_json_bytes(sdk.snapshot(root / CONTENTS).data, label="native package contents")
    sdk.require(actual == expected, "native package contents identity differs")
    files = inventory(root)
    files.pop(CONTENTS)
    sdk.require(files == expected["files"], "native package members or bytes changed")
    contract = abi.load(root / "include")
    sdk.require(len(contract["functions"]) == 158, "native package owner ABI differs")
    licenses.verify(root / "LICENSES/dependencies", expected_target=expected["target"], root_package=c.NAME)


def selected_execution(outside: Path, result: dict) -> dict:
    profiles.require_native(result, profiles.PROFILES)
    sdk.require("failure" not in result and result.get("release_claim_eligible") is False,
                "native package requires the completed C qualification")
    selected = result["execution"]["release"].get("binaries", {}).get("C_library")
    sdk.require(type(selected) is dict and set(selected) == {"path", "sha256", "bytes"},
                "qualified Release library identity is absent")
    expected = outside / "c-installed-release" / LIBRARY
    sdk.require(selected["path"] == str(expected), "qualified Release library path differs")
    observed = sdk.snapshot(expected, maximum=LIMITS.maximum_member_bytes)
    sdk.require(type(selected["bytes"]) is int and (observed.size, observed.sha256)
                == (selected["bytes"], selected["sha256"]), "qualified Release library bytes differ")
    return selected


def _probe() -> bytes:
    return b'''#define _GNU_SOURCE
#include "qpc_owner.h"
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2) return 10;
    void *symbol = dlsym(RTLD_DEFAULT, "qpc_owner_v1_open");
    Dl_info owner;
    char observed[PATH_MAX], expected[PATH_MAX];
    if (!symbol || !dladdr(symbol, &owner) || !owner.dli_fname ||
        !realpath(owner.dli_fname, observed) || !realpath(argv[1], expected) ||
        strcmp(observed, expected)) return 11;
    qpc_error_v1 error;
    uint64_t handle = 99;
    if (qpc_owner_v1_open(NULL, 0, 1, &handle, &error) != QPC_ARGUMENT || handle != 0) return 12;
    handle = 99;
    if (qpc_owner_v1_open(NULL, 0, 1, &handle, NULL) != QPC_ARGUMENT || handle != 99) return 13;
    if (qpc_owner_v1_close(0, &error) != QPC_CLOSED) return 14;
    if (puts("NATIVE_OWNER_PASS installed_library=true argument_refusal=true") == EOF) return 15;
    return 0;
}
'''


def qualify_native(outside: Path, output: Path, native: dict, cargo: list[str], environment: dict,
                   *, source_commit: str, engine_package_id: str) -> dict:
    sdk.require(os.uname().sysname == "Linux" and os.uname().machine in TARGETS,
                "native companion packaging requires an admitted Linux host")
    sdk.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", engine_package_id) is not None
                and engine_package_id != "continuity-native", "native engine dependency ID differs")
    sdk.require(not outside.resolve().is_relative_to(package.ROOT), "native package work must be outside checkout")
    sdk.require(sdk.inspect_package_source(package.ROOT, allow_dirty=False) == (source_commit, False),
                "native source commit differs or checkout is modified")
    target = TARGETS[os.uname().machine][0]
    source = {"commit": source_commit,
              "tree": run_git_text(package.ROOT, ["rev-parse", "--verify", source_commit + "^{tree}"])}
    sdk.require(all(re.fullmatch(r"[0-9a-f]{40}", value) for value in source.values()),
                "native source identity is malformed")
    selected = selected_execution(outside, native)
    receipt = sdk.snapshot(output / "C_CONSUMER.json")
    sdk.require(parse_strict_json_bytes(receipt.data, label="C qualification") == native,
                "retained C qualification differs from this execution")
    prefix = f"{NAME}-{VERSION}-{target}"
    work = outside / "native-package"
    work.mkdir(mode=0o700)
    staging = work / prefix
    staging.mkdir(mode=0o700)
    consumer = outside / "c-consumer"
    evidence = output / "native-package"
    evidence.mkdir(mode=0o700)
    before = inventory(consumer)
    result = {"schema_version": 1, "kind": "qperiapt.continuity_native_package", "completed": False,
              "name": NAME, "version": VERSION, "abi": ABI, "target": target, "source": source,
              "c_execution": {"file": "C_CONSUMER.json", "sha256": receipt.sha256, "bytes": receipt.size},
              "release_claim_eligible": False, "publication_performed": False,
              "scope": "unchanged qualified Linux Release C owner, deterministic archive readback and relocated public C probe"}
    env = {key: value for key, value in environment.items()
           if not key.startswith(("LD_", "DYLD_")) and key not in {"LIBRARY_PATH", "CPATH", "C_INCLUDE_PATH"}}
    def run(argv, label, cwd=consumer):
        return sdk.command(argv, evidence / label, cwd, environment=env)
    try:
        sdk.copy(Path(selected["path"]), staging / "lib" / LIBRARY, maximum=LIMITS.maximum_member_bytes)
        for relative in ("qpc_owner.h", abi.CONTRACT):
            sdk.require(sdk.snapshot(consumer / relative).data == sdk.snapshot(c.FIXTURE / relative).data,
                        "installed native header or ABI differs from current source")
            sdk.copy(consumer / relative, staging / "include" / relative)
        result["native"] = verify_native(staging / "lib" / LIBRARY, target, run)
        sdk.require(result["native"]["sha256"] == selected["sha256"], "native package selected another build")
        metadata = parse_strict_json_bytes(run([*cargo, "metadata", "--locked", "--offline", "--format-version", "1",
                                               "--filter-platform", target], "licenses"), label="native runtime metadata")
        notices = staging / "LICENSES/dependencies"
        notices.mkdir(parents=True)
        licenses.collect(consumer, notices, target, root_package=c.NAME, resolved_metadata=metadata)
        for name in ("LICENSE", "LICENSE-APACHE", "LICENSE-MIT"):
            sdk.copy(package.CANDIDATE / name, staging / name)
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md"):
            sdk.copy(package.ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name,
                     staging / "LICENSES/mlkem-native" / name)
        rust_docs = Path(env["RUSTC"]).resolve(strict=True).parent.parent / "share/doc/rust"
        sdk.require(sdk.snapshot(rust_docs / "COPYRIGHT-library.html").data ==
                    sdk.snapshot(package.ROOT / "LICENSES/Rust-1.98.1-library.html").data,
                    "native Rust library notices differ from the selected compiler")
        sdk.copy(rust_docs / "COPYRIGHT-library.html", staging / "LICENSES/Rust-1.98.1-library.html")
        for path in sorted((rust_docs / "licenses").rglob("*")):
            sdk.require(not path.is_symlink(), "Rust license tree contains a symlink")
            if path.is_file():
                sdk.copy(path, staging / "LICENSES/rust-standard-library" / path.relative_to(rust_docs / "licenses"))
        sdk.copy(package.ROOT / "docs/continuity/NATIVE_DISTRIBUTION_0_2.md", staging / "README.md")
        contents = {"schema_version": 1, "kind": "qperiapt.continuity_native_contents",
                    "name": NAME, "version": VERSION, "abi": ABI, "target": target, "source": source,
                    "native": result["native"], "c_execution_sha256": receipt.sha256, "files": inventory(staging)}
        write(staging / CONTENTS, canonical(contents))
        verify_package(staging, contents)
        archive = output / (prefix + ".zip")
        audit = create_zip(staging, archive, root_name=prefix, mtime=MTIME, limits=LIMITS)
        installed = work / "installed"
        extract_zip(archive, installed, root_name=prefix, mtime=MTIME,
                    expected_sha256=audit.archive_sha256, limits=LIMITS)
        extracted = installed / prefix
        verify_package(extracted, contents)
        sdk.require(verify_native(extracted / "lib" / LIBRARY, target,
                    lambda argv, label: run(argv, "installed-" + label)) == result["native"],
                    "installed native loader contract changed")
        probe_source, probe = installed / "owner_probe.c", installed / "owner-probe"
        write(probe_source, _probe())
        cc = Path(native["compiler"]["path"])
        sdk.require(sdk.snapshot(cc, maximum=c.MAX_BINARY).sha256 == native["compiler"]["sha256"],
                    "qualified C compiler changed")
        run([str(cc), "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", str(probe_source),
             "-I", str(extracted / "include"), "-L", str(extracted / "lib"), "-l" + c.LIBRARY,
             "-ldl", "-Wl,-rpath,$ORIGIN/" + prefix + "/lib", "-o", str(probe)], "probe-build", installed)
        sdk.require(run([str(probe), str(extracted / "lib" / LIBRARY)], "probe-run", installed)
                    == b"NATIVE_OWNER_PASS installed_library=true argument_refusal=true\n", "installed native probe failed")
        verify_package(extracted, contents)
        sdk.require(inventory(consumer) == before and selected_execution(outside, native) == selected
                    and sdk.snapshot(output / "C_CONSUMER.json").sha256 == receipt.sha256
                    and sdk.snapshot(archive, maximum=LIMITS.maximum_archive_bytes).sha256 == audit.archive_sha256
                    and sdk.snapshot(cc, maximum=c.MAX_BINARY).sha256 == native["compiler"]["sha256"],
                    "native source or qualification inputs changed")
        sdk.require(sdk.inspect_package_source(package.ROOT, allow_dirty=False) == (source_commit, False),
                    "native source changed during packaging")
        result.update(completed=True, archive={"path": archive.name, "bytes": audit.archive_bytes,
                      "sha256": audit.archive_sha256}, installed_members_verified=True,
                      installed_probe={"completed": True, "sha256": sdk.snapshot(probe, maximum=c.MAX_BINARY).sha256},
                      qualified_library_unchanged=True)
        identity = {"schema_version": 1, "kind": "qperiapt.continuity_distribution_identity",
                    "name": NAME, "version": VERSION, "source": source, "dependencies": [engine_package_id],
                    "interfaces": ["continuity_c"], "artifacts": [result["archive"]]}
        write(output / IDENTITY, canonical(identity))
        def ref(name):
            if name == REPORT:
                data = canonical(result)
                return {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            value = sdk.snapshot(output / name)
            return {"path": name, "bytes": value.size, "sha256": value.sha256}
        write(output / ROW, canonical({"id": "continuity-native", "role": "native", "name": NAME, "version": VERSION,
              "format": "distribution", "metadata": ref(IDENTITY), "workspace": None,
              "dependencies": [engine_package_id], "interfaces": ["continuity_c"],
              "artifacts": [result["archive"]], "assessments": [ref(REPORT)]}))
    except Exception as error:
        result["completed"] = False
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / REPORT, result)
    return result
