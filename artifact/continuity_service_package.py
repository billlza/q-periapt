#!/usr/bin/env python3
"""Build, archive and independently reopen the existing Linux Continuity services.

The outer 0.2.0 distribution retains the reference Cargo package's 0.0.0 identity
and existing commands, configuration and persisted formats. Packaging evidence
is separate from account/directory protocol qualification and release admission.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import struct
import tempfile
import tomllib

import continuity_service_installation as installation
import continuity_service_licenses as service_licenses
import rust_sdk_profile as sdk
import third_party_licenses as licenses
from bounded_process import capture_output
from deterministic_archive import ArchiveLimits, create_tar_gz, extract_tar_gz
from evidence_io import fresh_output_directory, parse_strict_json_bytes
from git_provenance import run_git_text
from rust_sdk_msrv import tool_identity

ROOT = Path(__file__).resolve().parent.parent
APP = "research/continuity-reference-app"
SOURCE_PACKAGE = "q-periapt-continuity-reference-app"
NAME, VERSION = "q-periapt-continuity-services", "0.2.0"
BINARIES = ("q-periapt-prekey-directory", "q-periapt-continuity-witness",
            "q-periapt-policy-publisher", "q-periapt-sdk-policy-authority", "q-periapt-native-device")
EXECUTABLES = frozenset("bin/" + name for name in BINARIES)
DOCS = {"docs/continuity/SERVICE_DISTRIBUTION_0_2.md": "README.md",
        APP + "/DIRECTORY_LEASES.md": "docs/DIRECTORY_LEASES.md",
        APP + "/SDK_AUTHORITY.md": "docs/SDK_AUTHORITY.md",
        APP + "/POLICY_PUBLISHER.md": "docs/POLICY_PUBLISHER.md",
        APP + "/NATIVE_DEVICE.md": "docs/NATIVE_DEVICE.md",
        APP + "/README.md": "docs/REFERENCE_APPLICATION.md"}
CONTENTS = "PACKAGE_CONTENTS.json"
REPORT = "CONTINUITY_SERVICE_PACKAGE.json"
INSTALLATION = "CONTINUITY_SERVICE_INSTALLATION.json"
IDENTITY = "CONTINUITY_SERVICE_DISTRIBUTION.json"
ROW = "CONTINUITY_SERVICE_PACKAGE_ROW.json"
TARGETS = {"x86_64": ("x86_64-unknown-linux-gnu", 62, "/lib64/ld-linux-x86-64.so.2"),
           "aarch64": ("aarch64-unknown-linux-gnu", 183, "/lib/ld-linux-aarch64.so.1")}
MTIME = 1767225600
LIMITS = ArchiveLimits(maximum_archive_bytes=256 * 1024**2,
                       maximum_member_bytes=128 * 1024**2, maximum_total_bytes=512 * 1024**2)


def canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o644)


def inventory(root: Path) -> dict[str, str]:
    sdk.require(root.is_dir() and not root.is_symlink(), "service package is not a plain directory")
    result = {}
    for path in sorted(root.rglob("*")):
        sdk.require(not path.is_symlink(), "service package contains a symlink")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            sdk.require(stat.S_IMODE(path.stat().st_mode) == (0o755 if relative in EXECUTABLES else 0o644),
                        "service package member permission differs: " + relative)
            result[relative] = sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes).sha256
        else:
            sdk.require(path.is_dir(), "service package contains a special file")
    return result


def document(data: bytes, relative: str, commit: str) -> bytes:
    """Keep document text and give repository links a stable packaged destination."""
    base = "https://github.com/billlza/q-periapt/blob/" + commit + "/"
    def link(match):
        target = match[1]
        if target.startswith(("#", "/")) or re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target):
            return match[0]
        resolved = posixpath.normpath(str(PurePosixPath(relative).parent / target))
        sdk.require(not resolved.startswith("../"), "service documentation link escapes repository")
        return "](" + base + resolved + ")"
    return re.sub(r"\]\(([^\s)]+)\)", link, data.decode("utf-8")).encode()


def archive_executables(prefix: str) -> frozenset[str]:
    return frozenset(prefix + "/" + name for name in EXECUTABLES)


def cargo_configuration(cwd: Path, cargo_home: Path) -> list[str]:
    """Cargo searches its invocation directory's ancestors even with --manifest-path."""
    paths = {cargo_home / name for name in ("config", "config.toml", "credentials", "credentials.toml")}
    paths.update(parent / ".cargo" / name for parent in (cwd, *cwd.parents) for name in ("config", "config.toml"))
    for path in sorted(paths):
        sdk.require(not path.exists() and not path.is_symlink(),
                    "service Cargo configuration or credential override: " + str(path))
    return [str(path) for path in sorted(paths)]


def executable_contract(data: bytes, text: str, target: str) -> dict:
    entry = next((row for row in TARGETS.values() if row[0] == target), None)
    sdk.require(entry is not None, "unsupported service target")
    sdk.require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
                and data[7] in (0, 3) and data[8:16] == bytes(8), "service executable is not Linux ELF64")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    sdk.require(kind in (2, 3) and (machine, version) == (entry[1], 1)
                and struct.unpack_from("<H", data, 52)[0] == 64, "service ELF architecture differs")
    interpreter = re.findall(r"\[Requesting program interpreter: ([^\]]+)\]", text)
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", text)
    allowed = {"libc.so.6", "libgcc_s.so.1", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1",
               "libssl.so.3", "libcrypto.so.3", Path(entry[2]).name}
    sdk.require(interpreter == [entry[2]] and "libc.so.6" in needed
                and len(needed) == len(set(needed)) and set(needed) <= allowed,
                "service interpreter or system dependency inventory differs")
    sdk.require(re.search(r"\((?:SONAME|RPATH|RUNPATH|TEXTREL|FILTER|AUXILIARY|AUDIT|DEPAUDIT)\)", text) is None,
                "service executable has an unexpected loader path or dynamic dependency")
    versions = re.findall(r"\bName: ([A-Za-z0-9_.]+)", text)
    sdk.require(versions and all(re.fullmatch(r"(?:GLIBC|GCC|OPENSSL)_[0-9]+(?:\.[0-9]+)*", value)
                                for value in versions), "service runtime symbol versions differ")
    return {"interpreter": entry[2], "needed": sorted(needed),
            "symbol_versions": sorted(set(versions)), "loader_search_path": None}


def verify_binary(path: Path, target: str, run, label: str) -> dict:
    before = sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes)
    dynamic = run(["/usr/bin/readelf", "-l", "-d", "--version-info", "-W", str(path)], label).decode()
    result = executable_contract(before.data, dynamic, target)
    sdk.require(sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes).sha256 == before.sha256,
                "service executable changed during inspection")
    return {"bytes": before.size, "sha256": before.sha256, **result}


def source_package(root: Path) -> dict:
    value = tomllib.loads(sdk.snapshot(root / APP / "Cargo.toml").data.decode())["package"]
    sdk.require(value["name"] == SOURCE_PACKAGE and value["version"] == "0.0.0"
                and value["publish"] is False, "service source package identity differs")
    return {"name": value["name"], "version": value["version"], "registry_publish": False,
            "manifest": APP + "/Cargo.toml", "lock_sha256": sdk.snapshot(root / APP / "Cargo.lock").sha256}


def select_build(data: bytes, metadata: dict, build: Path, target: str, root: Path) -> dict[str, Path]:
    roots = [row for row in metadata["packages"] if row["name"] == SOURCE_PACKAGE and row["source"] is None]
    sdk.require(len(roots) == 1 and roots[0]["version"] == "0.0.0"
                and Path(roots[0]["manifest_path"]) == root / APP / "Cargo.toml",
                "service build resolved another source package")
    rows = [parse_strict_json_bytes(line, label="service Cargo build") for line in data.splitlines()]
    sdk.require([row for row in rows if row.get("reason") == "build-finished"]
                == [{"reason": "build-finished", "success": True}], "service build did not finish successfully")
    result = {}
    for row in rows:
        if row.get("reason") != "compiler-artifact" or row.get("executable") is None:
            continue
        name = row["target"]["name"]
        expected = build / target / "release" / name
        sdk.require(row["package_id"] == roots[0]["id"] and name in BINARIES and name not in result
                    and row["target"]["kind"] == ["bin"]
                    and row["profile"]["test"] is False and row["profile"]["opt_level"] == "3"
                    and row["target"]["src_path"] == str(root / APP / "src/bin" / (name + ".rs"))
                    and row["executable"] == str(expected), "service Cargo executable selection differs")
        result[name] = expected
    sdk.require(set(result) == set(BINARIES), "service build omitted a selected executable")
    return result


def verify_package(root: Path, expected: dict) -> None:
    sdk.require(parse_strict_json_bytes(sdk.snapshot(root / CONTENTS).data, label="service contents") == expected,
                "service contents identity differs")
    files = inventory(root)
    files.pop(CONTENTS)
    sdk.require(files == expected["files"], "service package members or bytes changed")
    sdk.require({name for name in files if name.startswith("bin/")} == EXECUTABLES,
                "service executable inventory differs")
    licenses.verify(root / "LICENSES/dependencies", expected_target=expected["target"], root_package=SOURCE_PACKAGE)


def records(output: Path, result: dict, engine_package_id: str) -> None:
    sdk.require(result.get("completed") is True and "failure" not in result,
                "service package records require a completed package")
    installed = parse_strict_json_bytes(sdk.snapshot(output / INSTALLATION).data, label="service installation")
    sdk.require(installed.get("kind") == "qperiapt.continuity_service_installation"
                and installed.get("completed") is True and "failure" not in installed
                and installed.get("source") == result["source"] and installed.get("archive") == result["archive"],
                "service installation identity differs or is incomplete")
    def ref(name):
        data = canonical(result) if name == REPORT else sdk.snapshot(output / name).data
        return {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    identity = {"schema_version": 1, "kind": "qperiapt.continuity_distribution_identity", "name": NAME,
                "version": VERSION, "source": result["source"], "dependencies": [engine_package_id],
                "interfaces": [], "artifacts": [result["archive"]]}
    write(output / IDENTITY, canonical(identity))
    write(output / ROW, canonical({"id": "continuity-services", "role": "service", "name": NAME,
          "version": VERSION, "format": "distribution", "metadata": ref(IDENTITY), "workspace": None,
          "dependencies": [engine_package_id], "interfaces": [], "artifacts": [result["archive"]],
          "assessments": [ref(REPORT), ref(INSTALLATION)]}))


def qualify(args: argparse.Namespace) -> dict:
    sdk.require(os.uname().sysname == "Linux" and os.uname().machine in TARGETS,
                "service distribution requires a supported Linux host")
    sdk.require(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", args.engine_package_id) is not None
                and args.engine_package_id != "continuity-services", "service engine package ID differs")
    commit, dirty = sdk.inspect_package_source(ROOT, allow_dirty=False)
    sdk.require(not dirty, "service distribution requires clean source")
    source = {"commit": commit, "tree": run_git_text(ROOT, ["rev-parse", "--verify", commit + "^{tree}"])}
    original_package = source_package(ROOT)
    target = TARGETS[os.uname().machine][0]
    output = fresh_output_directory(args.output, within=ROOT / "target", label="service package evidence")
    output.mkdir(parents=True, mode=0o700)
    work = Path(tempfile.mkdtemp(prefix="qperiapt-services-")).resolve()
    sdk.require(not work.is_relative_to(ROOT), "service installation must be outside source checkout")
    toolchain, cargo_home = args.toolchain_root.resolve(strict=True), args.cargo_home.resolve(strict=True)
    sdk.require(cargo_home.is_dir(), "service Cargo cache is not a directory")
    config_paths = cargo_configuration(work, cargo_home)
    tools = tool_identity(toolchain)
    cc = Path("/usr/bin/cc").resolve(strict=True)
    system_compiler = {"path": str(cc), "sha256": sdk.snapshot(cc, maximum=256 * 1024**2).sha256}
    build = work / "build"
    environment = {key: value for key, value in os.environ.items()
                   if key in {"HOME", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
                              "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy"}}
    environment.update(PATH=str(toolchain / "bin") + ":/usr/bin:/bin", LC_ALL="C", LANG="C",
                       CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(build), CARGO_INCREMENTAL="0",
                       CARGO_TERM_COLOR="never", CARGO_HTTP_MULTIPLEXING="false", RUSTFLAGS="-D warnings",
                       RUSTC=str(toolchain / "bin/rustc"), RUSTDOC=str(toolchain / "bin/rustdoc"),
                       LD_LIBRARY_PATH=str(toolchain / "lib"), CC="/usr/bin/cc", AR="/usr/bin/ar")
    runtime_environment = {key: value for key, value in environment.items() if not key.startswith("LD_")}
    evidence = output / "commands"
    evidence.mkdir(mode=0o700)
    result = {"schema_version": 1, "kind": "qperiapt.continuity_service_package", "completed": False,
              "name": NAME, "version": VERSION, "source_package": original_package, "source": source,
              "target": target, "tool_binaries": tools, "outside_checkout": str(work),
              "c_compiler": system_compiler,
              "excluded_cargo_configuration_paths": config_paths,
              "release_claim_eligible": False, "publication_performed": False,
              "scope": "locked Linux Release build, deterministic service archive and extracted local process readback"}

    def run(argv, label, cwd=ROOT, *, expected_exit=0, expected_stderr=None, compiler=False):
        with contextlib.chdir(cwd):
            executed = capture_output(argv, timeout_seconds=900, maximum_stdout_bytes=16 * 1024**2,
                                      maximum_stderr_bytes=16 * 1024**2,
                                      environment=environment if compiler else runtime_environment)
        write(evidence / (label + ".stdout"), executed.stdout)
        write(evidence / (label + ".stderr"), executed.stderr)
        write(evidence / (label + ".json"), canonical({"argv": argv, "cwd": str(cwd),
              "returncode": executed.returncode, "expected_returncode": expected_exit,
              "expected_stderr_contains": expected_stderr}))
        sdk.require(executed.returncode == expected_exit, f"service command failed: {label}.stderr")
        sdk.require(expected_stderr is None or expected_stderr.encode() in executed.stderr,
                    f"service refusal reason differs: {label}.stderr")
        return executed.stdout

    try:
        rustc = run([str(toolchain / "bin/rustc"), "-vV"], "rustc", cwd=work, compiler=True).decode()
        cargo = str(toolchain / "bin/cargo")
        cargo_version = run([cargo, "--version"], "cargo", cwd=work, compiler=True).decode()
        sdk.require(rustc.startswith("rustc 1.98.1 ") and cargo_version.startswith("cargo 1.98.1 "),
                    "service compiler differs from pinned Rust 1.98.1")
        result["compiler_version"] = rustc
        run([str(cc), "--version"], "cc")
        metadata = parse_strict_json_bytes(run([cargo, "metadata", "--locked", "--format-version", "1",
                "--filter-platform", target, "--manifest-path", str(ROOT / APP / "Cargo.toml")],
                "metadata", cwd=work, compiler=True), label="service Cargo metadata")
        args_build = [cargo, "build", "--locked", "--offline", "--release", "--manifest-path", str(ROOT / APP / "Cargo.toml"),
                      "--target", target, "--message-format=json", "-j", "2"]
        for name in BINARIES:
            args_build.extend(["--bin", name])
        build_output = run(args_build, "build", cwd=work, compiler=True)
        binaries = select_build(build_output, metadata, build, target, ROOT)
        prefix = f"{NAME}-{VERSION}-{target}"
        staging = work / prefix
        staging.mkdir(mode=0o700)
        binaries_before = {}
        for name, path in binaries.items():
            binaries_before[name] = sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes).sha256
            sdk.copy(path, staging / "bin" / name, maximum=LIMITS.maximum_member_bytes)
            (staging / "bin" / name).chmod(0o755)
        contracts = {}
        for relative, destination in DOCS.items():
            observed = sdk.snapshot(ROOT / relative)
            contracts[relative] = {"sha256": observed.sha256, "bytes": observed.size,
                                   "packaged_path": destination}
            write(staging / destination, document(observed.data, relative, commit))
        native = {name: verify_binary(staging / "bin" / name, target, run, "elf-" + name) for name in BINARIES}
        result["binaries"] = native
        notices = staging / "LICENSES/dependencies"
        notices.mkdir(parents=True)
        supplemental, origins = service_licenses.select(ROOT, metadata, cargo_home)
        collected = licenses.collect(ROOT / APP, notices, target, root_package=SOURCE_PACKAGE, resolved_metadata=metadata,
                                     supplemental_licenses=supplemental)
        service_licenses.verify_inventory(collected, origins)
        write(staging / "LICENSES/UPSTREAM_LICENSE_ORIGINS.json", canonical(origins))
        result["upstream_license_origins"] = origins
        sdk.copy(ROOT / "LICENSE", staging / "LICENSE")
        for name in ("Apache-2.0.txt", "MIT.txt"):
            sdk.copy(ROOT / "LICENSES" / name, staging / "LICENSES" / name)
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md"):
            sdk.copy(ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name, staging / "LICENSES/mlkem-native" / name)
        rust_docs = toolchain / "share/doc/rust"
        sdk.require(sdk.snapshot(rust_docs / "COPYRIGHT-library.html").data ==
                    sdk.snapshot(ROOT / "LICENSES/Rust-1.98.1-library.html").data,
                    "service Rust library notices differ from the selected compiler")
        sdk.copy(rust_docs / "COPYRIGHT-library.html", staging / "LICENSES/Rust-1.98.1-library.html")
        for path in sorted((rust_docs / "licenses").rglob("*")):
            sdk.require(not path.is_symlink(), "Rust license tree contains a symlink")
            if path.is_file():
                sdk.copy(path, staging / "LICENSES/rust-standard-library" / path.relative_to(rust_docs / "licenses"))
        contents = {"schema_version": 1, "kind": "qperiapt.continuity_service_contents", "name": NAME,
                    "version": VERSION, "source_package": original_package, "source": source, "target": target,
                    "binaries": native, "configuration_documents": contracts, "files": inventory(staging)}
        write(staging / CONTENTS, canonical(contents))
        verify_package(staging, contents)
        archive = output / (prefix + ".tar.gz")
        audit = create_tar_gz(staging, archive, root_name=prefix, mtime=MTIME, limits=LIMITS,
                             executable_paths=archive_executables(prefix))
        result["archive"] = {"path": archive.name, "bytes": audit.archive_bytes, "sha256": audit.archive_sha256}
        installed_root = work / "installed"
        extract_tar_gz(archive, installed_root, root_name=prefix, mtime=MTIME, limits=LIMITS,
                       expected_sha256=audit.archive_sha256, executable_paths=archive_executables(prefix))
        installed = installed_root / prefix
        verify_package(installed, contents)
        for name in BINARIES:
            sdk.require(verify_binary(installed / "bin" / name, target, run, "installed-elf-" + name) == native[name],
                        "extracted service binary contract changed")
        installed_result = {"schema_version": 1, "kind": "qperiapt.continuity_service_installation", "completed": False,
                            "source": source, "archive": result["archive"], "target": target,
                            "formal_account_qualification": False, "release_claim_eligible": False,
                            "scope": "fresh extracted processes and local original-service readback"}
        try:
            installed_result["checks"] = installation.exercise(installed, work / "private-probe-state", run)
            verify_package(installed, contents)
            installed_result["completed"] = True
        except BaseException as error:
            installed_result["failure"] = str(error)
            raise
        finally:
            write(output / INSTALLATION, canonical(installed_result))
        sdk.require(all(sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes).sha256 == binaries_before[name]
                        for name, path in binaries.items()), "service build bytes changed during packaging")
        sdk.require(sdk.snapshot(archive, maximum=LIMITS.maximum_archive_bytes).sha256 == audit.archive_sha256
                    and tools == tool_identity(toolchain) and original_package == source_package(ROOT)
                    and sdk.snapshot(cc, maximum=256 * 1024**2).sha256 == system_compiler["sha256"]
                    and cargo_configuration(work, cargo_home) == config_paths
                    and sdk.inspect_package_source(ROOT, allow_dirty=False) == (commit, False),
                    "service source, compiler or archive changed during packaging")
        installed_receipt = sdk.snapshot(output / INSTALLATION)
        result.update(completed=True, archive_members=len(audit.entries), installed_members_verified=True,
                      installation={"path": INSTALLATION, "bytes": installed_receipt.size,
                                    "sha256": installed_receipt.sha256})
        records(output, result, args.engine_package_id)
    except BaseException as error:
        result["completed"] = False
        result["failure"] = str(error)
        raise
    finally:
        write(output / REPORT, canonical(result))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "toolchain-root", "cargo-home"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--engine-package-id", default="continuity-engine")
    print(json.dumps(qualify(parser.parse_args())))


if __name__ == "__main__":
    main()
