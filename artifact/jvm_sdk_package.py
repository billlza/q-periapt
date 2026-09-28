#!/usr/bin/env python3
"""Stage a pinned JVM SDK and verify real Maven consumers; never publish remotely."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile

from bounded_process import capture_output
from c_abi_contract import load_contract, verify_dynamic_library, verify_header
from c_package_manifest import (SDK_CONTRACT_PATH, SDK_EMBEDDED_CONTRACT,
    expected_profile_files, source_fingerprints, verify_sealed_payload)
from deterministic_archive import create_tar_gz, extract_tar_gz
from evidence_io import load_json_object_snapshot, parse_strict_json_bytes, read_regular_snapshot
from third_party_licenses import INVENTORY_RELATIVE

ROOT = Path(__file__).resolve().parent.parent
BINDING = ROOT / "bindings/kotlin"
VERSION = "0.2.0"
GROUP = "dev.qperiapt"
NAME = "q-periapt-hybrid"
KOTLIN = "2.4.10"
COORDINATE = f"{GROUP}:{NAME}:{VERSION}"
MODULE = "dev.qperiapt.hybrid"
MAVEN_PATH = Path("dev/qperiapt") / NAME / VERSION
PREFIX = f"{NAME}-{VERSION}"
CONTENTS = "PACKAGE_CONTENTS.json"
MTIME = 946684800
SHA = re.compile(r"[0-9a-f]{64}")
POLICIES = {"enabled": "signed-policy-vectors.json", "disabled": "sdk-policy-revocation-vectors.json",
            "reenabled": "sdk-policy-update-vectors.json"}
NOTICE_PATHS = {f"META-INF/licenses/{name}": ROOT / "LICENSES" / name for name in ("Apache-2.0.txt", "MIT.txt")}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def snapshot(path: Path):
    return read_regular_snapshot(path, maximum=64 * 1024 * 1024, label="JVM SDK input")


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def copy(source: Path, destination: Path) -> None:
    data = snapshot(source).data
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(data)
    destination.chmod(0o644)


def entries(root: Path) -> dict:
    files = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "JVM package symlink is forbidden")
        if path.is_dir():
            continue
        record = snapshot(path)
        files[path.relative_to(root).as_posix()] = {"bytes": record.size, "sha256": record.sha256}
    return files


def sources() -> dict:
    paths = [BINDING / name for name in ("build.gradle.kts", "settings.gradle.kts", "PackageREADME.md",
        "gradle/verification-metadata.xml")]
    for area in ("src", "consumer"):
        paths.extend(path for path in (BINDING / area).rglob("*") if path.is_file())
    paths.extend(ROOT / "bindings" / name for name in POLICIES.values())
    paths.extend(NOTICE_PATHS.values())
    paths.extend(ROOT / "artifact" / name for name in ("jvm_sdk_package.py", "bounded_process.py",
        "evidence_io.py", "deterministic_archive.py"))
    return {"native": source_fingerprints(ROOT, "sdk-020"),
            "jvm": {path.relative_to(ROOT).as_posix(): snapshot(path).sha256 for path in sorted(paths)}}


def run(argv: list[str], log: Path, cwd: Path, environment: dict, *, rejection: str | None = None) -> bytes:
    with contextlib.chdir(cwd):
        result = capture_output(argv, timeout_seconds=900, maximum_stdout_bytes=8 * 1024 * 1024,
            maximum_stderr_bytes=8 * 1024 * 1024, environment=environment)
    log.with_suffix(".stdout").write_bytes(result.stdout)
    log.with_suffix(".stderr").write_bytes(result.stderr)
    write_json(log.with_suffix(".json"), {"argv": argv, "cwd": str(cwd), "returncode": result.returncode,
                                        "expected_rejection": rejection})
    if rejection is None:
        require(result.returncode == 0, f"command failed ({result.returncode}); see {log}.stderr")
    else:
        require(result.returncode != 0 and rejection.encode() in result.stderr
                and b"INSTALLED_JAVA_MODULE_PATH_PASS" not in result.stdout,
                f"negative control did not reject as expected; see {log}.stderr")
    return result.stdout


def jar_files(path: Path) -> dict[str, bytes]:
    """Inspect bounded JAR contents in memory, without extracting any ZIP path."""
    with zipfile.ZipFile(io.BytesIO(snapshot(path).data)) as archive:
        rows = archive.infolist()
        require(len(rows) <= 1024 and sum(row.file_size for row in rows) <= 16 * 1024 * 1024,
                "JAR content limit exceeded")
        seen = set()
        result = {}
        for row in rows:
            name = row.filename.rstrip("/")
            parts = PurePosixPath(name).parts
            require(name and not name.startswith("/") and "\\" not in name and ":" not in name
                    and all(part not in (".", "..") for part in parts)
                    and PurePosixPath(name).as_posix() == name and name not in seen,
                    "JAR contains a duplicate or unsafe path")
            seen.add(name)
            require((row.external_attr >> 16) & 0o170000 != 0o120000, "JAR symlink is forbidden")
            if not row.is_dir():
                result[name] = archive.read(row)
        return result


def jar_manifest(data: bytes) -> dict[str, str]:
    # java.util.jar line continuation is a single leading space.
    lines = data.decode("utf-8").replace("\r\n", "\n").replace("\n ", "").strip().split("\n")
    result = {}
    for line in lines:
        name, separator, value = line.partition(": ")
        require(separator == ": " and name not in result, "JAR manifest is malformed")
        result[name] = value
    return result


def verify_maven(repository: Path) -> dict:
    directory = repository / MAVEN_PATH
    names = {f"{PREFIX}{suffix}" for suffix in (".jar", "-sources.jar", ".pom", ".module")}
    expected = {str(MAVEN_PATH / name) for name in names}
    expected |= {f"{name}.{algorithm}" for name in tuple(expected) for algorithm in ("md5", "sha1", "sha256", "sha512")}
    require(set(entries(repository)) == expected, "Maven candidate inventory differs")
    for name in names:
        data = snapshot(directory / name).data
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            require(snapshot(directory / f"{name}.{algorithm}").data.decode("ascii").strip()
                    == hashlib.new(algorithm, data).hexdigest(), "Maven checksum differs")
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    pom = ET.fromstring(snapshot(directory / f"{PREFIX}.pom").data)
    require([pom.findtext(f"m:{key}", namespaces=namespace) for key in ("groupId", "artifactId", "version")]
            == [GROUP, NAME, VERSION], "Maven coordinate differs")
    dependencies = pom.findall("m:dependencies/m:dependency", namespace)
    require(len(dependencies) == 1 and
        {child.tag.split("}")[-1]: child.text for child in dependencies[0]}
        == {"groupId": "org.jetbrains.kotlin", "artifactId": "kotlin-stdlib", "version": KOTLIN, "scope": "compile"},
        "Maven dependencies differ")
    require(not any(pom.find(f"m:{key}", namespace) is not None for key in
                    ("repositories", "pluginRepositories", "parent", "build", "profiles")), "Maven resolution override is forbidden")
    binary = jar_files(directory / f"{PREFIX}.jar")
    manifest = jar_manifest(binary["META-INF/MANIFEST.MF"])
    require(manifest == {"Manifest-Version": "1.0", "Automatic-Module-Name": MODULE,
        "Implementation-Title": "Q-Periapt Kotlin/JVM SDK", "Implementation-Version": VERSION,
        "QPeriapt-ABI": "2", "QPeriapt-SDK-Extension": "1"}, "JAR manifest identity differs")
    class_names = {name for name in binary if name.endswith(".class")}
    require({f"dev/qperiapt/{name}.class" for name in ("QPeriaptRuntime", "QPeriaptKey", "QPeriaptSecret",
            "QPeriaptExpert", "QPeriaptHybrid")} <= class_names, "JAR product classes are missing")
    require(set(binary) == class_names | set(NOTICE_PATHS) | {"META-INF/MANIFEST.MF", "META-INF/dev.qperiapt_q-periapt-hybrid.kotlin_module"},
            "JAR contains an unexpected resource or embedded native library")
    for name in class_names:
        require(name.startswith("dev/qperiapt/") and binary[name][:8] == b"\xca\xfe\xba\xbe\x00\x00\x00\x45",
                "JAR bytecode must be non-preview JDK 25 in the SDK namespace")
    source = jar_files(directory / f"{PREFIX}-sources.jar")
    source_root = BINDING / "src/main/kotlin"
    source_paths = {p.relative_to(source_root).as_posix(): p for p in source_root.rglob("*.kt")}
    require(set(source) == set(source_paths) | set(NOTICE_PATHS) | {"META-INF/MANIFEST.MF"}, "sources JAR inventory differs")
    for name, path in source_paths.items():
        require(source[name] == snapshot(path).data, "sources JAR does not match the source checkout")
    for name, path in NOTICE_PATHS.items():
        require(binary[name] == source[name] == snapshot(path).data, "JAR project license differs")
    module = parse_strict_json_bytes(snapshot(directory / f"{PREFIX}.module").data,
                                     label="JVM Gradle module metadata")
    require(module["formatVersion"] == "1.1" and module["component"] == {"group": GROUP, "module": NAME,
            "version": VERSION, "attributes": {"org.gradle.status": "release"}}, "Gradle module identity differs")
    require(module["createdBy"] == {"gradle": {"version": "9.2.1"}}, "Gradle module producer differs")
    require([row["name"] for row in module["variants"]] == ["apiElements", "runtimeElements", "sourcesElements"],
            "Gradle module variants differ")
    for row in module["variants"]:
        require("available-at" not in row, "Gradle module redirect is forbidden")
        require(set(row) == {"name", "attributes", "files"} | ({"dependencies"} if row["name"] != "sourcesElements" else set()),
                "Gradle module contains an unsupported resolution override")
        if row["name"] != "sourcesElements":
            require(row["attributes"]["org.gradle.jvm.version"] == 25 and row["dependencies"] == [
                {"group": "org.jetbrains.kotlin", "module": "kotlin-stdlib", "version": {"requires": KOTLIN}}],
                "Gradle JVM version or dependency differs")
        else:
            require("dependencies" not in row, "sources JAR must not add dependencies")
        require(len(row["files"]) == 1, "Gradle variant must resolve one JAR")
        file = row["files"][0]
        name = f"{PREFIX}{'-sources' if row['name'] == 'sourcesElements' else ''}.jar"
        data = snapshot(directory / name)
        require(file["name"] == file["url"] == name and file["size"] == data.size
                and all(file[algorithm] == hashlib.new(algorithm, data.data).hexdigest()
                        for algorithm in ("md5", "sha1", "sha256", "sha512")), "Gradle module artifact digest differs")
    return {"coordinate": COORDINATE, "classes": len(class_names), "jvm_version": 25,
            "jar_sha256": snapshot(directory / f"{PREFIX}.jar").sha256}


def verify_native(root: Path, manifest_sha: str, host: str) -> dict:
    manifest = verify_sealed_payload(root, manifest_sha)
    require(manifest["schema_version"] == 3 and manifest["version"] == VERSION and manifest["host"] == host,
            "native SDK identity differs")
    expected_sources = {**source_fingerprints(ROOT, "sdk-020"),
                        "third_party_rust_license_inventory": snapshot(root / INVENTORY_RELATIVE).sha256}
    require(manifest["source_inputs_sha256"] == expected_sources,
            "native SDK source inputs differ from the current checkout")
    platform = "macos" if host.endswith("apple-darwin") else "linux"
    contract = load_contract(ROOT / SDK_CONTRACT_PATH)
    identity = contract.document["package"]["platforms"][platform]
    abi = manifest["abi"]
    exports = hashlib.sha256(("\n".join(sorted(contract.export_names)) + "\n").encode()).hexdigest()
    require(abi == {"major": 2, "export_count": 43, "platform": platform, "runtime_identity": identity,
            "contract_path": SDK_CONTRACT_PATH, "embedded_contract_path": SDK_EMBEDDED_CONTRACT,
            "contract_sha256": contract.sha256, "exports_sha256": exports,
            "shared_filename": identity["shared_filename"], "static_filename": identity["static_filename"]},
            "native ABI 2 contract differs")
    require(snapshot(root / SDK_EMBEDDED_CONTRACT).data == snapshot(ROOT / SDK_CONTRACT_PATH).data,
            "embedded native contract differs")
    required = expected_profile_files(root, host, identity, "sdk-020") | {"MANIFEST.json", "SHA256SUMS"}
    require(set(entries(root)) == required, "native SDK file inventory differs")
    verify_header(contract, root / "include/qperiapt/abi2/q_periapt.h")
    verify_dynamic_library(contract, root / "lib" / identity["shared_filename"], platform)
    return manifest


def verify_package(root: Path, manifest_sha: str) -> dict:
    record = load_json_object_snapshot(root / CONTENTS, maximum=1024 * 1024, label="JVM SDK manifest")
    require(record.file.sha256 == manifest_sha, "JVM SDK pinned manifest differs")
    manifest = record.value
    require(set(manifest) == {"schema_version", "coordinate", "release_claim_eligible", "sources", "tools", "native", "files"}
            and manifest["schema_version"] == 1 and manifest["coordinate"] == COORDINATE
            and manifest["release_claim_eligible"] is False, "JVM candidate manifest identity differs")
    actual = entries(root)
    del actual[CONTENTS]
    require(actual == manifest["files"], "JVM SDK payload inventory or digest differs")
    native_name = f"q-periapt-c-abi2-{VERSION}-{manifest['native']['host']}.tar.gz"
    require(manifest["native"]["archive"] == native_name and "/" not in native_name and "\\" not in native_name,
            "JVM SDK native archive name differs")
    require(set(actual) == {f"maven/{name}" for name in entries(root / "maven")} | {"README.md", f"native/{native_name}"},
            "JVM SDK contains an unlisted package component")
    verify_maven(root / "maven")
    require(snapshot(root / "README.md").data == snapshot(BINDING / "PackageREADME.md").data,
            "JVM SDK package README differs")
    require(snapshot(root / "native" / manifest["native"]["archive"]).sha256 == manifest["native"]["sha256"],
            "JVM SDK native archive differs")
    return manifest


def pin_consumer_dependencies(consumer: Path, repository: Path) -> None:
    # Preserve every existing strict upstream checksum; append this candidate's
    # exact local artifact hashes. No trust-all, ignored or changing dependency.
    tree = ET.fromstring(snapshot(BINDING / "gradle/verification-metadata.xml").data)
    namespace = tree.tag.split("}")[0] + "}"
    components = tree.find(f"{namespace}components")
    require(components is not None, "Gradle dependency pins are missing")
    require(not any(row.get("group") == GROUP for row in components), "candidate coordinate is already pinned")
    component = ET.SubElement(components, f"{namespace}component", {"group": GROUP, "name": NAME, "version": VERSION})
    for suffix in (".jar", ".pom", ".module"):
        name = f"{PREFIX}{suffix}"
        artifact = ET.SubElement(component, f"{namespace}artifact", {"name": name})
        ET.SubElement(artifact, f"{namespace}sha256", {"value": snapshot(repository / MAVEN_PATH / name).sha256,
                                                     "origin": "pinned local SDK candidate"})
    ET.register_namespace("", namespace[1:-1])
    path = consumer / "gradle/verification-metadata.xml"
    path.parent.mkdir()
    with path.open("xb") as stream:
        ET.ElementTree(tree).write(stream, encoding="utf-8", xml_declaration=True)


def consumer_fixtures(consumer: Path) -> None:
    directory = consumer / "fixtures"
    directory.mkdir()
    root = None
    for label, name in POLICIES.items():
        value = parse_strict_json_bytes(snapshot(ROOT / "bindings" / name).data, label=f"policy fixture {name}")
        key = bytes.fromhex(value["verification_key"])
        require(root is None or root == key, "consumer policy roots differ")
        root = key
        (directory / f"{label}.policy").write_bytes(value["policy_toml"].encode())
        (directory / f"{label}.signature").write_bytes(bytes.fromhex(value["signature"]))
        if label == "enabled":
            (directory / "future-state").write_bytes((value["policy_version"] + 1).to_bytes(4, "little")
                                                       + bytes.fromhex(value["policy_digest"]))
    (directory / "root").write_bytes(root)


def build(args: argparse.Namespace) -> dict:
    output = args.output.absolute()
    require(not output.exists(), "JVM SDK output must be a fresh directory")
    require(SHA.fullmatch(args.native_sha256) is not None and SHA.fullmatch(args.native_manifest_sha256) is not None,
            "native archive and manifest require pinned SHA-256 digests")
    require(shutil.disk_usage(ROOT).free >= 1024 ** 3, "JVM SDK build needs at least 1 GiB free")
    require(tomllib.loads(snapshot(ROOT / "Cargo.toml").data.decode())["workspace"]["package"]["version"] == VERSION,
            "JVM SDK version differs from workspace")
    env = dict(os.environ)
    for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "GRADLE_OPTS", "CLASSPATH",
                 "DYLD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "LD_LIBRARY_PATH", "LD_PRELOAD"):
        env.pop(name, None)
    java_home = Path(env.get("JAVA_HOME", ""))
    require(java_home.is_absolute(), "select an absolute JDK 25 JAVA_HOME for this invocation")
    java = str(java_home / "bin/java")
    require(Path(shutil.which("java") or "").resolve() == Path(java).resolve(), "PATH java must match JAVA_HOME")
    output.mkdir(parents=True)
    before = sources()
    write_json(output / "sources-before.json", before)
    versions = {}
    for name, command in {"java": [java, "--version"], "javac": [str(java_home / "bin/javac"), "--version"],
                          "gradle": [args.gradle, "--version"], "rustc": ["rustc", "-vV"]}.items():
        versions[name] = run(command, output / f"version-{name}", ROOT, env).decode().strip()
    require(re.match(r"(?:openjdk|java) 25(?:[ .])", versions["java"]) is not None
            and versions["javac"].startswith("javac 25"), "JVM SDK candidate requires JDK 25")
    require("\nGradle 9.2.1\n" in versions["gradle"], "JVM SDK candidate requires Gradle 9.2.1")
    host = re.search(r"^host: (.+)$", versions["rustc"], re.MULTILINE).group(1)
    require(host in ("aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"),
            "JVM SDK package qualification supports 64-bit macOS and GNU/Linux hosts")
    native_name = f"q-periapt-c-abi2-{VERSION}-{host}"
    native_archive = args.native_archive.resolve(strict=True)
    native_audit = extract_tar_gz(native_archive, output / "native-build", root_name=native_name,
                                 expected_sha256=args.native_sha256)
    native_root = output / "native-build" / native_name
    native = verify_native(native_root, args.native_manifest_sha256, host)
    library_name = native["abi"]["shared_filename"]
    command = [args.gradle, "--no-daemon", "--warning-mode", "fail", "--dependency-verification", "strict"]
    if args.offline:
        command.append("--offline")
    staged = output / "staged-maven"
    run([*command, "--project-dir", str(BINDING), "--rerun-tasks", "test", "publishSdkPublicationToSdkStagingRepository",
         f"-Pqperiapt.stagingRepository={staged}", f"-Pqperiapt.lib={native_root / 'lib' / library_name}"],
        output / "gradle-package", ROOT, env)
    results = [ET.fromstring(snapshot(path).data) for path in (BINDING / "build/test-results/test").glob("TEST-*.xml")]
    require(results and sum(int(row.attrib["tests"]) for row in results) >= 17
            and all(all(int(row.attrib[key]) == 0 for key in ("failures", "errors", "skipped")) for row in results),
            "JVM source tests are incomplete or failed")
    for path in (BINDING / "build/test-results/test").glob("TEST-*.xml"):
        copy(path, output / "source-test-results" / path.name)
    package_name = f"q-periapt-jvm-{VERSION}-{host}"
    package = output / package_name
    package.mkdir()
    # Fixed versions need no time-varying Maven latest/release metadata.
    for path in (staged / MAVEN_PATH).iterdir():
        copy(path, package / "maven" / MAVEN_PATH / path.name)
    maven = verify_maven(package / "maven")
    copy(native_archive, package / "native" / f"{native_name}.tar.gz")
    copy(BINDING / "PackageREADME.md", package / "README.md")
    native_record = {"archive": f"{native_name}.tar.gz", "sha256": args.native_sha256,
        "manifest_sha256": args.native_manifest_sha256, "host": host, "mtime": native_audit.mtime,
        "library": library_name, "library_sha256": snapshot(native_root / "lib" / library_name).sha256,
        "diagnostic_only": native["diagnostic_only"]}
    write_json(package / CONTENTS, {"schema_version": 1, "coordinate": COORDINATE, "release_claim_eligible": False,
        "sources": before, "tools": versions, "native": native_record, "files": entries(package)})
    manifest_sha = snapshot(package / CONTENTS).sha256
    verify_package(package, manifest_sha)
    archive = output / f"{package_name}.tar.gz"
    create_tar_gz(package, archive, root_name=package_name, mtime=MTIME)
    archive_sha = snapshot(archive).sha256
    consumer = Path(tempfile.mkdtemp(prefix="qperiapt-jvm-install-")).resolve()
    require(not consumer.is_relative_to(ROOT), "JVM installed consumer must be outside the checkout")
    write_json(output / "consumer-location.json", {"path": str(consumer)})
    extract_tar_gz(archive, consumer / "sdk", root_name=package_name, expected_sha256=archive_sha, mtime=MTIME)
    installed = consumer / "sdk" / package_name
    verify_package(installed, manifest_sha)
    extract_tar_gz(installed / "native" / native_record["archive"], consumer / "native", root_name=native_name,
                  expected_sha256=args.native_sha256, mtime=native_audit.mtime)
    installed_native = consumer / "native" / native_name
    verify_native(installed_native, args.native_manifest_sha256, host)
    for relative in entries(BINDING / "consumer"):
        copy(BINDING / "consumer" / relative, consumer / relative)
    consumer_fixtures(consumer)
    pin_consumer_dependencies(consumer, installed / "maven")
    installed_jar = installed / "maven" / MAVEN_PATH / f"{PREFIX}.jar"
    installed_lib = installed_native / "lib" / library_name
    kotlin_output = run([*command, "--project-dir", str(consumer), "verifyInstalled",
        f"-PsdkRepository={installed / 'maven'}", f"-PsdkLibrary={installed_lib}", f"-PsdkJar={installed_jar}"],
        output / "installed-kotlin", consumer, env)
    for marker in ("OWNER_POLICY_KDF", "CANCELLATION_CONCURRENCY", "TAMPER_ROLLBACK"):
        require(f"INSTALLED_KOTLIN_{marker}_PASS".encode() in kotlin_output, "installed Kotlin result is missing")
    resolutions = []
    for line in snapshot(consumer / "build/runtime.tsv").data.decode().splitlines():
        coordinate, path, digest = line.split("\t")
        file = Path(path)
        require(not file.is_relative_to(ROOT) and snapshot(file).sha256 == digest,
                "Maven consumer dependency points into checkout or changed bytes")
        resolutions.append({"coordinate": coordinate, "path": path, "sha256": digest})
    require({row["coordinate"] for row in resolutions} == {COORDINATE, f"org.jetbrains.kotlin:kotlin-stdlib:{KOTLIN}",
                                                           "org.jetbrains:annotations:13.0"}, "runtime dependency closure differs")
    require(next(row["sha256"] for row in resolutions if row["coordinate"] == COORDINATE) == maven["jar_sha256"],
            "resolved SDK JAR differs from candidate")
    java_command = [java, "--illegal-native-access=deny", "--module-path", os.pathsep.join(row["path"] for row in resolutions),
        "--add-modules", f"{MODULE},kotlin.stdlib", "-cp", str(consumer / "build/classes/java/main"),
        f"-Dsdk.fixtures={consumer / 'fixtures'}", f"-Dsdk.expectedJar={installed_jar}"]
    granted = [*java_command, f"--enable-native-access={MODULE}"]
    passed = run([*granted, f"-Dqperiapt.lib={installed_lib}", "consumer.LoaderProbe"],
                 output / "installed-java-module", consumer, env)
    require(b"INSTALLED_JAVA_MODULE_PATH_PASS" in passed, "installed Java module result is missing")
    negatives = {
        "missing-property": (granted, "qperiapt.lib must be set"),
        "relative-path": ([*granted, "-Dqperiapt.lib=relative-library"], "qperiapt.lib must be an absolute path"),
        "missing-library": ([*granted, f"-Dqperiapt.lib={consumer / 'missing-library'}"], "does not name a regular file"),
        "directory-library": ([*granted, f"-Dqperiapt.lib={consumer / 'fixtures'}"], "does not name a regular file"),
        "denied-native-access": ([*java_command, f"-Dqperiapt.lib={installed_lib}"], "IllegalCallerException"),
    }
    incompatible = consumer / "incompatible.c"
    incompatible.write_text("int deliberately_incompatible(void);\nint deliberately_incompatible(void) { return 0; }\n")
    bad_lib = consumer / library_name
    run(["cc", "-Wall", "-Wextra", "-Werror", "-pedantic", "-dynamiclib" if host.endswith("apple-darwin") else "-shared",
         "-fPIC", str(incompatible), "-o", str(bad_lib)], output / "incompatible-library", consumer, env)
    negatives["missing-symbol"] = ([*granted, f"-Dqperiapt.lib={bad_lib}"], "NoSuchElementException")
    for name, (arguments, rejection) in negatives.items():
        run([*arguments, "consumer.LoaderProbe"], output / f"negative-{name}", consumer, env, rejection=rejection)
    verify_package(installed, manifest_sha)
    verify_native(installed_native, args.native_manifest_sha256, host)
    require(snapshot(archive).sha256 == archive_sha and snapshot(native_archive).sha256 == args.native_sha256,
            "JVM SDK or native input archive changed during consumption")
    after = sources()
    write_json(output / "sources-after.json", after)
    require(before == after, "JVM SDK sources changed during packaging")
    report = {"coordinate": COORDINATE, "host": host, "archive": str(archive), "sha256": archive_sha,
        "manifest_sha256": manifest_sha, "native": native_record, "installed": str(installed),
        "maven": maven, "resolved_runtime": resolutions, "sources_unchanged": True,
        "source_tests": sum(int(row.attrib["tests"]) for row in results),
        "installed_kotlin": "passed", "java_module_path": "passed", "negative_controls": sorted(negatives),
        "release_claim_eligible": False}
    write_json(output / "INSTALLED_CONSUMER.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-archive", type=Path, required=True)
    parser.add_argument("--native-sha256", required=True)
    parser.add_argument("--native-manifest-sha256", required=True)
    parser.add_argument("--gradle", default="gradle")
    parser.add_argument("--offline", action="store_true")
    print(json.dumps(build(parser.parse_args()), indent=2))


if __name__ == "__main__":
    main()
