#!/usr/bin/env python3
"""Stage the Android Maven SDK and build independent minified APKs; no device or public upload."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile

import android_elf as android
from android_agp_consumer import (_apk_entries, verify_release_manifest_dump, verify_r8_configuration,
                                  DEFAULT_PROGUARD_SHA256)
from android_agp_build import collector_gradle_home, normalized
from bounded_process import capture_output
from claim_ledger import canonical_tree_digest, repository_paths
from deterministic_archive import create_tar_gz, extract_tar_gz
from evidence_io import fresh_output_directory, load_json_object_snapshot, read_regular_snapshot

ROOT = Path(__file__).resolve().parent.parent
NAME = "q-periapt-android"
VERSION = "0.2.0"
COORDINATE = f"dev.qperiapt:{NAME}:{VERSION}"
MAVEN_PATH = Path("dev/qperiapt") / NAME / VERSION
PREFIX = f"{NAME}-{VERSION}"
CONTENTS = "PACKAGE_CONTENTS.json"
FIXTURES = ("signed-policy-vectors.json", "sdk-policy-revocation-vectors.json", "sdk-policy-update-vectors.json")
SMOKE = ROOT / "bindings/android/smoke"
PROFILE = "sdk-020"


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def snapshot(path: Path):
    return read_regular_snapshot(path, maximum=android.MAX_ARCHIVE_BYTES, label="Android SDK package input")


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(snapshot(source).data)


def entries(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "Android SDK package contains a symlink")
        if not path.is_dir():
            item = snapshot(path)
            result[path.relative_to(root).as_posix()] = {"bytes": item.size, "sha256": item.sha256}
    return result


def run(args: list[str], log: Path, cwd: Path, env: dict) -> bytes:
    with contextlib.chdir(cwd):
        result = capture_output(args, timeout_seconds=900, maximum_stdout_bytes=16 * 1024 * 1024,
                                maximum_stderr_bytes=8 * 1024 * 1024, environment=env)
    log.with_suffix(".stdout").write_bytes(result.stdout)
    log.with_suffix(".stderr").write_bytes(result.stderr)
    write_json(log.with_suffix(".json"), {"argv": args, "cwd": str(cwd), "returncode": result.returncode})
    require(result.returncode == 0, f"command failed ({result.returncode}); see {log}.stderr")
    return result.stdout


def verify_maven(repository: Path, aar_sha256: str) -> None:
    directory = repository / MAVEN_PATH
    artifacts = {f"{PREFIX}{suffix}" for suffix in (".aar", ".pom", "-sources.jar")}
    names = artifacts | {f"{name}.{algorithm}" for name in artifacts for algorithm in ("md5", "sha1", "sha256", "sha512")}
    require(set(entries(repository)) == {(MAVEN_PATH / name).as_posix() for name in names}, "Android Maven inventory differs")
    for name in artifacts:
        data = snapshot(directory / name).data
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            require(snapshot(directory / f"{name}.{algorithm}").data.decode("ascii").strip()
                    == hashlib.new(algorithm, data).hexdigest(), "Android Maven checksum differs")
    require(snapshot(directory / f"{PREFIX}.aar").sha256 == aar_sha256, "Maven AAR differs from selected native package")
    pom = ET.fromstring(snapshot(directory / f"{PREFIX}.pom").data)
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    require([pom.findtext(f"m:{name}", namespaces=ns) for name in ("groupId", "artifactId", "version", "packaging")]
            == ["dev.qperiapt", NAME, VERSION, "aar"], "Android Maven coordinate or packaging differs")
    require(not any(pom.find(f"m:{name}", ns) is not None for name in
                    ("dependencies", "repositories", "pluginRepositories", "profiles", "parent", "build")),
            "Android Maven POM adds a dependency or resolution override")
    sources = ROOT / "bindings/android/src/main/java"
    expected = {p.relative_to(sources).as_posix(): snapshot(p).data for p in sources.rglob("*.java")}
    expected.update({f"META-INF/licenses/{name}": snapshot(ROOT / "LICENSES" / name).data for name in ("Apache-2.0.txt", "MIT.txt")})
    expected["META-INF/MANIFEST.MF"] = b"Manifest-Version: 1.0\r\n\r\n"
    with zipfile.ZipFile(io.BytesIO(snapshot(directory / f"{PREFIX}-sources.jar").data)) as archive:
        # Gradle sources JARs contain directory records; the canonical AAR reader
        # deliberately forbids those. Inspect this bounded JAR without extraction.
        rows = archive.infolist()
        require(len(rows) <= 256 and sum(row.file_size for row in rows) <= 16 * 1024 * 1024,
                "Android sources JAR exceeds its content limit")
        actual, seen = {}, set()
        directories = {parent.as_posix() for name in expected for parent in Path(name).parents if parent.as_posix() != "."}
        for row in rows:
            name = row.filename.rstrip("/") if row.is_dir() else row.filename
            android._validate_zip_name(name, label="Android sources JAR")
            require(name not in seen and (row.external_attr >> 16) & 0o170000 != 0o120000,
                    "Android sources JAR has a duplicate or symlink")
            seen.add(name)
            if row.is_dir():
                require(name in directories and row.file_size == 0, "Android sources JAR has an unexpected directory")
            else:
                actual[name] = archive.read(row)
    require(actual == expected, "Android sources JAR or project notices differ")


def verify_bundle(package: Path, manifest_sha256: str) -> dict:
    snapshot_json = load_json_object_snapshot(package / CONTENTS, maximum=1024 * 1024, label="Android SDK bundle manifest")
    require(snapshot_json.file.sha256 == manifest_sha256, "Android SDK pinned manifest differs")
    manifest = snapshot_json.value
    require(set(manifest) == {"schema", "coordinate", "source_tree_sha256", "aar_sha256", "aar_manifest_sha256", "files", "release_claim_eligible"}
            and manifest["schema"] == 1 and manifest["coordinate"] == COORDINATE
            and manifest["release_claim_eligible"] is False, "Android SDK candidate identity differs")
    actual = entries(package)
    del actual[CONTENTS]
    require(actual == manifest["files"], "Android SDK bundle inventory or digest differs")
    require(set(actual) == {f"maven/{name}" for name in entries(package / "maven")} | {"MANIFEST.json", "README.md"},
            "Android SDK bundle component set differs")
    verify_maven(package / "maven", manifest["aar_sha256"])
    require(snapshot(package / "MANIFEST.json").sha256 == manifest["aar_manifest_sha256"], "Android AAR manifest differs")
    require(snapshot(package / "README.md").data == snapshot(ROOT / "bindings/android/PackageREADME.md").data,
            "Android package README differs")
    return manifest


def inspect_apk(apk: Path, aar_entries: dict, output: Path, sdk: Path, env: dict, variant: str) -> dict:
    contents = _apk_entries(apk)
    native = {name: data for name, data in contents.items() if name.endswith(".so")}
    expected = {name.replace("jni/", "lib/", 1): data for name, data in aar_entries.items() if name.startswith("jni/")}
    require(native == expected, "APK native library set or bytes differ from the selected AAR")
    with zipfile.ZipFile(io.BytesIO(snapshot(apk).data)) as archive:
        require(all(archive.getinfo(name).compress_type == zipfile.ZIP_STORED for name in expected),
                "APK native libraries must remain uncompressed for in-APK loading")
    build_tools = sdk / "build-tools/36.0.0"
    dump_parts = []
    dex_names = sorted(name for name in contents if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex", name))
    require(dex_names, "APK has no DEX")
    for name in dex_names:
        path = output / f"{variant}-{name}"
        path.write_bytes(contents[name])
        dump_parts.append(run([str(build_tools / "dexdump"), str(path)], output / f"{variant}-dump-{name.replace('.', '-')}", ROOT, env))
    dump = b"\n".join(dump_parts)
    android.verify_minimal_consumer_dump(dump.decode(), package_version=VERSION)
    manifest = run([str(build_tools / "aapt2"), "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)],
                   output / f"{variant}-apk-manifest", ROOT, env)
    verify_release_manifest_dump(manifest.decode())
    extraction = re.findall(r"android:extractNativeLibs\([^)]*\)=([^\n]+)", manifest.decode())
    require(len(extraction) == 1 and extraction[0].strip() in {"false", "(type 0x12)0x0"},
            "APK must explicitly disable legacy native extraction")
    run([str(build_tools / "zipalign"), "-c", "-P", "16", "-v", "4", str(apk)], output / f"{variant}-zipalign", ROOT, env)
    assets = {name for name in contents if name.startswith("assets/")}
    require(assets == ({"assets/" + name for name in FIXTURES} if variant == "full" else set()),
            "APK fixture assets differ from its workload")
    return {"apk": str(apk), "sha256": snapshot(apk).sha256, "bytes": snapshot(apk).size,
            "native_libraries": {name: hashlib.sha256(data).hexdigest() for name, data in native.items()},
            "native_unchanged": True, "jni_methods": 26, "page_alignment": 16384,
            "minified": True, "debuggable": False, "signed": False, "runtime_executed": False}


def build(args: argparse.Namespace) -> dict:
    output = fresh_output_directory(args.output, within=ROOT / "target", label="Android SDK output")
    require(all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in (args.aar_sha256, args.manifest_sha256)),
            "Android SDK requires pinned AAR and manifest SHA-256")
    require(shutil.disk_usage(ROOT).free >= 1024 ** 3, "Android SDK packaging needs at least 1 GiB free")
    sdk = args.sdk.resolve(strict=True)
    ndk = sdk / "ndk/29.0.14206865"
    require(android.verify_ndk_r29(ndk) == "29.0.14206865", "Android SDK requires pinned NDK r29")
    toolchain = android.find_ndk_toolchain(ndk)
    aar, aar_manifest = args.aar.absolute(), args.manifest.absolute()
    verified = android.verify_aar(aar, llvm_nm=toolchain / "bin/llvm-nm", llvm_readelf=toolchain / "bin/llvm-readelf",
        manifest=aar_manifest, expected_aar_sha256=args.aar_sha256, expected_manifest_sha256=args.manifest_sha256,
        source_root=ROOT, profile=PROFILE, forbidden_text=(str(ROOT),))
    before = canonical_tree_digest(ROOT, repository_paths(ROOT))
    require(verified["source_tree_sha256"] == before, "Android AAR source tree differs before packaging")
    output.mkdir(parents=True)
    env = dict(os.environ)
    for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "GRADLE_OPTS", "CLASSPATH"):
        env.pop(name, None)
    java_home = Path(env.get("JAVA_HOME", ""))
    require(java_home.is_absolute() and java_home.resolve() == java_home, "select the canonical JDK 21 JAVA_HOME")
    gradle_home = collector_gradle_home()
    require(not any((gradle_home / name).exists() for name in ("init.gradle", "init.gradle.kts"))
            and (not (gradle_home / "init.d").exists() or not any((gradle_home / "init.d").iterdir())),
            "Android SDK qualification does not accept global Gradle init scripts")
    env["GRADLE_USER_HOME"] = str(gradle_home)
    env["ANDROID_HOME"] = str(sdk)
    version = run([str(java_home / "bin/java"), "--version"], output / "java-version", ROOT, env).decode()
    require(version.startswith("openjdk 21.") or version.startswith("java 21."), "Android SDK qualification requires JDK 21")
    gradle_version = run([args.gradle, "--version"], output / "gradle-version", ROOT, env).decode()
    require("\nGradle 9.7.1\n" in gradle_version, "Android SDK qualification requires Gradle 9.7.1")
    common = [args.gradle, "--no-daemon", "--warning-mode", "fail"]
    if args.offline:
        common.append("--offline")
    run([*common, "--project-dir", str(ROOT / "bindings/android/publish"), "--project-cache-dir", str(output / "publisher-cache"),
         "publishSdkPublicationToSdkStagingRepository", f"-PqperiaptBuildDirectory={output / 'publisher-build'}",
         f"-PqperiaptStagingRepository={output / 'staged-maven'}", f"-PqperiaptAar={aar}", f"-PqperiaptAarSha256={args.aar_sha256}"],
        output / "maven-publication", ROOT, env)
    package_name = f"q-periapt-android-sdk-{VERSION}"
    package = output / package_name
    package.mkdir()
    for path in (output / "staged-maven" / MAVEN_PATH).iterdir():
        copy(path, package / "maven" / MAVEN_PATH / path.name)
    verify_maven(package / "maven", args.aar_sha256)
    copy(aar_manifest, package / "MANIFEST.json")
    copy(ROOT / "bindings/android/PackageREADME.md", package / "README.md")
    write_json(package / CONTENTS, {"schema": 1, "coordinate": COORDINATE, "source_tree_sha256": before,
        "aar_sha256": args.aar_sha256, "aar_manifest_sha256": args.manifest_sha256,
        "files": entries(package), "release_claim_eligible": False})
    manifest_sha = snapshot(package / CONTENTS).sha256
    verify_bundle(package, manifest_sha)
    archive = output / f"{package_name}.tar.gz"
    create_tar_gz(package, archive, root_name=package_name, mtime=946684800)
    archive_sha = snapshot(archive).sha256
    consumer = Path(tempfile.mkdtemp(prefix="qperiapt-android-sdk-install-")).resolve()
    require(not consumer.is_relative_to(ROOT), "Android Maven consumer must be outside the checkout")
    write_json(output / "consumer-location.json", {"path": str(consumer)})
    extract_tar_gz(archive, consumer / "sdk", root_name=package_name, mtime=946684800, expected_sha256=archive_sha)
    installed = consumer / "sdk" / package_name
    verify_bundle(installed, manifest_sha)
    installed_aar = installed / "maven" / MAVEN_PATH / f"{PREFIX}.aar"
    installed_entries, _ = android.audit_aar(installed_aar, profile=PROFILE)
    for name in entries(ROOT / "artifact/android-agp-consumer"):
        copy(ROOT / "artifact/android-agp-consumer" / name, consumer / "project" / name)
    for area in ("common", "sdk", "sdk-minimal"):
        for name in entries(SMOKE / area):
            copy(SMOKE / area / name, consumer / "smoke" / area / name)
    for name in FIXTURES:
        copy(ROOT / "bindings" / name, consumer / "fixtures" / name)
    consumers = {}
    for variant in ("full", "minimal"):
        build_output = run([*common, "--project-dir", str(consumer / "project"), ":app:captureSdkResolution", f":app:assemble{variant.title()}Release",
             "-PqperiaptSdkMaven=true", f"-PqperiaptVariant={variant}", f"-PqperiaptMavenRepository={installed / 'maven'}",
             f"-PqperiaptSmokeRoot={consumer / 'smoke'}", f"-PqperiaptFixtureAssets={consumer / 'fixtures'}",
             f"-PqperiaptInputCapture={output / (variant + '-inputs.txt')}", f"-PqperiaptJvmCapture={output / (variant + '-jvm.json')}",
             f"-PqperiaptResolutionCapture={output / (variant + '-resolution.json')}"], output / variant, consumer, env)
        require(f"> Task :app:minify{variant.title()}ReleaseWithR8".encode() in build_output,
                "AGP did not report the required R8 task")
        resolution = load_json_object_snapshot(output / f"{variant}-resolution.json", maximum=65536, label="resolved AAR").value
        require(resolution["coordinate"] == COORDINATE and resolution["sha256"] == args.aar_sha256
                and Path(resolution["path"]).samefile(installed_aar), "AGP did not resolve the installed Maven AAR")
        for dependency in resolution["runtime_dependencies"]:
            require(snapshot(Path(dependency["path"])).sha256 == dependency["sha256"], "resolved runtime dependency changed")
        inputs = snapshot(output / f"{variant}-inputs.txt").data.decode().splitlines()
        selected = "sdk" if variant == "full" else "sdk-minimal"
        expected_inputs = {str((consumer / "smoke" / area / name).resolve()) for area in ("common", selected)
                           for name in entries(SMOKE / area) if name.endswith(".java")}
        expected_inputs.add(str(consumer / "project/app/src/main/java/dev/qperiapt/androidsmoke/QPeriaptResultInstrumentation.java"))
        require(set(inputs) == expected_inputs and len(inputs) == len(expected_inputs), "AGP compiler source inputs differ")
        jvm = load_json_object_snapshot(output / f"{variant}-jvm.json", maximum=65536, label="compile JVM").value
        require(jvm["java_home"] == jvm["compiler_java_home"] == str(java_home)
                and jvm["compiler_fork"] is False and jvm["java_version"].startswith("21."), "AGP compile JVM differs")
        apk = consumer / f"project/app/build/outputs/apk/{variant}/release/app-{variant}-release-unsigned.apk"
        mapping = consumer / f"project/app/build/outputs/mapping/{variant}Release"
        default = ROOT / "artifact/fixtures/android-agp-proguard-9.4.0.txt"
        require(snapshot(default).sha256 == DEFAULT_PROGUARD_SHA256, "pinned AGP default rules differ")
        aapt = consumer / f"project/app/build/intermediates/aapt_proguard_file/{variant}Release/process{variant.title()}ReleaseResources/aapt_rules.txt"
        rules = normalized(snapshot(mapping / "configuration.txt").data,
                           {"PROJECT": consumer / "project", "GRADLE_HOME": gradle_home})
        verify_r8_configuration(rules.decode(), default=snapshot(default).data.decode(),
            manifest=snapshot(aapt).data.decode(), aar_rules=installed_entries["proguard.txt"].decode(), package_version=VERSION)
        (output / f"{variant}-normalized-r8.txt").write_bytes(rules)
        consumers[variant] = inspect_apk(apk, installed_entries, output, sdk, env, variant)
        copy(apk, output / f"{variant}-unsigned.apk")
        for name in ("configuration.txt", "mapping.txt", "usage.txt"):
            path = consumer / f"project/app/build/outputs/mapping/{variant}Release/{name}"
            copy(path, output / f"{variant}-r8-{name}")
    verify_bundle(installed, manifest_sha)
    require(snapshot(archive).sha256 == archive_sha and snapshot(aar).sha256 == args.aar_sha256
            and snapshot(aar_manifest).sha256 == args.manifest_sha256, "selected Android package changed during consumption")
    after = canonical_tree_digest(ROOT, repository_paths(ROOT))
    require(before == after, "Android SDK source tree changed during packaging")
    report = {"coordinate": COORDINATE, "archive": str(archive), "sha256": archive_sha, "manifest_sha256": manifest_sha,
        "aar_sha256": args.aar_sha256, "aar_manifest_sha256": args.manifest_sha256, "installed": str(installed),
        "source_tree_sha256": before, "sources_unchanged": True, "native_abi_major": 2, "c_exports": 50, "jni_methods": 26,
        "consumers": consumers, "agp_version": "9.4.1", "gradle_version": "9.7.1", "runtime_executed": False,
        "public_registry_publication": False, "release_claim_eligible": False}
    write_json(output / "INSTALLED_CONSUMERS.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--aar", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--aar-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--gradle", default="gradle")
    parser.add_argument("--offline", action="store_true")
    print(json.dumps(build(parser.parse_args()), indent=2))


if __name__ == "__main__":
    main()
