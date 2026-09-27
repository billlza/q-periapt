"""Exact-AAR AGP Release consumer evidence; no device management lives here."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import zipfile
import tempfile
from typing import Any

import android_device_proof as runtime
import android_elf
import android_runtime_state as runtime_state
from android_runtime_profile import DEFAULT_RUNTIME_PROFILE, RUNTIME_PROFILES
from bounded_process import BoundedProcessError, capture_output
from evidence_io import load_json_object_snapshot, read_regular_snapshot


from android_agp_consumer_contract import (
    AGP_VERSION,
    GRADLE_VERSION,
    ALL_PROFILES,
    SDK_PROFILES,
    RUN_ID,
    SHA256,
    AndroidAgpConsumerError,
    require,
    profile_spec,
    runtime_target,
    validate_profile_projection,
)

INSTRUMENTATION = "dev.qperiapt.androidsmoke/.QPeriaptResultInstrumentation"
INSTRUMENTATION_DESCRIPTOR = "Ldev/qperiapt/androidsmoke/QPeriaptResultInstrumentation;"
BUILD_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "profile",
        "status",
        "source_commit",
        "source_tree_sha256",
        "aar_sha256",
        "aar_manifest_sha256",
        "agp_version",
        "gradle_version",
        "minify_enabled",
        "debuggable",
        "app_q_keep_rules",
        "files",
        "dex_sha256",
        "source_files",
        "compiled_application_sources",
        "tools",
        "diagnostics",
        "signing_input",
    }
)
BUILD_FILE_NAMES = {
    "agp_apk": "agp-unsigned.apk",
    "apk": "consumer-unsigned.apk",
    "dexdump": "dexdump.txt",
    "manifest_dump": "manifest-dump.txt",
    "mapping": "mapping.txt",
    "r8_configuration": "r8-configuration.txt",
    "gradle_log": "gradle-build.log",
    "gradle_version": "gradle-version.txt",
    "build_jvm": "build-jvm.json",
    "compilation_inputs": "compilation-inputs.txt",
    "default_proguard": "default-proguard.txt",
    "manifest_proguard": "manifest-proguard.txt",
}
CONSUMER_FIELDS = frozenset(
    {"profile", "build_receipt", "instrumentation_output", "instrumentation"}
)
RECORD_FIELDS = frozenset({"path", "sha256", "bytes"})
MAX_JSON = 16 * 1024 * 1024
MAX_TEXT = 16 * 1024 * 1024
MAX_APK = 256 * 1024 * 1024
APP_METADATA_ENTRY = "META-INF/com/android/build/gradle/app-metadata.properties"
APP_METADATA_CONTENT = b"appMetadataVersion=1.1\nandroidGradlePluginVersion=9.4.0\n"
VCS_METADATA_ENTRY = "META-INF/version-control-info.textproto"
SIGNING_INPUT_POLICY = "agp-9.4-v1-signing-input-v1"
V1_SIGNATURE_ENTRIES = frozenset(
    {"META-INF/QPERIAPT.SF", "META-INF/QPERIAPT.RSA", "META-INF/MANIFEST.MF"}
)


DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")
TEMPLATE_ROOT = "artifact/android-agp-consumer"
SMOKE_ROOT = "bindings/android/smoke"
JAVA_PACKAGE = "dev/qperiapt/androidsmoke"
INSTRUMENTATION_SOURCE = (
    TEMPLATE_ROOT
    + "/app/src/main/java/"
    + JAVA_PACKAGE
    + "/QPeriaptResultInstrumentation.java"
)
TEMPLATE_FILES = tuple(
    TEMPLATE_ROOT + "/" + name
    for name in (
        "gradlew",
        "gradle/wrapper/gradle-wrapper.jar",
        "gradle/wrapper/gradle-wrapper.properties",
        "settings.gradle.kts",
        "build.gradle.kts",
        "gradle.properties",
        "app/build.gradle.kts",
        "app/src/main/AndroidManifest.xml",
        "app/src/main/java/" + JAVA_PACKAGE + "/QPeriaptResultInstrumentation.java",
    )
)
NORMALIZATION_POLICY = "known-path-roots-v1"
# Exact optimized default extracted by the pinned AGP 9.4.0 distribution.
# A changed SDK default needs explicit review; it cannot add application Q rules.
DEFAULT_PROGUARD_SHA256 = (
    "0c2037f6eca949ee82dad4ade741ad1e3fcb7a5d98e4b31d08be89b26cf0d7d0"
)
NORMALIZED_FILES = frozenset(
    {
        "gradle-version.txt",
        "build-jvm.json",
        "gradle-build.log",
        "mapping.txt",
        "r8-configuration.txt",
        "dexdump.txt",
        "manifest-dump.txt",
        "compilation-inputs.txt",
        "manifest-proguard.txt",
    }
)
RAW_DIAGNOSTIC_FILES = NORMALIZED_FILES - {"manifest-proguard.txt"}
BUILD_JVM_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "task",
        "java_home",
        "java_version",
        "java_runtime_version",
        "java_vendor",
        "compiler_java_home",
        "compiler_fork",
        "java_vm_vendor",
        "java_vm_version",
    }
)


@dataclasses.dataclass(frozen=True)
class GradleJvm:
    version: str
    vendor_description: str
    java_home: str


def parse_gradle_jvm(text: str, *, normalized: bool) -> GradleJvm:
    """Read the selected JVM from the pinned wrapper's actual version output."""

    lines = text.splitlines()
    require(
        [line for line in lines if line.startswith("Gradle ")]
        == [f"Gradle {GRADLE_VERSION}"],
        "actual Gradle version output mismatch",
    )
    launcher = [line for line in lines if line.startswith("Launcher JVM:")]
    daemon = [line for line in lines if line.startswith("Daemon JVM:")]
    require(
        len(launcher) == len(daemon) == 1, "Gradle JVM identity is missing or ambiguous"
    )
    launch = re.fullmatch(
        r"Launcher JVM:[ \t]+([0-9][0-9A-Za-z.+_-]{0,127}) \(([^()\r\n]{1,256})\)",
        launcher[0],
    )
    home = re.fullmatch(
        r"Daemon JVM:[ \t]+(.+) \(no Daemon JVM specified, using current Java home\)",
        daemon[0],
    )
    require(
        launch is not None and home is not None,
        "Gradle must use its selected Launcher JVM for the build",
    )
    selected_home = home.group(1)
    require(
        (
            selected_home == "${JAVA_HOME}"
            if normalized
            else (
                selected_home.startswith("/")
                and len(selected_home) <= 4096
                and all(
                    ord(character) >= 32 and ord(character) != 127
                    for character in selected_home
                )
            )
        ),
        "Gradle JVM home is not an exact declared normalization root",
    )
    return GradleJvm(launch.group(1), launch.group(2), selected_home)


def verify_build_jvm(value: object, selected: GradleJvm, *, profile: str) -> None:
    """Bind the actual JavaCompile task JVM and compiler to the Gradle selection."""

    _profile(profile)
    record = _object(value, BUILD_JVM_FIELDS, "actual AGP build JVM")
    flavor = profile_spec(profile).flavor
    require(
        type(record["schema"]) is int
        and record["schema"] == 1
        and record["kind"] == "qperiapt.android_agp_build_jvm"
        and record["task"] == f":app:compile{flavor}ReleaseJavaWithJavac",
        "actual AGP build JVM schema or task differs",
    )
    require(
        record["compiler_fork"] is False, "AGP compiler must use the selected build JVM"
    )
    for name in BUILD_JVM_FIELDS - {"schema", "kind", "task", "compiler_fork"}:
        text = record[name]
        require(
            isinstance(text, str)
            and 0 < len(text) <= 4096
            and all(
                ord(character) >= 32 and ord(character) != 127 for character in text
            ),
            "actual AGP build JVM identity is malformed",
        )
    version = record["java_version"]
    require(
        record["java_home"] == record["compiler_java_home"] == selected.java_home
        and version == selected.version
        and selected.vendor_description
        == record["java_vm_vendor"] + " " + record["java_vm_version"],
        "actual AGP build JVM differs from the selected Gradle Launcher/Daemon JVM",
    )


def collector_proof_path(requested: pathlib.Path) -> pathlib.Path:
    """Admit the existing immutable run layout before a CLI reads any proof."""

    try:
        relative = requested.absolute().relative_to(runtime_state.RUNS_ROOT)
    except ValueError as error:
        raise AndroidAgpConsumerError(
            "AGP collector proof must use the executing checkout's run directory"
        ) from error
    require(
        len(relative.parts) == 3
        and relative.parts[1:] == ("proof", runtime.ANDROID_PROOF_LEAF),
        "AGP collector proof must use the fixed immutable run layout",
    )
    try:
        layout = runtime_state.AndroidRunLayout.from_run_id(relative.parts[0])
    except runtime_state.AndroidRuntimeStateError as error:
        raise AndroidAgpConsumerError(str(error)) from error
    return layout.proof / runtime.ANDROID_PROOF_LEAF


def compiled_sources(profile: str) -> list[str]:
    _profile(profile)
    spec = profile_spec(profile)
    names = [
        INSTRUMENTATION_SOURCE,
        f"{SMOKE_ROOT}/common/{JAVA_PACKAGE}/QPeriaptSmokeResults.java",
        f"{SMOKE_ROOT}/{spec.smoke_directory}/{JAVA_PACKAGE}/QPeriaptSmokeActivity.java",
    ]
    if spec.workload is not None:
        names.append(f"{SMOKE_ROOT}/{spec.smoke_directory}/{JAVA_PACKAGE}/{spec.workload}")
    return sorted(names)


def source_inputs(profile: str) -> list[str]:
    names = (
        set(TEMPLATE_FILES)
        | set(compiled_sources(profile))
        | {
            "artifact/android_agp_consumer.py",
            "artifact/android_agp_consumer_contract.py",
            "artifact/android_agp_build.py",
            "artifact/android-device-smoke.sh",
            "artifact/android_elf.py",
            "artifact/android_device_proof.py",
            "artifact/android_bounded_command.py",
            "artifact/bounded_process.py",
        }
    )
    names.update("bindings/" + name for name in profile_spec(profile).fixtures)
    if profile in SDK_PROFILES:
        names.add("artifact/sdk_abi2_spec.py")
    return sorted(names)


def verify_normalized_text(text: str) -> None:
    require(
        not any(
            prefix in text
            for prefix in (
                "/Users/",
                "/home/",
                "/private/tmp/",
                "/private/var/",
                "/tmp/",
            )
        ),
        "public AGP diagnostics contain an unrecognized private path",
    )


def _rules(text: str) -> str:
    return "\n".join(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def verify_diagnostic_log(text: str) -> None:
    require(
        re.search(r"(?im)(?:^w:|^WARNING\b|\bwarning:|^FAILURE:|BUILD FAILED)", text)
        is None,
        "AGP tool emitted a warning or failure",
    )


def verify_agp_dex_dump(text: str, *, package_version: str = "0.1.5") -> None:
    android_elf.verify_minimal_consumer_dump(text, package_version=package_version)
    classes = android_elf.parse_consumer_dex_classes(text)
    methods = classes.get(INSTRUMENTATION_DESCRIPTOR, [])
    for expected_name, expected_type in (
        ("<init>", "()V"),
        ("onCreate", "(Landroid/os/Bundle;)V"),
        ("onStart", "()V"),
    ):
        matched = [
            set(flags.split())
            for name, descriptor, flags in methods
            if name == expected_name and descriptor == expected_type
        ]
        require(
            len(matched) == 1
            and "PUBLIC" in matched[0]
            and not ({"NATIVE", "ABSTRACT", "STATIC"} & matched[0]),
            "shrunk APK lost a concrete Instrumentation entrypoint",
        )
        if expected_name == "<init>":
            require(
                "CONSTRUCTOR" in matched[0],
                "Instrumentation constructor access differs",
            )


def verify_r8_configuration(
    text: str, *, default: str, manifest: str, aar_rules: str, package_version: str = "0.1.5"
) -> None:
    """Audit merged rule origins and their full bodies; no app-supplied Q keep is accepted."""
    require(package_version in {"0.1.5", "0.2.0-alpha.1"}, "unsupported R8 consumer package version")
    verify_normalized_text(text)
    begin = "# The proguard configuration file for the following section is "
    end = "# End of content from "
    sections: dict[str, str] = {}
    origin = None
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith(begin):
            require(origin is None, "nested R8 rule source")
            origin = line[len(begin) :]
            require(origin not in sections, "duplicate R8 rule source")
            lines = []
        elif line.startswith(end):
            require(
                origin is not None and line[len(end) :] == origin,
                "R8 rule source terminator mismatch",
            )
            sections[origin] = "\n".join(lines)
            origin = None
        elif origin is not None:
            lines.append(line)
        else:
            require(not line.strip(), "R8 directives lack a checked provenance section")
    require(origin is None and sections, "incomplete R8 rule source capture")
    matched = set()
    for origin, rules in sections.items():
        if origin.startswith(f"Android Gradle plugin {AGP_VERSION} (extracted file: "):
            require(
                origin.endswith(f"/proguard-android-optimize.txt-{AGP_VERSION})"),
                "R8 default rule origin differs",
            )
            kind, expected = "default", default
        elif (
            origin.endswith("/proguard.txt)")
            and "Generated ProGuard rules (extracted file: " in origin
        ):
            kind, expected = "generated", ""
        elif origin.endswith("/proguard.txt)") or origin.endswith("/proguard.txt"):
            require(
                f"q-periapt-android-{package_version}" in origin and "${GRADLE_HOME}/" in origin,
                "R8 consumer rule origin is not the selected AAR transform",
            )
            kind, expected = "aar", aar_rules
        elif origin.endswith("/aapt_rules.txt)") or origin.endswith("/aapt_rules.txt"):
            kind, expected = "manifest", manifest
        elif origin == "<unknown>":
            kind, expected = "internal", ""
        else:
            raise AndroidAgpConsumerError("R8 consumed an unregistered rule source")
        require(kind not in matched, "R8 has duplicate rule-source kinds")
        matched.add(kind)
        require(
            _rules(rules) == _rules(expected),
            "R8 consumed modified or additional rules",
        )
    require(
        {"default", "aar"} <= matched,
        "R8 did not consume the default and exact AAR rules",
    )
    # These are AAPT's two manifest entrypoint roots, not a general keep layer.
    expected_manifest = {
        "-keep class dev.qperiapt.androidsmoke.QPeriaptSmokeActivity { <init>(); }",
        "-keep class dev.qperiapt.androidsmoke.QPeriaptResultInstrumentation { <init>(); }",
    }
    require(
        set(_rules(manifest).splitlines()) == expected_manifest,
        "AAPT manifest keep roots differ from the two application components",
    )


def _object(
    value: object, fields: frozenset[str] | set[str], label: str
) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == fields, f"{label} fields differ")
    return value


def _profile(value: object) -> runtime.RuntimeResultProfile:
    require(
        isinstance(value, str) and value in ALL_PROFILES, "unknown AGP consumer profile"
    )
    return runtime.RuntimeResultProfile(value)


def _hash(value: object, label: str) -> str:
    require(
        isinstance(value, str) and SHA256.fullmatch(value) is not None,
        f"invalid {label} SHA-256",
    )
    return value


def _relative(value: object, label: str) -> str:
    require(isinstance(value, str) and value != "", f"missing {label} path")
    path = pathlib.PurePosixPath(value)
    require(
        not path.is_absolute() and ".." not in path.parts and "." not in path.parts,
        f"unsafe {label} path",
    )
    require(
        str(path) == value and "\\" not in value and "\x00" not in value,
        f"noncanonical {label} path",
    )
    return value


def _json(path: pathlib.Path) -> dict[str, Any]:
    try:
        return load_json_object_snapshot(
            path, label="AGP consumer JSON", maximum=MAX_JSON
        ).value
    except (OSError, ValueError) as error:
        raise AndroidAgpConsumerError(
            f"cannot read AGP consumer JSON: {path.name}"
        ) from error


def _bytes(path: pathlib.Path, maximum: int = MAX_TEXT) -> bytes:
    try:
        return read_regular_snapshot(
            path, maximum=maximum, label="AGP consumer evidence"
        ).data
    except (OSError, ValueError) as error:
        raise AndroidAgpConsumerError(
            f"cannot read AGP consumer evidence: {path.name}"
        ) from error


def _digest(path: pathlib.Path, maximum: int = MAX_TEXT) -> str:
    return hashlib.sha256(_bytes(path, maximum)).hexdigest()


def _record(value: object, label: str) -> dict[str, Any]:
    record = _object(value, RECORD_FIELDS, label)
    _relative(record["path"], label)
    _hash(record["sha256"], label)
    require(
        type(record["bytes"]) is int and record["bytes"] > 0, f"invalid {label} length"
    )
    return record


def _check_record(
    path: pathlib.Path, value: object, label: str, maximum: int = MAX_TEXT
) -> None:
    record = _record(value, label)
    data = _bytes(path, maximum)
    require(
        len(data) == record["bytes"]
        and hashlib.sha256(data).hexdigest() == record["sha256"],
        f"{label} bytes differ from their record",
    )


def decode_instrumentation_output(data: bytes, run_id: str) -> tuple[bytes, bytes]:
    """Decode one bounded, completed same-APK Instrumentation response, never logcat guesses."""
    require(RUN_ID.fullmatch(run_id) is not None, "invalid instrumentation run id")
    require(len(data) <= MAX_TEXT, "instrumentation output exceeds limit")
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise AndroidAgpConsumerError("instrumentation output is not UTF-8") from error
    require(
        re.findall(r"(?m)^INSTRUMENTATION_CODE: (-?\d+)\s*$", text) == ["-1"],
        "instrumentation did not complete successfully exactly once",
    )
    for line in text.splitlines():
        require(
            not line.strip()
            or line.startswith("INSTRUMENTATION_RESULT: ")
            or line.startswith("INSTRUMENTATION_CODE: "),
            "unexpected Instrumentation diagnostic",
        )
    fields: dict[str, str] = {}
    for name, value in re.findall(
        r"(?m)^INSTRUMENTATION_RESULT: ([A-Za-z0-9_]+)=(.*)$", text
    ):
        require(name not in fields, "duplicate instrumentation result field")
        fields[name] = value.rstrip("\r")
    require(
        set(fields)
        == {
            "qperiapt_run_id",
            "qperiapt_result_text_base64",
            "qperiapt_result_json_base64",
        },
        "unexpected instrumentation result fields",
    )
    require(fields["qperiapt_run_id"] == run_id, "instrumentation run id mismatch")
    decoded = []
    for name in ("qperiapt_result_text_base64", "qperiapt_result_json_base64"):
        try:
            value = base64.b64decode(fields[name], validate=True)
        except ValueError as error:
            raise AndroidAgpConsumerError(
                "invalid instrumentation result encoding"
            ) from error
        require(
            base64.b64encode(value).decode("ascii") == fields[name],
            "noncanonical result encoding",
        )
        require(
            0 < len(value) <= 4 * 1024 * 1024,
            "instrumentation result length exceeds limit",
        )
        decoded.append(value)
    return decoded[0], decoded[1]


def verify_release_manifest_dump(text: str) -> None:
    """Check the actual SDK manifest dump, including the fixed Instrumentation component."""
    require(
        len(re.findall(r"(?m)^\s*E: application(?:\s|$)", text)) == 1,
        "Release APK must have one application",
    )
    debuggable = re.findall(r"android:debuggable\([^)]*\)=([^\n]+)", text)
    require(
        len(debuggable) <= 1
        and all(re.fullmatch(r"\(type 0x12\)0x0\s*", v) for v in debuggable),
        "AGP Release APK is debuggable or has ambiguous flags",
    )
    components = list(
        re.finditer(r"(?m)^([ \t]*)E: instrumentation(?:[ \t].*)?$", text)
    )
    require(len(components) == 1, "AGP APK must retain exactly one Instrumentation")
    component = components[0]
    indent = len(component.group(1))
    block_lines = []
    for line in text[component.end() :].splitlines():
        sibling = re.match(r"^([ \t]*)E:", line)
        if sibling is not None and len(sibling.group(1)) <= indent:
            break
        block_lines.append(line)
    block = "\n".join(block_lines)
    require(
        re.search(
            r'android:name\([^)]*\)="(?:dev\.qperiapt\.androidsmoke\.|\.)QPeriaptResultInstrumentation"',
            block,
        )
        is not None,
        "AGP APK lost its fixed Instrumentation class",
    )
    require(
        re.search(
            r'android:targetPackage\([^)]*\)="dev\.qperiapt\.androidsmoke"', block
        )
        is not None,
        "AGP Instrumentation targets another package",
    )


def _apk_entries(path: pathlib.Path) -> dict[str, bytes]:
    """Reuse the runtime APK admission rules on the exact bounded input snapshot."""
    return _apk_snapshot_entries(_bytes(path, MAX_APK))


def _apk_snapshot_entries(data: bytes) -> dict[str, bytes]:
    """Retain directory entries too, so payload comparisons cover every name."""
    import io

    require(len(data) <= MAX_APK, "AGP APK snapshot exceeds its size limit")
    try:
        with tempfile.TemporaryDirectory(prefix="qperiapt-agp-apk-audit-") as temporary:
            selected = pathlib.Path(temporary) / "consumer.apk"
            selected.write_bytes(data)
            runtime.scan_apk_contents(selected, forbidden_text=[])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return {info.filename: archive.read(info) for info in archive.infolist()}
    except (SystemExit, OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, AndroidAgpConsumerError):
            raise
        raise AndroidAgpConsumerError(f"invalid APK archive: {error}") from error


def signing_input_entries(original: dict[str, bytes]) -> dict[str, bytes]:
    """Select the fixed AGP payload before the existing alignment/signing steps."""
    require(
        VCS_METADATA_ENTRY not in original,
        "AGP release must disable VCS metadata through vcsInfo.include",
    )
    require(
        original.get(APP_METADATA_ENTRY) == APP_METADATA_CONTENT,
        "AGP app metadata is missing or differs from the pinned producer",
    )
    require(
        {
            name
            for name in original
            if name.startswith("META-INF/") and not name.endswith("/")
        }
        == {APP_METADATA_ENTRY},
        "AGP unsigned APK contains unexpected metadata or signature entries",
    )
    return {name: data for name, data in original.items() if name != APP_METADATA_ENTRY}


def verify_signing_input(
    original_apk: pathlib.Path, prepared_apk: pathlib.Path
) -> dict[str, object]:
    """Recheck the complete entry/content delta; ZIP layout is not an identity claim."""
    expected = signing_input_entries(_apk_entries(original_apk))
    require(
        _apk_entries(prepared_apk) == expected,
        "AGP signing input changed entries beyond the fixed app metadata removal",
    )
    return {
        "policy": SIGNING_INPUT_POLICY,
        "removed": {
            APP_METADATA_ENTRY: {
                "bytes": len(APP_METADATA_CONTENT),
                "sha256": hashlib.sha256(APP_METADATA_CONTENT).hexdigest(),
            }
        },
    }


@dataclasses.dataclass(frozen=True)
class ProgramInspection:
    raw_dexdump: bytes
    raw_manifest_dump: bytes
    dexdump: bytes
    manifest_dump: bytes
    private_root: pathlib.Path


def run_sdk_tool(tool: pathlib.Path, arguments: list[str]) -> bytes:
    """Bounded read-only SDK replay; neither Gradle nor Android device commands."""
    try:
        result = capture_output(
            [str(tool), *arguments],
            timeout_seconds=60,
            maximum_stdout_bytes=MAX_TEXT,
            maximum_stderr_bytes=1024 * 1024,
        )
    except (BoundedProcessError, OSError) as error:
        raise AndroidAgpConsumerError(f"{tool.name} replay failed: {error}") from error
    require(
        result.returncode == 0,
        f"{tool.name} replay failed with exit {result.returncode}",
    )
    require(not result.stderr, f"{tool.name} replay emitted diagnostics")
    verify_diagnostic_log(result.stdout.decode("utf-8"))
    return result.stdout


def inspect_apk_program(
    apk: pathlib.Path, *, dexdump: pathlib.Path, aapt2: pathlib.Path,
    package_version: str = "0.1.5",
) -> ProgramInspection:
    """Reconstruct SDK dumps from the selected APK's actual DEX and manifest bytes."""
    apk_data = _bytes(apk, MAX_APK)
    with tempfile.TemporaryDirectory(prefix="qperiapt-agp-program-") as temporary:
        directory = pathlib.Path(temporary)
        selected = directory / "qperiapt-program.apk"
        selected.write_bytes(apk_data)
        entries = _apk_entries(selected)
        dumps = []
        for name in sorted(entries):
            if DEX_NAME.fullmatch(name):
                require(
                    entries[name].startswith(b"dex\n"), "APK entry is not a DEX file"
                )
                dex = directory / name
                dex.write_bytes(entries[name])
                dumps.append(run_sdk_tool(dexdump, [str(dex)]))
        require(dumps, "AGP APK has no DEX program")
        raw_dex = b"\n".join(dumps)
        raw_manifest = run_sdk_tool(
            aapt2, ["dump", "xmltree", "--file", "AndroidManifest.xml", str(selected)]
        )
        normal_dex = raw_dex.replace(str(directory).encode(), b"${APK_INSPECTION}")
        normal_manifest = raw_manifest.replace(
            str(directory).encode(), b"${APK_INSPECTION}"
        )
        verify_normalized_text(normal_dex.decode("utf-8"))
        verify_normalized_text(normal_manifest.decode("utf-8"))
        verify_agp_dex_dump(normal_dex.decode("utf-8"), package_version=package_version)
        verify_release_manifest_dump(normal_manifest.decode("utf-8"))
        return ProgramInspection(
            raw_dex, raw_manifest, normal_dex, normal_manifest, directory
        )


def _sdk_tools(
    sdk: pathlib.Path | None, proof: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, pathlib.Path]:
    try:
        selected = (
            sdk
            if sdk is not None
            else runtime_state.registered_sdk_root(
                os.environ.get(
                    "QPERIAPT_ANDROID_SDK_ROOT",
                    os.environ.get(
                        "ANDROID_HOME",
                        os.environ.get(
                            "ANDROID_SDK_ROOT",
                            str(
                                runtime_state.ADB_PROFILE_PATHS[
                                    "macos-account"
                                ].parent.parent
                            ),
                        ),
                    ),
                )
            )
        )
    except runtime_state.AndroidRuntimeStateError as error:
        raise AndroidAgpConsumerError(str(error)) from error
    directory = (selected / "build-tools/36.0.0").resolve(strict=True)
    require(
        directory.name == "36.0.0" and directory.parent.name == "build-tools",
        "AGP SDK layout differs",
    )
    tools = {}
    for name in ("dexdump", "aapt2", "apksigner", "zipalign"):
        try:
            tool = runtime.require_executable_file(directory / name, "AGP SDK " + name)
        except SystemExit as error:
            raise AndroidAgpConsumerError(str(error)) from error
        require(
            tool.name == name and tool.parent == directory,
            "AGP SDK tools are not from one Build Tools directory",
        )
        expected = (
            receipt["tools"][name]
            if name in ("dexdump", "aapt2")
            else proof["android"][name + "_sha256"]
        )
        require(
            _digest(tool, MAX_APK) == expected,
            f"AGP {name} differs from the recorded SDK tool",
        )
        tools[name] = tool
    return tools


def replay_apk_evidence(
    paths: dict[str, pathlib.Path],
    build_paths: dict[str, pathlib.Path],
    proof: dict[str, Any],
    receipt: dict[str, Any],
    *,
    sdk: pathlib.Path | None,
    profile: str = "agp_full_release",
) -> None:
    tools = _sdk_tools(sdk, proof, receipt)
    data = _bytes(paths["smoke_apk"], MAX_APK)
    require(
        hashlib.sha256(data).hexdigest() == proof["artifacts"]["smoke_apk_sha256"],
        "selected signed APK changed before replay",
    )
    with tempfile.TemporaryDirectory(prefix="qperiapt-agp-replay-") as temporary:
        apk = pathlib.Path(temporary) / "qperiapt-android-smoke.apk"
        apk.write_bytes(data)
        signer = run_sdk_tool(
            tools["apksigner"],
            ["verify", "--min-sdk-version", "23", "--print-certs", str(apk)],
        )
        require(
            signer == _bytes(paths["apksigner_verify"]),
            "independent AGP APK signature result differs",
        )
        alignment = run_sdk_tool(
            tools["zipalign"], ["-c", "-P", "16", "-v", "4", str(apk)]
        )
        alignment = alignment.replace(str(apk).encode(), apk.name.encode())
        require(
            alignment == _bytes(paths["zipalign_verify"]),
            "independent AGP APK alignment result differs",
        )
        inspected = inspect_apk_program(
            apk, dexdump=tools["dexdump"], aapt2=tools["aapt2"],
            package_version=profile_spec(profile).version,
        )
        require(
            inspected.dexdump == _bytes(build_paths["dexdump"]),
            "archived DEX dump differs from the selected APK",
        )
        require(
            inspected.manifest_dump == _bytes(build_paths["manifest_dump"]),
            "archived manifest dump differs from the selected APK",
        )


def _verify_build(
    root: pathlib.Path,
    receipt: dict[str, Any],
    paths: dict[str, pathlib.Path],
    *,
    profile: str,
    aar: pathlib.Path,
    signed_apk: pathlib.Path,
) -> None:
    spec = profile_spec(profile)
    _object(receipt, BUILD_FIELDS, "AGP build receipt")
    require(
        type(receipt["schema"]) is int
        and receipt["schema"] == 1
        and receipt["kind"] == spec.build_kind
        and receipt["status"] == "pass",
        "AGP build did not pass its fixed schema",
    )
    require(
        receipt["profile"] == profile
        and receipt["agp_version"] == AGP_VERSION
        and receipt["gradle_version"] == GRADLE_VERSION,
        "AGP build profile/toolchain mismatch",
    )
    require(
        receipt["minify_enabled"] is True
        and receipt["debuggable"] is False
        and receipt["app_q_keep_rules"] == [],
        "AGP build is not an unassisted minified Release consumer",
    )
    files = _object(receipt["files"], set(BUILD_FILE_NAMES), "AGP build evidence")
    require(set(paths) == set(BUILD_FILE_NAMES), "AGP selected build evidence differs")
    for key, filename in BUILD_FILE_NAMES.items():
        require(
            _record(files[key], key)["path"] == filename,
            "AGP build evidence filename differs",
        )
        _check_record(
            paths[key],
            files[key],
            key,
            MAX_APK if key in {"apk", "agp_apk"} else MAX_TEXT,
        )
    dump = _bytes(paths["dexdump"]).decode("utf-8")
    verify_agp_dex_dump(dump, package_version=spec.version)
    verify_release_manifest_dump(_bytes(paths["manifest_dump"]).decode("utf-8"))
    verify_build_jvm(
        _json(paths["build_jvm"]),
        parse_gradle_jvm(
            _bytes(paths["gradle_version"]).decode("utf-8"), normalized=True
        ),
        profile=profile,
    )
    gradle_log = _bytes(paths["gradle_log"]).decode("utf-8")
    flavor = spec.flavor
    require(
        "BUILD SUCCESSFUL" in gradle_log
        and gradle_log.splitlines().count(
            f"> Task :app:compile{flavor}ReleaseJavaWithJavac"
        )
        == 1
        and gradle_log.splitlines().count(f"> Task :app:minify{flavor}ReleaseWithR8")
        == 1,
        "actual JavaCompile/R8 execution is not present in the successful build log",
    )
    for key in (
        "gradle_log",
        "gradle_version",
        "manifest_dump",
        "dexdump",
    ):
        verify_diagnostic_log(_bytes(paths[key]).decode("utf-8"))
    sources = receipt["source_files"]
    require(
        isinstance(sources, dict) and set(sources) == set(source_inputs(profile)),
        "AGP source input inventory is missing",
    )
    for rel, digest in sources.items():
        _relative(rel, "AGP source")
        require(
            _digest(root / rel, MAX_APK) == _hash(digest, rel),
            f"AGP source input changed: {rel}",
        )
    compiled = receipt["compiled_application_sources"]
    require(
        isinstance(compiled, list) and compiled == compiled_sources(profile),
        "AGP compiled source inventory is invalid",
    )
    actual_inputs = _bytes(paths["compilation_inputs"]).decode("utf-8").splitlines()
    require(
        actual_inputs == compiled, "AGP compiled sources differ from the task capture"
    )
    for rel in compiled:
        require(
            isinstance(rel, str) and rel in sources,
            "AGP compiled input is outside the source inventory",
        )
    # The exact compiled_sources equality above also forbids either full workload
    # from entering a minimal build and requires the selected full workload.
    require(
        isinstance(receipt["tools"], dict)
        and set(receipt["tools"]) == {"dexdump", "aapt2", "gradle_wrapper"},
        "AGP tool identity inventory differs",
    )
    for name, digest in receipt["tools"].items():
        _hash(digest, name)
    signing_input = _object(
        receipt["signing_input"], {"policy", "removed"}, "AGP signing input"
    )
    removed = _object(
        signing_input["removed"], {APP_METADATA_ENTRY}, "AGP removed metadata"
    )
    metadata = _object(
        removed[APP_METADATA_ENTRY], {"bytes", "sha256"}, "AGP removed metadata record"
    )
    require(
        type(metadata["bytes"]) is int,
        "AGP removed metadata byte count must be an exact integer",
    )
    _hash(metadata["sha256"], "removed AGP metadata")
    require(
        signing_input == verify_signing_input(paths["agp_apk"], paths["apk"]),
        "AGP signing input receipt differs from the complete APK delta",
    )
    unsigned = _apk_entries(paths["apk"])
    signed = _apk_entries(signed_apk)
    require(
        set(signed) - set(unsigned) <= V1_SIGNATURE_ENTRIES
        and all(signed.get(name) == data for name, data in unsigned.items()),
        "signed APK changed the prepared AGP payload beyond signature entries",
    )
    dex = {
        name: hashlib.sha256(data).hexdigest()
        for name, data in unsigned.items()
        if DEX_NAME.fullmatch(name)
    }
    require(
        dex and receipt["dex_sha256"] == dex, "AGP DEX payload hash inventory mismatch"
    )
    aar_entries, _ = android_elf.audit_aar(aar, profile=spec.aar_profile)
    require(
        _digest(paths["default_proguard"]) == DEFAULT_PROGUARD_SHA256,
        "AGP optimized default rules differ from the pinned tool distribution",
    )
    verify_r8_configuration(
        _bytes(paths["r8_configuration"]).decode("utf-8"),
        default=_bytes(paths["default_proguard"]).decode("utf-8"),
        manifest=_bytes(paths["manifest_proguard"]).decode("utf-8"),
        aar_rules=aar_entries["proguard.txt"].decode("utf-8"),
        package_version=spec.version,
    )
    diagnostics = _object(
        receipt["diagnostics"],
        {"policy", "normalized_public", "raw_private_sha256"},
        "AGP diagnostics",
    )
    require(
        diagnostics["policy"] == NORMALIZATION_POLICY
        and diagnostics["normalized_public"] == sorted(NORMALIZED_FILES),
        "AGP diagnostic normalization contract differs",
    )
    originals = _object(
        diagnostics["raw_private_sha256"],
        set(RAW_DIAGNOSTIC_FILES),
        "private raw diagnostic digests",
    )
    for name, digest in originals.items():
        _hash(digest, name)
    for name in NORMALIZED_FILES:
        key = next(
            key for key, filename in BUILD_FILE_NAMES.items() if filename == name
        )
        verify_normalized_text(_bytes(paths[key]).decode("utf-8"))
    expected_native = {
        "lib/" + name[4:]: data
        for name, data in aar_entries.items()
        if name.startswith("jni/")
    }
    require(
        {
            name: data
            for name, data in signed.items()
            if name.startswith("lib/") and not name.endswith("/")
        }
        == expected_native,
        "AGP APK native payload differs from the exact AAR",
    )
    if profile in SDK_PROFILES:
        require(
            {name: data for name, data in signed.items()
             if name.startswith("assets/") and not name.endswith("/")}
            == {"assets/" + name: _bytes(root / "bindings" / name) for name in spec.fixtures},
            "AGP fixture assets differ from the exact selected workload",
        )
        with zipfile.ZipFile(signed_apk) as archive:
            require(all(archive.getinfo(name).compress_type == zipfile.ZIP_STORED
                        for name in expected_native), "SDK APK native libraries must remain uncompressed")
        extraction = re.findall(r"android:extractNativeLibs\([^)]*\)=([^\n]+)",
                                _bytes(paths["manifest_dump"]).decode("utf-8"))
        require(len(extraction) == 1 and extraction[0].strip() in {"false", "(type 0x12)0x0"},
                "SDK APK must disable legacy native extraction")
    elif profile == "agp_full_release":
        require(
            signed.get("assets/signed-policy-vectors.json")
            == _bytes(root / "bindings/signed-policy-vectors.json"),
            "full AGP consumer did not use the original signed-policy vectors",
        )
    else:
        require(
            not any(name.startswith("assets/") and not name.endswith("/") for name in signed),
            "full fixtures entered the minimal APK",
        )


def _read_selection(root: pathlib.Path, proof_path: pathlib.Path, *, expected_profile: str | None = None) -> tuple[
    dict[str, Any],
    dict[str, pathlib.Path],
    dict[str, pathlib.Path],
    pathlib.Path,
    pathlib.Path,
]:
    proof = _json(proof_path)
    _object(proof, runtime.PROOF_FIELDS | {"kind", "consumer"}, "AGP runtime proof")
    consumer = _object(proof.get("consumer"), CONSUMER_FIELDS, "AGP consumer")
    require(isinstance(proof.get("paths"), dict), "AGP runtime paths are missing")
    paths = {name: root / _relative(rel, name) for name, rel in proof["paths"].items()}
    build_record = _record(consumer["build_receipt"], "AGP build receipt")
    build_path = root / build_record["path"]
    build_paths = {
        name: build_path.parent / filename
        for name, filename in BUILD_FILE_NAMES.items()
    }
    instrumentation = (
        root
        / _record(consumer["instrumentation_output"], "instrumentation output")["path"]
    )
    try:
        runtime.verify_runtime_record_shape(proof, _profile(expected_profile if expected_profile is not None else consumer["profile"]))
        checked = runtime.proof_paths(root, proof)
        require(checked == paths, "AGP runtime paths are not canonical target paths")
        runtime.validate_selected_run_layout(
            root, proof_path, proof, paths, require_unique_run=True
        )
    except (SystemExit, OSError, ValueError) as error:
        raise AndroidAgpConsumerError(
            f"invalid AGP runtime selection: {error}"
        ) from error
    require(
        build_path == proof_path.parent / "agp-build/receipt.json",
        "AGP build receipt is outside the selected run",
    )
    require(
        instrumentation == proof_path.parent / "adb-instrumentation.txt",
        "AGP Instrumentation output is outside the selected run",
    )
    return proof, paths, build_paths, build_path, instrumentation


def _validate(
    root: pathlib.Path,
    proof_path: pathlib.Path,
    proof: dict[str, Any],
    paths: dict[str, pathlib.Path],
    build_paths: dict[str, pathlib.Path],
    build_path: pathlib.Path,
    instrumentation_path: pathlib.Path,
    *,
    bundled: bool,
    expected_profile: str,
    expected_aar_sha256: str,
    expected_aar_manifest_sha256: str,
    expected_source_commit: str,
    sdk: pathlib.Path | None = None,
    expected_device_abi: str | None = None,
    expected_runtime_profile: str = DEFAULT_RUNTIME_PROFILE,
) -> dict[str, object]:
    selected = _profile(expected_profile)
    spec = profile_spec(expected_profile)
    target = runtime_target(expected_profile, expected_device_abi, expected_runtime_profile)
    _object(proof, runtime.PROOF_FIELDS | {"kind", "consumer"}, "AGP runtime proof")
    require(
        type(proof["schema"]) is int
        and proof["schema"] == 1
        and proof["kind"] == spec.proof_kind,
        "invalid AGP runtime proof schema",
    )
    consumer = _object(proof["consumer"], CONSUMER_FIELDS, "AGP consumer")
    require(
        consumer["profile"] == selected.value
        and consumer["instrumentation"] == INSTRUMENTATION,
        "AGP runtime profile/component mismatch",
    )
    _check_record(build_path, consumer["build_receipt"], "AGP build receipt")
    _check_record(
        instrumentation_path,
        consumer["instrumentation_output"],
        "instrumentation output",
    )
    receipt = _json(build_path)
    require(
        receipt.get("source_commit") == proof["git_commit"] == expected_source_commit,
        "AGP build/runtime source commit mismatch",
    )
    require(
        receipt.get("source_tree_sha256") == proof["proof_source_tree_sha256"],
        "AGP build/runtime source tree mismatch",
    )
    require(
        receipt.get("aar_sha256") == expected_aar_sha256
        and receipt.get("aar_manifest_sha256") == expected_aar_manifest_sha256,
        "AGP build selected another AAR/manifest",
    )
    try:
        runtime.verify_runtime_record_shape(proof, selected)
        runtime.verify_runtime_contents(
            root,
            proof,
            paths,
            result_profile=selected,
            expected_device_kind=target["kind"],
            expected_device_abi=target["abi"],
            expected_runtime_profile=expected_runtime_profile,
            expected_device_sdk=target["sdk"],
            expected_page_size=target["page_size"],
            require_release_mode=True,
            bundled=bundled,
        )
        if expected_profile in SDK_PROFILES:
            entries, _ = android_elf.audit_aar(paths["aar"], profile=spec.aar_profile)
            android_elf.verify_manifest(
                paths["aar_manifest"], aar_path=paths["aar"], entries=entries,
                aar_sha256=expected_aar_sha256,
                expected_manifest_sha256=expected_aar_manifest_sha256,
                require_release=True, forbidden_text=[str(root)], source_root=root,
                profile=spec.aar_profile,
            )
        _verify_build(
            root,
            receipt,
            build_paths,
            profile=selected.value,
            aar=paths["aar"],
            signed_apk=paths["smoke_apk"],
        )
    except (
        SystemExit,
        OSError,
        ValueError,
        android_elf.AndroidVerificationError,
    ) as error:
        raise AndroidAgpConsumerError(
            f"AGP evidence verification failed: {error}"
        ) from error
    replay_apk_evidence(paths, build_paths, proof, receipt, sdk=sdk, profile=expected_profile)
    text, result = decode_instrumentation_output(
        _bytes(instrumentation_path), proof["run_id"]
    )
    require(
        text == _bytes(paths["result_txt"]) and result == _bytes(paths["result_json"]),
        "runtime result differs from the actual Instrumentation response",
    )
    projection = {
        "profile": selected.value,
        "proof_sha256": _digest(proof_path),
        "run_id": proof["run_id"],
        "source_commit": proof["git_commit"],
        "source_tree_sha256": proof["proof_source_tree_sha256"],
        "aar_sha256": _digest(paths["aar"], MAX_APK),
        "aar_manifest_sha256": _digest(paths["aar_manifest"]),
        "apk_sha256": _digest(paths["smoke_apk"], MAX_APK),
        "build_receipt_sha256": _digest(build_path),
        "result_json_sha256": _digest(paths["result_json"]),
        "passed_tests": proof["result"]["passed_tests"],
        "agp_version": receipt["agp_version"],
        "gradle_version": receipt["gradle_version"],
    }
    if expected_profile in SDK_PROFILES:
        projection["runtime_target"] = {key: proof["device"][key] for key in target}
    return validate_profile_projection(
        projection,
        expected_profile=expected_profile,
        expected_aar_sha256=expected_aar_sha256,
        expected_aar_manifest_sha256=expected_aar_manifest_sha256,
        expected_source_commit=expected_source_commit,
        expected_device_abi=expected_device_abi,
        expected_runtime_profile=expected_runtime_profile,
    )


def validate_completed_profile(
    root: pathlib.Path,
    proof_path: pathlib.Path,
    *,
    expected_profile: str,
    expected_aar_sha256: str,
    expected_aar_manifest_sha256: str,
    expected_source_commit: str,
    sdk: pathlib.Path | None = None,
    expected_device_abi: str | None = None,
    expected_runtime_profile: str = DEFAULT_RUNTIME_PROFILE,
) -> dict[str, object]:
    """Validate local evidence with read-only Git/SDK replay; never run Gradle/devices."""
    proof, paths, build_paths, build_path, instrumentation = _read_selection(
        root, proof_path, expected_profile=expected_profile
    )
    return _validate(
        root,
        proof_path,
        proof,
        paths,
        build_paths,
        build_path,
        instrumentation,
        bundled=False,
        expected_profile=expected_profile,
        expected_aar_sha256=expected_aar_sha256,
        expected_aar_manifest_sha256=expected_aar_manifest_sha256,
        expected_source_commit=expected_source_commit,
        sdk=sdk,
        expected_device_abi=expected_device_abi,
        expected_runtime_profile=expected_runtime_profile,
    )


def profile_bundle_paths(proof: dict[str, Any], profile: str) -> dict[str, str]:
    names = runtime.bundle_file_paths(proof)
    spec = profile_spec(profile)
    if profile in SDK_PROFILES:
        names["aar"] = f"artifacts/q-periapt-android-{spec.version}.aar"
        names["aar_manifest"] = f"artifacts/q-periapt-android-{spec.version}.MANIFEST.json"
    return names


def profile_evidence_files(
    root: pathlib.Path, proof_path: pathlib.Path, *, sdk: pathlib.Path | None = None,
    expected_device_abi: str | None = None,
    expected_runtime_profile: str = DEFAULT_RUNTIME_PROFILE,
) -> dict[str, pathlib.Path]:
    """Return fixed archive-relative names for a complete, portable per-profile closure."""
    proof, paths, build_paths, build_path, instrumentation = _read_selection(
        root, proof_path
    )
    consumer = _object(proof.get("consumer"), CONSUMER_FIELDS, "AGP consumer")
    validate_completed_profile(
        root,
        proof_path,
        expected_profile=consumer["profile"],
        expected_aar_sha256=proof["artifacts"]["aar_sha256"],
        expected_aar_manifest_sha256=proof["artifacts"]["aar_manifest_sha256"],
        expected_source_commit=proof["git_commit"],
        sdk=sdk,
        expected_device_abi=expected_device_abi,
        expected_runtime_profile=expected_runtime_profile,
    )
    names = profile_bundle_paths(proof, consumer["profile"])
    result = {
        "proof.json": proof_path,
        "build/receipt.json": build_path,
        "instrumentation.txt": instrumentation,
    }
    for key, path in paths.items():
        require(key in names, "runtime archive path mapping is incomplete")
        result["runtime/" + names[key]] = path
    result.update(
        {"build/" + BUILD_FILE_NAMES[key]: path for key, path in build_paths.items()}
    )
    return result


def verify_exported_profile(
    root: pathlib.Path,
    directory: pathlib.Path,
    *,
    expected_profile: str,
    expected_aar_sha256: str,
    expected_aar_manifest_sha256: str,
    expected_source_commit: str,
    sdk: pathlib.Path | None = None,
    expected_device_abi: str | None = None,
    expected_runtime_profile: str = DEFAULT_RUNTIME_PROFILE,
) -> dict[str, object]:
    """Verify safely extracted evidence through the same checks, with no original run paths."""
    require(
        directory.is_dir() and not directory.is_symlink(),
        "exported AGP directory is invalid",
    )
    proof_path = directory / "proof.json"
    proof = _json(proof_path)
    try:
        names = profile_bundle_paths(proof, expected_profile)
        keys = runtime.expected_proof_path_keys(proof)
    except SystemExit as error:
        raise AndroidAgpConsumerError(
            f"invalid exported AGP device: {error}"
        ) from error
    paths = {key: directory / "runtime" / names[key] for key in keys}
    build_paths = {
        key: directory / "build" / name for key, name in BUILD_FILE_NAMES.items()
    }
    expected_names = (
        {"proof.json", "build/receipt.json", "instrumentation.txt"}
        | {"runtime/" + names[key] for key in paths}
        | {"build/" + name for name in BUILD_FILE_NAMES.values()}
    )
    actual = set()
    for entry in directory.rglob("*"):
        require(not entry.is_symlink(), "exported AGP evidence contains a symlink")
        if entry.is_file():
            actual.add(entry.relative_to(directory).as_posix())
        else:
            require(entry.is_dir(), "exported AGP evidence contains a special node")
    require(
        actual == expected_names,
        "exported AGP closure is missing files or contains extras",
    )
    return _validate(
        root,
        proof_path,
        proof,
        paths,
        build_paths,
        directory / "build/receipt.json",
        directory / "instrumentation.txt",
        bundled=True,
        expected_profile=expected_profile,
        expected_aar_sha256=expected_aar_sha256,
        expected_aar_manifest_sha256=expected_aar_manifest_sha256,
        expected_source_commit=expected_source_commit,
        sdk=sdk,
        expected_device_abi=expected_device_abi,
        expected_runtime_profile=expected_runtime_profile,
    )


def export_completed_profile(
    root: pathlib.Path, proof_path: pathlib.Path, directory: pathlib.Path, *,
    expected_profile: str, expected_aar_sha256: str,
    expected_aar_manifest_sha256: str, expected_source_commit: str,
    sdk: pathlib.Path | None = None, expected_device_abi: str | None = None,
    expected_runtime_profile: str = DEFAULT_RUNTIME_PROFILE,
) -> dict[str, object]:
    """Export a verified closure, then replay it independently of original run paths."""
    expected = dict(expected_profile=expected_profile, expected_aar_sha256=expected_aar_sha256,
                    expected_aar_manifest_sha256=expected_aar_manifest_sha256,
                    expected_source_commit=expected_source_commit, sdk=sdk,
                    expected_device_abi=expected_device_abi,
                    expected_runtime_profile=expected_runtime_profile)
    before = validate_completed_profile(root, proof_path, **expected)
    files = profile_evidence_files(
        root, proof_path, sdk=sdk, expected_device_abi=expected_device_abi,
        expected_runtime_profile=expected_runtime_profile,
    )
    require(not directory.exists() and not directory.is_symlink(), "AGP export already exists")
    directory.mkdir(mode=0o700)
    for name, source in files.items():
        target = directory / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(_bytes(source, MAX_APK))
            # The collector runs with umask 077. Only the exported copy has the
            # portable bundle mode; its containing directory stays private and
            # the live receipt remains 0600. Set mode on the new descriptor.
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())
    after = verify_exported_profile(root, directory, **expected)
    require(after == before, "AGP exported evidence changed during collection")
    return after


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    decode = commands.add_parser("decode-instrumentation")
    decode.add_argument("--input", type=pathlib.Path, required=True)
    decode.add_argument("--run-id", required=True)
    decode.add_argument("--text-output", type=pathlib.Path, required=True)
    decode.add_argument("--json-output", type=pathlib.Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--proof", type=pathlib.Path, required=True)
    verify.add_argument("--export-to", type=pathlib.Path)
    exported = commands.add_parser("verify-export")
    exported.add_argument("--directory", type=pathlib.Path, required=True)
    for command in (verify, exported):
        command.add_argument("--root", type=pathlib.Path, required=True)
        command.add_argument("--sdk", type=pathlib.Path)
        command.add_argument("--expected-device-abi", choices=("arm64-v8a", "x86_64"))
        command.add_argument("--expected-runtime-profile", choices=tuple(RUNTIME_PROFILES),
                             default=DEFAULT_RUNTIME_PROFILE)
        for name in (
            "profile",
            "expected-aar-sha256",
            "expected-aar-manifest-sha256",
            "expected-source-commit",
        ):
            command.add_argument("--" + name, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "decode-instrumentation":
            text, result = decode_instrumentation_output(
                _bytes(arguments.input), arguments.run_id
            )
            for path, data in (
                (arguments.text_output, text),
                (arguments.json_output, result),
            ):
                with path.open("xb") as output:
                    output.write(data)
        elif arguments.command in {"verify", "verify-export"}:
            root = runtime_state.collector_repository_root(arguments.root)
            if arguments.command == "verify":
                proof = collector_proof_path(arguments.proof)
            sdk = (
                runtime_state.registered_sdk_root(arguments.sdk)
                if arguments.sdk is not None
                else None
            )
            expected = dict(
                expected_profile=arguments.profile,
                expected_aar_sha256=arguments.expected_aar_sha256,
                expected_aar_manifest_sha256=arguments.expected_aar_manifest_sha256,
                expected_source_commit=arguments.expected_source_commit,
                sdk=sdk,
                expected_device_abi=arguments.expected_device_abi,
                expected_runtime_profile=arguments.expected_runtime_profile,
            )
            if arguments.command == "verify-export":
                value = verify_exported_profile(root, arguments.directory, **expected)
            elif arguments.export_to is None:
                value = validate_completed_profile(root, proof, **expected)
            else:
                destination = arguments.export_to.absolute()
                require(destination.parent.resolve(strict=True) == destination.parent,
                        "AGP export parent must be canonical")
                require(destination.parent.is_relative_to(root / "target"),
                        "AGP export must be under the executing repository target")
                value = export_completed_profile(root, proof, destination, **expected)
            print(json.dumps(value, sort_keys=True))
            print("ANDROID_AGP_CONSUMER_VERIFY_PASS")
    except (
        AndroidAgpConsumerError,
        runtime_state.AndroidRuntimeStateError,
        OSError,
    ) as error:
        parser.exit(1, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
