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
from bounded_process import BoundedProcessError, capture_output
from evidence_io import load_json_object_snapshot, read_regular_snapshot


from android_agp_consumer_contract import (
    AGP_VERSION,
    BUILD_KIND,
    GRADLE_VERSION,
    PROFILES,
    PROOF_KIND,
    RUN_ID,
    SHA256,
    AndroidAgpConsumerError,
    require,
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
    }
)
BUILD_FILE_NAMES = {
    "apk": "consumer-unsigned.apk",
    "dexdump": "dexdump.txt",
    "manifest_dump": "manifest-dump.txt",
    "mapping": "mapping.txt",
    "r8_configuration": "r8-configuration.txt",
    "gradle_log": "gradle-build.log",
    "gradle_version": "gradle-version.txt",
    "java_version": "java-version.txt",
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
        "java-version.txt",
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


def compiled_sources(profile: str) -> list[str]:
    _profile(profile)
    flavor = "full" if profile == "agp_full_release" else "minimal"
    names = [
        INSTRUMENTATION_SOURCE,
        f"{SMOKE_ROOT}/common/{JAVA_PACKAGE}/QPeriaptSmokeResults.java",
        f"{SMOKE_ROOT}/{flavor}/{JAVA_PACKAGE}/QPeriaptSmokeActivity.java",
    ]
    if profile == "agp_full_release":
        names.append(f"{SMOKE_ROOT}/full/{JAVA_PACKAGE}/QPeriaptSmokeWorkload.java")
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
    if profile == "agp_full_release":
        names.add("bindings/signed-policy-vectors.json")
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


def verify_agp_dex_dump(text: str) -> None:
    android_elf.verify_minimal_consumer_dump(text)
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
    text: str, *, default: str, manifest: str, aar_rules: str
) -> None:
    """Audit merged rule origins and their full bodies; no app-supplied Q keep is accepted."""
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
                "q-periapt-android-0.1.5" in origin and "${GRADLE_HOME}/" in origin,
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
        isinstance(value, str) and value in PROFILES, "unknown AGP consumer profile"
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
    import io

    data = _bytes(path, MAX_APK)
    try:
        with tempfile.TemporaryDirectory(prefix="qperiapt-agp-apk-audit-") as temporary:
            selected = pathlib.Path(temporary) / "consumer.apk"
            selected.write_bytes(data)
            runtime.scan_apk_contents(selected, forbidden_text=[])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return {
                info.filename: archive.read(info)
                for info in archive.infolist()
                if not info.is_dir()
            }
    except (SystemExit, OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, AndroidAgpConsumerError):
            raise
        raise AndroidAgpConsumerError(f"invalid APK archive: {error}") from error


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
    apk: pathlib.Path, *, dexdump: pathlib.Path, aapt2: pathlib.Path
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
        verify_agp_dex_dump(normal_dex.decode("utf-8"))
        verify_release_manifest_dump(normal_manifest.decode("utf-8"))
        return ProgramInspection(
            raw_dex, raw_manifest, normal_dex, normal_manifest, directory
        )


def _sdk_tools(
    sdk: pathlib.Path | None, proof: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, pathlib.Path]:
    selected = (
        sdk
        if sdk is not None
        else pathlib.Path(
            os.environ.get(
                "QPERIAPT_ANDROID_SDK_ROOT",
                os.environ.get(
                    "ANDROID_HOME",
                    os.environ.get(
                        "ANDROID_SDK_ROOT",
                        str(pathlib.Path.home() / "Library/Android/sdk"),
                    ),
                ),
            )
        )
    )
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
            apk, dexdump=tools["dexdump"], aapt2=tools["aapt2"]
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
    _object(receipt, BUILD_FIELDS, "AGP build receipt")
    require(
        type(receipt["schema"]) is int
        and receipt["schema"] == 1
        and receipt["kind"] == BUILD_KIND
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
            paths[key], files[key], key, MAX_APK if key == "apk" else MAX_TEXT
        )
    dump = _bytes(paths["dexdump"]).decode("utf-8")
    verify_agp_dex_dump(dump)
    verify_release_manifest_dump(_bytes(paths["manifest_dump"]).decode("utf-8"))
    require(
        f"Gradle {GRADLE_VERSION}" in _bytes(paths["gradle_version"]).decode("utf-8"),
        "actual Gradle version output mismatch",
    )
    gradle_log = _bytes(paths["gradle_log"]).decode("utf-8")
    flavor = "Full" if profile == "agp_full_release" else "Minimal"
    require(
        "BUILD SUCCESSFUL" in gradle_log
        and f"minify{flavor}ReleaseWithR8" in gradle_log,
        "AGP/R8 execution is not present in the successful build log",
    )
    for key in (
        "gradle_log",
        "gradle_version",
        "java_version",
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
    if profile == "agp_minimal_release":
        require(
            all("/smoke/full/" not in path for path in compiled),
            "full workload entered minimal R8 inputs",
        )
        require(
            any("/smoke/minimal/" in path for path in compiled),
            "minimal entrypoint was not compiled",
        )
    else:
        require(
            any(path.endswith("/QPeriaptSmokeWorkload.java") for path in compiled),
            "full consumer did not compile the complete original workload",
        )
    require(
        isinstance(receipt["tools"], dict)
        and set(receipt["tools"]) == {"dexdump", "aapt2", "gradle_wrapper"},
        "AGP tool identity inventory differs",
    )
    for name, digest in receipt["tools"].items():
        _hash(digest, name)
    unsigned = _apk_entries(paths["apk"])
    signed = _apk_entries(signed_apk)
    dex = {
        name: hashlib.sha256(data).hexdigest()
        for name, data in unsigned.items()
        if DEX_NAME.fullmatch(name)
    }
    require(
        dex and receipt["dex_sha256"] == dex, "AGP DEX payload hash inventory mismatch"
    )
    require(
        {name for name in signed if DEX_NAME.fullmatch(name)} == set(dex),
        "signed APK has different DEX entries",
    )
    for name in set(dex) | {"AndroidManifest.xml"}:
        require(
            signed.get(name) == unsigned[name],
            "signed APK changed the audited AGP program/manifest",
        )
    aar_entries, _ = android_elf.audit_aar(aar)
    require(
        _digest(paths["default_proguard"]) == DEFAULT_PROGUARD_SHA256,
        "AGP optimized default rules differ from the pinned tool distribution",
    )
    verify_r8_configuration(
        _bytes(paths["r8_configuration"]).decode("utf-8"),
        default=_bytes(paths["default_proguard"]).decode("utf-8"),
        manifest=_bytes(paths["manifest_proguard"]).decode("utf-8"),
        aar_rules=aar_entries["proguard.txt"].decode("utf-8"),
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
        {name: data for name, data in signed.items() if name.startswith("lib/")}
        == expected_native,
        "AGP APK native payload differs from the exact AAR",
    )
    if profile == "agp_full_release":
        require(
            signed.get("assets/signed-policy-vectors.json")
            == _bytes(root / "bindings/signed-policy-vectors.json"),
            "full AGP consumer did not use the original signed-policy vectors",
        )
    else:
        require(
            not any(name.startswith("assets/") for name in signed),
            "full fixtures entered the minimal APK",
        )


def _read_selection(root: pathlib.Path, proof_path: pathlib.Path) -> tuple[
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
        runtime.verify_runtime_record_shape(proof)
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
) -> dict[str, object]:
    selected = _profile(expected_profile)
    _object(proof, runtime.PROOF_FIELDS | {"kind", "consumer"}, "AGP runtime proof")
    require(
        type(proof["schema"]) is int
        and proof["schema"] == 1
        and proof["kind"] == PROOF_KIND,
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
        runtime.verify_runtime_record_shape(proof)
        runtime.verify_runtime_contents(
            root,
            proof,
            paths,
            result_profile=selected,
            expected_device_kind="emulator",
            expected_device_abi="arm64-v8a",
            expected_device_sdk=35,
            expected_page_size=16384,
            require_release_mode=True,
            bundled=bundled,
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
    replay_apk_evidence(paths, build_paths, proof, receipt, sdk=sdk)
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
    return validate_profile_projection(
        projection,
        expected_profile=expected_profile,
        expected_aar_sha256=expected_aar_sha256,
        expected_aar_manifest_sha256=expected_aar_manifest_sha256,
        expected_source_commit=expected_source_commit,
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
) -> dict[str, object]:
    """Validate local evidence with read-only Git/SDK replay; never run Gradle/devices."""
    proof, paths, build_paths, build_path, instrumentation = _read_selection(
        root, proof_path
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
    )


def profile_evidence_files(
    root: pathlib.Path, proof_path: pathlib.Path, *, sdk: pathlib.Path | None = None
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
    )
    names = runtime.bundle_file_paths(proof)
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
) -> dict[str, object]:
    """Verify safely extracted evidence through the same checks, with no original run paths."""
    require(
        directory.is_dir() and not directory.is_symlink(),
        "exported AGP directory is invalid",
    )
    proof_path = directory / "proof.json"
    proof = _json(proof_path)
    try:
        names = runtime.bundle_file_paths(proof)
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
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    decode = commands.add_parser("decode-instrumentation")
    decode.add_argument("--input", type=pathlib.Path, required=True)
    decode.add_argument("--run-id", required=True)
    decode.add_argument("--text-output", type=pathlib.Path, required=True)
    decode.add_argument("--json-output", type=pathlib.Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--root", type=pathlib.Path, required=True)
    verify.add_argument("--proof", type=pathlib.Path, required=True)
    verify.add_argument("--sdk", type=pathlib.Path)
    for name in (
        "profile",
        "expected-aar-sha256",
        "expected-aar-manifest-sha256",
        "expected-source-commit",
    ):
        verify.add_argument("--" + name, required=True)
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
        elif arguments.command == "verify":
            value = validate_completed_profile(
                arguments.root,
                arguments.proof,
                expected_profile=arguments.profile,
                expected_aar_sha256=arguments.expected_aar_sha256,
                expected_aar_manifest_sha256=arguments.expected_aar_manifest_sha256,
                expected_source_commit=arguments.expected_source_commit,
                sdk=arguments.sdk,
            )
            print(json.dumps(value, sort_keys=True))
            print("ANDROID_AGP_CONSUMER_VERIFY_PASS")
    except (AndroidAgpConsumerError, OSError) as error:
        parser.exit(1, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
