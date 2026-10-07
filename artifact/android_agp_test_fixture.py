"""Synthetic verifier fixtures, never evidence of JNI/ART or release completion.

Real Git/source inventories and canonical binary containers exercise the validators.
Only the fixed SDK command boundary is simulated; no schema/IO check is patched.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess

import android_agp_consumer as consumer
import android_agp_consumer_contract as contract
import android_device_proof as runtime
import android_elf
from test_android_device_proof import (
    complete_proof_shape,
    write_emulator_isolation_receipts,
)
from test_android_elf import AndroidElfVerifierTests, CLASS_BYTES, CLASS_ENTRIES, zip_bytes
from test_android_minimal_consumer import CALLBACK, EXCEPTION, FACADE, class_dump, complete_dump

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_DUMP = (
    "E: manifest (line=1)\n  E: application (line=2)\n"
    "  E: instrumentation (line=4)\n"
    '    A: android:name(0x01010003)=".QPeriaptResultInstrumentation" (Raw: ".QPeriaptResultInstrumentation")\n'
    '    A: android:targetPackage(0x01010021)="dev.qperiapt.androidsmoke" (Raw: "dev.qperiapt.androidsmoke")\n'
)
METHODS = (
    ("<init>", "()V", "PUBLIC CONSTRUCTOR"),
    ("onCreate", "(Landroid/os/Bundle;)V", "PUBLIC"),
    ("onStart", "()V", "PUBLIC"),
)
DEX_DUMP = complete_dump() + class_dump(0, consumer.INSTRUMENTATION_DESCRIPTOR, METHODS)
SDK_MANIFEST_DUMP = MANIFEST_DUMP.replace("  E: application (line=2)\n", "  E: application (line=2)\n    A: android:extractNativeLibs(0x010104ea)=false\n")
SDK_DEX_DUMP = (class_dump(0, FACADE, tuple((name, descriptor, "PRIVATE STATIC NATIVE")
    for name, descriptor in android_elf.package_profile("sdk-020").jni_methods.items()))
    + class_dump(1, EXCEPTION, CALLBACK) + class_dump(2, consumer.INSTRUMENTATION_DESCRIPTOR, METHODS))
SIGNER = b"fixture SDK signer certificate result\n"
ALIGNMENT = b"fixture SDK 16384-byte native alignment result\n"


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)


def record(path: pathlib.Path, relative: str | None = None) -> dict[str, object]:
    return {
        "path": relative if relative is not None else path.name,
        "bytes": path.stat().st_size,
        "sha256": digest(path),
    }


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def gradle_version(java_home: str = "${JAVA_HOME}", *, profile: str = "agp_full_release") -> bytes:
    return (
        f"Gradle {contract.profile_spec(profile).gradle_version}\n"
        "Launcher JVM:  21.0.11 (Homebrew 21.0.11)\n"
        f"Daemon JVM:    {java_home} (no Daemon JVM specified, using current Java home)\n"
    ).encode()


def build_jvm(profile: str, java_home: str = "${JAVA_HOME}") -> dict[str, object]:
    flavor = contract.profile_spec(profile).flavor
    return {
        "schema": 1,
        "kind": "qperiapt.android_agp_build_jvm",
        "task": f":app:compile{flavor}ReleaseJavaWithJavac",
        "java_home": java_home,
        "java_version": "21.0.11",
        "java_runtime_version": "21.0.11+10",
        "java_vendor": "Homebrew",
        "java_vm_vendor": "Homebrew",
        "java_vm_version": "21.0.11",
        "compiler_java_home": java_home,
        "compiler_fork": False,
    }


def sdk_runner(tool: pathlib.Path, arguments: list[str]) -> bytes:
    """The only mocked boundary. It inspects the real selected input bytes."""
    expected_prefixes = {
        "dexdump": [],
        "apksigner": ["verify", "--min-sdk-version", "23", "--print-certs"],
        "zipalign": ["-c", "-P", "16", "-v", "4"],
        "aapt2": ["dump", "xmltree", "--file", "AndroidManifest.xml"],
    }
    if (
        tool.name not in expected_prefixes
        or arguments[:-1] != expected_prefixes[tool.name]
    ):
        raise AssertionError(
            "SDK replay arguments differ from the fixed verification operation"
        )
    subject = pathlib.Path(arguments[-1])
    if tool.name == "dexdump":
        if subject.read_bytes() not in tuple(b"dex\n039\x00" + flavor.encode() for flavor in ("full", "minimal", "sdk-full", "sdk-minimal")):
            raise contract.AndroidAgpConsumerError(
                "fixture SDK rejected the changed DEX bytes"
            )
        dump = SDK_DEX_DUMP if subject.read_bytes().startswith(b"dex\n039\x00sdk-") else DEX_DUMP
        return f"Processing '{subject}'...\n".encode() + dump.encode()
    entries = consumer._apk_entries(subject)
    if tool.name == "apksigner":
        if entries.get("META-INF/QPERIAPT.RSA") != b"fixture-signature":
            raise contract.AndroidAgpConsumerError("fixture SDK rejected unsigned APK")
        return SIGNER
    if tool.name == "zipalign":
        if entries.get("alignment.fixture") != b"16384":
            raise contract.AndroidAgpConsumerError("fixture SDK rejected unaligned APK")
        return ALIGNMENT
    if tool.name == "aapt2":
        if entries.get("AndroidManifest.xml") not in (b"fixture binary manifest", b"fixture sdk binary manifest"):
            raise contract.AndroidAgpConsumerError(
                "fixture SDK rejected changed binary manifest"
            )
        return (SDK_MANIFEST_DUMP if entries["AndroidManifest.xml"] == b"fixture sdk binary manifest" else MANIFEST_DUMP).encode()
    raise AssertionError("unexpected SDK command in AGP fixture")


@dataclasses.dataclass(frozen=True)
class AgpProfileFixture:
    root: pathlib.Path
    proof: pathlib.Path
    sdk: pathlib.Path
    expected: dict[str, str]


@dataclasses.dataclass(frozen=True)
class AgpFixturePair:
    root: pathlib.Path
    sdk: pathlib.Path
    aar: pathlib.Path
    aar_manifest: pathlib.Path
    profiles: dict[str, AgpProfileFixture]


def create_agp_fixture_pair(directory: pathlib.Path, *, sdk_profile: bool = False,
                            device_abi: str = "arm64-v8a",
                            expected_runtime_profile: str = contract.DEFAULT_RUNTIME_PROFILE) -> AgpFixturePair:
    """Build two complete synthetic profiles sharing one real source commit and AAR."""
    root = directory.resolve() / "source"
    root.mkdir(mode=0o700, parents=True)
    original = AndroidElfVerifierTests()
    original.root = root
    _, aar, manifest, _, _, manifest_value = original.manifest_release_fixture()
    selected_profiles = ("agp_sdk_full_release", "agp_sdk_minimal_release") if sdk_profile else ("agp_full_release", "agp_minimal_release")
    package = android_elf.package_profile("sdk-020" if sdk_profile else "legacy")
    names = set()
    for profile in selected_profiles:
        contract.runtime_target(profile, device_abi, expected_runtime_profile)
        names.update(runtime.source_inputs(runtime.RuntimeResultProfile(profile)).values())
        names.update(consumer.source_inputs(profile))
    names.add(package.contract)
    if sdk_profile:
        names.update(android_elf.SDK_NOTICE_SOURCES.values())
        entries, _ = android_elf.audit_aar(aar)
        entries.update({name: (ROOT / path).read_bytes() for name, path in android_elf.SDK_NOTICE_SOURCES.items()})
        classes = dict(CLASS_ENTRIES)
        for name in ("QPeriaptSDK", *("QPeriaptSDK$" + owner for owner in
            ("Runtime", "Key", "PublicKey", "Ciphertext", "Secret", "DerivedKey", "Encapsulation", "KeyPurpose", "PolicyStates", "PolicyUpdate", "Expert"))):
            classes["dev/qperiapt/android/" + name + ".class"] = CLASS_BYTES
        entries["classes.jar"] = zip_bytes(classes)
        aar = aar.with_name(f"q-periapt-android-{package.version}.aar")
        write(aar, zip_bytes(entries))
        manifest_value.update(schema_version=package.schema, kind=package.kind, version=package.version, package=aar.name,
            jni={"extension_version": 1, "method_count": 26, "methods": package.jni_methods})
        manifest_value["abi"].update(contract_path=package.contract, export_count=len(package.exports),
            exports_sha256=hashlib.sha256(("\n".join(sorted(package.exports)) + "\n").encode()).hexdigest())
        manifest_value["artifacts"].update(aar_sha256=digest(aar), classes_jar_sha256=hashlib.sha256(entries["classes.jar"]).hexdigest())
    for name in names:
        write(root / name, (ROOT / name).read_bytes())
    subprocess.run(
        ["git", "-C", str(root), "add", "."], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "-qm", "Record consumer fixture source"],
        check=True,
        capture_output=True,
    )
    commit = runtime.git_commit(root)
    tree = runtime.current_source_tree_digest(root)
    epoch = int(
        subprocess.check_output(
            ["git", "-C", str(root), "show", "-s", "--format=%ct", "HEAD"], text=True
        )
    )
    manifest_value.update(
        git_commit=commit,
        source_tree_sha256=tree,
        source_date_epoch=epoch,
        generated_at=dt.datetime.fromtimestamp(epoch, dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
    )
    manifest_value["abi"]["contract_sha256"] = digest(
        root / manifest_value["abi"]["contract_path"]
    )
    for field, source in {
        "java_facade_sha256": "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java",
        "jni_adapter_sha256": "bindings/android/jni/qperiapt_jni.c",
        "script_sha256": "artifact/android-aar.sh",
        "elf_verifier_sha256": "artifact/android_elf.py",
        "release_binary_scan_sha256": "artifact/release_binary_scan.py",
        "third_party_license_collector_sha256": "artifact/third_party_licenses.py",
    }.items():
        manifest_value["artifacts"][field] = digest(root / source)
    if sdk_profile:
        manifest_value["artifacts"].update(
            java_sdk_sha256=digest(root / "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptSDK.java"),
            sdk_spec_sha256=digest(root / "artifact/sdk_abi2_spec.py"))
    write(manifest, android_elf.canonical_json(manifest_value))
    aar_entries, _ = android_elf.audit_aar(aar, profile="sdk-020" if sdk_profile else "legacy")
    sdk = root / "target/sdk"
    for tool in ("apksigner", "zipalign", "dexdump", "aapt2"):
        path = sdk / "build-tools/36.0.0" / tool
        write(path, b"#!/bin/sh\nexit 99\n")
        path.chmod(0o700)
    profiles = {}
    for profile, run_id in zip(selected_profiles, ("a" * 32, "b" * 32)):
        spec = contract.profile_spec(profile)
        proof_root = root / "target" / runtime.ANDROID_RUNS_ROOT_LEAF / run_id / "proof"
        proof_root.mkdir(mode=0o700, parents=True)
        proof_root.parent.chmod(0o700)
        proof_root.parent.parent.chmod(0o700)
        proof_path = proof_root / runtime.ANDROID_PROOF_LEAF
        proof = complete_proof_shape()
        proof.update(
            schema=1,
            kind=spec.proof_kind,
            git_commit=commit,
            proof_source_tree_sha256=tree,
            run_id=run_id,
            release_candidate_mode=True,
        )
        proof["device"].update(contract.runtime_target(profile, device_abi, expected_runtime_profile))
        if proof["device"]["kind"] == "physical":
            proof["emulator_control"] = None
        else:
            proof["emulator_control"]["backend"]["identity"] = "qemu-system-" + ("aarch64" if device_abi == "arm64-v8a" else "x86_64") + "-headless"
        proof["abi"]["contract_path"] = package.contract
        tests = list(contract.PROFILE_TESTS[profile])
        marker = (
            runtime.expected_marker(
                run_id, runtime.RuntimeResultProfile(profile)
            ).encode()
            + b"\n"
        )
        result = json_bytes(
            {
                "schema": 1,
                "status": "pass",
                "run_id": run_id,
                "test_count": len(tests),
                "passed_tests": tests,
            }
        )
        leaves = runtime.bundle_file_paths(proof)
        paths = {
            name: proof_root / pathlib.Path(leaves[name]).name
            for name in runtime.expected_proof_path_keys(proof)
        }
        paths.update(
            aar=aar,
            aar_manifest=manifest,
            smoke_apk=proof_root / "qperiapt-android-smoke.apk",
            result_txt=proof_root / "qperiapt-android-device-result.txt",
            result_json=proof_root / "qperiapt-android-device-result.json",
            logcat=proof_root / "logcat.txt",
            apksigner_verify=proof_root / "apksigner-verify.txt",
            zipalign_verify=proof_root / "zipalign-verify.txt",
        )
        flavor = spec.flavor.lower()
        apk_entries = {
            "AndroidManifest.xml": b"fixture sdk binary manifest" if sdk_profile else b"fixture binary manifest",
            "classes.dex": b"dex\n039\x00" + (("sdk-" if sdk_profile else "") + flavor).encode(),
            "alignment.fixture": b"16384",
        }
        apk_entries.update(
            {
                "lib/" + name[4:]: data
                for name, data in aar_entries.items()
                if name.startswith("jni/")
            }
        )
        apk_entries.update({"assets/" + name: (root / "bindings" / name).read_bytes() for name in spec.fixtures})
        write(
            paths["smoke_apk"],
            zip_bytes({**apk_entries, "META-INF/QPERIAPT.RSA": b"fixture-signature"}),
        )
        write(paths["result_txt"], marker)
        write(paths["result_json"], result)
        write(paths["apksigner_verify"], SIGNER)
        write(paths["zipalign_verify"], ALIGNMENT)
        write(paths["logcat"], b"I/QPeriaptSmoke: " + marker)
        if proof["emulator_control"] is not None:
            private = proof["emulator_control"]["private_adb"]
            status = (
                f'executable_absolute_path: {json.dumps(str(proof_root.parent / "work" / ("adb-" + run_id)))}\n'
                f'keystore_path: {json.dumps(str(runtime.current_account_home() / ".android/adbkey"))}\nmdns_enabled: false\n'
            ).encode()
            listener = f"p123\nu{os.geteuid()}\nf7\nn/tmp/qperiapt-adb.abcdefgh/adb.sock\n".encode()
            write(proof_root / "adb-server-status-registered.txt", status)
            write(proof_root / "adb-listener-registered.txt", listener)
            private["server_status_sha256"] = hashlib.sha256(status).hexdigest()
            private["listener_snapshot_sha256"] = hashlib.sha256(listener).hexdigest()
            routing, checkpoints = write_emulator_isolation_receipts(
                proof_root, run_id=run_id, private_adb=private
            )
            paths["emulator_routing"] = routing
            external = runtime._parse_emulator_routing_receipt(
                routing, run_id=run_id, expected_private_adb=private, bundled=False
            )
            proof["emulator_control"]["external_adb"] = external
            for item, checkpoint in zip(
                proof["emulator_control"]["native_notifier"]["admission_checkpoints"],
                runtime.ADB_ISOLATION_CHECKPOINTS,
            ):
                paths[runtime.ADB_ISOLATION_PATH_KEY_BY_CHECKPOINT[checkpoint]] = (
                    checkpoints[checkpoint]
                )
                item["receipt_sha256"] = digest(checkpoints[checkpoint])
        proof["abi"]["contract_sha256"] = digest(root / proof["abi"]["contract_path"])
        for tool in ("apksigner", "zipalign"):
            proof["android"][tool + "_sha256"] = digest(
                sdk / "build-tools/36.0.0" / tool
            )
        proof["source_hashes"] = {
            key + "_sha256": digest(root / name)
            for key, name in runtime.source_inputs(runtime.RuntimeResultProfile(profile)).items()
        }
        for field, key in (
            ("aar_sha256", "aar"),
            ("aar_manifest_sha256", "aar_manifest"),
            ("smoke_apk_sha256", "smoke_apk"),
            ("apksigner_verify_sha256", "apksigner_verify"),
            ("zipalign_verify_sha256", "zipalign_verify"),
            ("logcat_sha256", "logcat"),
        ):
            proof["artifacts"][field] = digest(paths[key])
        proof["artifacts"]["native"] = manifest_value["artifacts"]["native"]
        proof["result"] = {
            "marker_sha256": digest(paths["result_txt"]),
            "json_sha256": digest(paths["result_json"]),
            "status": "pass",
            "test_count": len(tests),
            "passed_tests": tests,
        }
        proof["paths"] = {
            key: str(path.relative_to(root)) for key, path in paths.items()
        }
        build_root = proof_root / "agp-build"
        build_root.mkdir(mode=0o700)
        default = (
            ROOT / "artifact/fixtures/android-agp-proguard-9.4.0.txt"
        ).read_bytes()

        def section(origin: str, body: bytes) -> bytes:
            return (
                f"# The proguard configuration file for the following section is {origin}\n".encode()
                + body
                + b"\n"
                + f"# End of content from {origin}\n".encode()
            )

        manifest_rules = b"-keep class dev.qperiapt.androidsmoke.QPeriaptSmokeActivity { <init>(); }\n-keep class dev.qperiapt.androidsmoke.QPeriaptResultInstrumentation { <init>(); }\n"
        merged = section(
            f"Android Gradle plugin {spec.agp_version} (extracted file: ${{WORK}}/project/app/build/intermediates/default_proguard_files/global/proguard-android-optimize.txt-{spec.agp_version})",
            default,
        )
        merged += section(
            f"${{GRADLE_HOME}}/caches/{spec.gradle_version}/transforms/fixture/transformed/q-periapt-android-" + spec.version + "/proguard.txt",
            aar_entries["proguard.txt"],
        )
        merged += section("<unknown>", b"")
        data = {
            "agp_apk": zip_bytes(
                {
                    **apk_entries,
                    consumer.APP_METADATA_ENTRY: consumer.app_metadata_content(profile),
                }
            ),
            "apk": zip_bytes(apk_entries),
            "dexdump": b"Processing '${APK_INSPECTION}/classes.dex'...\n"
            + (SDK_DEX_DUMP if sdk_profile else DEX_DUMP).encode(),
            "manifest_dump": (SDK_MANIFEST_DUMP if sdk_profile else MANIFEST_DUMP).encode(),
            "mapping": b"fixture mapping\n",
            "r8_configuration": merged,
            "gradle_log": (
                f"> Task :app:compile{flavor.title()}ReleaseJavaWithJavac\n"
                f"> Task :app:minify{flavor.title()}ReleaseWithR8\nBUILD SUCCESSFUL\n"
            ).encode(),
            "gradle_version": gradle_version(profile=profile),
            "build_jvm": json_bytes(build_jvm(profile)),
            "compilation_inputs": (
                "\n".join(consumer.compiled_sources(profile)) + "\n"
            ).encode(),
            "default_proguard": default,
            "manifest_proguard": manifest_rules,
        }
        build_paths = {
            key: build_root / name for key, name in consumer.BUILD_FILE_NAMES.items()
        }
        for key, path in build_paths.items():
            write(path, data[key])
        receipt = {
            "schema": 1,
            "kind": spec.build_kind,
            "profile": profile,
            "status": "pass",
            "source_commit": commit,
            "source_tree_sha256": tree,
            "aar_sha256": digest(aar),
            "aar_manifest_sha256": digest(manifest),
            "agp_version": spec.agp_version,
            "gradle_version": spec.gradle_version,
            "minify_enabled": True,
            "debuggable": False,
            "app_q_keep_rules": [],
            "signing_input": consumer.verify_signing_input(
                build_paths["agp_apk"], build_paths["apk"], profile=profile
            ),
            "files": {key: record(path) for key, path in build_paths.items()},
            "dex_sha256": {
                "classes.dex": hashlib.sha256(apk_entries["classes.dex"]).hexdigest()
            },
            "source_files": {
                name: digest(root / name) for name in consumer.source_inputs(profile)
            },
            "compiled_application_sources": consumer.compiled_sources(profile),
            "tools": {
                "dexdump": digest(sdk / "build-tools/36.0.0/dexdump"),
                "aapt2": digest(sdk / "build-tools/36.0.0/aapt2"),
                "gradle_wrapper": digest(root / consumer.TEMPLATE_ROOT / "gradlew"),
            },
            "diagnostics": {
                "policy": consumer.NORMALIZATION_POLICY,
                "normalized_public": sorted(consumer.NORMALIZED_FILES),
                "raw_private_sha256": {
                    name: "e" * 64 for name in consumer.RAW_DIAGNOSTIC_FILES
                },
            },
        }
        build_receipt = build_root / "receipt.json"
        write(build_receipt, json_bytes(receipt))
        import base64

        transport = (
            f"INSTRUMENTATION_RESULT: qperiapt_run_id={run_id}\n"
            f"INSTRUMENTATION_RESULT: qperiapt_result_text_base64={base64.b64encode(marker).decode()}\n"
            f"INSTRUMENTATION_RESULT: qperiapt_result_json_base64={base64.b64encode(result).decode()}\nINSTRUMENTATION_CODE: -1\n"
        ).encode()
        instrumentation = proof_root / "adb-instrumentation.txt"
        write(instrumentation, transport)
        proof["consumer"] = {
            "profile": profile,
            "build_receipt": record(
                build_receipt, str(build_receipt.relative_to(root))
            ),
            "instrumentation_output": record(
                instrumentation, str(instrumentation.relative_to(root))
            ),
            "instrumentation": consumer.INSTRUMENTATION,
        }
        write(proof_path, json_bytes(proof))
        profiles[profile] = AgpProfileFixture(
            root,
            proof_path,
            sdk,
            {
                "expected_profile": profile,
                "expected_aar_sha256": digest(aar),
                "expected_aar_manifest_sha256": digest(manifest),
                "expected_source_commit": commit,
                **({"expected_device_abi": device_abi,
                    "expected_runtime_profile": expected_runtime_profile} if sdk_profile else {}),
            },
        )
    return AgpFixturePair(root, sdk, aar, manifest, profiles)
