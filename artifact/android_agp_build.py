#!/usr/bin/env python3
"""Build one exact-AAR AGP Release profile; device ownership stays in the existing lane."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess

import android_agp_consumer as consumer
import android_device_proof as runtime
import android_elf
from android_agp_consumer_contract import (
    AGP_VERSION,
    BUILD_KIND,
    GRADLE_VERSION,
    AndroidAgpConsumerError,
    require,
)
from bounded_process import BoundedProcessError, capture_stdout


def write_new(path: pathlib.Path, data: bytes) -> None:
    with path.open("xb") as output:
        output.write(data)


def record(path: pathlib.Path) -> dict[str, object]:
    data = consumer._bytes(path, consumer.MAX_APK)
    return {
        "path": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def normalized(data: bytes, roots: dict[str, pathlib.Path]) -> bytes:
    """Replace only explicitly selected roots; preserve every diagnostic/rule and line."""
    text = data.decode("utf-8")
    for label, root in sorted(
        roots.items(), key=lambda item: len(str(item[1])), reverse=True
    ):
        text = text.replace(str(root), "${" + label + "}")
    consumer.verify_normalized_text(text)
    return text.encode("utf-8")


def _run(
    argv: list[str],
    raw_path: pathlib.Path,
    public_path: pathlib.Path,
    roots: dict[str, pathlib.Path],
    *,
    timeout: int,
) -> None:
    environment = dict(os.environ)
    environment["ANDROID_HOME"] = str(roots["SDK"])
    environment["ANDROID_SDK_ROOT"] = str(roots["SDK"])
    environment["JAVA_HOME"] = str(roots["JAVA_HOME"])
    # Preserve the bounded raw stream even on timeout, signal, or tool failure.
    with raw_path.open("xb") as output:

        def retain(chunk: bytes) -> None:
            output.write(chunk)
            output.flush()

        result = capture_stdout(
            argv,
            timeout_seconds=timeout,
            maximum_bytes=consumer.MAX_TEXT,
            stderr=subprocess.STDOUT,
            environment=environment,
            output_sink=retain,
        )
    # A failed tool result is retained too; it never receives a passing build receipt.
    write_new(public_path, normalized(result.stdout, roots))
    require(
        result.returncode == 0, f"{raw_path.name} failed with exit {result.returncode}"
    )
    consumer.verify_diagnostic_log(result.stdout.decode("utf-8"))


def build(args: argparse.Namespace) -> None:
    root = args.root.resolve(strict=True)
    consumer._profile(args.profile)
    require(
        not runtime.source_tree_dirty(root),
        "AGP collector requires a clean source checkout",
    )
    commit = runtime.git_commit(root)
    source_tree = runtime.current_source_tree_digest(root)
    require(commit == args.expected_source_commit, "selected AGP source commit differs")
    require(
        consumer._digest(args.aar, consumer.MAX_APK) == args.expected_aar_sha256,
        "selected exact AAR hash differs",
    )
    require(
        consumer._digest(args.aar_manifest) == args.expected_aar_manifest_sha256,
        "selected exact AAR manifest hash differs",
    )
    entries, _ = android_elf.audit_aar(args.aar)
    android_elf.verify_manifest(
        args.aar_manifest,
        aar_path=args.aar,
        entries=entries,
        aar_sha256=args.expected_aar_sha256,
        expected_manifest_sha256=args.expected_aar_manifest_sha256,
        require_release=True,
        forbidden_text=[str(root)],
        source_root=root,
    )
    require(
        consumer._json(args.aar_manifest)["git_commit"] == commit,
        "AAR manifest does not identify the selected source commit",
    )
    for path in (args.work, args.output, args.raw_output):
        require(
            not path.exists() and not path.is_symlink(), "AGP output already exists"
        )
        path.parent.resolve(strict=True).relative_to(root / "target")
    for name in ("GRADLE_OPTS", "JAVA_OPTS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"):
        require(not os.environ.get(name), f"{name} must be unset for the AGP consumer")
    gradle_home = pathlib.Path(
        os.environ.get("GRADLE_USER_HOME", str(pathlib.Path.home() / ".gradle"))
    ).resolve()
    require(
        not any(
            (gradle_home / name).exists() for name in ("init.gradle", "init.gradle.kts")
        ),
        "AGP consumer refuses global Gradle initialization scripts",
    )
    if (gradle_home / "init.d").exists():
        require(
            not any((gradle_home / "init.d").iterdir()),
            "AGP consumer refuses Gradle init.d entries",
        )
    require(
        bool(os.environ.get("JAVA_HOME")), "AGP consumer requires an explicit JAVA_HOME"
    )
    java_home = pathlib.Path(os.environ["JAVA_HOME"]).resolve(strict=True)
    distributions = list(
        (gradle_home / f"wrapper/dists/gradle-{GRADLE_VERSION}-bin").glob(
            f"*/gradle-{GRADLE_VERSION}/bin/gradle"
        )
    )
    require(
        len(distributions) == 1 and distributions[0].is_file(),
        "pinned Gradle distribution is not already cached",
    )
    sdk = args.sdk.resolve(strict=True)
    tools = sdk / "build-tools/36.0.0"
    for name in ("dexdump", "aapt2"):
        require(
            (tools / name).is_file(), "AGP consumer requires SDK Build Tools 36.0.0"
        )
    args.work.mkdir(mode=0o700)
    args.output.mkdir(mode=0o700)
    args.raw_output.mkdir(mode=0o700)
    project = args.work / "project"
    project.mkdir(mode=0o700)
    # Only the reviewed template and the selected workload's exact Java files are copied.
    for rel in consumer.TEMPLATE_FILES:
        source = root / rel
        target = project / pathlib.PurePosixPath(rel).relative_to(
            consumer.TEMPLATE_ROOT
        )
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(target, consumer._bytes(source))
        if target.name == "gradlew":
            target.chmod(0o700)
    smoke = args.work / "smoke"
    for rel in consumer.compiled_sources(args.profile):
        if rel.startswith(consumer.SMOKE_ROOT + "/"):
            target = smoke / pathlib.PurePosixPath(rel).relative_to(consumer.SMOKE_ROOT)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_new(target, consumer._bytes(root / rel))
    exact = args.work / args.aar.name
    write_new(exact, consumer._bytes(args.aar, consumer.MAX_APK))
    assets = args.work / "assets"
    assets.mkdir(mode=0o700)
    if args.profile == "agp_full_release":
        write_new(
            assets / "signed-policy-vectors.json",
            consumer._bytes(root / "bindings/signed-policy-vectors.json"),
        )
    roots = {
        "WORK": args.work.resolve(),
        "SOURCE": root,
        "SDK": sdk,
        "GRADLE_HOME": gradle_home,
        "JAVA_HOME": java_home,
        "USER_HOME": pathlib.Path.home().resolve(),
    }
    wrapper = project / "gradlew"
    base = [
        str(wrapper),
        "--project-dir",
        str(project),
        "--offline",
        "--no-daemon",
        "--no-build-cache",
        "--no-configuration-cache",
        "--max-workers=2",
        "--warning-mode=fail",
        "--console=plain",
    ]
    _run(
        base + ["--version"],
        args.raw_output / "gradle-version.txt",
        args.output / "gradle-version.txt",
        roots,
        timeout=120,
    )
    _run(
        [str(java_home / "bin/java"), "-version"],
        args.raw_output / "java-version.txt",
        args.output / "java-version.txt",
        roots,
        timeout=30,
    )
    flavor = "Full" if args.profile == "agp_full_release" else "Minimal"
    capture = args.work / "compilation-inputs.txt"
    _run(
        base
        + [
            f"-PqperiaptAar={exact}",
            f"-PqperiaptSmokeRoot={smoke}",
            f"-PqperiaptFixtureAssets={assets}",
            f"-PqperiaptInputCapture={capture}",
            f":app:assemble{flavor}Release",
        ],
        args.raw_output / "gradle-build.log",
        args.output / "gradle-build.log",
        roots,
        timeout=900,
    )
    compiled = []
    raw_inputs = consumer._bytes(capture)
    write_new(args.raw_output / "compilation-inputs.txt", raw_inputs)
    selected_paths = {
        str(
            (
                smoke / pathlib.PurePosixPath(rel).relative_to(consumer.SMOKE_ROOT)
            ).resolve()
        ): rel
        for rel in consumer.compiled_sources(args.profile)
        if rel.startswith(consumer.SMOKE_ROOT + "/")
    }
    instrumentation_rel = consumer.INSTRUMENTATION_SOURCE
    instrumentation_path = project / pathlib.PurePosixPath(
        instrumentation_rel
    ).relative_to(consumer.TEMPLATE_ROOT)
    selected_paths[str(instrumentation_path.resolve())] = instrumentation_rel
    for path in raw_inputs.decode("utf-8").splitlines():
        require(
            path in selected_paths,
            "JavaCompile received an unregistered application source",
        )
        compiled.append(selected_paths[path])
    require(
        len(compiled) == len(set(compiled))
        and set(compiled) == set(consumer.compiled_sources(args.profile)),
        "JavaCompile did not receive the exact selected profile inputs",
    )
    compiled.sort()
    write_new(
        args.output / "compilation-inputs.txt", ("\n".join(compiled) + "\n").encode()
    )
    variant = flavor.lower() + "Release"
    apk = (
        project
        / f"app/build/outputs/apk/{flavor.lower()}/release/app-{flavor.lower()}-release-unsigned.apk"
    )
    write_new(
        args.output / "consumer-unsigned.apk", consumer._bytes(apk, consumer.MAX_APK)
    )
    mapping = project / f"app/build/outputs/mapping/{variant}"
    for original, output in (
        ("mapping.txt", "mapping.txt"),
        ("configuration.txt", "r8-configuration.txt"),
    ):
        data = consumer._bytes(mapping / original)
        write_new(args.raw_output / output, data)
        write_new(args.output / output, normalized(data, roots))
    default = (
        project
        / f"app/build/intermediates/default_proguard_files/global/proguard-android-optimize.txt-{AGP_VERSION}"
    )
    write_new(args.output / "default-proguard.txt", consumer._bytes(default))
    # AAPT manifest roots are kept independently of Java test reachability.
    aapt_rules = (
        project
        / f"app/build/intermediates/aapt_proguard_file/{variant}/process{flavor}ReleaseResources/aapt_rules.txt"
    )
    write_new(
        args.output / "manifest-proguard.txt",
        normalized(consumer._bytes(aapt_rules), roots),
    )
    apk_entries = consumer._apk_entries(apk)
    dex_hashes = {
        name: hashlib.sha256(data).hexdigest()
        for name, data in apk_entries.items()
        if consumer.DEX_NAME.fullmatch(name)
    }
    inspection = consumer.inspect_apk_program(
        apk, dexdump=tools / "dexdump", aapt2=tools / "aapt2"
    )
    for name, raw, public in (
        ("dexdump.txt", inspection.raw_dexdump, inspection.dexdump),
        ("manifest-dump.txt", inspection.raw_manifest_dump, inspection.manifest_dump),
    ):
        write_new(args.raw_output / name, raw)
        write_new(args.output / name, public)
    private_roots = {label: str(path) for label, path in roots.items()}
    private_roots["APK_INSPECTION"] = str(inspection.private_root)
    write_new(
        args.raw_output / "normalization-roots.json",
        (
            json.dumps(
                {
                    "policy": consumer.NORMALIZATION_POLICY,
                    "roots": private_roots,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode(),
    )
    require(
        not runtime.source_tree_dirty(root)
        and runtime.git_commit(root) == commit
        and runtime.current_source_tree_digest(root) == source_tree,
        "AGP source changed during collection",
    )
    require(
        consumer._digest(args.aar, consumer.MAX_APK) == args.expected_aar_sha256
        and consumer._digest(args.aar_manifest) == args.expected_aar_manifest_sha256,
        "selected AAR changed during collection",
    )
    files = {
        key: record(args.output / name)
        for key, name in consumer.BUILD_FILE_NAMES.items()
    }
    receipt = {
        "schema": 1,
        "kind": BUILD_KIND,
        "profile": args.profile,
        "status": "pass",
        "source_commit": commit,
        "source_tree_sha256": source_tree,
        "aar_sha256": args.expected_aar_sha256,
        "aar_manifest_sha256": args.expected_aar_manifest_sha256,
        "agp_version": AGP_VERSION,
        "gradle_version": GRADLE_VERSION,
        "minify_enabled": True,
        "debuggable": False,
        "app_q_keep_rules": [],
        "files": files,
        "dex_sha256": dex_hashes,
        "compiled_application_sources": compiled,
        "source_files": {
            rel: consumer._digest(root / rel)
            for rel in consumer.source_inputs(args.profile)
        },
        "tools": {
            "dexdump": consumer._digest(tools / "dexdump"),
            "aapt2": consumer._digest(tools / "aapt2"),
            "gradle_wrapper": consumer._digest(wrapper),
        },
        "diagnostics": {
            "policy": consumer.NORMALIZATION_POLICY,
            "normalized_public": sorted(consumer.NORMALIZED_FILES),
            "raw_private_sha256": {
                name: consumer._digest(args.raw_output / name)
                for name in consumer.RAW_DIAGNOSTIC_FILES
            },
        },
    }
    consumer._verify_build(
        root,
        receipt,
        {key: args.output / name for key, name in consumer.BUILD_FILE_NAMES.items()},
        profile=args.profile,
        aar=args.aar,
        signed_apk=apk,
    )
    write_new(
        args.output / "receipt.json",
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
    )
    print(
        f"ANDROID_AGP_BUILD_PASS profile={args.profile} receipt={args.output / 'receipt.json'}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "work", "output", "raw-output", "aar", "aar-manifest", "sdk"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    for name in (
        "profile",
        "expected-source-commit",
        "expected-aar-sha256",
        "expected-aar-manifest-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    try:
        build(parser.parse_args())
    except (
        AndroidAgpConsumerError,
        BoundedProcessError,
        android_elf.AndroidVerificationError,
        OSError,
        ValueError,
    ) as error:
        parser.exit(1, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
