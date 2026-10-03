#!/usr/bin/env python3
"""Build and install a local product WASM npm candidate; never publish a release."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import tomllib

from bounded_process import capture_output
from c_package_manifest import rust_workspace_source_digest
from deterministic_archive import create_tar_gz, extract_tar_gz
from evidence_io import load_json_object_snapshot, parse_strict_json_bytes, read_regular_snapshot
from third_party_licenses import collect as collect_licenses, verify as verify_licenses

ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "crates/q-periapt-sdk-wasm"
NAME = "q-periapt-sdk-wasm"
VERSION = "0.2.0"
TARGET = "wasm32-unknown-unknown"
CONTENTS = "PACKAGE_CONTENTS.json"
MTIME = 946684800
GENERATED = ("q_periapt_sdk_wasm.js", "q_periapt_sdk_wasm.d.ts", "q_periapt_sdk_wasm_bg.wasm")
POLICIES = ("signed-policy-vectors.json", "sdk-policy-revocation-vectors.json", "sdk-policy-update-vectors.json")
NOTICES = ("LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt", "LICENSES/Rust-1.98.1-library.html")
VENDOR_NOTICES = ("LICENSE.mlkem-native", "PROVENANCE.md", "INVENTORY.sha256", "LICENSE-INVENTORY.md")
CONSUMER_FILES = ("product.cjs", "installed.mjs", "browser.html", "browser-acceptance.js",
                  "browser-suite.mjs", "browser-worker.mjs", "serve.cjs", "types.mts", "types.cts")
NODE_TESTS = {
    "product.cjs": "WASM_PRODUCT_LIFECYCLE_POLICY_ROUNDTRIP_FAILURE_PASS",
    "installed.mjs": "WASM_INSTALLED_CJS_ESM_SINGLE_INSTANCE_PASS",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def snapshot(path: Path):
    return read_regular_snapshot(path, maximum=16 * 1024 * 1024, label="WASM SDK package input")


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")


def copy(source: Path, destination: Path) -> None:
    data = snapshot(source).data
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as out:
        out.write(data)
    destination.chmod(0o644)


def entries(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"package symlink is forbidden: {path}")
        if path.is_dir():
            continue
        data = snapshot(path)
        result[path.relative_to(root).as_posix()] = {"bytes": data.size, "sha256": data.sha256}
    return result


def sources() -> dict:
    paths = [ROOT / name for name in (*NOTICES, "artifact/wasm_sdk_package.py",
        "artifact/third_party_licenses.py", "artifact/deterministic_archive.py", "artifact/evidence_io.py",
        "artifact/bounded_process.py", "artifact/c_package_manifest.py")]
    paths += [ROOT / "bindings" / name for name in POLICIES]
    return {"rust_workspace_sha256": rust_workspace_source_digest(ROOT),
            "inputs": {p.relative_to(ROOT).as_posix(): snapshot(p).sha256 for p in paths}}


def verify_packlist(value: object, expected: dict) -> None:
    """Bind npm 12's package-name keyed report to the complete staged payload."""
    require(isinstance(value, dict) and set(value) == {NAME},
            "npm packlist must describe exactly the SDK package")
    package = value[NAME]
    require(isinstance(package, dict) and package.get("name") == NAME
            and package.get("version") == VERSION and package.get("id") == f"{NAME}@{VERSION}"
            and package.get("filename") == f"{NAME}-{VERSION}.tgz",
            "npm packlist package identity differs")
    files = package.get("files")
    require(isinstance(files, list) and len(files) == len(expected), "npm packlist file count differs")
    seen = set()
    for entry in files:
        require(isinstance(entry, dict) and set(entry) == {"path", "size", "mode"},
                "npm packlist file record differs")
        path = entry["path"]
        require(isinstance(path, str) and path in expected and path not in seen,
                "npm packlist contains an unexpected or duplicate file")
        require(type(entry["size"]) is int and entry["size"] == expected[path]["bytes"]
                and type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o777,
                "npm packlist file size or mode differs")
        seen.add(path)
    require(seen == set(expected), "npm packlist omitted or added package files")


def run(argv: list[str], log: Path, cwd: Path, *, environment=None) -> bytes:
    with contextlib.chdir(cwd):
        result = capture_output(argv, timeout_seconds=900, maximum_stdout_bytes=8 * 1024 * 1024,
            maximum_stderr_bytes=8 * 1024 * 1024, environment=environment)
    log.with_suffix(".stdout").write_bytes(result.stdout)
    log.with_suffix(".stderr").write_bytes(result.stderr)
    write_json(log.with_suffix(".json"), {"argv": argv, "cwd": str(cwd), "returncode": result.returncode})
    require(result.returncode == 0, f"command failed ({result.returncode}); see {log}.stderr")
    return result.stdout


def verify(root: Path, manifest_sha256: str) -> dict:
    record = load_json_object_snapshot(root / CONTENTS, maximum=1024 * 1024, label="WASM SDK manifest")
    require(record.file.sha256 == manifest_sha256, "WASM SDK pinned manifest digest differs")
    manifest = record.value
    require(set(manifest) == {"schema_version", "name", "version", "release_claim_eligible", "sources", "tools", "files"}
            and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
            and manifest["release_claim_eligible"] is False,
            "WASM SDK candidate manifest schema differs")
    require(manifest.get("name") == NAME and manifest.get("version") == VERSION,
            "WASM SDK package identity differs")
    actual = entries(root)
    del actual[CONTENTS]
    require(actual == manifest["files"], "WASM SDK payload inventory or digest differs")
    for relative, expected in entries(CRATE / "package").items():
        require(actual.get(relative) == expected, f"WASM SDK public entry differs: {relative}")
    shipped = {name: ROOT / name for name in NOTICES}
    shipped["README.md"] = CRATE / "PackageREADME.md"
    shipped.update({f"LICENSES/mlkem-native/{name}": ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name
                    for name in VENDOR_NOTICES})
    for relative, path in shipped.items():
        source = snapshot(path)
        require(actual.get(relative) == {"sha256": source.sha256, "bytes": source.size},
                f"WASM SDK notice or README differs: {relative}")
    for environment in ("node", "web"):
        for name in GENERATED:
            require(f"{environment}/{name}" in actual, "WASM SDK generated payload is incomplete")
    verify_licenses(root, expected_target=TARGET, root_package=NAME)
    return manifest


def validate_node_version(actual: str, expected: str | None) -> None:
    match = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)", actual)
    require(match is not None and int(match[1]) >= 24, "WASM SDK requires Node >=24")
    if expected is not None:
        require(actual == expected, "selected Node version differs from the required exact version")


def validate_consumer_source(manifest: dict) -> None:
    require(manifest.get("sources") == sources(),
            "WASM SDK archive source differs from this consumer checkout")


def runtime_inputs(node: Path, npm_cli: Path) -> dict:
    return {
        name: {"path": str(path), "sha256": read_regular_snapshot(
            path, maximum=256 * 1024 * 1024, label=f"WASM consumer {name}").sha256}
        for name, path in (("node", node), ("npm_cli", npm_cli))
    }


def consume(archive: Path, archive_sha: str, manifest_sha: str, output: Path, *,
            node: Path, npm_cli: Path, expected_node_version: str | None = None) -> dict:
    """Install and exercise one pinned archive with an explicitly selected runtime."""
    for digest in (archive_sha, manifest_sha):
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "expected SHA-256 is malformed")
    node, npm_cli = node.resolve(strict=True), npm_cli.resolve(strict=True)
    tools_before = runtime_inputs(node, npm_cli)
    before = sources()
    extract_tar_gz(archive, output / "extracted", root_name="package", mtime=MTIME,
                   expected_sha256=archive_sha)
    manifest = verify(output / "extracted/package", manifest_sha)
    validate_consumer_source(manifest)
    consumer = Path(tempfile.mkdtemp(prefix="qperiapt-wasm-install-")).resolve()
    require(not consumer.is_relative_to(ROOT), "WASM SDK consumer must be outside the checkout")
    write_json(output / "consumer-location.json", {"path": str(consumer)})
    write_json(consumer / "package.json", {"name": "q-periapt-sdk-consumer", "private": True})
    env = {name: value for name, value in os.environ.items()
           if name not in ("NODE_OPTIONS", "NODE_PATH") and not name.lower().startswith("npm_config_")}
    env["PATH"] = str(node.parent) + os.pathsep + env.get("PATH", os.defpath)
    env["npm_config_cache"] = str(output / "npm-cache")
    env["npm_config_update_notifier"] = "false"
    for name in ("userconfig", "globalconfig"):
        config = output / f"npm-{name}"
        with config.open("x", encoding="utf-8") as stream:
            stream.write("")
        env[f"npm_config_{name}"] = str(config)
    identity = parse_strict_json_bytes(run([str(node), "-p",
        "JSON.stringify({version:process.version,execPath:process.execPath,platform:process.platform,arch:process.arch,versions:process.versions})"],
        output / "consumer-node-identity", consumer, environment=env), label="Node runtime identity")
    require(isinstance(identity, dict) and isinstance(identity.get("version"), str), "Node identity is malformed")
    validate_node_version(identity["version"], expected_node_version)
    require(Path(identity["execPath"]).resolve(strict=True) == node, "Node executed from a different path")
    npm = [str(node), str(npm_cli)]
    npm_version = run([*npm, "--version"], output / "consumer-npm-version", consumer, environment=env).decode().strip()
    run([*npm, "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", str(archive)],
        output / "npm-install", consumer, environment=env)
    installed = consumer / "node_modules" / NAME
    verify(installed, manifest_sha)
    for name in POLICIES:
        copy(ROOT / "bindings" / name, consumer / "fixtures" / name)
    for name in CONSUMER_FILES:
        copy(CRATE / "tests" / name, consumer / name)
    env.update(QPERIAPT_SDK_PACKAGE=NAME, QPERIAPT_SDK_FIXTURES=str(consumer / "fixtures"))
    for name, marker in NODE_TESTS.items():
        log = output / f"consumer-{name}"
        result = run([str(node), str(consumer / name)], log, consumer, environment=env)
        require(result.decode().splitlines() == [marker], "WASM SDK consumer completion record differs")
        require(log.with_suffix(".stderr").read_bytes() == b"", "WASM SDK consumer emitted diagnostics")
    compiler = [*npm, "exec", "--offline", "--ignore-scripts", "--yes", "--package", "typescript@7.0.2", "--", "tsc"]
    compiler_env = dict(env)
    del compiler_env["npm_config_cache"]  # Read the preinstalled tool cache offline.
    typescript_version = run([*compiler, "--version"], output / "typescript-version", consumer, environment=compiler_env)
    require(typescript_version.decode().strip() == "Version 7.0.2", "TypeScript compiler identity differs")
    run([*compiler, "--noEmit", "--strict", "--module", "nodenext", "--target", "es2022",
         "--lib", "es2022,dom,esnext.disposable", "types.mts", "types.cts"],
        output / "typescript", consumer, environment=compiler_env)
    verify(installed, manifest_sha)
    require(snapshot(archive).sha256 == archive_sha, "WASM SDK archive changed during consumption")
    require(before == sources(), "WASM SDK consumer source changed during execution")
    require(tools_before == runtime_inputs(node, npm_cli), "WASM SDK runtime changed during execution")
    licenses = verify_licenses(installed, expected_target=TARGET, root_package=NAME)
    report = {"name": NAME, "version": VERSION, "archive": str(archive), "sha256": archive_sha,
        "manifest_sha256": manifest_sha, "installed": str(installed), "sources_unchanged": True,
        "source_bound": True, "runtime": identity, "runtime_inputs": tools_before, "npm_version": npm_version,
        "expected_node_version": expected_node_version,
        "consumer_inputs": {name: snapshot(consumer / name).sha256 for name in CONSUMER_FILES},
        "license_packages": len(licenses["packages"]), "installed_node_tests": "passed",
        "browser_runtime": "not-run", "typescript": "7.0.2 strict NodeNext passed", "release_claim_eligible": False}
    return report


def build(output: Path) -> dict:
    require(not output.exists(), "WASM SDK output must be a fresh directory")
    require(shutil.disk_usage(ROOT).free >= 1024 ** 3, "WASM SDK build needs at least 1 GiB free")
    require(tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"] == VERSION,
            "WASM SDK version differs from workspace")
    output.mkdir(parents=True)
    before = sources()
    write_json(output / "sources-before.json", before)
    tools = {}
    for tool in ("rustc", "cargo", "node", "npm", "wasm-pack"):
        tools[tool] = run([tool, "--version"], output / f"version-{tool}", ROOT).decode().strip()
    require(tools["rustc"].startswith("rustc 1.98.1 "), "Rust notices require the pinned Rust 1.98.1 toolchain")
    require(tools["npm"] == "12.1.0", "WASM SDK producer requires npm 12.1.0")
    require(tools["wasm-pack"] == "wasm-pack 0.15.0", "WASM SDK requires pinned wasm-pack 0.15.0")
    require(int(tools["node"].split(".")[0].lstrip("v")) >= 24, "WASM SDK requires Node >=24")
    for target in ("nodejs", "web"):
        run(["wasm-pack", "build", str(CRATE), "--mode", "no-install", "--target", target,
             "--release", "--out-dir", str(output / "generated" / target), "--", "--locked"],
             output / f"build-{target}", ROOT)
    package = output / "package"
    package.mkdir()
    for relative in entries(CRATE / "package"):
        copy(CRATE / "package" / relative, package / relative)
    for source, destination in (("nodejs", "node"), ("web", "web")):
        for name in GENERATED:
            copy(output / "generated" / source / name, package / destination / name)
    copy(CRATE / "PackageREADME.md", package / "README.md")
    for name in NOTICES:
        copy(ROOT / name, package / name)
    for name in VENDOR_NOTICES:
        copy(ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name, package / "LICENSES/mlkem-native" / name)
    collect_licenses(ROOT, package, TARGET, root_package=NAME)
    write_json(package / CONTENTS, {"schema_version": 1, "name": NAME, "version": VERSION,
        "release_claim_eligible": False, "sources": before, "tools": tools,
        "files": entries(package)})
    manifest_sha = snapshot(package / CONTENTS).sha256
    verify(package, manifest_sha)
    # Check npm's own packlist. The archive uses the existing bounded canonical
    # tar writer; npm consumes its standard package/ layout without any scripts.
    packlist = parse_strict_json_bytes(run(["npm", "pack", "--dry-run", "--ignore-scripts", "--json"],
        output / "npm-packlist", package), label="npm package file list")
    verify_packlist(packlist, entries(package))
    archive = output / f"{NAME}-{VERSION}.tgz"
    create_tar_gz(package, archive, root_name="package", mtime=MTIME)
    archive_sha = snapshot(archive).sha256
    node, npm = shutil.which("node"), shutil.which("npm")
    require(node is not None and npm is not None, "Node/npm consumer tools are missing")
    npm_cli = Path(npm).resolve(strict=True)
    if npm_cli.suffix.lower() in (".cmd", ".ps1"):
        npm_cli = npm_cli.parent / "node_modules/npm/bin/npm-cli.js"
    report = consume(archive, archive_sha, manifest_sha, output, node=Path(node), npm_cli=npm_cli)
    after = sources()
    write_json(output / "sources-after.json", after)
    require(before == after, "WASM SDK source inputs changed during packaging")
    write_json(output / "INSTALLED_CONSUMER.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--archive-sha256")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--node", type=Path)
    parser.add_argument("--npm-cli", type=Path)
    parser.add_argument("--expected-node-version")
    args = parser.parse_args()
    options = (args.archive, args.archive_sha256, args.manifest_sha256, args.node, args.npm_cli, args.expected_node_version)
    if any(value is not None for value in options):
        require(all(value is not None for value in options), "archive consumption requires all digest and runtime arguments")
        output = args.output.absolute()
        require(not output.exists(), "WASM SDK consumer output must be a fresh directory")
        output.mkdir(parents=True)
        report = consume(args.archive.absolute(), args.archive_sha256, args.manifest_sha256,
                         output, node=args.node, npm_cli=args.npm_cli, expected_node_version=args.expected_node_version)
        write_json(output / "INSTALLED_CONSUMER.json", report)
    else:
        report = build(args.output.absolute())
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
