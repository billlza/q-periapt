#!/usr/bin/env python3
"""Build the independent peer's native counterpart from exact installed archives.

This produces a test counterpart, not a released protocol or account service.
Runtime qualification must separately identify and execute the returned binary.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib

import continuity_package as package
from evidence_io import fresh_output_directory, parse_strict_json_bytes
from installed_rust_graph import verify_resolution
import rust_sdk_profile as sdk
from rust_sdk_msrv import validate_report

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "research/continuity-openssl-peer/native"
NAME = "q-periapt-independent-peer-counterpart"
PRODUCTS = tuple(name for name in sdk.CONSUMER_CRATES if name != "q-periapt-rustls")
VERSIONS = dict.fromkeys(PRODUCTS, sdk.VERSION) | {package.NAME: package.VERSION}


def installed_manifest(original: bytes) -> bytes:
    """Keep source settings; replace only the explicitly supported path edges."""
    parsed = tomllib.loads(original.decode())
    sdk.require(parsed["package"]["name"] == NAME and parsed["package"]["publish"] is False
                and parsed.get("workspace") == {} and "patch" not in parsed,
                "counterpart manifest identity or workspace differs")
    text = original.decode()
    expected = {package.NAME, "q-periapt-backends", "q-periapt-core", "q-periapt-policy",
                "q-periapt-sdk", "q-periapt-sig"}
    dependencies = parsed["dependencies"]
    sdk.require({name for name in dependencies if name.startswith("q-periapt")} == expected,
                "counterpart product dependencies differ")
    for name in sorted(expected):
        dep = dependencies[name]
        sdk.require(type(dep) is dict and set(dep) == {"path"} and type(dep["path"]) is str,
                    "counterpart dependency settings require explicit review")
        old = f'{name} = {{ path = "{dep["path"]}" }}'
        sdk.require(text.count(old) == 1, "counterpart dependency declaration differs")
        text = text.replace(old, f'{name} = {{ version = "={VERSIONS[name]}", '
                            f'path = "packages/{name}-{VERSIONS[name]}" }}')
    # Cargo automatically admits path dependencies below a workspace. These
    # literal exclusions keep installed dependencies from becoming test members.
    exclusions = [f"packages/{name}-{version}" for name, version in sorted(VERSIONS.items())]
    sdk.require(text.count("[workspace]\n") == 1, "counterpart workspace declaration differs")
    text = text.replace("[workspace]\n", "[workspace]\nexclude = " + json.dumps(exclusions) + "\n")
    text += "\n[patch.crates-io]\n" + "".join(
        f'{name} = {{ path = "packages/{name}-{sdk.VERSION}" }}\n' for name in PRODUCTS)
    return text.encode()


def verify_graph(metadata: dict, consumer: Path, lock: bytes, original: bytes) -> dict:
    root = metadata["resolve"]["root"]
    owners = [p["id"] for p in metadata["packages"] if p["name"] == NAME]
    sdk.require(owners == [root] and metadata["workspace_members"] == [root]
                and metadata["workspace_default_members"] == [root],
                "installed dependencies became workspace members")
    sdk.require(all(p["source"] == "registry+https://github.com/rust-lang/crates.io-index"
                    for p in metadata["packages"] if not p["name"].startswith("q-periapt")),
                "installed external dependency source differs")
    result = verify_resolution(metadata, consumer, lock, original,
                               consumer_name=NAME, versions=VERSIONS)
    sdk.require(lock == original, "installed counterpart changed the original lockfile")
    return result


def native_files() -> list[Path]:
    names = subprocess.check_output(["git", "ls-files", "-z", "--", str(SOURCE.relative_to(ROOT))], cwd=ROOT)
    files = [ROOT / name.decode() for name in names.split(b"\0") if name]
    sdk.require(SOURCE / "Cargo.toml" in files and SOURCE / "src/main.rs" in files,
                "tracked counterpart inputs are incomplete")
    return files


def source_inputs() -> dict[str, str]:
    files = native_files()
    files += [ROOT / "artifact" / name for name in (
        "continuity_independent_package.py", "continuity_package.py", "rust_sdk_profile.py",
        "rust_sdk_msrv.py", "installed_rust_graph.py", "rust_publish_contract.py")]
    return {p.relative_to(ROOT).as_posix(): sdk.snapshot(p).sha256 for p in sorted(files)}


def prepare_counterpart(consumer: Path) -> bytes:
    sdk.require(not consumer.exists(), "counterpart installation must be fresh")
    for path in native_files():
        sdk.copy(path, consumer / path.relative_to(SOURCE))
    manifest = installed_manifest(sdk.snapshot(consumer / "Cargo.toml").data)
    (consumer / "Cargo.toml").write_bytes(manifest)
    return sdk.snapshot(consumer / "Cargo.lock").data


def build(args: argparse.Namespace) -> dict:
    sdk.validate_no_registry_credentials(os.environ)
    host = (os.uname().sysname, os.uname().machine)
    target = {("Darwin", "arm64"): "aarch64-apple-darwin",
              ("Linux", "x86_64"): "x86_64-unknown-linux-gnu"}
    sdk.require(host in target, "installed counterpart supports Apple Silicon or Linux x86_64")
    commit, dirty = sdk.inspect_package_source(ROOT, allow_dirty=False)
    sdk.require(not dirty, "installed counterpart requires clean source")
    pinned = sdk.snapshot(args.report)
    cohort = validate_report(pinned.data, args.report_sha256, pinned.sha256,
                             sdk.source_identity()["rust_workspace_sha256"])
    output = fresh_output_directory(args.output, within=ROOT / "target", label="installed counterpart evidence")
    output.mkdir(parents=True, mode=0o700)
    outside = Path(tempfile.mkdtemp(prefix="qperiapt-independent-package-")).resolve()
    sdk.require(not outside.is_relative_to(ROOT), "installed counterpart must be outside checkout")
    sdk.write_json(output / "LOCATION.json", {"path": str(outside)})
    toolchain = args.toolchain_root.resolve(strict=True)
    home = (args.cargo_home.resolve(strict=True) if args.cargo_home is not None else outside / "cargo-home")
    if args.cargo_home is None:
        home.mkdir(mode=0o700)
    sdk.require(home.is_dir() and not any((home / name).exists() for name in
                ("config", "config.toml", "credentials", "credentials.toml")),
                "registry cache must not supply configuration or credentials")
    before, tools = source_inputs(), package.compiler_identity(toolchain)
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("CARGO_", "RUST", "DYLD_", "LD_", "QPERIAPT_", "QPC_"))}
    environment.update(CARGO_HOME=str(home), CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never",
                       CARGO_INCREMENTAL="0", CARGO_TARGET_DIR=str(outside / "producer-build"),
                       RUSTC=str(toolchain / "bin/rustc"), RUSTDOC=str(toolchain / "bin/rustdoc"),
                       RUSTFLAGS="-D warnings", RUSTDOCFLAGS="-D warnings",
                       PATH=str(toolchain / "bin") + os.pathsep + environment.get("PATH", os.defpath))
    environment["DYLD_FALLBACK_LIBRARY_PATH" if os.uname().sysname == "Darwin" else "LD_LIBRARY_PATH"] = str(toolchain / "lib")
    cargo = [str(toolchain / "bin/cargo")]

    def run(argv, label, cwd=ROOT, *, env=None):
        return sdk.command(argv, output / label, cwd, environment=environment if env is None else env)

    result = {"schema_version": 1, "kind": "qperiapt.independent_installed_counterpart",
              "completed": False, "runtime_qualified": False, "release_claim_eligible": False,
              "source_commit": commit, "source_inputs": before, "tools": tools,
              "sdk_report_sha256": pinned.sha256, "sdk_base_commit": cohort["base_commit"],
              "host_os": host[0], "host_arch": host[1]}
    try:
        rustc = run([str(toolchain / "bin/rustc"), "-vV"], "rustc").decode()
        sdk.require(rustc.splitlines()[0] == "rustc 1.98.1 (48a229cea 2026-09-01)"
                    and "host: " + target[host] in rustc.splitlines(), "counterpart compiler differs")
        result["rustc"] = rustc
        metadata = parse_strict_json_bytes(run([*cargo, "metadata", "--locked", "--offline", "--no-deps",
                                               "--format-version", "1"], "workspace-metadata"), label="SDK metadata")
        packages = sdk.classify(metadata)
        record, candidate = package.package_candidate(cargo, outside / "producer", outside / "producer-build",
            args.report.parent, cohort, packages, output, run, environment)
        result["candidate_archive"] = record
        consumer = outside / "counterpart"
        original = prepare_counterpart(consumer)
        sdk.copy(consumer / "Cargo.toml", output / "consumer-Cargo.toml")
        for name in PRODUCTS:
            row = cohort["crates"][name]
            artifact = sdk.snapshot(args.report.parent / "crates" / row["file"])
            sdk.require(artifact.sha256 == row["sha256"], "installed SDK archive digest changed")
            members = sdk.validate_archive(artifact.data, name, packages[name], set(row["files"]))
            for relative, body in members.items():
                path = consumer / "packages" / f"{name}-{sdk.VERSION}" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as stream: stream.write(body)
        destination = consumer / "packages" / f"{package.NAME}-{package.VERSION}"
        for relative, body in candidate.items():
            path = destination / relative; path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream: stream.write(body)
        environment["CARGO_TARGET_DIR"] = str(outside / "consumer-build")
        metadata = parse_strict_json_bytes(run([*cargo, "metadata", "--locked", "--offline", "--format-version", "1"],
                                               "consumer-metadata", consumer), label="installed counterpart metadata")
        result["resolution"] = verify_graph(metadata, consumer, sdk.snapshot(consumer / "Cargo.lock").data, original)
        sdk.copy(consumer / "Cargo.lock", output / "consumer-Cargo.lock")
        run([*cargo, "build", "--release", "--locked", "--offline", "-j", "2"], "consumer-build", consumer)
        run([*cargo, "clippy", "--release", "--locked", "--offline", "--all-targets", "-j", "2", "--", "-D", "warnings"],
            "consumer-clippy", consumer)
        binary = outside / "consumer-build/release" / NAME
        sdk.copy(binary, output / "counterpart"); (output / "counterpart").chmod(0o700)
        result["native_sha256"] = sdk.snapshot(binary).sha256
        sdk.verify_consumed_sources(consumer, args.report.parent, cohort["crates"], names=PRODUCTS)
        package.verify_candidate_files(destination, candidate)
        package.verify_candidate_archive(output, record)
        sdk.require(source_inputs() == before and package.compiler_identity(toolchain) == tools
                    and sdk.snapshot(args.report).sha256 == pinned.sha256
                    and sdk.inspect_package_source(ROOT, allow_dirty=False) == (commit, False),
                    "installed counterpart inputs changed")
        result.update(completed=True, sources_unchanged=True)
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "INSTALLED_COUNTERPART.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("report", "toolchain-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--report-sha256", required=True)
    parser.add_argument("--cargo-home", type=Path, help="explicit registry cache without configuration or credentials")
    args = parser.parse_args(); args.report = args.report.resolve(strict=True)
    result = build(args)
    print(json.dumps({k: result[k] for k in ("completed", "native_sha256", "runtime_qualified")}))


if __name__ == "__main__":
    main()
