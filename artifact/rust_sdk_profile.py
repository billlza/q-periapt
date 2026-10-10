#!/usr/bin/env python3
"""Package the alpha Rust cohort and consume its exact archives outside the checkout.

This is a pre-publication package gate. The frozen 0.1.5 handoff/uploader and its
remote receipts remain separate. No command in this module uploads anything.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import tomllib

from bounded_process import capture_output
from c_package_manifest import rust_workspace_source_digest
from crates_io_registry_metadata import registry_metadata
from evidence_io import parse_strict_json_bytes, read_regular_snapshot
from rust_publish_contract import (
    exact_internal_dependency_requirement, inspect_package_source,
    validate_cargo_output, validate_cargo_package_completion,
    validate_no_registry_credentials, validate_mlkem_native_manifest_features,
    validate_packaged_mlkem_native_source_contract, validate_rustsec_advisory_database,
)

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.2.0"
PROFILE = "sdk-020"
# Normal, optional and target-specific production edges must point backwards.
COHORT = (
    "q-periapt-mlkem-native-sys", "q-periapt-core", "q-periapt-kem", "q-periapt-sig",
    "q-periapt-backends", "q-periapt-policy", "q-periapt-sdk", "q-periapt-host-store",
    "q-periapt-rustls", "q-periapt-ffi", "q-periapt-wasm", "q-periapt-cli",
)
PRIVATE = frozenset({"q-periapt-sdk-wasm", "q-periapt-tls-demo", "q-periapt-ctstats",
    "q-periapt-continuity-model", "q-periapt-migration", "q-periapt-policy-agent"})
CONSUMER_CRATES = COHORT[:9]
CONSUMER_NAME = "q-periapt-sdk-package-consumer"
CONSUMER_TESTS = frozenset({
    "owned_roundtrip_derivation_transfer_and_revocation",
    "signed_policy_failures_and_explicit_transition",
    "private_store_restart_rollback_rejection_and_reenable",
    "public_reference_connection_with_mutual_identity_and_fragmented_io",
})
FIXTURE = "bindings/rust/SDKPackageConsumer"
POLICIES = ("signed-policy-vectors.json", "sdk-policy-revocation-vectors.json", "sdk-policy-update-vectors.json")
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_MEMBERS = 1024
MAX_MEMBER = 16 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def snapshot(path: Path, maximum: int = MAX_ARCHIVE):
    return read_regular_snapshot(path, maximum=maximum, label="Rust SDK candidate input")


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def copy(source: Path, target: Path, *, maximum: int = MAX_ARCHIVE) -> None:
    data = snapshot(source, maximum=maximum).data
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(data)
    target.chmod(0o644)


def source_identity() -> dict:
    files = [ROOT / name for name in ("README.md", "artifact/rust_sdk_profile.py", "artifact/rust-publish-contract.sh",
        "artifact/rust_publish_contract.py", "artifact/crates_io_registry_metadata.py",
        "artifact/bounded_process.py", "artifact/evidence_io.py", "artifact/git_provenance.py",
        "artifact/c_package_manifest.py")]
    files.extend(path for path in (ROOT / FIXTURE).rglob("*") if path.is_file())
    files.extend(ROOT / "bindings" / name for name in POLICIES)
    return {"rust_workspace_sha256": rust_workspace_source_digest(ROOT),
        "files": {p.relative_to(ROOT).as_posix(): snapshot(p).sha256 for p in sorted(files)}}


def command(argv: list[str], prefix: Path, cwd: Path, *, environment=None) -> bytes:
    with contextlib.chdir(cwd):
        result = capture_output(argv, timeout_seconds=900, maximum_stdout_bytes=16 * 1024 * 1024,
                                maximum_stderr_bytes=16 * 1024 * 1024, environment=environment)
    prefix.with_suffix(".stdout").write_bytes(result.stdout)
    prefix.with_suffix(".stderr").write_bytes(result.stderr)
    write_json(prefix.with_suffix(".json"), {"argv": argv, "cwd": str(cwd), "returncode": result.returncode})
    require(result.returncode == 0, f"command failed ({result.returncode}): {prefix}.stderr")
    validate_cargo_output(prefix.name, [result.stdout.decode(), result.stderr.decode()])
    return result.stdout


def classify(metadata: dict) -> dict:
    members = set(metadata["workspace_members"])
    packages = {p["name"]: p for p in metadata["packages"] if p["id"] in members}
    require(set(packages) == set(COHORT) | PRIVATE, "alpha Rust workspace classification differs")
    requirement = exact_internal_dependency_requirement(VERSION)
    for name, package in packages.items():
        require(package["version"] == VERSION, f"alpha crate version differs: {name}")
        if name in PRIVATE:
            require(package["publish"] == [], f"research/application crate must remain private: {name}")
        else:
            require(package["publish"] in (None, ["crates-io"]), f"product crate registry differs: {name}")
            require(all(package.get(field) for field in ("license", "repository", "homepage", "readme")),
                    f"product crate metadata incomplete: {name}")
            require(package["license"] == "Apache-2.0 OR MIT", f"product license differs: {name}")
        for dependency in package["dependencies"]:
            other = dependency["name"]
            if not other.startswith("q-periapt"):
                continue
            require(other in packages and dependency["req"] == requirement,
                    f"internal alpha dependency differs: {name} -> {other}")
            if name in COHORT and dependency["kind"] != "dev":
                require(other in COHORT and COHORT.index(other) < COHORT.index(name),
                        f"unpublishable or misordered product dependency: {name} -> {other}")
    return packages


def archive_files(data: bytes, name: str, *, version: str = VERSION) -> dict[str, bytes]:
    """Read Cargo's archive with bounded expansion and a closed regular-file tree."""
    require(0 < len(data) <= MAX_ARCHIVE, "crate archive size exceeds its bound")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        expanded = stream.read(MAX_EXPANDED + 1)
    require(len(expanded) <= MAX_EXPANDED, "crate expansion exceeds its bound")
    prefix = f"{name}-{version}/"
    result, folded = {}, set()
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for member in archive:
            require(len(result) < MAX_MEMBERS and member.isfile() and not member.sparse,
                    "crate has excessive or non-regular members")
            require(member.name.startswith(prefix), "crate member root differs")
            relative = member.name[len(prefix):]
            path = PurePosixPath(relative)
            require(relative and not path.is_absolute() and str(path) == relative
                    and ".." not in path.parts and "\\" not in relative
                    and all(ord(c) >= 32 for c in relative), "crate member path is unsafe")
            require(relative.casefold() not in folded, "crate member path collides")
            folded.add(relative.casefold())
            require(0 <= member.size <= MAX_MEMBER, "crate member exceeds its bound")
            content = archive.extractfile(member)
            require(content is not None, "crate member cannot be read")
            with content:
                value = content.read(MAX_MEMBER + 1)
            require(len(value) == member.size, "crate member size differs")
            result[relative] = value
        require(not any(expanded[archive.offset:]), "crate has an unparsed trailing payload")
    require({"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", "README.md"} <= result.keys(),
            "crate is missing normalized package inputs")
    return result


def validate_archive(data: bytes, name: str, package: dict, expected_files: set[str]) -> dict[str, bytes]:
    files = archive_files(data, name)
    require(set(files) == expected_files, f"crate differs from Cargo's source package list: {name}")
    manifest = tomllib.loads(files["Cargo.toml"].decode())
    require(manifest["package"]["name"] == name and manifest["package"]["version"] == VERSION,
            "normalized crate identity differs")
    metadata = registry_metadata(data)
    require(metadata["name"] == name and metadata["vers"] == VERSION, "registry metadata identity differs")
    for dependency in metadata["deps"]:
        if dependency["name"].startswith("q-periapt"):
            require(dependency["name"] in COHORT and dependency["version_req"] == f"={VERSION}",
                    "normalized internal dependency differs")
    require(files["Cargo.toml.orig"] == snapshot(Path(package["manifest_path"])).data,
            "original manifest differs from the selected source")
    source = Path(package["manifest_path"]).parent
    for relative, value in files.items():
        if relative in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}:
            continue
        origin = Path(package["readme"]) if relative == manifest["package"].get("readme") else source / relative
        if not origin.is_absolute():
            origin = source / origin
        origin = Path(os.path.abspath(origin))
        require(origin.is_relative_to(ROOT), "packaged source points outside the selected repository")
        require(value == snapshot(origin).data, f"crate source member differs: {name}/{relative}")
    if name == "q-periapt-mlkem-native-sys":
        validate_mlkem_native_manifest_features(manifest.get("features", {}), package_version=VERSION)
        local_sources = {path: data for path, data in files.items() if path == "build.rs" or path.startswith("src/")}
        validate_packaged_mlkem_native_source_contract(local_sources, package_version=VERSION)
    license_files = {"LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt"} if name == "q-periapt-mlkem-native-sys" \
        else {"LICENSE", "LICENSE-APACHE", "LICENSE-MIT"}
    require(license_files <= files.keys(), f"product license texts missing: {name}")
    return files


def external_lock(lock: bytes) -> dict:
    packages = tomllib.loads(lock.decode())["package"]
    result = {}
    for package in packages:
        if "source" not in package or package["name"].startswith("q-periapt"):
            continue
        identity = (package["name"], package["version"])
        checksum = package.get("checksum")
        require(identity not in result and package["source"] == "registry+https://github.com/rust-lang/crates.io-index"
                and isinstance(checksum, str) and re.fullmatch(r"[a-f0-9]{64}", checksum) is not None,
                "external dependency identity/source/checksum is invalid")
        result[identity] = (package["source"], checksum)
    return result


def verify_consumer_resolution(metadata: dict, consumer: Path, lock: bytes, original_lock: bytes,
                              *, consumer_name: str = CONSUMER_NAME) -> dict:
    rows = [row for row in metadata["packages"] if row["name"].startswith("q-periapt")]
    local = {row["name"]: row for row in rows}
    require(len(local) == len(rows) and set(local) == set(CONSUMER_CRATES) | {consumer_name},
            "installed consumer resolved a mixed product graph")
    require(Path(local[consumer_name]["manifest_path"]).resolve() == consumer / "Cargo.toml"
            and local[consumer_name]["source"] is None, "installed consumer manifest origin differs")
    for name in CONSUMER_CRATES:
        expected = consumer / "packages" / f"{name}-{VERSION}" / "Cargo.toml"
        require(Path(local[name]["manifest_path"]).resolve() == expected
                and local[name]["version"] == VERSION and local[name]["source"] is None,
                "installed consumer resolved checkout or mixed-version crates")
    resolved, original = external_lock(lock), external_lock(original_lock)
    require(all(original.get(key) == value for key, value in resolved.items()),
            "installed consumer changed external dependency versions, sources or checksums")
    return {"product_crates": len(CONSUMER_CRATES), "external_packages": len(resolved),
            "lockfile_sha256": hashlib.sha256(lock).hexdigest()}


def verify_consumer_tests(stdout: bytes) -> None:
    text = stdout.decode("utf-8")
    passed = re.findall(r"^test tests::([a-z_]+) \.\.\. ok$", text, re.MULTILINE)
    require(len(passed) == len(CONSUMER_TESTS) and set(passed) == CONSUMER_TESTS
            and re.search(r"^test result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                          text, re.MULTILINE) is not None,
            "installed consumer did not execute all four public API tests")


def verify_consumed_sources(consumer: Path, output: Path, records: dict,
                            *, names: tuple[str, ...] = CONSUMER_CRATES) -> None:
    for name in names:
        record = records[name]
        artifact = snapshot(output / "crates" / record["file"])
        require(artifact.sha256 == record["sha256"], "consumed crate archive digest changed")
        files = archive_files(artifact.data, name)
        require(set(files) == set(record["files"]), "consumed crate archive inventory changed")
        package = consumer / "packages" / f"{name}-{VERSION}"
        actual = set()
        for path in package.rglob("*"):
            require(not path.is_symlink(), "consumed crate contains a symlink")
            if path.is_dir():
                continue
            relative = path.relative_to(package).as_posix()
            actual.add(relative)
            require(relative in files and snapshot(path).data == files[relative], "consumed crate source changed")
        require(actual == set(files), "consumed crate source inventory changed")


def validate_audit_report(report: dict, package_count: int) -> None:
    settings = report["settings"]
    require(settings["ignore"] == [] and settings["target_arch"] == [] and settings["target_os"] == []
            and settings["severity"] is None
            and set(settings["informational_warnings"]) == {"unmaintained", "unsound", "notice"},
            "dependency audit settings filtered findings")
    require(report["vulnerabilities"]["count"] == 0 and report["vulnerabilities"]["found"] is False
            and not any(report["warnings"].values()), "dependency audit is not clean")
    require(report["lockfile"]["dependency-count"] == package_count,
            "dependency audit lockfile coverage differs")


def validate_audit_database_identity(reported: str | None, current: str, prior: str | None) -> None:
    matches = reported == current if prior is None else prior == current and reported in (None, current)
    require(matches, "dependency audit database identity changed")


def audit_lockfile(lock: Path, output: Path, label: str, environment: dict, *, fetch: bool) -> dict:
    before = snapshot(lock)
    prior_commit = None if fetch else validate_rustsec_advisory_database(output / "advisory-db")
    argv = ["cargo", "audit", "--json", "--deny", "warnings", "--file", str(lock), "--db", str(output / "advisory-db")]
    if not fetch:
        argv.append("--no-fetch")
    report = parse_strict_json_bytes(command(argv, output / label, lock.parent,
        environment=dict(environment, CARGO_NET_OFFLINE="false")), label="Cargo audit report")
    # cargo-audit 0.22.2 can exit zero with warnings={} while stderr reports
    # that registry/yank checks could not run. JSON counts alone are insufficient.
    require(not snapshot((output / label).with_suffix(".stderr")).data.strip(),
            "dependency audit emitted diagnostics; refusing an incomplete result")
    validate_audit_report(report, len(tomllib.loads(before.data.decode())["package"]))
    commit = validate_rustsec_advisory_database(output / "advisory-db")
    # cargo-audit 0.22.2 omits Git metadata in --no-fetch JSON.
    # Bind that read to our checked, clean database identity on both sides.
    validate_audit_database_identity(report["database"]["last-commit"], commit, prior_commit)
    require(snapshot(lock).sha256 == before.sha256, "dependency audit lock identity changed")
    return {"advisory_db_commit": commit, "lockfile_sha256": before.sha256,
            "packages": report["lockfile"]["dependency-count"], "vulnerabilities": 0, "warnings": 0}


def prepare_consumer_fixture(consumer: Path) -> None:
    """Materialize the public API tests and their fixed/generated test inputs."""
    for path in (ROOT / FIXTURE).rglob("*"):
        if path.is_file():
            copy(path, consumer / path.relative_to(ROOT / FIXTURE))
    fixture_dir = consumer / "fixtures"
    fixture_dir.mkdir(exist_ok=True)
    for vector, stem in zip(POLICIES, ("policy", "revoke", "enable")):
        value = parse_strict_json_bytes(snapshot(ROOT / "bindings" / vector).data, label=f"policy fixture {vector}")
        with (fixture_dir / f"{stem}.toml").open("x", encoding="utf-8") as stream:
            stream.write(value["policy_toml"])
        signature_name = "signature.bin" if stem == "policy" else f"{stem}-signature.bin"
        with (fixture_dir / signature_name).open("xb") as stream:
            stream.write(bytes.fromhex(value["signature"]))
        if stem == "policy":
            with (fixture_dir / "root.bin").open("xb") as stream:
                stream.write(bytes.fromhex(value["verification_key"]))


def extract_recorded_crates(consumer: Path, output: Path, records: dict) -> None:
    """Extract exact pinned cohort bytes; fresh producers additionally check source correspondence."""
    patches = ["\n[patch.crates-io]"]
    for name in CONSUMER_CRATES:
        record = records[name]
        require(record["file"] == f"{name}-{VERSION}.crate", "recorded crate filename differs")
        artifact = snapshot(output / "crates" / record["file"])
        require(artifact.sha256 == record["sha256"], "crate digest changed before extraction")
        contents = archive_files(artifact.data, name)
        require(set(contents) == set(record["files"]), "recorded crate file inventory differs")
        manifest = tomllib.loads(contents["Cargo.toml"].decode())
        require(manifest["package"]["name"] == name and manifest["package"]["version"] == VERSION,
                "recorded crate identity differs")
        destination = consumer / "packages" / f"{name}-{VERSION}"
        for relative, data in contents.items():
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)
        patches.append(f'{name} = {{ path = "packages/{name}-{VERSION}" }}')
    with (consumer / "Cargo.toml").open("a", encoding="utf-8") as stream:
        stream.write("\n".join(patches) + "\n")


def consume(output: Path, records: dict, packages: dict, environment: dict) -> dict:
    consumer = Path(tempfile.mkdtemp(prefix="qperiapt-rust-sdk-consumer-")).resolve()
    require(not consumer.is_relative_to(ROOT), "Rust consumer must be outside the checkout")
    write_json(output / "consumer-location.json", {"path": str(consumer)})
    prepare_consumer_fixture(consumer)
    # A new package qualification still requires byte-for-byte current-source
    # correspondence, in addition to the pinned archive closure below.
    for name in CONSUMER_CRATES:
        record = records[name]
        artifact = snapshot(output / "crates" / record["file"])
        require(artifact.sha256 == record["sha256"], "crate digest changed before source verification")
        validate_archive(artifact.data, name, packages[name], set(record["files"]))
    extract_recorded_crates(consumer, output, records)
    # Retain the audited workspace's external versions while Cargo adds this
    # standalone consumer and the archive-derived local patch identities.
    copy(ROOT / "Cargo.lock", consumer / "Cargo.lock")
    env = dict(environment, CARGO_TARGET_DIR=str(output / "consumer-target"))
    tested = command(["cargo", "test", "--offline", "-j", "2"], output / "consumer-test", consumer, environment=env)
    verify_consumer_tests(tested)
    resolved = command(["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
                       output / "consumer-metadata", consumer, environment=env)
    metadata = parse_strict_json_bytes(resolved, label="consumer Cargo metadata")
    resolution = verify_consumer_resolution(metadata, consumer, snapshot(consumer / "Cargo.lock").data,
                                           snapshot(ROOT / "Cargo.lock").data)
    command(["cargo", "clippy", "--locked", "--offline", "--all-targets", "-j", "2", "--", "-D", "warnings"],
            output / "consumer-clippy", consumer, environment=env)
    audit = audit_lockfile(consumer / "Cargo.lock", output, "consumer-audit", env, fetch=False)
    verify_consumed_sources(consumer, output, records)
    copy(consumer / "Cargo.lock", output / "consumer-Cargo.lock")
    return {"path": str(consumer), "tests": len(CONSUMER_TESTS), "external_packages": resolution["external_packages"],
        "audit": audit,
        "dependency_source": "nine exact archive-derived path patches outside checkout; not a public registry installation"}


def build(output: Path) -> dict:
    validate_no_registry_credentials(os.environ)
    dirty_option = os.environ.get("QPERIAPT_ALLOW_DIRTY_RUST_PACKAGE_CONTRACT", "0")
    require(dirty_option in {"0", "1"}, "dirty diagnostic option must be 0 or 1")
    commit, dirty = inspect_package_source(ROOT, allow_dirty=dirty_option == "1")
    require(not output.exists(), "Rust SDK output must be a fresh directory")
    require(shutil.disk_usage(ROOT).free >= 4 * 1024 ** 3, "Rust SDK packaging needs at least 4 GiB free")
    output.mkdir(parents=True, mode=0o700)
    before = source_identity()
    write_json(output / "sources-before.json", before)
    cargo_home = output / "cargo-home"
    cargo_home.mkdir(mode=0o700)
    environment = dict(os.environ, CARGO_HOME=str(cargo_home), CARGO_NET_OFFLINE="true",
                       CARGO_TERM_COLOR="never", RUSTFLAGS="-D warnings", RUSTUP_TOOLCHAIN="1.98.1")
    version = command(["rustc", "--version"], output / "rustc-version", ROOT, environment=environment).decode().strip()
    require(version.startswith("rustc 1.98.1 "), "Rust SDK package toolchain differs")
    cargo_version = command(["cargo", "--version"], output / "cargo-version", ROOT, environment=environment).decode().strip()
    audit_version = command(["cargo-audit", "--version"], output / "audit-version", ROOT, environment=environment).decode().strip()
    require(cargo_version.startswith("cargo 1.98.1 ") and audit_version == "cargo-audit 0.22.2",
            "Rust SDK package Cargo/audit toolchain differs")
    metadata = command(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"],
                       output / "metadata", ROOT, environment=environment)
    packages = classify(parse_strict_json_bytes(metadata, label="workspace Cargo metadata"))
    write_json(output / "classification.json", {"product": COHORT, "private": sorted(PRIVATE)})
    command(["sh", "artifact/python-run.sh", "crates/q-periapt-mlkem-native-sys/scripts/verify-vendor.py"],
            output / "vendor", ROOT, environment=environment)
    command(["cargo", "fetch", "--locked"], output / "fetch", ROOT,
            environment=dict(environment, CARGO_NET_OFFLINE="false"))
    # The separate fuzz lock has registry packages absent from the workspace.
    # Populate their index/cache before cargo-audit checks their yank status.
    command(["cargo", "fetch", "--locked", "--manifest-path", "fuzz/Cargo.toml"],
            output / "fetch-fuzz", ROOT,
            environment=dict(environment, CARGO_NET_OFFLINE="false"))
    audits = {"workspace": audit_lockfile(ROOT / "Cargo.lock", output, "workspace-audit", environment, fetch=True),
              "fuzz": audit_lockfile(ROOT / "fuzz/Cargo.lock", output, "fuzz-audit", environment, fetch=False)}
    expected_files = {}
    for name in COHORT:
        argv = ["cargo", "package", "--registry", "crates-io", "--locked", "--offline", "--list", "-p", name]
        if dirty:
            argv.append("--allow-dirty")
        listing = command(argv, output / f"list-{name}", ROOT, environment=environment).decode().splitlines()
        require(listing and len(listing) == len(set(listing)), "Cargo package list is empty or ambiguous")
        expected_files[name] = set(listing)
    argv = ["cargo", "package", "--registry", "crates-io", "--locked", "--offline", "--target-dir", str(output / "build"),
            "-j", "2", "--features", "q-periapt-rustls/reference-connection,q-periapt-cli/sdk-cbom"]
    if dirty:
        argv.append("--allow-dirty")
    for name in COHORT:
        argv.extend(["-p", name])
    command(argv, output / "package", ROOT, environment=environment)
    streams = [(output / f"package.{suffix}").read_text() for suffix in ("stdout", "stderr")]
    records = {}
    (output / "crates").mkdir()
    for name in COHORT:
        validate_cargo_package_completion(name, streams)
        filename = f"{name}-{VERSION}.crate"
        artifact = snapshot(output / "build/package" / filename)
        files = validate_archive(artifact.data, name, packages[name], expected_files[name])
        copy(artifact.path, output / "crates" / filename)
        records[name] = {"file": filename, "bytes": artifact.size, "sha256": artifact.sha256,
                         "members": len(files), "files": sorted(files)}
    consumer = consume(output, records, packages, environment)
    require(len({audit["advisory_db_commit"] for audit in [*audits.values(), consumer["audit"]]}) == 1,
            "cohort dependency audits used different advisory database identities")
    after = source_identity()
    write_json(output / "sources-after.json", after)
    require(before == after, "Rust SDK source changed during packaging/consumption")
    require(inspect_package_source(ROOT, allow_dirty=dirty_option == "1") == (commit, dirty),
            "Rust SDK Git source identity changed during packaging/consumption")
    for record in records.values():
        require(snapshot(output / "crates" / record["file"]).sha256 == record["sha256"], "crate changed during consumption")
    report = {"schema_version": 1, "profile": PROFILE, "version": VERSION, "native_abi_major": 2,
        "completed_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base_commit": commit, "git_dirty": dirty, "diagnostic_only": dirty_option == "1", "crates": records,
        "source_inputs": before, "sources_unchanged": True, "rustc": version, "consumer": consumer,
        "dependency_audits": audits,
        "cargo": cargo_version, "cargo_audit": audit_version,
        "cargo_home_isolated": True, "registry_network_phase": "locked fetch and dependency audit; package and consumer are offline",
        "publication_performed": False, "release_claim_eligible": False,
        "scope": "host Cargo archive reconstruction and external Rust consumer; platform/security/public-registry gates remain separate"}
    write_json(output / "RUST_SDK_PACKAGE.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = build(args.output.absolute())
    print(json.dumps({"profile": PROFILE, "version": VERSION, "crates": len(report["crates"]),
        "consumer": report["consumer"], "release_claim_eligible": False}, indent=2))


if __name__ == "__main__":
    main()
