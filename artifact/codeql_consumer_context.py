#!/usr/bin/env python3
"""Supply declared, temporary Cargo inputs for the two installed-package consumers.

The pinned Rust Analyzer loads each manifest from its own workspace directory.
Scoped Cargo patches therefore resolve current source without editing consumer
manifests or replacing their installed-package acceptance path. Every target must
compile before analysis; this is not installed-package or CodeQL qualification.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tomllib

import rust_sdk_profile as sdk
from git_provenance import git_commit, run_git_bytes

ROOT = Path(__file__).resolve().parents[1]
CONSUMERS = {
    "continuity-c": "bindings/c/ContinuityPackageConsumer",
    "sdk-rust": sdk.FIXTURE,
}
CANDIDATE = "research/continuity-identity-candidate"
ALIAS = "packages/q-periapt-continuity-identity-candidate-0.0.0"


def identity(path: Path) -> dict:
    info = path.lstat()
    result = {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode}
    if stat.S_ISLNK(info.st_mode):
        result["link"] = os.readlink(path)
    elif stat.S_ISREG(info.st_mode):
        result["sha256"] = sdk.snapshot(path).sha256
    else:
        sdk.require(stat.S_ISDIR(info.st_mode), "unsupported analysis input type")
    return result


def allowed_paths(root: Path) -> set[str]:
    paths = {f"{relative}/{suffix}" for relative in CONSUMERS.values()
             for suffix in (".cargo", ".cargo/config.toml", "Cargo.lock")}
    paths.update(f"{CONSUMERS['continuity-c']}/{suffix}" for suffix in ("packages", ALIAS))
    paths.update(f"{CONSUMERS['sdk-rust']}/fixtures/{name}" for name in sdk.policy_fixture_inputs(root))
    return paths


def verify_owned(root: Path, owned: dict) -> None:
    sdk.require(set(owned) <= allowed_paths(root), "unexpected temporary input path")
    for relative, expected in owned.items():
        path = root / relative
        sdk.require(identity(path) == expected, f"analysis input changed: {relative}")
        if stat.S_ISDIR(expected["mode"]):
            children = {str(child.relative_to(root)) for child in path.iterdir()}
            sdk.require(children <= owned.keys(), f"unowned file in analysis directory: {relative}")


def remove_owned(root: Path, owned: dict) -> None:
    # Validate every object first. Unknown/replaced files are preserved on error.
    verify_owned(root, owned)
    for relative in sorted(owned, key=lambda value: len(Path(value).parts), reverse=True):
        path = root / relative
        path.rmdir() if stat.S_ISDIR(owned[relative]["mode"]) else path.unlink()


def providers(root: Path, label: str) -> dict[str, tuple[Path, str]]:
    workspace = tomllib.loads(sdk.snapshot(root / "Cargo.toml").data.decode())["workspace"]
    names = set(sdk.CONSUMER_CRATES)
    if label == "continuity-c":
        names.add("q-periapt-continuity-identity-candidate")
    found = {}
    for relative in [*workspace["members"], CANDIDATE]:
        manifest = root / relative / "Cargo.toml"
        package = tomllib.loads(sdk.snapshot(manifest).data.decode())["package"]
        if package["name"] in names:
            version = package["version"]
            if isinstance(version, dict):
                sdk.require(version == {"workspace": True}, "unsupported provider version")
                version = workspace["package"]["version"]
            sdk.require(package["name"] not in found, "duplicate analysis provider")
            found[package["name"]] = (manifest, version)
    sdk.require(set(found) == names, "analysis provider inventory differs")
    return found


def external_packages(data: bytes) -> set[tuple]:
    return {tuple(item.get(key) for key in ("name", "version", "source", "checksum"))
            for item in tomllib.loads(data.decode())["package"] if "source" in item}


def check_metadata(metadata: dict, original: dict, selected: dict) -> None:
    consumer = [item for item in metadata["packages"] if item["name"] == original["name"]]
    sdk.require(len(consumer) == 1 and consumer[0]["targets"] == original["targets"],
                "consumer target paths or attributes changed")
    found = set()
    for item in metadata["packages"]:
        name = item["name"]
        if name.startswith("q-periapt") and name != original["name"]:
            sdk.require(name in selected, "unexpected analysis dependency")
            manifest, version = selected[name]
            sdk.require(item["source"] is None and item["manifest_path"] == str(manifest)
                        and item["version"] == version, "analysis used registry or stale source")
            found.add(name)
    sdk.require(found == set(selected), "missing analysis provider")


def check_tree(root: Path, state: dict) -> None:
    sdk.require(git_commit(root) == state["commit"], "analysis checkout commit changed")
    sdk.require(not run_git_bytes(root, ["diff", "HEAD", "--"]), "tracked analysis source changed")
    untracked = set(run_git_bytes(root, ["ls-files", "--others", "--exclude-standard", "-z"]).decode().split("\0")) - {""}
    sdk.require(untracked <= state["owned"].keys(), "unexpected untracked analysis input")
    sdk.require(set(state["owned"]) == allowed_paths(root), "incomplete analysis input inventory")
    verify_owned(root, state["owned"])


def prepare(root: Path, output: Path, toolchains: list[str]) -> None:
    sdk.require(toolchains and len(toolchains) == len(set(toolchains))
                and set(toolchains) <= {"1.97.0", "1.98.1"}, "unexpected analysis toolchain")
    output.mkdir(mode=0o700)
    state = {"commit": git_commit(root), "owned": {}, "consumers": {}, "prepared": False}
    environment = dict(os.environ, RUSTUP_AUTO_INSTALL="0", RUSTFLAGS="-D warnings",
                       CARGO_TARGET_DIR=str(output / "build"))

    def remember(path):
        state["owned"][str(path.relative_to(root))] = identity(path)

    def directory(path):
        path.mkdir()
        remember(path)

    def write(path, data):
        with path.open("xb") as stream:
            stream.write(data)
        remember(path)

    def command(argv, label, cwd):
        return sdk.command(argv, output / label, cwd, environment=environment)

    try:
        sdk.require(not run_git_bytes(root, ["status", "--porcelain"]),
                    "analysis preparation requires a clean checkout")
        sdk.require(not any(os.path.lexists(root / path) for path in allowed_paths(root)),
                    "analysis input already exists")
        admitted = set().union(*(external_packages(sdk.snapshot(root / path).data)
                                for path in ("Cargo.lock", CANDIDATE + "/Cargo.lock")))
        for label, relative in CONSUMERS.items():
            consumer = root / relative
            cargo = ["cargo", "+" + toolchains[0]]
            original = json.loads(command([*cargo, "metadata", "--no-deps", "--frozen", "--format-version", "1"],
                                          label + "-targets", consumer))["packages"][0]
            selected = providers(root, label)
            config = "[patch.crates-io]\n" + "".join(
                name + " = { path = " + json.dumps(str(manifest.parent)) + " }\n"
                for name, (manifest, _) in sorted(selected.items()))
            directory(consumer / ".cargo")
            write(consumer / ".cargo/config.toml", config.encode())
            lock = consumer / "Cargo.lock"
            write(lock, sdk.snapshot(root / "Cargo.lock").data)
            if label == "continuity-c":
                directory(consumer / "packages")
                (consumer / ALIAS).symlink_to(root / CANDIDATE, target_is_directory=True)
                remember(consumer / ALIAS)
            else:
                for name, data in sdk.policy_fixture_inputs(root).items():
                    write(consumer / "fixtures" / name, data)
            metadata = json.loads(command([*cargo, "metadata", "--format-version", "1", "--all-features", "--offline"],
                                          label + "-resolve", consumer))
            remember(lock)  # Cargo is the declared writer during resolution only.
            check_metadata(metadata, original, selected)
            sdk.require(external_packages(sdk.snapshot(lock).data) <= admitted,
                        "consumer selected a dependency outside the canonical lockfiles")
            for toolchain in toolchains:
                prefix = label + "-" + toolchain.replace(".", "_")
                argv = ["cargo", "+" + toolchain]
                replay = json.loads(command([*argv, "metadata", "--format-version", "1", "--all-features", "--locked", "--offline"],
                                            prefix + "-metadata", consumer))
                check_metadata(replay, original, selected)
                command([*argv, "check", "--all-targets", "--all-features", "--locked", "--offline"],
                        prefix + "-check", consumer)
                verify_owned(root, state["owned"])
            state["consumers"][label] = {"target_count": len(original["targets"]), "toolchains": toolchains}
        check_tree(root, state)
        state["prepared"] = True
    except BaseException as exc:
        state["error"] = str(exc)
        try:
            remove_owned(root, state["owned"])
            state["cleanup_completed"] = True
        except (OSError, ValueError) as cleanup:
            state["cleanup_error"] = str(cleanup)
            exc.add_note("analysis inputs preserved: " + str(cleanup))
        raise
    finally:
        sdk.write_json(output / "STATE.json", state)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify", "remove"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--toolchain", action="append")
    args = parser.parse_args()
    output = args.output.absolute()
    sdk.require(output == output.resolve() and not output.is_relative_to(ROOT),
                "analysis receipts and build outputs must be outside checkout")
    if args.action == "prepare":
        prepare(ROOT, output, args.toolchain or ["1.97.0", "1.98.1"])
    else:
        state = json.loads(sdk.snapshot(output / "STATE.json").data)
        sdk.require(state["prepared"], "analysis context was not prepared")
        check_tree(ROOT, state)
        if args.action == "remove":
            remove_owned(ROOT, state["owned"])
            sdk.write_json(output / "REMOVED.json", {"commit": state["commit"], "removed": True})
    print("CODEQL_CONSUMER_CONTEXT_PASS action=" + args.action)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        sys.exit("error: CodeQL consumer context: " + str(exc))
