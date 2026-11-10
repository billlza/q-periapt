#!/usr/bin/env python3
"""Reopen a real current-source native build without claiming full qualification.

The input consumer is a separate source build with explicit local SDK patches.
The formal producer remains attached to the installed-archive C qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--consumer", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    sys.path.insert(0, str(root / "artifact"))
    import continuity_native_package as native
    import continuity_c_abi as abi
    import continuity_c_consumer as c
    import rust_sdk_profile as sdk
    from deterministic_archive import create_zip, extract_zip
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    target = native.TARGETS[os.uname().machine][0]
    consumer = args.consumer.resolve(strict=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("LD_", "DYLD_"))}
    env.update(RUSTC=str(args.toolchain / "bin/rustc"), CARGO_NET_OFFLINE="true")
    def run(argv, name, cwd=consumer):
        return sdk.command(argv, output / name, cwd, environment=env)
    def git_text(arguments):
        # This diagnostic admits a Git worktree and records it as such. The
        # formal producer retains its stricter release-provenance checks.
        return subprocess.check_output(["git", "-C", str(root), *arguments], timeout=30).decode().strip()
    observed = sdk.snapshot(args.library, maximum=native.LIMITS.maximum_member_bytes)
    source = git_text(["rev-parse", "HEAD"])
    # Only the packaging increment is allowed to differ; code actually built
    # retains this exact base. A fresh target directory belongs to this run.
    run(["git", "diff", "--exit-code", "HEAD", "--", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
         "crates", "bindings/c/ContinuityPackageConsumer", "research/continuity-identity-candidate"],
        "built-source-diff", root)
    untracked = git_text(["ls-files", "--others", "--exclude-standard", "--", "crates",
        "bindings/c/ContinuityPackageConsumer", "research/continuity-identity-candidate"])
    sdk.require(not untracked, "untracked built-source input")
    result = {"schema_version": 1, "kind": "qperiapt.native_distribution_current_source_control",
              "completed": False, "source_commit": source, "target": target,
              "scope": "real current-source Release C library; complete native export/loader inspection; archive/readback; relocated C/ABI probes and existing C self-check",
              "input_channel": "separate current-source C consumer with explicit local SDK patches",
              "source_is_git_worktree": (root / ".git").is_file(),
              "full_installed_c_qualification": False, "release_claim_eligible": False,
              "publication_performed": False, "source_tool_sha256": hashlib.sha256((root / "artifact/continuity_native_package.py").read_bytes()).hexdigest()}
    try:
        prefix = f"native-current-source-control-{target}"
        staging = output / "stage" / prefix
        staging.mkdir(parents=True)
        sdk.copy(args.library, staging / "lib" / native.LIBRARY, maximum=native.LIMITS.maximum_member_bytes)
        for name in ("qpc_owner.h", abi.CONTRACT):
            sdk.require(sdk.snapshot(consumer / name).data == sdk.snapshot(c.FIXTURE / name).data, "C source differs")
            sdk.copy(consumer / name, staging / "include" / name)
        result["native"] = native.verify_native(staging / "lib" / native.LIBRARY, target, run)
        result["rustc"] = run([str(args.toolchain / "bin/rustc"), "--version", "--verbose"], "rustc").decode()
        result["cargo"] = run([str(args.toolchain / "bin/cargo"), "--version"], "cargo").decode()
        metadata = json.loads(run([str(args.toolchain / "bin/cargo"), "metadata", "--locked", "--offline",
                                  "--format-version", "1", "--filter-platform", target], "metadata"))
        notices = staging / "LICENSES/dependencies"; notices.mkdir(parents=True)
        native.licenses.collect(consumer, notices, target, root_package=c.NAME, resolved_metadata=metadata)
        for name in ("LICENSE", "LICENSE-APACHE", "LICENSE-MIT"):
            sdk.copy(native.package.CANDIDATE / name, staging / name)
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md"):
            sdk.copy(root / "crates/q-periapt-mlkem-native-sys/vendor" / name, staging / "LICENSES/mlkem-native" / name)
        rust_docs = args.toolchain / "share/doc/rust"
        sdk.require(sdk.snapshot(rust_docs / "COPYRIGHT-library.html").data == sdk.snapshot(root / "LICENSES/Rust-1.98.1-library.html").data,
                    "compiler library notices differ")
        sdk.copy(rust_docs / "COPYRIGHT-library.html", staging / "LICENSES/Rust-1.98.1-library.html")
        for path in (rust_docs / "licenses").rglob("*"):
            sdk.require(not path.is_symlink(), "compiler license symlink")
            if path.is_file():
                sdk.copy(path, staging / "LICENSES/rust-standard-library" / path.relative_to(rust_docs / "licenses"))
        contents = {"schema_version": 1, "kind": "qperiapt.native_diagnostic_contents", "target": target,
                    "source_commit": source, "full_installed_c_qualification": False,
                    "native": result["native"], "files": native.inventory(staging)}
        native.write(staging / native.CONTENTS, native.canonical(contents))
        native.verify_package(staging, contents)
        archive = output / (prefix + ".zip")
        audit = create_zip(staging, archive, root_name=prefix, mtime=native.MTIME, limits=native.LIMITS)
        destination = output / "installed"
        extract_zip(archive, destination, root_name=prefix, mtime=native.MTIME,
                    expected_sha256=audit.archive_sha256, limits=native.LIMITS)
        installed = destination / prefix
        native.verify_package(installed, contents)
        sdk.require(native.verify_native(installed / "lib" / native.LIBRARY, target,
                    lambda argv, label: run(argv, "installed-" + label)) == result["native"], "installed library differs")
        cc = Path("/usr/bin/cc").resolve(strict=True)
        result["cc"] = {"sha256": sdk.snapshot(cc, maximum=c.MAX_BINARY).sha256,
                        "version": run([str(cc), "--version"], "cc").decode()}
        for name, data in (("owner-probe", native._probe()), ("abi-probe", abi.c_probe(abi.load(installed / "include")))):
            code, binary = destination / (name + ".c"), destination / name
            native.write(code, data)
            run([str(cc), "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", str(code),
                 "-I", str(installed / "include"), "-L", str(installed / "lib"), "-l" + c.LIBRARY, "-ldl",
                 "-Wl,-rpath,$ORIGIN/" + prefix + "/lib", "-o", str(binary)], name + "-compile", destination)
            stdout = run([str(binary), *([str(installed / "lib" / native.LIBRARY)] if name == "owner-probe" else [])],
                         name + "-run", destination)
            if name == "owner-probe":
                sdk.require(stdout == b"NATIVE_OWNER_PASS installed_library=true argument_refusal=true\n", "owner probe failed")
            else:
                layouts = abi.layouts(stdout, abi.load(installed / "include"), rust=False)
                result["c_abi_layout_entries"] = len(layouts["layouts"])
                result["c_abi_function_signatures"] = len(layouts["signatures"])
        client = destination / "qpc-c-client"
        run([str(cc), "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-pthread", "-O2",
             str(consumer / "client.c"), str(consumer / "recovery_client.c"), str(consumer / "opening_client.c"),
             "-I", str(consumer), "-L", str(installed / "lib"), "-l" + c.LIBRARY,
             "-Wl,-rpath,$ORIGIN/" + prefix + "/lib", "-o", str(client)], "c-client-compile", destination)
        sdk.require(run([str(client), "self-check"], "c-client-self-check", destination) == b"self-check-passed\n",
                    "existing C self-check failed")
        native.verify_package(installed, contents)
        sdk.require(sdk.snapshot(args.library, maximum=native.LIMITS.maximum_member_bytes).sha256 == observed.sha256,
                    "original native library changed")
        for name in ("Cargo.toml", "Cargo.lock"):
            sdk.copy(consumer / name, output / ("consumer-" + name))
        result.update(completed=True, original_library_sha256=observed.sha256,
                      archive={"path": archive.name, "bytes": audit.archive_bytes, "sha256": audit.archive_sha256},
                      archive_members=len(audit.entries), existing_c_self_check=True, relocated_owner_probe=True)
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "RESULT.json", result)


if __name__ == "__main__":
    main()
