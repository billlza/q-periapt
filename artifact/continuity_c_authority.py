"""Actual C registry ownership and deferred managed-admission qualification."""
from pathlib import Path

import rust_sdk_profile as sdk

MARKER = (b"AUTHORITY_C_OWNER exact_mapping=true snapshot=true short_header=true "
          b"pending_closed=202 same_registry_reopen=true wrong_root_before_create=211 managed_enrollment_constructed=true explicit_selection=true "
          b"traffic_qualified=false\n")


def verify_execution(stdout: bytes) -> dict:
    sdk.require(stdout == MARKER, "C account registry owner workload did not execute completely")
    return {"completed": True, "exact_mapping": True, "options_copied": True,
            "short_header_refused": True, "pending_closed_code": 202,
            "same_registry_reopen": True, "wrong_root_before_create": 211,
            "managed_enrollment_constructed": True, "explicit_selection": True,
            "traffic_qualified": False, "release_claim_eligible": False,
            "scope": "Compiled C caller, installed native engine, registry lifecycle and deferred enrollment; no managed traffic or other language qualification"}


def qualify(outside: Path, consumer: Path, installed: Path, fixture: Path,
            cc: Path, platform_flags: list[str], profile: str, run, *, darwin: bool,
            runtime: dict, filename: str) -> dict:
    from continuity_c_consumer import verify_linkage
    # Reuse the selected installed library; no build-tree library search fallback.
    executable = installed / "qpc-c-authority-client"
    run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         *(["-O2"] if profile == "release" else ["-O0", "-g"]),
         str(consumer / "authority_client.c"), "-I", str(consumer), "-L", str(installed),
         "-lq_periapt_continuity_c_consumer",
         "-Wl,-rpath," + ("@loader_path" if darwin else "$ORIGIN"), "-o", str(executable)],
        "authority-compile-" + profile)
    if darwin:
        dependencies = run(["/usr/bin/otool", "-L", str(executable)], "authority-dependencies-" + profile).decode()
        loader = run(["/usr/bin/otool", "-l", str(executable)], "authority-loader-" + profile).decode()
    else:
        dependencies = run(["/usr/bin/readelf", "-d", str(executable)], "authority-dependencies-" + profile).decode()
        loader = dependencies
    verify_linkage(dependencies, loader, filename, darwin=darwin)
    directory = outside / ("c-" + profile + "-authority-runtime")
    directory.mkdir(mode=0o700)
    for name in ("registry", "enrollment"):
        (directory / name).mkdir(mode=0o700)
    before = sdk.snapshot(executable, maximum=256 * 1024**2)
    library = sdk.snapshot(installed / filename, maximum=256 * 1024**2)
    result = verify_execution(run([str(executable), str(fixture), str(directory / "registry"),
                                   str(directory / "enrollment")], "authority-" + profile, runtime=runtime))
    sdk.require(sdk.snapshot(executable, maximum=256 * 1024**2).sha256 == before.sha256,
                "C authority executable changed during qualification")
    sdk.require(sdk.snapshot(installed / filename, maximum=256 * 1024**2).sha256 == library.sha256,
                "installed authority library changed during qualification")
    result["executable_sha256"] = before.sha256
    result["source_sha256"] = sdk.snapshot(consumer / "authority_client.c").sha256
    result["header_sha256"] = sdk.snapshot(consumer / "qpc_owner.h").sha256
    result["library_sha256"] = library.sha256
    return result
