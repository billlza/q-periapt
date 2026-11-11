"""Separately compiled C short-structure boundary; no lifecycle qualification."""
from pathlib import Path
import rust_sdk_profile as sdk

MARKER = (b"ROOT_C_CONTRACT guarded_short_scope=true guarded_short_alternative=true "
          b"outputs_preserved=true lifecycle_qualified=false\n")


def qualify(consumer: Path, installed: Path, cc: Path, platform_flags: list[str],
            profile: str, run, *, darwin: bool, runtime: dict, filename: str) -> dict:
    from continuity_c_consumer import verify_linkage
    executable = installed / "qpc-c-root-contract"
    source = consumer / "root_contract_client.c"
    run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         *(["-O2"] if profile == "release" else ["-O0", "-g"]), str(source), "-I", str(consumer),
         "-L", str(installed), "-lq_periapt_continuity_c_consumer",
         "-Wl,-rpath," + ("@loader_path" if darwin else "$ORIGIN"), "-o", str(executable)],
        "root-contract-compile-" + profile)
    if darwin:
        dependencies = run(["/usr/bin/otool", "-L", str(executable)], "root-contract-dependencies-" + profile).decode()
        loader = run(["/usr/bin/otool", "-l", str(executable)], "root-contract-loader-" + profile).decode()
    else:
        dependencies = run(["/usr/bin/readelf", "-d", str(executable)], "root-contract-dependencies-" + profile).decode()
        loader = dependencies
    verify_linkage(dependencies, loader, filename, darwin=darwin)
    before = sdk.snapshot(executable, maximum=256 * 1024**2)
    library = sdk.snapshot(installed / filename, maximum=256 * 1024**2)
    sdk.require(run([str(executable)], "root-contract-" + profile, runtime=runtime) == MARKER,
                "C root guarded options contract did not execute completely")
    sdk.require(sdk.snapshot(executable, maximum=256 * 1024**2).sha256 == before.sha256
                and sdk.snapshot(installed / filename, maximum=256 * 1024**2).sha256 == library.sha256,
                "root contract executable or installed library changed")
    return {"completed": True, "executable_sha256": before.sha256,
            "library_sha256": library.sha256, "source_sha256": sdk.snapshot(source).sha256,
            "header_sha256": sdk.snapshot(consumer / "qpc_owner.h").sha256,
            "lifecycle_qualified": False, "release_claim_eligible": False}
