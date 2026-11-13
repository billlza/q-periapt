"""Installed Swift root facade against the shared crash/recovery fixture and C peer."""
from pathlib import Path

import rust_sdk_profile as sdk
import continuity_c_root as driver
from continuity_c_witness import export_selected

SCOPE = ("Installed Swift public root-controller facade and C peer, same-host macOS arm64 and shared "
         "Rust engine; exact original approvals, retirement cleanup, signed witness query loss, mutual TLS, "
         "epoch-1 rekey and bidirectional original-message recovery. Actual Swift worker stack is observed; "
         "no custom stack size is selected. ROOT_C_* markers name the shared native fixture wire format, "
         "not the client language. Not independent-implementation or power-loss qualification.")


def verify_execution(stdout: bytes, directory: Path, *, variant: str) -> dict:
    result = driver.verify_execution(stdout, directory, darwin=True, variant=variant)
    selected = sdk.snapshot(directory / "public/client-language", maximum=5)
    sdk.require(selected.data == b"Swift", "root fixture did not select the Swift public facade")
    result["public_readbacks"]["public/client-language"] = selected.sha256
    revoked = sdk.snapshot(directory / "public/arc-revokes-successor", maximum=8)
    sdk.require(revoked.data == (1).to_bytes(8, "big"), "final Swift ARC release did not revoke the successor")
    result["public_readbacks"]["public/arc-revokes-successor"] = revoked.sha256
    result["final_arc_release_revokes_successor"] = True
    result.update(scope=SCOPE, client_language="Swift", route=variant)
    # The shared fixture records the system's configured pthread default and
    # actual worker stack independently; do not claim they are the same stack.
    for observation in (result, result["application_traffic"], result["application_traffic"]["reverse"]):
        observation["thread_stack_observations"] = observation.pop("default_thread_stacks")
    return result


def qualify(outside: Path, output: Path, profile: str, runtime: dict, client: Path,
            native: dict, library: Path, run) -> dict:
    from continuity_c_consumer import MAX_BINARY
    selected = {}
    for name in ("driver", "peer"):
        row = native[name]
        path = Path(row["path"])
        sdk.require(sdk.snapshot(path, maximum=MAX_BINARY).sha256 == row["sha256"],
                    "native root fixture changed before Swift execution")
        selected[name] = path
    identities = {path: sdk.snapshot(path, maximum=MAX_BINARY).sha256
                  for path in (client, library, *selected.values())}
    sdk.require(identities[library] == native["binaries"][library.name],
                "Swift root facade does not use its qualified native library")
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False, "routes": {}}
    for variant in ("original", *driver.alternatives.VARIANTS):
        evidence = outside / ("swift-" + profile + "-root-" + variant)
        env = dict(runtime, QPC_ROOT_CLIENT=str(client), QPC_ROOT_CLIENT_LANGUAGE="Swift", QPC_ROOT_VARIANT=variant,
                   QPC_ROOT_EVIDENCE=str(evidence), QPERIAPT_C_CLIENT=str(selected["peer"]),
                   QPERIAPT_EXPECTED_CONTINUITY_LIBRARY=str(library))
        env.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
        stdout = run([str(selected["driver"]), "--exact", driver.TEST, "--nocapture"], "root-" + profile + "-" + variant, runtime=env)
        checked = verify_execution(stdout, evidence, variant=variant)
        checked["exported_public_files"] = export_selected(checked, evidence,
            output / "swift-root-public" / profile / variant, SCOPE,
            replay=lambda path: verify_execution(stdout, path, variant=variant))
        result["routes"][variant] = checked
    sdk.require(all(sdk.snapshot(path, maximum=MAX_BINARY).sha256 == digest for path, digest in identities.items()),
                "Swift root binaries changed during qualification")
    result["binaries"] = {name: {"path": str(path), "sha256": identities[path]}
                          for name, path in {"Swift_client": client, "native_library": library,
                                             "native_driver": selected["driver"], "C_peer": selected["peer"]}.items()}
    result["completed"] = True
    return result
