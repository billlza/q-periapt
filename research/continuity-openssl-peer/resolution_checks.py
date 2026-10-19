#!/usr/bin/env python3
"""Original outcome reporting, explicit application accounting and bounded history."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("provider-root", "native", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    peer = Path(__file__).resolve().parent
    sys.path.append(str(peer))
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    def inventory():
        sources = [*sorted((peer / "qperiapt_continuity_reference").glob("*.py")), *sorted(peer.glob("*.py")),
                   *sorted((peer / "native/src").glob("*.rs")), peer / "native/Cargo.toml",
                   peer / "native/Cargo.lock", peer / "requirements.txt"]
        return {str(p.relative_to(peer)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    before, native = inventory(), hashlib.sha256(args.native.read_bytes()).hexdigest()
    from resolution_scenario import ResolutionScenario
    scenario = ResolutionScenario(args, archived_version=3)
    try:
        scenario.run()
        scenario.native_call("close", 3, expected=b"closed")
        scenario.require(scenario.native.process.wait(timeout=5) == 0, "native shutdown")
        scenario.require(before == inventory() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(), "source changed during resolution run")
        report = {"scope": "Independent closed-epoch application accounting against actual Rust journal; local-only, fixed authority, separate host transaction",
                  "epochs": 6, "worker_operations": scenario.driver.operations, "native_commands": scenario.native.commands,
                  "control_steps": scenario.steps, "checks": scenario.checks, "application_decisions": scenario.decisions,
                  "codec_refusals": scenario.codec_refusals, "process_kills": sum("signal" in row for row in scenario.driver.operations),
                  "resolution": scenario.report, "old_codec_sha256": scenario.old_codec_sha256,
                  "archived_capture_sha256": hashlib.sha256(Path("research/sdk-alpha1/evidence/20261018-independent-control/CAPTURE.zip").read_bytes()).hexdigest(),
                  "source_files": before, "native_sha256": native, "sources_unchanged": True,
                  "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()},
                  "private_keys_or_images_in_artifact": False, "hardware_power_loss": False, "native_process_restart": False,
                  "Python_physical_erasure": False, "external_application_atomicity": False}
        (scenario.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"epochs": 6, "worker_operations": len(report["worker_operations"]),
                          "native_commands": len(report["native_commands"]), "process_kills": report["process_kills"],
                          "codec_refusals": report["codec_refusals"]}))
    finally:
        scenario.native.close()


if __name__ == "__main__":
    main()
