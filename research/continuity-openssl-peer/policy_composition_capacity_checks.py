#!/usr/bin/env python3
"""Full original business allowance through P/G/R and retained policy history."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import sys


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments()
    args.output, args.native, args.provider_root = args.output.resolve(), args.native.resolve(), args.provider_root.resolve()
    crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    from roster_capacity_checks import scenario
    root = Path(__file__).resolve().parent
    def inventory():
        files = [*sorted((root / "qperiapt_continuity_reference").glob("*.py")), *sorted(root.glob("*.py")),
                 *sorted((root / "native/src").glob("*.rs")), root / "native/Cargo.toml", root / "native/Cargo.lock", root / "requirements.txt"]
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    before, native = inventory(), hashlib.sha256(args.native.read_bytes()).hexdigest()
    args.output.mkdir()
    report = {"source_files": before, "native_sha256": native,
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profiles"] = [scenario(args, witnessed, policy_composition=True) for witnessed in (False, True)]
    require(before == inventory() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(), "full composition inputs changed")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps([{k:r[k] for k in ("members", "witnessed", "workers", "process_kills")} for r in report["profiles"]]))


if __name__ == "__main__":
    main()
