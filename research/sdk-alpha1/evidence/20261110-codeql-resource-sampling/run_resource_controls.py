"""Reproduce short real-process resource controls; no CodeQL query is launched."""

from __future__ import annotations

import argparse
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import platform
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True) / "artifact"
    sys.path.insert(0, str(source))
    import codeql_process_resources as resources
    import codeql_summary_control as control
    from bounded_process import BoundedProcessError

    args.output.mkdir(parents=True, exist_ok=False)
    control.ProcessResourceSampler = partial(resources.ProcessResourceSampler, interval_seconds=0.05)
    child = "import os,time; data=bytearray(b'x')*(32*1024**2); print(os.getpid(),flush=True); time.sleep(1.3)"
    parent = ("import os,subprocess,sys; data=bytearray(b'y')*(24*1024**2); "
              f"p=subprocess.Popen([sys.executable,'-c',{child!r}],stdout=subprocess.PIPE,text=True); "
              "print(str(os.getpid())+' '+p.stdout.readline().strip(),flush=True); p.wait()")
    cases = [("completed", parent, 5),
             ("timeout", "import os,time; data=bytearray(b'x')*(8*1024**2); print(os.getpid(),flush=True); time.sleep(20)", 1)]
    results = {}
    for name, program, seconds in cases:
        destination = args.output / name
        destination.mkdir()
        caught = None
        try:
            control.run_queries([sys.executable, "-c", program], destination,
                                {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, seconds=seconds)
        except BoundedProcessError as error:
            caught = {"kind": error.kind, "cleanup_ambiguous": error.cleanup_ambiguous}
        receipt = json.loads((destination / "query.json").read_text())
        observation = receipt["resource_observation"]
        assert observation["status"] == "stopped" and observation["shutdown_complete"], observation
        assert observation["samples_with_processes"] > 0
        if name == "completed":
            assert receipt["returncode"] == 0 and caught is None
            assert observation["observed_root_identities"] == 1 and observation["observed_process_identities"] == 2
            assert observation["peak_sampled_tree_rss_bytes"] > 50 * 1024**2
        else:
            assert caught == {"kind": "timeout", "cleanup_ambiguous": False}
            assert receipt["stopped"] == "timeout"
        results[name] = {"evaluation": receipt, "caught": caught}
    source_names = ["codeql_process_resources.py", "codeql_summary_control.py", "bounded_process.py",
                    "codeql_log_recovery.py", "evidence_io.py", "codeql_rust_queries.json"]
    report = {"schema": 1, "kind": "qperiapt.codeql_resource_sampling_control",
              "workload": "synthetic Python allocation and sleep using real supervised processes",
              "codeql_queries_executed": False, "host": {"system": platform.system(), "release": platform.release(),
                    "machine": platform.machine(), "python": platform.python_version()},
              "sources": {name: {"bytes": (source / name).stat().st_size,
                          "sha256": hashlib.sha256((source / name).read_bytes()).hexdigest()} for name in source_names},
              "cases": results}
    (args.output / "LIVE_CONTROLS.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({name: {key: case["evaluation"]["resource_observation"][key]
          for key in ("samples", "samples_with_processes", "peak_sampled_tree_rss_bytes",
                      "peak_sampled_roots_rss_bytes", "sampler_cpu_seconds", "sampling_wall_seconds")}
          for name, case in results.items()}, indent=2))


if __name__ == "__main__":
    main()
