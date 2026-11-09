#!/usr/bin/env python3
"""Run a source-bound native retry-readiness ablation with the original driver."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


BASE = "358b921ab3469ce49f166633fc9a762ff6ed7e3d"
RUST = "1.98.1"
MIN_SENDER_TURNS = 4
NATIVE = Path("research/continuity-identity-candidate")
MATCHED_HASHES = {
    "native_driver.rs.txt": "8ca7ea6b0d17923d16eff6f48c2a1ac07ce2eb5929c4b4526510e41a50db0fca",
    "run.py": "0d089a5913adfa47e14a2ac85eb74771e505cde67ff18385a163bc533624547e",
    "validate.py": "80a2eed73944decaa8edde69db1b3523a12475930dd5e4da4821ca52add636bc",
    "schedule.py": "1d3b361c6d99b0e28c2b0044c99287835f4eba41e9163c0fda2614e954b23b18",
}
HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    require(path.is_file() and not path.is_symlink(), f"nonregular input: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text, old, new):
    require(text.count(old) == 1, "retry instrumentation anchor changed")
    return text.replace(old, new)


def aged_driver(original, age=MIN_SENDER_TURNS):
    require(type(age) is int and 1 <= age <= 32, "invalid retry age")
    source = replace_once(original, "const N: usize = 2048;",
                          f"const N: usize = 2048;\nconst MIN_RETRY_SENDER_TURNS: usize = {age};")
    source = replace_once(source, "    cursor: usize,\n}",
                          "    cursor: usize,\n    sender_turn: usize,\n    last_data_turn: BTreeMap<usize, usize>,\n}")
    source = replace_once(source,
                          "    fn choose(&mut self, owner: usize, opportunity: usize) -> Option<Frame> {\n        self.plan_control(owner);",
                          "    fn choose(&mut self, owner: usize, opportunity: usize) -> Option<Frame> {\n"
                          "        let turn = {\n"
                          "            let q = self.queues.get_mut(owner).expect(\"owner\");\n"
                          "            q.sender_turn = q.sender_turn.checked_add(1).expect(\"sender turn bound\");\n"
                          "            q.sender_turn\n"
                          "        };\n"
                          "        self.plan_control(owner);")
    source = replace_once(source,
                          "self.queues.get(owner).expect(\"owner\").unacked.first_key_value().map(|(_, f)| f.clone()).map(|mut f| {",
                          "self.queues.get(owner).expect(\"owner\").unacked.iter().find(|(request, _)| {\n"
                          "                    let last = self.queues.get(owner).expect(\"owner\").last_data_turn\n"
                          "                        .get(*request).expect(\"unacknowledged frame has emission turn\");\n"
                          "                    turn.checked_sub(*last).expect(\"monotone sender turns\") >= MIN_RETRY_SENDER_TURNS\n"
                          "                }).map(|(_, f)| f.clone()).map(|mut f| {")
    source = replace_once(source,
                          "            if selected.is_some() {\n"
                          "                self.queues.get_mut(owner).expect(\"owner\").cursor = (choice + 1) % 4;\n"
                          "                return selected;\n"
                          "            }",
                          "            if let Some(frame) = selected {\n"
                          "                let q = self.queues.get_mut(owner).expect(\"owner\");\n"
                          "                if let Kind::Data { request, .. } = frame.kind {\n"
                          "                    q.last_data_turn.insert(request, turn);\n"
                          "                }\n"
                          "                q.cursor = (choice + 1) % 4;\n"
                          "                return Some(frame);\n"
                          "            }")
    return source


def validate_retry_age(trace, minimum):
    """Recount sender-local opportunities without using the driver's counters."""
    turns = [0, 0]
    emitted = {}
    ages = []
    for row in trace:
        if row["event"] == "opportunity":
            owner = row["owner"]
            require(type(owner) is int and owner in (0, 1), "invalid opportunity owner")
            turns[owner] += 1
        elif row["event"] == "emit" and row["kind"] in ("application", "retry"):
            identity = (row["owner"], row["logical"])
            current = turns[row["owner"]]
            if row["kind"] == "retry":
                require(identity in emitted, "retry without first transmission")
                age = current - emitted[identity]
                require(age >= minimum, "premature retry")
                ages.append(age)
            else:
                require(identity not in emitted, "second first transmission")
            emitted[identity] = current
    return {"minimum_sender_turns": minimum, "retry_emissions": len(ages),
            "minimum_observed_sender_turns": min(ages) if ages else None,
            "maximum_observed_sender_turns": max(ages) if ages else None}


def load_matched(repository):
    matched = repository / "research/continuity-matched-comparison"
    for name, expected in MATCHED_HASHES.items():
        require(sha(matched/name) == expected, f"matched input changed: {name}")
    sys.path.insert(0, str(matched))
    import importlib.util
    spec = importlib.util.spec_from_file_location("matched_source_runner", matched/"run.py")
    require(spec is not None and spec.loader is not None, "matched runner module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return matched, module


def prepare(repository, output):
    matched, m = load_matched(repository)
    require(m.git(repository, "rev-parse", BASE).decode().strip() == BASE, "explicit base unavailable")
    output.mkdir()
    source = output/"source"
    m.archive(repository, BASE, source, m.SOURCE_PATHS)
    before = m.inventory(source)
    original = (matched/"native_driver.rs.txt").read_text()
    modified = aged_driver(original)
    test_path = source/NATIVE/"src/durable/messages/tests.rs"
    with test_path.open("a") as stream:
        stream.write("\nmod matched_comparison {\n"+original+"\n}\n")
        stream.write("\nmod retry_age_comparison {\n"+modified+"\n}\n")
    m.save(output/"drivers.json", {
        "baseline_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "retry_age_sha256": hashlib.sha256(modified.encode()).hexdigest(),
        "minimum_sender_turns": MIN_SENDER_TURNS,
        "policies": ["immediate", "sender-turns-4"],
    })
    (output/"retry_age_driver.rs.txt").write_text(modified)
    receipt = {
        "schema": 1, "status": "prepared_not_executed", "base_commit": BASE,
        "base_tree": m.git(repository, "rev-parse", BASE+"^{tree}").decode().strip(),
        "research_head": m.git(repository, "rev-parse", "HEAD").decode().strip(),
        "before": before, "after": m.inventory(source),
        "original_matched_inputs": MATCHED_HASHES,
        "ablation_inputs": [{"path": str(p.relative_to(repository)), "sha256": sha(p)}
                            for p in sorted(HERE.iterdir()) if p.is_file() and p.suffix in (".py", ".md")],
        "workflow_sha256": sha(repository/".github/workflows/continuity-retry-age-comparison.yml"),
        "toolchain": RUST, "minimum_sender_turns": MIN_SENDER_TURNS,
    }
    require([item["path"] for item in before] == [item["path"] for item in receipt["after"]],
            "source inventory paths changed")
    changes = [new["path"] for old,new in zip(before,receipt["after"]) if old != new]
    require(changes == [str(NATIVE/"src/durable/messages/tests.rs")], "unexpected source derivative")
    m.save(output/"preparation.json", receipt)
    return m, receipt


def run(repository, output):
    m, prepared = prepare(repository, output)
    source = output/"source"
    env = {**os.environ, "CARGO_TARGET_DIR": str(output/"build"), "RUSTUP_TOOLCHAIN": RUST,
           "RUST_BACKTRACE": "1"}
    started = time.time_ns()
    runtime = {"schema": 1, "started_ns": started, "platform": platform.platform(), "python": sys.version}
    runtime["rustc"] = m.command(["rustc", "+"+RUST, "-Vv"], cwd=source,
                                 logfile=output/"logs/rustc.log", env=env).strip()
    runtime["cargo"] = m.command(["cargo", "+"+RUST, "-V"], cwd=source,
                                 logfile=output/"logs/cargo.log", env=env).strip()
    m.save(output/"runtime.json", runtime)
    build = m.command(["cargo", "+"+RUST, "test", "--manifest-path", str(source/NATIVE/"Cargo.toml"),
                       "--locked", "--release", "--lib", "--no-run", "--message-format=json"], cwd=source,
                      logfile=output/"logs/native-build.jsonl", env=env)
    executables = []
    for line in build.splitlines():
        if line.startswith("{"):
            entry = json.loads(line)
            if entry.get("reason") == "compiler-artifact" and entry.get("executable") and entry["profile"]["test"]:
                executables.append(Path(entry["executable"]))
    require(len(executables) == 1, "native executable inventory")
    executable = executables[0]
    listing = m.command([str(executable), "--list"], cwd=source, logfile=output/"logs/tests.log", env=env)
    exact_names = {}
    for policy,module in (("immediate", "matched_comparison"), ("sender-turns-4", "retry_age_comparison")):
        suffix = "::"+module+"::matched_directed_opportunities_native: test"
        names = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(suffix)]
        require(len(names) == 1, "exact ablation test inventory: "+policy)
        exact_names[policy] = names[0]
    executable_digest = sha(executable)
    m.save(output/"executable.json", {"path": str(executable.relative_to(output)), "sha256": executable_digest,
                                     "exact_tests": exact_names})
    evidence = output/"evidence"
    evidence.mkdir()
    from schedule import SCENARIOS
    from validate import read_rows, verify_native
    policies = []
    for policy,minimum in (("immediate", 0), ("sender-turns-4", MIN_SENDER_TURNS)):
        directory = evidence/policy
        directory.mkdir()
        run_env = {**env, "QPERIAPT_MATCHED_OUTPUT": str(directory)}
        m.command([str(executable), "--exact", exact_names[policy], "--nocapture", "--test-threads=1"],
                  cwd=source, logfile=output/("logs/"+policy+".log"), env=run_env)
        require({p.name for p in directory.iterdir()} == {
            f"continuity-{budget}-{scenario}.jsonl" for budget in (32,64) for scenario in SCENARIOS},
            "ablation trace inventory")
        reports = []
        for budget in (32,64):
            for scenario in SCENARIOS:
                profile = f"continuity-{budget}"
                path = directory/(profile+"-"+scenario+".jsonl")
                report = verify_native(path,profile,scenario)
                report["retry_readiness"] = validate_retry_age(read_rows(path),minimum)
                reports.append(report)
        policies.append({"policy": policy, "rows": reports})
    require(m.inventory(source) == prepared["after"], "execution changed source")
    require(sha(executable) == executable_digest, "execution changed test executable")
    m.save(evidence/"retry-age-report.json", {
        "schema": 1, "status": "passed", "execution": "native_compiled_and_executed",
        "base_commit": BASE, "research_head": prepared["research_head"],
        "elapsed_seconds": (time.time_ns()-started)/1e9, "policies": policies,
        "boundary": "same native service, opportunity list, snapshot predictor, budgets and persistence; application retry-readiness only",
        "timing": "combined experiment elapsed time; no per-service speed comparison",
    })
    m.save(evidence/"manifest.json", {"schema": 1, "status": "complete", "files": m.inventory(evidence)})
    print("Completed 28 native retry-readiness cases.", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "run"))
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository,output = args.repository.resolve(),args.output.absolute()
    if args.mode == "prepare":
        prepare(repository,output)
    else:
        run(repository,output)


if __name__ == "__main__":
    main()
