#!/usr/bin/env python3
"""Install a source-bound wheel outside checkout and run the registered owner.

The supplied native counterpart and provider are separately qualified inputs.
This is reference lifecycle qualification, not deployed account authentication.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

from bounded_process import capture_output
from continuity_independent_python import PACKAGE, inspect_wheel, require, verify_installation, verify_extension_session
from evidence_io import fresh_output_directory, parse_strict_json_bytes, read_regular_snapshot
from git_provenance import git_commit, run_git_bytes

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "research/continuity-openssl-peer"
WHEEL = PACKAGE + "-0.0.0-py3-none-any.whl"


def snapshot(path: Path):
    return read_regular_snapshot(path, maximum=16 * 1024**2, label="independent Python input")


def write_json(path: Path, value) -> None:
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")


def runtime_files() -> list[Path]:
    return [*sorted((SOURCE / PACKAGE).glob("*.py")), *sorted(SOURCE.glob("*.py")),
            *sorted((SOURCE / "native/src").glob("*.rs")),
            *(SOURCE / n for n in ("native/Cargo.toml", "native/Cargo.lock", "requirements.txt"))]


def source_inputs(commit: str) -> dict[str, str]:
    paths = runtime_files() + [SOURCE / name for name in
        ("pyproject.toml", "README.md", "LICENSE-APACHE", "LICENSE-MIT", "build-requirements.txt")]
    paths += [ROOT / "artifact" / name for name in (
        "continuity_independent_python.py", "continuity_independent_python_probe.py",
        "continuity_independent_python_run.py", "python_bootstrap.py", "bounded_process.py",
        "evidence_io.py", "git_provenance.py")]
    result = {}
    for path in paths:
        name = path.relative_to(ROOT).as_posix()
        data = snapshot(path)
        require(data.data == run_git_bytes(ROOT, ["show", commit + ":" + name]),
                "reference execution source differs from selected commit: " + name)
        result[name] = data.sha256
    return result


def copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(snapshot(source).data)


def installed_files(path: Path) -> dict[str, bytes]:
    result = {}
    for item in path.rglob("*"):
        require(not item.is_symlink(), "installed reference contains a symlink")
        if item.is_file():
            result[item.relative_to(path).as_posix()] = snapshot(item).data
        else:
            require(item.is_dir(), "installed reference contains a special file")
    return result


def qualify(args: argparse.Namespace) -> dict:
    require(sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 14),
            "reference qualification requires CPython 3.14")
    require((os.uname().sysname, os.uname().machine) in {("Darwin", "arm64"), ("Linux", "x86_64")},
            "reference qualification supports Apple Silicon and Linux x86_64")
    commit = git_commit(ROOT)
    before = source_inputs(commit)
    wheel = snapshot(args.wheel)
    require(args.wheel.name == WHEEL, "reference wheel filename differs")
    modules = {p.name: snapshot(p).data for p in sorted((SOURCE / PACKAGE).glob("*.py"))}
    expected = {name: hashlib.sha256(body).hexdigest() for name, body in modules.items()}
    files = inspect_wheel(wheel.data, modules,
                          {name: snapshot(SOURCE / name).data for name in ("LICENSE-APACHE", "LICENSE-MIT")},
                          snapshot(SOURCE / "README.md").data)
    native = snapshot(args.native)
    provider = args.provider_root.resolve(strict=True)
    require(provider.is_dir() and not provider.is_relative_to(ROOT), "provider must be outside checkout")
    output = fresh_output_directory(args.output, within=ROOT / "target", label="installed Python qualification")
    output.mkdir(parents=True, mode=0o700)
    outside = Path(tempfile.mkdtemp(prefix="qperiapt-installed-python-")).resolve()
    require(not outside.is_relative_to(ROOT), "Python consumer must be outside checkout")
    write_json(output / "LOCATION.json", {"path": str(outside)})
    application = outside / "research/continuity-openssl-peer"
    cache = outside / "private-cache"
    cache.mkdir(mode=0o700)
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("PYTHON", "PIP_", "DYLD_", "LD_"))}
    result = {"schema_version": 3, "kind": "qperiapt.independent_python_installation",
              "completed": False, "release_claim_eligible": False, "source_commit": commit,
              "source_inputs": before, "wheel_sha256": wheel.sha256, "native_sha256": native.sha256}

    def run(argv: list[str], label: str) -> None:
        with contextlib.chdir(outside):
            executed = capture_output(argv, timeout_seconds=900, maximum_stdout_bytes=1024**2,
                                      maximum_stderr_bytes=1024**2, environment=environment)
        (output / (label + ".stdout")).write_bytes(executed.stdout)
        (output / (label + ".stderr")).write_bytes(executed.stderr)
        write_json(output / (label + ".json"), {"argv": argv, "cwd": str(outside), "exit": executed.returncode})
        require(executed.returncode == 0 and not executed.stderr, "installed Python command failed: " + label)

    try:
        captured = output / WHEEL
        with captured.open("xb") as stream:
            stream.write(wheel.data)
        requirements = output / "wheel-requirements.txt"
        requirements.write_text(captured.as_uri() + " --hash=sha256:" + wheel.sha256 + "\n")
        run([sys.executable, "-I", "-m", "pip", "install", "--isolated", "--disable-pip-version-check",
             "--no-index", "--no-deps", "--no-compile", "--require-hashes", "--target", str(application),
             "-r", str(requirements)], "install")
        installed = installed_files(application)
        verify_installation(installed, files, wheel_url=captured.as_uri(), digest=wheel.sha256)
        write_json(output / "INSTALLED_FILES.json", {n: hashlib.sha256(b).hexdigest() for n, b in installed.items()})
        for path in runtime_files():
            if not path.is_relative_to(SOURCE / PACKAGE):
                copy(path, application / path.relative_to(SOURCE))
        copy(ROOT / "artifact/python_bootstrap.py", outside / "artifact/python_bootstrap.py")
        copy(ROOT / "artifact/evidence_io.py", outside / "artifact/evidence_io.py")
        copy(ROOT / "artifact/continuity_independent_python_probe.py", outside / "probe.py")
        write_json(output / "EXPECTED_MODULES.json", expected)
        interpreter = [sys.executable, "-I", "-S", "-B", "-X", "pycache_prefix=" + str(cache),
                       str(outside / "artifact/python_bootstrap.py")]
        probe = [*interpreter, str(outside / "probe.py"), str(application), str(provider), str(ROOT),
                 str(output / "EXPECTED_MODULES.json"), str(output / "PROVENANCE.json")]
        run(probe, "probe")
        run([*interpreter, str(application / "registration_checks.py"), "--provider-root", str(provider),
             "--native", str(args.native), "--output", str(output / "registration")], "registration")
        observed = parse_strict_json_bytes(snapshot(output / "registration/RESULT.json").data, label="installed registration")
        current = {p.relative_to(SOURCE).as_posix(): snapshot(p).sha256 for p in runtime_files()}
        require(observed["source_files"] == current and observed["native_sha256"] == native.sha256,
                "installed registration source or native identity differs")
        require(observed["local"] == {"workers": 42, "native_commands": 15, "process_kills": 10}
                and observed["witness"] == {"workers": 50, "native_commands": 232, "process_kills": 11},
                "installed registration workload differs")
        run([*interpreter, str(application / "enrollment_session_checks.py"),
             "--implementation-root", str(application), "--provider-root", str(provider),
             "--native", str(args.native), "--output", str(output / "client-session")], "client-session")
        client_session = parse_strict_json_bytes(snapshot(output / "client-session/RESULT.json").data,
                                                label="installed enrollment client session")
        refusals = ["configuration-directory-alias", "prepared-child-refuses-roster-retarget",
                    "closed-client-revokes-child", "nested-client-operation",
                    "callback-close-withholds-result", "outer-directory-admission", "repaired-path-does-not-revive-child"]
        require(client_session["completed"] is True and client_session["provider"] == "48.0.1"
                and client_session["implementation"] == str(application / PACKAGE / "enrollment_client.py")
                and client_session["native_sha256"] == native.sha256
                and client_session["profiles"] == [
                    {"completed": True, "profile": "local", "witness_requests": 0,
                     "native_commands": 7, "refusal_cases": refusals},
                    {"completed": True, "profile": "witness", "witness_requests": 138,
                     "native_commands": 150, "refusal_cases": refusals + ["original-write-result-unknown"]}],
                "installed enrollment client session workload or implementation differs")
        run([*interpreter, str(application / "enrollment_extension_session.py"),
             "--implementation-root", str(application), "--provider-root", str(provider),
             "--native", str(args.native), "--output", str(output / "extension-session")], "extension-session")
        extension_session = parse_strict_json_bytes(snapshot(output / "extension-session/RESULT.json").data,
                                                   label="installed post-expiry enrollment session")
        verify_extension_session(extension_session,
                                 implementation=str(application / PACKAGE / "enrollment_client.py"),
                                 native_sha256=native.sha256)
        run([*interpreter, str(application / "peer_intermediate_checks.py"),
             "--provider-root", str(provider), "--native", str(args.native),
             "--output", str(output / "peer-intermediate")], "peer-intermediate")
        intermediate = parse_strict_json_bytes(snapshot(output / "peer-intermediate/RESULT.json").data,
                                              label="installed intermediate peer")
        require(intermediate["source_files"] == current and intermediate["native_sha256"] == native.sha256
                and intermediate["profiles"] == {
                    "local": {"worker_operations": 21, "native_commands": 10},
                    "witness": {"worker_operations": 21, "native_commands": 164}},
                "installed intermediate peer source or workload differs")
        for label in ("local", "witness"):
            row = parse_strict_json_bytes(snapshot(output / "peer-intermediate" / label / "RESULT.json").data,
                                         label="installed intermediate peer recovery")
            require(row["local_owner_original_mismatch_refused"] is True
                    and len(row["direct_refusals"]) == 9
                    and len([op for op in row["worker_operations"] if op.get("signal") == "SIGKILL"
                             and op.get("cut") == "committed:intent"]) == 1,
                    "installed intermediate peer authority or recovery differs")
        # The consumer adds only declared test files; pip's installed files and
        # all copied inputs must remain byte-identical after real process cuts.
        after = installed_files(application)
        harness = {p.relative_to(SOURCE).as_posix(): snapshot(p).data for p in runtime_files()
                   if not p.is_relative_to(SOURCE / PACKAGE)}
        require(after == installed | harness and not any(cache.iterdir()), "installed consumer files or cache changed")
        require(source_inputs(commit) == before and git_commit(ROOT) == commit
                and snapshot(args.wheel).sha256 == wheel.sha256 and snapshot(args.native).sha256 == native.sha256,
                "Python qualification inputs changed")
        result.update(completed=True, sources_unchanged=True, modules=expected,
                      registration={label: observed[label] for label in ("local", "witness")},
                      client_session=client_session, extension_session=extension_session,
                      intermediate_peer=intermediate, provider=observed["provider"])
    except BaseException as error:
        result["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        write_json(output / "PYTHON_INSTALLATION.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("wheel", "provider-root", "native", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.wheel = args.wheel.resolve(strict=True)
    args.native = args.native.resolve(strict=True)
    result = qualify(args)
    print(json.dumps({key: result[key] for key in ("completed", "wheel_sha256", "native_sha256", "registration")}))


if __name__ == "__main__":
    main()
