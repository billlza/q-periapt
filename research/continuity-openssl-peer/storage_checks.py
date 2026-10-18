#!/usr/bin/env python3
"""Actual-process interruption and refusal controls for the independent store."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

OLD = b"QPTEST01original state"
NEW = b"QPTEST01next exact state"
CUTS = ("stage-synced:intent", "published:intent", "committed:intent",
        "stage-synced:head", "published:head", "committed:head",
        "removed:intent", "committed:removal")


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--provider-root", type=Path, required=True)
    p.add_argument("--output", type=Path)
    p.add_argument("--worker", choices=("update", "create", "open"))
    p.add_argument("--root", type=Path)
    p.add_argument("--configuration", type=Path)
    p.add_argument("--cut", choices=CUTS)
    return p.parse_args()


def validate(payload: bytes):
    if not payload.startswith(b"QPTEST01"):
        raise ValueError("test payload schema")


def snapshot(path: Path):
    return {p.name: {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                     "mode": p.stat().st_mode & 0o777}
            for p in path.iterdir() if p.is_file() and not p.is_symlink()}


def main():
    args = arguments()
    provider = args.provider_root.resolve(strict=True)
    sys.path.append(str(Path(__file__).resolve().parent))
    from provider import load_provider
    cryptography, backend = load_provider(provider)
    from cryptography.exceptions import InvalidTag
    from peer.journal import Journal, Scope, Conflict, MissingState
    from peer.wire import require
    from worker_process import command as worker_command

    if args.worker:
        require(args.root is not None and args.configuration is not None, "worker inputs")
        raw = args.configuration.read_bytes()
        require(len(raw) == 128, "private configuration length")
        key, scope = raw[:32], Scope(raw[32:64], raw[64:96], raw[96:128])
        def observe(stage):
            if stage == args.cut:
                print(json.dumps({"pid": os.getpid(), "stage": stage}), flush=True)
                signal.pause()
                raise RuntimeError("interrupted worker unexpectedly resumed")
        if args.worker == "create":
            owner = Journal.create(args.root, scope, key, OLD, validate, observe)
        else:
            owner = Journal.open(args.root, scope, key, validate, observer=observe)
            if args.worker == "update":
                owner.update(owner.read().digest, NEW)
        value = owner.read()
        owner.close()
        print(json.dumps({"revision": value.revision, "digest": value.digest.hex()}))
        return

    require(args.output is not None, "new output directory required")
    output = args.output.resolve()
    output.mkdir()
    private = Path(tempfile.mkdtemp(prefix="qperiapt-independent-store-")).resolve()
    require(not private.is_relative_to(output), "private storage must be outside output")
    (output / "private-fixture-path").write_text(str(private) + "\n")
    key = os.urandom(32)
    scope = Scope(os.urandom(32), os.urandom(32), os.urandom(32))
    configuration = private / "configuration"
    fd = os.open(configuration, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key + scope.wire())
        stream.flush()
        os.fsync(stream.fileno())
    results, killed_pids = [], []

    def new_store(name):
        directory = private / name
        directory.mkdir(mode=0o700)
        owner = Journal.create(directory, scope, key, OLD, validate)
        return directory, owner

    def rejected(name, function, errors=(ValueError, InvalidTag, OSError)):
        try:
            function()
        except errors as error:
            results.append({"case": name, "refused": type(error).__name__})
        else:
            raise ValueError("negative control accepted: " + name)

    def killed(name, directory, action, cut):
        command = worker_command(Path(__file__),
                   "--provider-root", str(provider), "--worker", action, "--root", str(directory),
                   "--configuration", str(configuration), "--cut", cut)
        with (output / (name + ".stderr")).open("xb") as err:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, start_new_session=True, bufsize=0)
            try:
                require(process.stdout is not None, "missing worker output")
                line = bytearray()
                deadline = time.monotonic() + 30
                while not line.endswith(b"\n"):
                    ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
                    require(bool(ready), "worker stage timeout")
                    part = os.read(process.stdout.fileno(), 1)
                    require(bool(part) and len(line) < 128, "worker stage missing or oversized")
                    line.extend(part)
                marker = json.loads(line)
                require(marker == {"pid": process.pid, "stage": cut}, "wrong worker identity or stage")
                os.killpg(process.pid, signal.SIGKILL)
                require(process.wait(timeout=5) == -signal.SIGKILL, "worker was not killed")
                killed_pids.append(process.pid)
                (output / (name + ".stage")).write_bytes(line)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
        require((output / (name + ".stderr")).stat().st_size == 0, "worker diagnostics")

    for number, cut in enumerate(CUTS):
        name = "update-cut-" + str(number)
        directory, owner = new_store(name)
        expected_target = owner._seal(2, NEW)
        owner.close()
        killed(name, directory, "update", cut)
        owner = Journal.open(directory, scope, key, validate)
        observed = owner.read()
        expected_revision = 1 if number == 0 else 2
        require(observed.revision == expected_revision
                and observed.payload == (OLD if number == 0 else NEW), "wrong recovered transition")
        if number != 0:
            require((directory / "head").read_bytes() == expected_target, "recovery changed sealed target")
        require(not (directory / "intent").exists(), "unresolved intent after recovery")
        owner.close()
        owner = Journal.open(directory, scope, key, validate)
        require(owner.read() == observed, "second reopen incremented again")
        owner.close()
        results.append({"case": name, "signal": "SIGKILL", "cut": cut, "revision": observed.revision,
                        "exact_target": number != 0, "second_reopen_idempotent": True})

    for number, cut in enumerate(CUTS):
        name = "creation-cut-" + str(number)
        directory = private / name
        directory.mkdir(mode=0o700)
        killed(name, directory, "create", cut)
        if number == 0:
            before = snapshot(directory)
            rejected(name + "-no-formal-intent", lambda: Journal.open(directory, scope, key, validate, creation=True), (MissingState,))
            require(snapshot(directory) == before, "missing creation was repaired")
        else:
            if not (directory / "head").exists():
                rejected(name + "-active-open", lambda: Journal.open(directory, scope, key, validate), (MissingState,))
            owner = Journal.open(directory, scope, key, validate, creation=True)
            require(owner.read().revision == 1 and owner.read().payload == OLD, "creation reconciliation differs")
            owner.close()
            results.append({"case": name, "signal": "SIGKILL", "cut": cut, "original_creation_recovered": True})

    directory, owner = new_store("original")
    before = owner.read()
    rejected("competing-owner", lambda: Journal.open(directory, scope, key, validate), (BlockingIOError,))
    rejected("stale-expected-head", lambda: owner.update(bytes(32), NEW), (Conflict,))
    require(owner.read() == before, "stale update changed original")
    owner.update(before.digest, NEW)
    owner.close()
    rejected("advanced-creation-reader", lambda: Journal.open(directory, scope, key, validate, creation=True), (Conflict,))
    for name, bad_key, bad_scope in (("wrong-key", os.urandom(32), scope),
                                    ("wrong-scope", key, Scope(os.urandom(32), scope.owner, scope.context))):
        saved = snapshot(directory)
        rejected(name, lambda bad_key=bad_key, bad_scope=bad_scope: Journal.open(directory, bad_scope, bad_key, validate))
        require(snapshot(directory) == saved, "unauthorized recovery wrote state")

    for name in ("missing-head", "changed-head", "short-head", "public-head", "hardlinked-head", "symlink-head"):
        target = private / name
        shutil.copytree(directory, target)
        head = target / "head"
        if name == "missing-head": head.unlink()
        elif name == "changed-head":
            value = head.read_bytes();head.write_bytes(value[:-1] + bytes([value[-1] ^ 1]))
        elif name == "short-head": head.write_bytes(b"short")
        elif name == "public-head": head.chmod(0o644)
        elif name == "hardlinked-head": os.link(head, target / "alias")
        else:
            head.rename(target / "original-head");head.symlink_to("original-head")
        saved = snapshot(target)
        rejected(name, lambda target=target: Journal.open(target, scope, key, validate))
        require(snapshot(target) == saved, "invalid state was altered")

    directory, owner = new_store("uncertain-write")
    def fail_after_intent(stage):
        if stage == "committed:intent": raise OSError("injected acknowledgement loss")
    owner._directory.observer = fail_after_intent
    rejected("write-acknowledgement-lost", lambda: owner.update(owner.read().digest, NEW), (OSError,))
    rejected("failed-owner-closed", owner.read, (ValueError,))
    preserved = private / "tampered-intent"
    shutil.copytree(directory, preserved)
    value = (preserved / "intent").read_bytes();(preserved / "intent").write_bytes(value[:-1] + bytes([value[-1] ^ 1]))
    saved = snapshot(preserved)
    rejected("tampered-intent", lambda: Journal.open(preserved, scope, key, validate), (ValueError,))
    require(snapshot(preserved) == saved, "bad intent repaired")
    owner = Journal.open(directory, scope, key, validate)
    require(owner.read().revision == 2 and owner.read().payload == NEW, "lost acknowledgement did not recover exact target")
    owner.close()
    results.append({"case": "lost-ack-recovery", "revision": 2, "original_target": True})

    directory, owner = new_store("concurrent-CAS")
    original = owner.read()
    barrier = threading.Barrier(3)
    outcomes = []
    def compete(payload):
        barrier.wait(timeout=5)
        try:
            result = owner.update(original.digest, payload)
            outcomes.append(("committed", result.payload))
        except Conflict:
            outcomes.append(("conflict", payload))
    threads = [threading.Thread(target=compete, args=(b"QPTEST01writer" + bytes([n]),)) for n in (1, 2)]
    for thread in threads: thread.start()
    barrier.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=10)
        require(not thread.is_alive(), "concurrent writer stalled")
    require(sorted(kind for kind, _ in outcomes) == ["committed", "conflict"], "CAS admitted multiple writers")
    require(owner.read().revision == 2 and owner.read().payload == next(p for k, p in outcomes if k == "committed"),
            "CAS result differs from authoritative state")
    owner.close()
    results.append({"case": "concurrent-CAS", "committed": 1, "conflicts": 1})

    directory, owner = new_store("wrong-predecessor")
    target = owner._seal(8, NEW)
    intent = owner._intent(7, os.urandom(32), target)
    owner._directory.publish("intent", intent)
    owner.close()
    before = snapshot(directory)
    rejected("authenticated-wrong-predecessor", lambda: Journal.open(directory, scope, key, validate), (Conflict,))
    require(snapshot(directory) == before, "wrong predecessor was rebased")

    directory, owner = new_store("capacity-before-intent")
    for number in range(126):
        fd = os.open(directory / (".stage-control-" + str(number)), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    before = snapshot(directory)
    rejected("capacity-reserved-before-intent", lambda: owner.update(owner.read().digest, NEW), (ValueError,))
    require(snapshot(directory) == before and not (directory / "intent").exists(), "capacity failure admitted intent")

    directory, owner = new_store("capacity-during-recovery")
    for number in range(125):
        fd = os.open(directory / (".stage-held-" + str(number)), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
    held = {name: value for name, value in snapshot(directory).items() if name.startswith(".stage-held-")}
    target = owner._seal(2, NEW)
    owner.close()
    killed("quota-update-cut", directory, "update", "stage-synced:head")
    for length in (0, 7, len(target) - 1):
        partial = private / ("partial-target-" + str(length))
        shutil.copytree(directory, partial)
        with (partial / ".stage-head").open("r+b") as stream:
            stream.truncate(length)
            stream.flush()
            os.fsync(stream.fileno())
        recovered = Journal.open(partial, scope, key, validate)
        require(recovered.read().revision == 2 and (partial / "head").read_bytes() == target,
                "partial output slot changed the original target")
        recovered.close()
        results.append({"case": "partial-reserved-output", "constructed_prefix_bytes": length, "exact_target": True})
    conflict = private / "conflicting-reserved-output"
    shutil.copytree(directory, conflict)
    staged = (conflict / ".stage-head").read_bytes()
    (conflict / ".stage-head").write_bytes(staged[:-1] + bytes([staged[-1] ^ 1]))
    before_conflict = snapshot(conflict)
    rejected("conflicting-reserved-output", lambda: Journal.open(conflict, scope, key, validate), (ValueError,))
    require(snapshot(conflict) == before_conflict, "conflicting output slot was overwritten")
    for number in range(2):
        require(len(list(directory.iterdir())) == 128, "write exceeded admitted file count")
        killed("quota-recovery-cut-" + str(number), directory, "open", "stage-synced:head")
    owner = Journal.open(directory, scope, key, validate)
    require(owner.read().revision == 2 and (directory / "head").read_bytes() == target,
            "bounded recovery changed the original target")
    owner.close()
    require({name: value for name, value in snapshot(directory).items() if name.startswith(".stage-held-")} == held,
            "recovery removed unrelated staging files")
    results.append({"case": "repeated-recovery-at-file-quota", "process_kills": 3,
                    "exact_target": True, "unrelated_staging_files_preserved": 125})
    directory, owner = new_store("close-during-publication")
    def close_after_write(stage):
        if stage == "stage-synced:head":
            owner.close()
    owner._directory.observer = close_after_write
    rejected("close-during-publication", lambda: owner.update(owner.read().digest, NEW), (ValueError,))
    rejected("publication-owner-closed", owner.read, (ValueError,))
    recovered = Journal.open(directory, scope, key, validate)
    require(recovered.read().payload == NEW and recovered.read().revision == 2, "closed publication lost target")
    lease = recovered._directory
    recovered.close()
    rejected("closed-directory-read", lambda: lease.read("head"), (ValueError,))
    rejected("closed-directory-quota", lambda: lease.quota(1), (ValueError,))
    report = {"scope": "Independent local-only journal primitive with tagged test payloads; protocol owner recovery is a separate validation lane",
              "provider": {"cryptography": cryptography.__version__, "openssl": backend.openssl_version_text()},
              "process_kills": len(killed_pids), "killed_worker_pids": killed_pids,
              "results": results, "hardware_power_loss": False,
              "private_keys_or_images_in_artifact": False}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"process_kills": len(killed_pids), "controls": len(results), "scope": report["scope"]}))


if __name__ == "__main__":
    main()
