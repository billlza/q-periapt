#!/usr/bin/env python3
"""Actual archived version-five writer continued by the original account owner."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import sys


def scenario(args, count):
    from local_credential_fixture import Fixture
    from shared_account_checks import request_arguments
    from qperiapt_continuity_reference.account_snapshot import base_size
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    f = Fixture(args, str(count), account_members=count, archived_five=True)
    owner = coordinator = None
    try:
        # This write uses the archived implementation, after an actual bootstrap.
        owner = f.archived_session.open(f.path, f.scope, f.key, f.archived_context)
        identity = owner.next_id(170)
        plaintext = b"actual archived common-account outbox"
        wire = owner.send(identity, plaintext, b"", 170)
        with owner._state(operational=False) as (snapshot, state):
            require(state.format_version == 5, "archived established state is not five")
            payload = snapshot.payload
        owner.close(); owner = None
        require(f.worker("current-reader-preserves-five", "storage_format", now=170) == 5,
                "opening an old state silently migrated it")
        require(f.value("current-original-replay", "resume", (identity,), now=170) == wire, "old original ciphertext")
        f.worker("expired-original-refused", "resume", (identity,), now=210, refusal="expired or premature authority")
        first = request_arguments(f, count, "complete-migration-grants", 1)
        f.worker("migration-stage-kill", "local_account_stage_files", first, now=210, cut="committed:intent")
        intent = (f.path / "intent").read_bytes()
        require(f.worker("migration-original-pending", "local_credential_status", (first[0],), now=210)["status"] == "Pending"
                and (f.path / "head").read_bytes() == intent[52:-32], "migration did not preserve exact pending target")
        coordinator = f.coordinator(first[0])
        with coordinator._state() as (snapshot, state, _current, _record):
            require(state.format_version == 9
                    and snapshot.payload[12:12 + base_size(snapshot.payload)] == payload,
                    "migration changed archived business or transcript bytes")
            f.refuses("archived-reader-refuses-nine", lambda: f.archived.decode(snapshot.payload, f.archived_context),
                      "snapshot schema/context")
        coordinator.close(); coordinator = None
        f.worker("migration-commit-kill", "local_credential_commit", (first[0],), now=210, cut="committed:head")
        require(f.worker("migration-committed", "local_credential_status", (first[0],), now=210)["status"] == "Committed",
                "original migrated commit")
        require(f.worker("migrated-format-nine", "storage_format", now=210) == 9
                and f.value("migrated-original-replay", "resume", (identity,), now=210) == wire,
                "migrated owner lost original outbox")
        second = request_arguments(f, count, "complete-following-grants", 2)
        f.worker("following-group-stage", "local_account_stage_files", second, now=310)
        require(f.worker("following-group-commit", "local_credential_commit", (second[0],), now=310)["status"] == "Committed"
                and f.value("original-after-two-groups", "resume", (identity,), now=310) == wire,
                "second group changed archived session")
        f.call("native-receives-archived-ciphertext", 7, application(b"", wire), plaintext)
        report = {"members": count, "archived_codec_sha256": f.archived_hash,
                  "original_payload_sha256": hashlib.sha256(payload).hexdigest(),
                  "original_ciphertext_sha256": hashlib.sha256(wire).hexdigest(),
                  "session": f.session.hex(), "original_format": 5, "migrated_format": 9,
                  "workers": len(f.driver.operations), "native_commands": len(f.native.commands),
                  "process_kills": sum(row.get("signal") == "SIGKILL" for row in f.driver.operations),
                  "scope": "Real archived writer, unchanged original journal/key and business payload. Native traffic fixture time170; no witness migration or bilateral real-time expiry claim."}
        (f.out / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        if owner is not None: owner.close()
        if coordinator is not None: coordinator.close()
        f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments()
    args.output, args.native, args.provider_root = args.output.resolve(), args.native.resolve(), args.provider_root.resolve()
    crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    root = Path(__file__).resolve().parent
    paths = [*sorted((root / "qperiapt_continuity_reference").glob("*.py")), *sorted(root.glob("*.py")),
             *sorted((root / "native/src").glob("*.rs")), root / "native/Cargo.toml", root / "native/Cargo.lock",
             root / "requirements.txt"]
    def sources():
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before = sources(); args.output.mkdir()
    report = {"source_files": before, "native_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(),
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profiles"] = [scenario(args, count) for count in (3, 32)]
    require(before == sources(), "source changed during archived common migration")
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["profiles"]))


if __name__ == "__main__":
    main()
