"""Test host's separate durable decisions; not an SDK application transaction."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os

from peer.private_files import sync_file
from peer.wire import require


def record(path, session, role, report):
    decision = {"schema": "independent-application-resolution/v1", "session": session.hex(), "role": role,
                "report_id": report["id"], "epoch": report["epoch"],
                "outgoing": [dict(row, decision="delivery_unknown") for row in report["outgoing"]],
                "incoming": [dict(row, decision="quarantined_without_application_effect") for row in report["incoming"]],
                "skipped": report["skipped"]}
    data = (json.dumps(decision, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(data) <= 3 * 1024**2, "application fixture record bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        sync_file(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    require(path.read_bytes() == data, "application decision readback")
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "decision": decision}
