"""Bounded, hash-selected public grant files for the existing process harness."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib

from pending_recovery_actions import bounded, file_path
from qperiapt_continuity_reference.account_request import MAX_REQUEST, fields
from qperiapt_continuity_reference.wire import require


def selected(arguments, directory):
    require(len(arguments) == 4 and len(arguments[0]) == 32
            and len(arguments[1]) == 40 and len(arguments[3]) == 32,
            "account renewal fixture arguments")
    wire = bounded(file_path(directory, arguments[2]), MAX_REQUEST)
    require(hashlib.sha256(wire).digest() == arguments[3], "account grant fixture changed")
    local, companions, target = fields(wire)
    require(target == arguments[1], "account fixture target differs from selected target")
    return local, companions, target


def stage(owner, arguments, directory, now):
    return owner.stage_account(*selected(arguments, directory), now=now)


def prepare(owner, arguments, directory, now):
    return owner.prepare_account(*selected(arguments, directory), now=now)
