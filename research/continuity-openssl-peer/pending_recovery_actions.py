"""Bounded test-worker files for public metadata larger than the control JSON."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import os
import re
from qperiapt_continuity_reference.pending_recovery import PendingWriteRecovery
from qperiapt_continuity_reference.pending_recovery_protocol import MAX_METADATA
from qperiapt_continuity_reference.private_files import sync_file
from qperiapt_continuity_reference.wire import require


def file_path(directory, encoded):
    name = encoded.decode('ascii')
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,120}(?:\.(?:proposal|metadata|signed))?', name) is not None,
            'pending recovery fixture file name')
    path = directory / name
    require(not path.is_symlink() and path.resolve().parent == directory.resolve(), 'pending fixture file boundary')
    return path


def bounded(path, capacity):
    with path.open('rb') as stream: value = stream.read(capacity + 1)
    require(len(value) <= capacity, 'pending fixture input capacity')
    return value


def exchange_files(owner, action, arguments, directory):
    require(len(arguments) == (1 if action == 'pending_recovery_request_files' else 3), 'pending recovery fixture arguments')
    if action == 'pending_recovery_request_files':
        prefix = file_path(directory, arguments[0])
        request = owner.request(); result = {}
        for name, value in [('proposal', request.proposal), ('metadata', request.metadata), ('signed', request.signed_request)]:
            destination = prefix.with_name(prefix.name + '.' + name)
            with destination.open('xb') as stream:
                stream.write(value); stream.flush(); sync_file(stream.fileno())
            result[name] = {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        return result
    require(action == 'pending_recovery_confirm_files' and len(arguments[2]) == 64, 'pending recovery confirmation arguments')
    proposal = bounded(file_path(directory, arguments[0]), 393)
    metadata = bounded(file_path(directory, arguments[1]), MAX_METADATA)
    require(hashlib.sha256(proposal).digest() + hashlib.sha256(metadata).digest() == arguments[2],
            'independently retained fixture inputs changed')
    return owner.confirm(proposal, metadata).hex()


def run(action, arguments, directory, path, scope, key, context, client, observer):
    require(len(arguments) == (1 if action == 'pending_recovery_request_files' else 3), 'pending recovery fixture arguments')
    owner = PendingWriteRecovery.open(path, scope, key, context, client=client, observer=observer)
    try:
        return exchange_files(owner, action, arguments, directory)
    finally:
        owner.close()
