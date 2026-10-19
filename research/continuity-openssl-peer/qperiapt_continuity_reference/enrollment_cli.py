"""Local reference-device enrollment. No account login or private-key export.

Run with `python -m qperiapt_continuity_reference.enrollment_cli --help`.
The host supplies a stable public client ID, a protected wrapping-key file and
independently trusted public authorization/policy inputs.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time


def read_file(path, maximum, *, private=False):
    from .private_files import open_directory, private_regular
    from .wire import require
    require(path.is_absolute() and '..' not in path.parts, 'absolute input path required')
    parent = open_directory(path.parent) if private else None
    fd = None
    try:
        fd = os.open(path.name if private else path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        before = os.fstat(fd)
        if private: private_regular(before)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'input type or size')
        value = bytearray()
        while len(value) < before.st_size:
            part = os.read(fd, before.st_size - len(value))
            require(bool(part), 'input truncated'); value.extend(part)
        require(not os.read(fd, 1), 'input grew')
        after = os.fstat(fd)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed')
        return bytes(value)
    finally:
        if fd is not None: os.close(fd)
        if parent is not None: os.close(parent)


def export_request(path, value):
    from .private_files import open_directory, sync_file
    from .wire import require
    parent = open_directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        remaining = memoryview(value)
        while remaining:
            count = os.write(fd, remaining); require(count > 0, 'request export zero-length write')
            remaining = remaining[count:]
        sync_file(fd); os.fsync(parent); sync_file(fd)
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-root', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--client-id', required=True, help='original host-retained 32-byte identifier, hexadecimal')
    parser.add_argument('--key-file', type=Path, required=True, help='original 32-byte key in a private 0600 file under a 0700 directory')
    commands = parser.add_subparsers(dest='command', required=True)
    begin = commands.add_parser('begin', help='explicit first use in an existing empty 0700 directory')
    begin.add_argument('--authority', type=Path, required=True)
    begin.add_argument('--invitation', type=Path, required=True)
    commands.add_parser('status', help='reopen original state and report its public identity')
    request = commands.add_parser('request', help='export the original binary request for external approval')
    request.add_argument('--output', type=Path, required=True, help='new file in a private directory; never overwritten')
    accept = commands.add_parser('accept', help='accept the approved result against independent current trust')
    for name in ('approved', 'issued', 'current', 'policy-pins', 'policy-materials'):
        accept.add_argument('--' + name, type=Path, required=True)
    refresh = commands.add_parser('refresh-roster', help='adopt current same-credential membership before child preparation')
    for name in ('current', 'policy-pins', 'policy-materials'):
        refresh.add_argument('--' + name, type=Path, required=True)
    extension = commands.add_parser('adopt-extension', help='adopt an explicit same-key extension before child preparation')
    for name in ('approved-enrollment', 'approved-extension', 'issued', 'current', 'policy-pins', 'policy-materials'):
        extension.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    owner = None
    try:
        from .provider import load_provider
        load_provider(args.provider_root)
        from .enrollment_client import EnrollmentClient
        from .wire import require
        client_id = bytes.fromhex(args.client_id)
        require(len(client_id) == 32 and any(client_id), 'client ID must be 32 nonzero bytes')
        key = read_file(args.key_file, 32, private=True)
        require(len(key) == 32, 'client wrapping key must be exactly 32 bytes')
        now = int(time.time())  # Host OS time, never a caller-supplied backdate.
        if args.command == 'begin':
            owner = EnrollmentClient.begin(args.directory, client_id, key, read_file(args.authority, 16384),
                                           read_file(args.invitation, 16384), now)
        else:
            owner = EnrollmentClient.open(args.directory, client_id, key)
        if args.command == 'request':
            proof = owner.request(now); export_request(args.output, proof)
            result = {'request_file':str(args.output), 'request_sha256':hashlib.sha256(proof).hexdigest()}
        elif args.command == 'accept':
            journal = owner.accept(read_file(args.approved, 16384), read_file(args.issued, 32768),
                                   read_file(args.current, 128 * 1024), read_file(args.policy_pins, 16384),
                                   read_file(args.policy_materials, 128 * 1024), now)
            result = {'phase':'Accepted', 'journal':journal}
        elif args.command == 'refresh-roster':
            checkpoint = owner.refresh_roster(read_file(args.current, 128 * 1024),
                                               read_file(args.policy_pins, 16384),
                                               read_file(args.policy_materials, 128 * 1024), now)
            result = {'phase':'Accepted', 'roster_checkpoint':checkpoint}
        elif args.command == 'adopt-extension':
            journal = owner.adopt_extension(read_file(args.approved_enrollment, 16384),
                                            read_file(args.approved_extension, 2048), read_file(args.issued, 32768),
                                            read_file(args.current, 128 * 1024), read_file(args.policy_pins, 16384),
                                            read_file(args.policy_materials, 128 * 1024), now)
            result = {'phase':'Accepted', 'journal':journal}
        else:
            result = owner.status()
        def public(value):
            if type(value) is bytes: return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
            raise TypeError('unsupported public result')
        print(json.dumps(result, default=public))
        return 0
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    finally:
        if owner is not None: owner.close()


if __name__ == '__main__':
    raise SystemExit(main())
