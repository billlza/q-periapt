"""Test-only identity owner file, separate from every session image and key."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import os
import stat
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from qperiapt_continuity_reference.private_files import private_regular, sync_file
from qperiapt_continuity_reference.wire import SigningKey, require


def write(path, signer):
    parent = path.parent.stat()
    require(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700,
            "private signing fixture directory")
    raw = signer._pq.private_bytes_raw() + signer._ec.private_numbers().private_value.to_bytes(32, "big")
    require(len(raw) == 64, "signing fixture seed format")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            sync_file(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        private_regular(os.fstat(fd))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(65)
    finally:
        os.close(fd)
    require(len(raw) == 64, "signing fixture length")
    signer = SigningKey.__new__(SigningKey)
    signer._pq = mldsa.MLDSA65PrivateKey.from_seed_bytes(raw[:32])
    signer._ec = ec.derive_private_key(int.from_bytes(raw[32:], "big"), ec.SECP256R1())
    return signer
