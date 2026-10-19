"""Bounded canonical fields shared by the versioned private snapshot codecs."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .wire import MAX_U64, require


@dataclass(frozen=True, repr=False)
class SendPlan:
    identity: bytes
    plaintext: bytes
    ad: bytes


def blob(value, cap):
    require(type(value) is bytes and len(value) <= cap, "snapshot field capacity")
    return len(value).to_bytes(4, "big") + value


def read_blob(reader, cap):
    size = reader.integer(4)
    require(size <= cap, "snapshot field capacity")
    return reader.take(size)


def indices(reader, cap):
    count, previous = reader.integer(2), -1
    require(count <= cap, "snapshot record count")
    for _ in range(count):
        index = reader.integer(8)
        require(previous < index < MAX_U64, "snapshot record order")
        previous = index
        yield index


def encode_pending(plan):
    return bytes([plan is not None]) + (plan.identity + blob(plan.plaintext, 16384) + blob(plan.ad, 1024)
                                      if plan is not None else b"")


def decode_pending(reader):
    present = reader.integer(1)
    require(present in (0, 1), "snapshot pending flag")
    return SendPlan(reader.take(32), read_blob(reader, 16384), read_blob(reader, 1024)) if present else None
