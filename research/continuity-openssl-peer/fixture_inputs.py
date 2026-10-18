"""Explicit test enrollment inputs; not an in-band trust discovery mechanism."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from peer.authority import DevicePin, Materials, Pins, authenticate
from peer.wire import Reader, VerificationKey, require


def read_public(directory, name):
    with (directory / name).open("rb") as stream:
        value = stream.read(65537)
    require(len(value) <= 65536, "public material bound")
    return value


def load(directory, admission_time, *, witness_pin=None):
    def read(name):
        return read_public(directory, name)
    def device(role):
        reader = Reader(read("pin-" + role + "-head"))
        pin = DevicePin(VerificationKey(read("pin-" + role + "-root")), reader.take(32),
                        reader.integer(8), reader.take(32), reader.take(16), reader.integer(8))
        reader.finish()
        return pin
    head = Reader(read("pin-policy-head"))
    pins = Pins(read("pin-sdk-root"), read("pin-sdk-state"), VerificationKey(read("pin-policy-root")),
                head.integer(8), head.take(32), device("i"), device("r"), read("pin-directory"))
    head.finish()
    materials = Materials(*(read(name) for name in (
        "sdk-document", "sdk-signature", "policy", "i-credential", "i-roster",
        "r-credential", "r-roster", "manifest", "proof-1", "proof-3")))
    return pins, materials, authenticate(pins, materials, admission_time, witness_pin=witness_pin)


def load_witness_pin(directory):
    from peer.witness import Pin
    return Pin(read_public(directory, "pin-witness-id"), VerificationKey(read_public(directory, "pin-witness-key")))
