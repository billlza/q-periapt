#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Independent fixture oracle: Python canonical hashes/trees and OpenSSL signatures.

Run through artifact/python-run.sh. This is a test consumer of public fixture
bytes, not a production parser, account enrollment, or interoperability protocol.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "artifact"))
from bounded_process import capture_output
from prekey_selection import decode_record, encode_input

CONTEXT = b"Q-PERIAPT-CONTINUITY-IDENTITY-CANDIDATE/v1"
ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(name: str, body: bytes) -> bytes:
    domain = ("Q-PERIAPT-CONTINUITY-" + name + "-CANDIDATE/v1").encode("ascii")
    return hashlib.sha3_256(
        len(domain).to_bytes(8, "big") + domain + len(body).to_bytes(8, "big") + body
    ).digest()


def save(path: Path, value: bytes) -> Path:
    with path.open("xb") as stream:
        stream.write(value)
    return path


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        require(0 <= size <= len(self.data) - self.offset, "truncated field")
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def integer(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def finish(self) -> None:
        require(self.offset == len(self.data), "trailing bytes")


def tlv(tag: int, data: bytes) -> bytes:
    size = len(data)
    if size < 128:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([128 + len(raw)]) + raw
    return bytes([tag]) + length + data


def integer_der(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return tlv(2, (b"\0" if raw[0] & 128 else b"") + raw)


def classic_der(signature: bytes) -> bytes:
    require(len(signature) == 64, "ECDSA signature length")
    return tlv(48, integer_der(int.from_bytes(signature[:32], "big"))
               + integer_der(int.from_bytes(signature[32:], "big")))


class Oracle:
    def __init__(self, fixture: Path, output: Path, openssl: str):
        self.fixture = fixture
        self.output = output
        self.openssl = openssl
        self.commands: list[dict] = []
        self.inputs: dict[str, str] = {}

    def read(self, name: str, length: int | None = None) -> bytes:
        with (self.fixture / name).open("rb") as stream:
            data = stream.read(32769)
        require(len(data) <= 32768, "fixture byte bound")
        if length is not None:
            require(len(data) == length, "wrong fixture length: " + name)
        self.inputs[name] = hashlib.sha256(data).hexdigest()
        return data

    def command(self, name: str, arguments: list[str], expected: int) -> bytes:
        result = capture_output(
            [self.openssl, *arguments], timeout_seconds=20,
            maximum_stdout_bytes=65536, maximum_stderr_bytes=65536,
        )
        save(self.output / (name + ".stdout"), result.stdout)
        save(self.output / (name + ".stderr"), result.stderr)
        self.commands.append({"name": name, "argv": [self.openssl, *arguments],
                              "returncode": result.returncode, "expected": expected})
        require(result.returncode == expected, "OpenSSL result differs: " + name)
        return result.stdout

    def envelope(self, name: str, purpose: int, key: bytes) -> bytes:
        wire = Reader(self.read(name + ".bin"))
        size = wire.integer(4)
        require(size <= 16384, "signed body bound")
        body = wire.take(size)
        pq_signature = wire.take(3309)
        classic_signature = wire.take(64)
        wire.finish()
        require(0 < int.from_bytes(classic_signature[32:], "big") <= ORDER // 2,
                "noncanonical ECDSA s")
        bound = CONTEXT + bytes([purpose]) + size.to_bytes(4, "big") + body
        message = save(self.output / (name + ".message"), bound)
        # ML-DSA-65 OID 2.16.840.1.101.3.4.3.18, absent parameters.
        pq_spki = tlv(48, tlv(48, bytes.fromhex("0609608648016503040312"))
                      + tlv(3, b"\0" + key[:1952]))
        # id-ecPublicKey with named prime256v1 and the compressed SEC1 point.
        ec_spki = tlv(48, tlv(48, bytes.fromhex("06072a8648ce3d020106082a8648ce3d030107"))
                      + tlv(3, b"\0" + key[1952:]))
        pq_public = save(self.output / (name + ".pq.der"), pq_spki)
        ec_public = save(self.output / (name + ".ec.der"), ec_spki)
        pq_sig = save(self.output / (name + ".pq.sig"), pq_signature)
        ec_sig = save(self.output / (name + ".ec.sig"), classic_der(classic_signature))
        pq_args = ["pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(pq_public),
                   "-sigfile", str(pq_sig), "-pkeyopt", "context-string:" + CONTEXT.decode()]
        ec_args = ["dgst", "-sha256", "-keyform", "DER", "-verify", str(ec_public),
                   "-signature", str(ec_sig)]
        self.command(name + "-pq", [*pq_args, "-in", str(message)], 0)
        self.command(name + "-ec", [*ec_args, str(message)], 0)
        changed = bound[:-1] + bytes([bound[-1] ^ 1])
        wrong_body = save(self.output / (name + ".wrong-body"), changed)
        wrong_purpose = save(self.output / (name + ".wrong-purpose"),
                             CONTEXT + bytes([purpose ^ 1]) + bound[len(CONTEXT) + 1:])
        for label, wrong in (("body", wrong_body), ("purpose", wrong_purpose)):
            self.command(name + "-pq-reject-" + label, [*pq_args, "-in", str(wrong)], 1)
            self.command(name + "-ec-reject-" + label, [*ec_args, str(wrong)], 1)
        wrong_context = [*pq_args[:-1], "context-string:wrong-context"]
        self.command(name + "-pq-reject-context", [*wrong_context, "-in", str(message)], 1)
        return body


def split(count: int) -> int:
    require(2 <= count <= 1024, "tree count")
    return 1 << ((count - 1).bit_length() - 1)


def tree(ids: list[bytes]) -> bytes:
    if len(ids) == 1:
        return ids[0]
    pivot = split(len(ids))
    return digest("PREKEY-NODE", tree(ids[:pivot]) + tree(ids[pivot:]))


def expected_path(ids: list[bytes], index: int) -> list[bytes]:
    if len(ids) == 1:
        return []
    pivot = split(len(ids))
    if index < pivot:
        return expected_path(ids[:pivot], index) + [tree(ids[pivot:])]
    return expected_path(ids[pivot:], index - pivot) + [tree(ids[:pivot])]


def verify(oracle: Oracle) -> dict:
    version = oracle.command("version", ["version", "-a"], 0).decode()
    root_key = oracle.read("root.pub", 1985)
    device_key = oracle.read("device.pub", 1985)
    account = digest("ACCOUNT", root_key)
    require(account == oracle.read("account.bin", 32), "account identity differs")
    family = oracle.read("family.bin", 32)
    require(family == bytes([6]) * 32, "fixture family differs")
    interval = (100).to_bytes(8, "big") + (200).to_bytes(8, "big")
    device_id = bytes([5]) * 16
    revision = (1).to_bytes(8, "big")
    certificate = oracle.envelope("credential", 1, root_key)
    require(certificate == b"QPCERT01" + account + device_id + revision + interval + family + device_key,
            "credential grammar or scope differs")
    certificate_digest = digest("CREDENTIAL", certificate)
    roster = oracle.envelope("roster", 2, root_key)
    require(roster == b"QPROST01" + account + revision + interval + b"\0\1"
            + device_id + revision + certificate_digest, "roster grammar or scope differs")
    roster_digest = digest("ROSTER", roster)
    require(roster_digest == oracle.read("roster-digest.bin", 32), "roster digest differs")
    authority = digest("AUTHORITY", account + revision + roster_digest + family)
    require(authority == oracle.read("authority.bin", 32), "authority binding differs")
    proof_total = 0
    selection_total = 0
    for count in (1, 2, 3, 5, 17):
        name = "manifest-" + str(count)
        body = oracle.envelope(name, 3, device_key)
        context = count.to_bytes(8, "big") + bytes([7]) * 32 + bytes([8]) * 32 + bytes([9]) * 32 + interval
        scope = account + device_id + revision + certificate_digest + revision + roster_digest + context
        require(len(body) == 290 and body[:258] == b"QPMANF01" + scope + count.to_bytes(2, "big"),
                "manifest grammar or scope differs")
        require(digest("MANIFEST", body) == oracle.read(name + ".digest", 32), "manifest digest differs")
        ids, paths, fingerprints = [], [], set()
        by_kind = {}
        for index in range(count):
            stem = f"proof-{count}-{index}"
            reader = Reader(oracle.read(stem + ".bin"))
            require(reader.integer(2) == index, "proof index differs")
            leaf = reader.take(reader.integer(2))
            leaf_reader = Reader(leaf)
            require(leaf_reader.take(8) == b"QPLEAF01", "leaf tag differs")
            kind = leaf_reader.integer(1)
            require(kind in (1, 2, 3, 4), "unknown leaf kind")
            require(leaf_reader.take(16) == interval, "leaf interval differs")
            public = leaf_reader.take(32 if kind <= 2 else 1184)
            leaf_reader.finish()
            require(any(public), "zero public key")
            fingerprint = digest("PREKEY-PUBLIC", bytes([1 if kind <= 2 else 2]) + public)
            require(fingerprint not in fingerprints, "duplicate exact public bytes")
            fingerprints.add(fingerprint)
            require(fingerprint == oracle.read(stem + ".fingerprint", 32), "fingerprint differs")
            leaf_id = digest("PREKEY-LEAF", scope + leaf)
            require(leaf_id == oracle.read(stem + ".id", 32), "leaf commitment differs")
            ids.append(leaf_id)
            by_kind.setdefault(kind, leaf_id)
            depth = reader.integer(1)
            require(depth <= 10, "proof depth bound")
            paths.append([reader.take(32) for _ in range(depth)])
            reader.finish()
        require(ids == sorted(set(ids)), "noncanonical leaf order")
        require(tree(ids) == body[258:], "independent tree root differs")
        for index, path in enumerate(paths):
            require(path == expected_path(ids, index), "independent membership path differs")
        proof_total += count
        if count >= 5:
            for quality, classical_mode, pq_mode, classical_kind, pq_kind in (
                (1, "one_time", "one_time", 2, 4),
                (2, "signed_only", "last_resort", 1, 3),
                (3, "signed_only", "one_time", 1, 4),
                (4, "one_time", "last_resort", 2, 3),
            ):
                expected = {
                    "suite_digest": (bytes([8]) * 32).hex(),
                    "responder": {"account_id": account.hex(), "device_id": device_id.hex(),
                                  "device_epoch": 1, "identity_credential_digest": certificate_digest.hex()},
                    "bundle_epoch": count, "directory_checkpoint_digest": (bytes([9]) * 32).hex(),
                    "signed_prekey_manifest_digest": digest("MANIFEST", body).hex(),
                    "classical": {"mode": classical_mode, "signed_prekey_id": by_kind[1].hex(),
                                  "selected_prekey_id": by_kind[classical_kind].hex()},
                    "post_quantum": {"mode": pq_mode, "last_resort_prekey_id": by_kind[3].hex(),
                                     "selected_prekey_id": by_kind[pq_kind].hex()},
                }
                stem = f"selection-{count}-{quality}"
                record = oracle.read(stem + ".record", 492)
                require(decode_record(record) == expected, "selection fields differ from authenticated members")
                encoded = encode_input(expected)
                require(encoded["record"] == record, "independent selection encoding differs")
                require(encoded["selection_digest"] == oracle.read(stem + ".digest", 32), "selection digest differs")
                require(encoded["quality_code"] == quality and oracle.read(stem + ".quality", 1) == bytes([quality]),
                        "selection quality differs")
                selection_total += 1
    return {"schema": 2, "status": "passed", "scope": "public candidate fixture cross-check",
            "openssl": version, "signed_envelopes": 7, "membership_proofs": proof_total,
            "authenticated_selections": selection_total,
            "fixture_sha256": oracle.inputs, "commands": oracle.commands}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openssl", required=True)
    args = parser.parse_args()
    args.output.mkdir()
    oracle = Oracle(args.fixtures, args.output, args.openssl)
    report = verify(oracle)
    save(args.output / "result.json", (json.dumps(report, indent=2) + "\n").encode())
    print("CANDIDATE_PUBLIC_VECTORS_PASS envelopes=7 proofs=28 selections=8 signature_negative_controls=35")


if __name__ == "__main__":
    main()
