#!/usr/bin/env python3
"""Independent untrusted bundle constructor, exercised through the real Rust importer.

Pins are explicit preexisting local fixture inputs. No trust material is copied
into the input package, and no signature verification is mocked by this builder.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def read(path, maximum=8192):
    with path.open("rb") as source:
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError(f"oversized fixture {path.name}")
    return value


def pack(fields, quality=2):
    return b"QPBNDL01" + bytes([quality]) + b"".join(
        len(field).to_bytes(2, "big") + field for field in fields
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--consumer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trust = args.fixtures.resolve(strict=True)
    consumer = args.consumer.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    proofs = {}
    for path in sorted(trust.glob("bootstrap-proof-*.bin")):
        proof = read(path)
        if len(proof) < 13 or proof[12] in proofs:
            raise ValueError("missing or duplicate encoded proof role")
        proofs[proof[12]] = proof
    if set(proofs) != {1, 3}:
        raise ValueError("expected the fixture's explicit reusable baseline proofs")
    names = ["bootstrap-i-credential.bin", "bootstrap-i-roster.bin",
             "bootstrap-r-credential.bin", "bootstrap-r-roster.bin", "bootstrap-manifest.bin"]
    fields = [read(trust / name) for name in names] + [proofs[1], proofs[3], b"", b""]
    valid = pack(fields)
    expected = read(trust / "bootstrap-context.digest", 32).hex()
    consumer_hash = hashlib.sha256(consumer.read_bytes()).hexdigest()
    rows = []

    def run(name, wire, success, quality=2, now=150):
        file = output / (name + ".bin")
        file.write_bytes(wire)
        argv = [str(consumer), str(trust), str(file), str(quality), str(now)]
        result = subprocess.run(argv, capture_output=True, timeout=30, check=False)
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        if success:
            if result.returncode != 0 or result.stdout.decode().strip() != expected:
                raise RuntimeError(f"valid cross-language import failed: {result.stderr!r}")
        elif result.returncode != 1 or not result.stderr.startswith(b"Error:"):
            raise RuntimeError(f"negative {name} did not produce a typed import failure: {result.returncode}")
        rows.append({"name": name, "argv": argv, "exit": result.returncode,
                     "accepted": success, "sha256": hashlib.sha256(wire).hexdigest()})

    run("valid", valid, True)
    run("trailing", valid + b"\0", False)
    run("truncated", valid[:-1], False)
    run("unknown-version", b"QPBNDL02" + valid[8:], False)
    run("unknown-mode", pack(fields, 255), False)
    run("wrong-requested-quality", valid, False, quality=1)
    run("expired", valid, False, now=200)
    run("future-validity", valid, False, now=99)
    run("oversized", bytes(65537), False)
    for index in range(7):
        altered = fields.copy()
        altered[index] = altered[index][:-1] + bytes([altered[index][-1] ^ 1])
        run(f"tampered-part-{index}", pack(altered), False)
        altered = fields.copy()
        altered[index] = b""
        run(f"missing-part-{index}", pack(altered), False)
    altered = fields.copy()
    altered[0], altered[2] = altered[2], altered[0]
    run("swapped-devices", pack(altered), False)
    altered = fields.copy()
    altered[5], altered[6] = altered[6], altered[5]
    run("swapped-proof-roles", pack(altered), False)
    altered = fields.copy()
    altered[7] = proofs[1]
    run("unexpected-optional-proof", pack(altered), False)
    if hashlib.sha256(consumer.read_bytes()).hexdigest() != consumer_hash:
        raise RuntimeError("consumer binary changed during the experiment")
    report = {"schema": 1, "consumer": str(consumer), "consumer_sha256": consumer_hash,
              "positive": 1, "negatives": len(rows) - 1, "context_digest": expected,
              "fixture_trust_supplied_separately": True, "production_binding_qualified": False, "cases": rows}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "cases"}))


if __name__ == "__main__":
    main()
