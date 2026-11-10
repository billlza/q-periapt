#!/usr/bin/env python3
"""Independent stdlib framing/KAT check; this does not execute the Rust SDK."""

from pathlib import Path
import hashlib
import hmac
import json


SALT = b"QPeriapt-SDK-HKDF-SHA256-v1"
DOMAIN = b"QPeriapt-SDK-Key-v1"


def info(purpose, label, context, state=bytes([2]) * 36, root=bytes([3]) * 32):
    assert purpose in range(1, 6)
    assert 1 <= len(label) <= 255
    assert all(0x21 <= b <= 0x7e for b in label)
    assert len(context) <= 65536
    return b"".join(
        [DOMAIN, (1).to_bytes(4, "big"), (2).to_bytes(4, "big"), state, root,
         purpose.to_bytes(4, "big"), len(label).to_bytes(2, "big"), label,
         len(context).to_bytes(4, "big"), context, (32).to_bytes(2, "big")]
    )


def mac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


def derive(secret, salt, information):
    return mac(mac(salt, secret), information + b"\x01")


def ell(length):
    return 1 + (length + 9 + 63) // 64


def main():
    checks = []

    def check(name, condition, **evidence):
        if not condition:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True, **evidence})

    check("literal-widths", len(SALT) == 27 and len(DOMAIN) == 19,
          salt_bytes=len(SALT), domain_bytes=len(DOMAIN))
    normalized = SALT + bytes(5)
    check("identical-HMAC-key-blocks",
          SALT.ljust(64, b"\x00") == normalized.ljust(64, b"\x00"))
    encoded = info(1, b"app/v1/aes256", b"transcript")
    key = derive(bytes([7]) * 32, SALT, encoded)
    expected = "899c3fe0b3419a6f3947c4e237daf8970b2c29442d9fce4385d30d2558242f65"
    check("pinned-purpose-Rust-KAT", key.hex() == expected,
          input_bytes=len(encoded), output_hex=key.hex())
    check("zero-extended-salt-same-KAT",
          derive(bytes([7]) * 32, normalized, encoded) == key)
    check("hashed-salt-is-different-encoding-control",
          derive(bytes([7]) * 32, hashlib.sha256(SALT).digest(), encoded) != key)

    lower = info(5, b"x", b"")
    upper = info(5, b"x" * 255, bytes(65536))
    check("exact-minimum-info-and-row-length", len(lower) == 108,
          info_bytes=len(lower), row_bytes=len(lower) + 1,
          continuation_compressions=ell(len(lower) + 1))
    check("exact-maximum-info-and-row-length", len(upper) == 65898,
          info_bytes=len(upper), row_bytes=len(upper) + 1,
          continuation_compressions=ell(len(upper) + 1))
    check("maximum-row-compression-bound", ell(65899) == 1031,
          hmac_compressions=2 + ell(65899))

    workload = [info(p, b"app/v1/aes256", b"authenticated-transcript")
                for p in range(1, 6)]
    check("five-purpose-workload-descriptors", len(set(workload)) == 5,
          distinct_infos=len(set(workload)))
    check("five-purpose-workload-lengths",
          all(len(v) == 144 and ell(len(v) + 1) == 4 for v in workload),
          label_bytes=13, context_bytes=24, info_bytes=144,
          row_bytes=145, column_budget_beyond_B=32, row_budget_beyond_B=2)
    check("full-info-repeat-is-exact-key-repeat",
          derive(bytes([7]) * 32, SALT, workload[0])
          == derive(bytes([7]) * 32, SALT, workload[0]))

    split_a = info(5, b"ab", b"c")
    split_b = info(5, b"a", b"bc")
    check("length-framing-distinguishes-boundary-splits",
          b"ab" + b"c" == b"a" + b"bc" and split_a != split_b)

    output = Path(__file__).with_name("encoding_receipt.json")
    receipt = {
        "schema": "q-periapt.sdk-purpose-independent-encoding-check.v1",
        "status": "PASS",
        "check_count": len(checks),
        "checks": checks,
        "claim_type": "Independent Python stdlib framing, known-answer and length accounting",
        "native_rust_execution": False,
        "global_key_inequality_claim": False,
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "checks": len(checks), "output": str(output)}))


if __name__ == "__main__":
    main()
