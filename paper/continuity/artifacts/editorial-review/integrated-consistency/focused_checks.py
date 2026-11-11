#!/usr/bin/env python3
"""Reproduce the bootstrap byte-correspondence checks of this audit.

This is a source-backed SHA3/HMAC calculation, not a native execution or
cryptographic security experiment. It writes only beside this script.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from datetime import datetime, timezone


# The substantive checks below intentionally use assertions. Reject every
# optimized interpreter mode before reading inputs or replacing a receipt.
if not __debug__:
    print(
        "ERROR: this audit checker requires enabled assertions; run without "
        "-O, -OO, or PYTHONOPTIMIZE.",
        file=sys.stderr,
    )
    raise SystemExit(2)


OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[4]
PAPER = ROOT / "paper/continuity"
BASELINE = "c7581ebc21f5d080d90840c13b52c793bcac9317"
PIN = PAPER / "artifacts/bootstrap/initial/source"
SOURCE = PIN / "research/continuity-identity-candidate/src"
ARCHIVE_PATHS = [
    SOURCE / "bootstrap.rs",
    SOURCE / "bootstrap/staged.rs",
    SOURCE / "bootstrap/response_staged.rs",
    SOURCE / "crypto.rs",
    SOURCE / "contract.rs",
    SOURCE / "durable/messages.rs",
    PIN / "crates/q-periapt-sdk/src/lib.rs",
    PIN / "crates/q-periapt-backends/src/lib.rs",
    PAPER / "artifacts/bootstrap/initial/SOURCE_PINS.json",
    PAPER / "artifacts/bootstrap/reply/SOURCE_PINS.json",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def baseline_bytes(relative: str) -> bytes:
    return subprocess.check_output(
        ["git", "show", BASELINE + ":" + relative], cwd=ROOT
    )


def historical_tex_paths() -> list[str]:
    inventory = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", "-z", BASELINE,
         "--", "paper/continuity"], cwd=ROOT
    )
    return sorted(
        relative
        for raw in inventory.split(b"\0") if raw
        for relative in [raw.decode("utf-8")]
        if PurePosixPath(relative).parent == PurePosixPath("paper/continuity")
        and PurePosixPath(relative).suffix == ".tex"
    )


def framed_hash(domain: bytes, value: bytes) -> bytes:
    return hashlib.sha3_256(
        len(domain).to_bytes(8, "big")
        + domain
        + len(value).to_bytes(8, "big")
        + value
    ).digest()


def extract(salt: bytes, source: bytes) -> bytes:
    return hmac.new(salt, source, hashlib.sha256).digest()


def main() -> None:
    baseline = subprocess.check_output(
        ["git", "rev-parse", "--verify", BASELINE + "^{commit}"],
        cwd=ROOT, text=True,
    ).strip()
    assert baseline == BASELINE, (baseline, BASELINE)
    archived = {}
    for path in ARCHIVE_PATHS:
        relative = str(path.relative_to(ROOT))
        content = path.read_bytes()
        if content != baseline_bytes(relative):
            raise SystemExit("Archived audit input differs from baseline: " + relative)
        archived[path] = content
    bootstrap = archived[SOURCE / "bootstrap.rs"].decode("utf-8")
    crypto = archived[SOURCE / "crypto.rs"].decode("utf-8")
    staged = archived[SOURCE / "bootstrap/staged.rs"].decode("utf-8")
    contract = archived[SOURCE / "contract.rs"].decode("utf-8")
    sdk = archived[PIN / "crates/q-periapt-sdk/src/lib.rs"].decode("utf-8")
    backend = archived[PIN / "crates/q-periapt-backends/src/lib.rs"].decode("utf-8")

    # Tie the independent calculation to the pinned native call order.
    response = bootstrap.split("fn response_body(", 1)[1].split(
        "fn prepared_response(", 1
    )[0]
    operations = [
        "body.extend_from_slice(&result.ciphertext.to_bytes());",
        'let core = hash(b"reply-core", &body);',
        "let keys = schedule(first, &result.secret, &core)?;",
        "body.extend_from_slice(&mac(keys.responder.as_bytes(), &core)?);",
    ]
    positions = [response.index(operation) for operation in operations]
    assert positions == sorted(positions)
    assert "salt: &[u8; 32]" in bootstrap
    assert "Hkdf::<Sha256>::extract(Some(salt), ikm)" in bootstrap
    assert "hash.update((domain.len() as u64).to_be_bytes());" in crypto
    assert "hash.update((length as u64).to_be_bytes());" in crypto

    kdf_domain = re.search(
        r'&\[b"([^"]+)", label\]', bootstrap
    ).group(1).encode()
    wire_domain = re.search(
        r'let mut domain = b"([^"]+)"\.to_vec\(\);', bootstrap
    ).group(1).encode()
    message_domain = re.search(
        r'pub const MESSAGE_DOMAIN: &\[u8\] = b"([^"]+)";', contract
    ).group(1).encode()
    names = [b"handshake-seed", b"confirmation-responder", b"confirmation-initiator"]
    infos = [kdf_domain + name for name in names]
    assert [len(value) for value in infos] == [62, 70, 70]
    assert [len(value) + 1 for value in infos] == [63, 71, 71]
    assert len(kdf_domain) == 48 and len(message_domain) == 43
    ctx = bytes(range(32))
    root_info = kdf_domain + b"session-root/" + ctx
    activation_info = message_domain + b"initial/HKDF-SHA256/ChaCha20Poly1305" + ctx
    chain_info = message_domain + b"chain" + (7).to_bytes(8, "big")
    ack_input = (
        message_domain + b"acknowledgement" + b"QPCMACK1" + bytes(32)
        + b"\x01" + (3).to_bytes(8, "big")
    )
    assert len(root_info) == 93
    assert len(activation_info) == 111
    assert [len(activation_info) + 1, len(activation_info) + 33] == [112, 144]
    assert [len(chain_info) + 1, len(chain_info) + 33] == [57, 89]
    assert len(ack_input) == 107

    # G bounds nonce draws in the reply-source profile: the only fresh nonce
    # in reserve follows its reply-key reservation; decode restores that nonce.
    reserve = staged.split("pub(crate) fn reserve(", 1)[1].split(
        "pub(crate) fn phase(", 1
    )[0]
    assert reserve.count("nonce()?") == 1
    assert reserve.index("recovery.reserve_key(") < reserve.index("nonce()?")
    assert "let nonce = d.array()?;" in staged

    ct_len = int(re.search(r"ML_KEM_768_CT_LEN = ([0-9]+)", backend).group(1))
    assert "pub const CIPHERTEXT_LEN: usize = ML_KEM_768_CT_LEN + 32;" in sdk
    ct_len += 32
    # A synthetic correctly sized core is enough to distinguish the two salt
    # interpretations. Its ciphertext bytes are not claimed to be a valid KEM.
    core = (
        b"QPBSR001" + ctx + bytes([0x22]) * 32 + bytes([0x33]) * 32
        + bytes((17 * i + 9) % 256 for i in range(ct_len))
    )
    t1 = framed_hash(wire_domain + b"reply-core", core)
    source = bytes(range(64))
    native_prk = extract(t1, source)
    literal_core_prk = extract(core, source)
    assert len(core) == 1224 and len(t1) == 32
    assert native_prk != literal_core_prk
    assert hashlib.sha256(core).digest() != t1

    tex_paths = historical_tex_paths()
    checked_paths = tex_paths + [str(path.relative_to(ROOT)) for path in ARCHIVE_PATHS]
    files = []
    for relative in checked_paths:
        content = baseline_bytes(relative)
        entry = {
            "path": relative,
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_origin": "baseline_git_object",
        }
        if relative in tex_paths:
            entry["labels"] = {
                label: line_number
                for line_number, line in enumerate(content.decode("utf-8").splitlines(), 1)
                for label in re.findall(r"\\label\{([^}]+)\}", line)
            }
        else:
            entry["archived_workspace_bytes_verified"] = True
        files.append(entry)
    manifest = {
        "baseline_commit": BASELINE,
        "purpose": "Source identity and label map for the independent integrated consistency audit",
        "tex_inventory_source": "git ls-tree of the baseline commit",
        "tex_content_and_labels_source": "git show of the baseline blobs",
        "archived_inputs": "Workspace archive bytes verified against the baseline before use",
        "files": files,
    }
    (OUT / "source-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    result = {
        "baseline_commit": BASELINE,
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "python_executable": sys.executable,
        "python_optimization_level": sys.flags.optimize,
        "checker_sha256": sha256(Path(__file__)),
        "kind": "Independent source-backed byte calculation; no native tests rerun",
        "status": "pass",
        "input_provenance": {
            "tex_files_from_baseline_git": len(tex_paths),
            "archived_workspace_files_verified_against_baseline": len(archived),
            "current_head_or_current_tex_required_to_equal_baseline": False,
        },
        "checks": {
            "native_reply_core_digest_precedes_schedule_and_confirmation": True,
            "digest_uses_framed_sha3_256_and_32_byte_hkdf_salt": True,
            "info_lengths": [len(value) for value in infos],
            "bootstrap_row_lengths": [len(value) + 1 for value in infos],
            "root_info_bytes": len(root_info),
            "activation_info_bytes": len(activation_info),
            "activation_row_lengths": [112, 144, 144, 144, 144],
            "chain_row_lengths": [57, 89],
            "ack_row_bytes": len(ack_input),
            "reply_key_reservation_bounds_fresh_initial_nonce_draws": True,
            "restoration_retains_original_initial_nonce": True,
        },
        "salt_interpretation_witness": {
            "fixture": "Synthetic 1224-byte core; ciphertext bytes serve only the deterministic encoding comparison",
            "core_bytes": len(core),
            "digest_bytes": len(t1),
            "core_sha256": hashlib.sha256(core).hexdigest(),
            "framed_sha3_t1": t1.hex(),
            "native_digest_salt_prk": native_prk.hex(),
            "literal_raw_core_salt_prk": literal_core_prk.hex(),
            "same_prk": native_prk == literal_core_prk,
            "implication": "Reading t1 as raw Reply-core bytes computes a different HMAC; the proposed digest definition restores the native 32-byte entry interface",
        },
    }
    (OUT / "focused-checks.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "status": result["status"],
        "source_files": len(files),
        "bootstrap_row_lengths": result["checks"]["bootstrap_row_lengths"],
        "native_digest_salt_matches_raw_core_interpretation": native_prk == literal_core_prk,
    }))


if __name__ == "__main__":
    main()
