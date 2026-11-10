#!/usr/bin/env python3
"""Check the explicitly supplied native checkout and retained ContextBound map.

This command requires every mapped source at both exact revisions and requires
the worktree bytes to match. Missing objects, wrong checkouts, or failed source
assertions are errors. It neither fetches replacements nor skips unavailable
native checks. The separate self-contained checker is the manuscript CI task.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


PIN = "228c944fc476e3e57d6c08063cacb19bca5b360e"
COMPARISON = "1c68aa666db22d36ee136be1ec712545a9e74f03"
MAP = (
    ("C01", "crates/q-periapt-core/src/lib.rs", [(34, 43), (457, 473), (480, 529), (561, 650)],
     "Ten LP8 fields; canonical nested policy context; component secrets are two separate fields."),
    ("C02", "crates/q-periapt-sdk/src/lib.rs", [(175, 214), (296, 308), (328, 403), (439, 462), (480, 528)],
     "Admitted policy-bound runtime; 64+32-byte key generation and 32+32-byte encapsulation tapes; actual paired key and fixed ciphertext widths."),
    ("C03", "crates/q-periapt-sdk/src/expert/replay.rs", [(21, 58), (94, 154), (157, 256)],
     "Original sealed reservation, exact policy/operation/input binding, platform-random tape before execution, and authenticated deterministic replay."),
    ("C04", "crates/q-periapt-kem/src/lib.rs", [(156, 187), (206, 238), (260, 312), (321, 347)],
     "PQ primitive precedes X25519 and both precede ContextBound; prepared decapsulation supplies its paired public key."),
    ("C05", "crates/q-periapt-backends/src/streaming_sha3.rs", [(3, 39)],
     "Native streaming ContextBound backend is SHA3-256, separately from HMAC-SHA256."),
    ("C06", "crates/q-periapt-backends/src/lib.rs", [(102, 108), (595, 653)],
     "Fixed suite bytes; X25519 contributes its raw DH output after the contributory check, without a prior uniform-key KDF."),
    ("C07", "research/continuity-identity-candidate/src/crypto.rs", [(202, 225)],
     "SHA3 domain hashing uses LP8(domain) followed by LP8(payload)."),
    ("C08", "research/continuity-identity-candidate/src/contract.rs", [(14, 25)],
     "Exact rekey domain and fixed profile descriptor."),
    ("C09", "research/continuity-identity-candidate/src/durable/messages/rekey.rs", [(23, 92), (124, 163), (284, 297), (317, 452)],
     "Generation slot and immutable original signed offer; exact body equality and retained token; scope uses authoritative journal, session and control prefix."),
    ("C10", "research/continuity-identity-candidate/src/durable/messages/rekey/response.rs", [(13, 107), (111, 177), (183, 375)],
     "Response retains the complete offer; changed offer conflicts; complete offer hash enters ContextBound; root uses fixed response core; stage transition discards the encapsulation token."),
    ("C11", "research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs", [(701, 709), (761, 931), (963, 1092)],
     "Proposer decapsulates only against its retained original offer and checks its regenerated paired public key; root installation replaces pending state; responder installs the saved root."),
    ("C12", "crates/q-periapt-sdk/src/expert.rs", [(75, 117), (120, 156)],
     "Broader expert operations exist; the declared native profile does not expose arbitrary selected-key component mixing or private export."),
    ("C13", "crates/q-periapt-sdk/src/tests.rs", [(59, 163), (966, 1008)],
     "Existing sealed-operation tests and original-versus-streaming policy-context test were read, not rerun in this audit."),
    ("C14", "crates/q-periapt-backends/src/contextbound_kat.rs", [(87, 214)],
     "Six source KAT values independently recomputed by the self-contained Python checker."),
)


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, "GIT_NO_LAZY_FETCH": "1"}).stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True,
                        help="explicit native checkout; all mapped worktree files must match --pin")
    parser.add_argument("--pin", default=PIN)
    parser.add_argument("--comparison", default=COMPARISON)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).with_name("fixtures.json"))
    args = parser.parse_args()
    sources = {}
    records = []
    for ident, path, ranges, finding in MAP:
        content = git(args.repo, "show", f"{args.pin}:{path}")
        comparison = git(args.repo, "show", f"{args.comparison}:{path}")
        worktree = (args.repo / path).read_bytes()
        if content != comparison or content != worktree:
            raise AssertionError(f"source identity mismatch: {path}")
        text = content.decode("utf-8")
        if max(end for _, end in ranges) > len(text.splitlines()):
            raise AssertionError(f"invalid source range: {path}")
        sources[ident] = text
        records.append({
            "id": ident, "path": path, "ranges": [{"start": a, "end": b} for a, b in ranges],
            "manual_source_finding": finding, "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "git_blob_sha1": git(args.repo, "rev-parse", f"{args.pin}:{path}").decode().strip(),
            "comparison_equal": True, "worktree_equal": True,
            "url": f"https://github.com/billlza/q-periapt/blob/{args.pin}/{path}",
        })

    claims = []
    def expect(name: str, condition: bool) -> None:
        if condition is not True:
            raise AssertionError(name)
        claims.append({"name": name, "passed": True})

    core = sources["C01"]
    expected_order = (
        "absorb_public_lp(&mut x, DOMAIN);",
        "absorb_public_lp(&mut x, input.suite_id);",
        "absorb_public_lp(&mut x, &input.policy_version.to_be_bytes());",
        "absorb_secret_lp(&mut x, input.ss_pq);",
        "absorb_secret_lp(&mut x, input.ss_trad);",
        "absorb_public_lp(&mut x, input.ct_pq);",
        "absorb_public_lp(&mut x, input.pk_pq);",
        "absorb_public_lp(&mut x, input.ct_trad);",
        "absorb_public_lp(&mut x, input.pk_trad);",
    )
    positions = [core.index(snippet) for snippet in expected_order]
    expect("actual-core-field-order", positions == sorted(positions))
    expect("nested-policy-context", all(snippet in core for snippet in (
        "absorb_public_lp(&mut x, POLICY_CONTEXT_DOMAIN);",
        "absorb_public_lp(&mut x, digest);", "absorb_secret_lp(&mut x, input.context);")))
    expect("runtime-policy-bound-streaming-SHA3", all(snippet in sources["C02"] for snippet in (
        "HybridKem::new_policy_bound(", "StreamingSha3_256Xof", "&self.digest,")))
    expect("actual-streaming-SHA3-backend", all(snippet in sources["C05"] for snippet in (
        "hash: Sha3_256", "self.hash.update(data)", "self.hash.finalize().into()")))
    expect("sealed-operation-tape-lengths", "Self::Generate => 64 + 32" in sources["C03"]
           and "Self::Encapsulate => 32 + 32" in sources["C03"])
    expect("sealed-input-binding-uses-SHA256", all(snippet in sources["C03"] for snippet in (
        "let mut digest = Sha256::new();", "digest.update(peer.to_bytes());",
        "digest.update((context.len() as u32).to_be_bytes());", "digest.update(context);")))
    expect("full-offer-kem-context", 'hash(b"response-kem", offer)' in sources["C10"])
    expect("response-retains-and-compares-exact-offer", all(snippet in sources["C10"] for snippet in (
        "if saved.offer != offer", "offer: offer.to_vec(),", "Stage::Encapsulation(reservation)")))
    expect("proposer-retained-key-public-correspondence", all(snippet in sources["C11"] for snippet in (
        ".decapsulate(&ciphertext, &response::kem_context(offer))", "BODY_LEN - PUBLIC_KEY_LEN..",
        "wire: offer,", "key: token,")))
    expect("exactly-two-live-rekey-root-assignments", sources["C11"].count("state.rekey = root;") == 2
           and "state.rekey =" not in sources["C09"] and "state.rekey =" not in sources["C10"])
    xpart = sources["C06"].split("impl Kem for X25519 {", 1)[1].split("/// Inline staging capacity", 1)[0]
    expect("X25519-is-raw-DH-not-a-prior-KDF", xpart.count("write_exact(ss, shared.as_bytes())") == 2
           and "Hkdf" not in xpart and "hash" not in xpart)
    fixtures = json.loads(args.fixtures.read_text())
    expect("all-six-independent-checker-KATs-match-source", len(fixtures["legacy_core_vectors"]) == 6
           and all(case["sha3_256"] in sources["C14"] for case in fixtures["legacy_core_vectors"]))

    receipt = {
        "schema": "q-periapt.contextbound-source-audit.v1", "status": "passed",
        "source_pin": args.pin, "comparison_revision": args.comparison,
        "source_count": len(records), "static_check_count": len(claims),
        "source_map": records, "static_checks": claims,
        "verification_type": "exact source identity and named static assertions; manual semantic audit in source_audit.md",
        "native_rust_execution": False,
        "independent_model_checker": "check_contextbound_adapter.py",
        "audit_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(args.fixtures.read_bytes()).hexdigest(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "source_count": len(records),
                      "static_check_count": len(claims), "output": str(args.output)}))


if __name__ == "__main__":
    main()
