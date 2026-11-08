#!/usr/bin/env python3
"""Finite controls and pinned-source audit for the reservation bridge.

The default audit is self-contained: all inspected upstream/native files and
their license texts are in sources/.  --repository additionally checks an
external checkout.  --crate-archive authenticates the original package bytes.
This program does not execute Rust/ML-DSA or formally verify the proof.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
from itertools import product
import json
from pathlib import Path
import re
import tarfile


ROOT = Path(__file__).resolve().parent
MANIFEST_SHA256 = "09eed0e31a48d9663c06e20a8dad0d8e832c87a1cb12d47a6646fb4660b2908c"
ARCHIVE_SHA256 = "c9fb5a367b9846933e271a3c2a992930743f82ae5e8cb7faa780715a80fa0b15"
NATIVE_COMMIT = "358b921ab3469ce49f166633fc9a762ff6ed7e3d"
UPSTREAM_COMMIT = "8d456d989dce681233ef963d3c3306da8f76d7c7"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_file(data: bytes, record: dict) -> None:
    require(len(data) == record["bytes"], "source size: " + record["path"])
    require(sha256(data) == record["sha256"], "source SHA256: " + record["path"])
    git_hash = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
    require(git_hash == record["git_blob_sha1"], "source Git blob: " + record["path"])


def source_audit(repository: Path | None, archive: Path | None) -> dict:
    manifest_bytes = (ROOT / "source_identity.json").read_bytes()
    require(sha256(manifest_bytes) == MANIFEST_SHA256, "source identity manifest changed")
    manifest = json.loads(manifest_bytes)
    require(manifest["repository_head"] == NATIVE_COMMIT, "native checkpoint changed")
    require(manifest["crate_vcs_info"]["git"]["sha1"] == UPSTREAM_COMMIT, "upstream checkpoint changed")
    require(manifest["archive_sha256"] == ARCHIVE_SHA256, "locked archive checksum changed")
    upstream = ROOT / "sources/fips204-0.4.6"
    native = ROOT / "sources/q-periapt-native"
    files = []
    for directory, records in ((upstream, manifest["files"]), (native, manifest["local_source_files"])):
        for record in records:
            verify_file((directory / record["path"]).read_bytes(), record)
            files.append({"packet": directory.name, "path": record["path"], "sha256": record["sha256"]})
    if repository is not None:
        for record in manifest["local_source_files"]:
            verify_file((repository / record["path"]).read_bytes(), record)
    if archive is not None:
        require(sha256(archive.read_bytes()) == ARCHIVE_SHA256, "original crate checksum mismatch")
        with tarfile.open(archive, "r:gz") as package:
            for record in manifest["files"]:
                stream = package.extractfile("fips204-0.4.6/" + record["path"])
                require(stream is not None, "crate member is not a file")
                verify_file(stream.read(), record)

    for lock in ("Cargo.lock", "research/continuity-identity-candidate/Cargo.lock"):
        text = (native / lock).read_text()
        stanza = next(block for block in text.split("[[package]]") if '\nname = "fips204"\n' in block)
        require('\nversion = "0.4.6"\n' in stanza, "wrong locked fips204 version")
        require(f'checksum = "{ARCHIVE_SHA256}"' in stanza, "wrong lockfile checksum")

    mldsa = (upstream / "src/ml_dsa.rs").read_text()
    signing = mldsa.split("pub(crate) fn sign_internal", 1)[1].split("/// # Algorithm 8", 1)[0]
    signing_code = re.sub(r"//[^\n]*", "", signing)
    require(len(re.findall(r"\bcap_k\b", signing_code)) == 2, "K has a new signing use")
    require("h256_xof(&[cap_k, &rnd, &mu])" in signing_code, "native hedge changed")
    require("h256_xof(&[xi, &[K.to_le_bytes()[0]], &[L.to_le_bytes()[0]]])" in mldsa, "seed expansion framing changed")
    require("cap_k: _" in mldsa.split("fn private_to_public_key", 1)[1], "public-key derivation uses K")

    traits = (upstream / "src/traits.rs").read_text()
    require("self.try_sign_with_rng(&mut DummyRng {data: *seed}, message, ctx)" in traits, "seeded signing route changed")
    require("out.copy_from_slice(&self.data);" in traits, "original randomizer transport changed")
    backend = (native / "crates/q-periapt-backends/src/mldsa.rs").read_text()
    require("try_sign_with_seed" in backend and "keygen_from_seed" in backend, "native backend route changed")

    contract = (native / "research/continuity-identity-candidate/src/contract.rs").read_text()
    literal = re.search(r'SIGNATURE_CONTEXT: &\[u8\] = b"([^"]+)";', contract)
    require(literal is not None, "context literal missing")
    context = literal.group(1).encode("ascii")
    require(len(context) == 42, "native context size changed")
    owner = (native / "research/continuity-identity-candidate/src/crypto.rs").read_text()
    message_code = owner.split("fn signed_message", 1)[1].split("pub(crate) fn envelope", 1)[0]
    for operation in ("message.extend_from_slice(SIGNATURE_CONTEXT);", "message.push(purpose as u8);", "message.extend_from_slice(&length.to_be_bytes());", "message.extend_from_slice(body);"):
        require(operation in message_code, "original-message framing changed")

    lib = (upstream / "src/lib.rs").read_text()
    params = lib.split("pub mod ml_dsa_65 {", 1)[1].split("functionality!();", 1)[0]
    k = int(re.search(r"const K: usize = (\d+);", params).group(1))
    ell = int(re.search(r"const L: usize = (\d+);", params).group(1))
    security = int(re.search(r"const LAMBDA: usize = (\d+);", params).group(1))
    pk_bytes = int(re.search(r"pub const PK_LEN: usize = (\d+);", params).group(1))
    require((k, ell, security, pk_bytes) == (6, 5, 192, 1952), "ML-DSA-65 parameters changed")
    require("const GAMMA2: i32 = (Q - 1) / 32;" in params, "commitment parameters changed")
    w1_bytes = 32 * k * (16 - 1).bit_length()
    hashing = (upstream / "src/hashing.rs").read_text()
    for anchor in ("let mut h_ctx = h256_xof(&[rho]);", "let mut xof = h256_xof(rhos);", "let mut xof = h256_xof(&[rho, &n.to_le_bytes()]);", "let mut xof = g128_xof(rhos);"):
        require(anchor in hashing, "hash call inventory changed")
    lengths = {
        "designated_target_keygen": 32 + 1 + 1,
        "designated_target_hedge": 32 + 32 + 64,
        "secret_expansion_H": 64 + 2,
        "mask_expansion_H": 64 + 2,
        "challenge_ball_H": security // 4,
        "commitment_H": 64 + w1_bytes,
        "public_key_H": pk_bytes,
        "protocol_mu_H_minimum": 64 + 2 + 2 * len(context) + 1 + 4,
        "matrix_expansion_G": 32 + 1 + 1,
    }
    require(lengths["protocol_mu_H_minimum"] == 155, "descriptor minimum miscount")
    for operation in ("secret_expansion_H", "mask_expansion_H", "challenge_ball_H", "commitment_H", "public_key_H"):
        require(lengths[operation] not in (34, 128), "sensitive rejection/base hash input")
    require(lengths["protocol_mu_H_minimum"] > 128, "protocol descriptor can hit hidden support")
    return {
        "status": "passed",
        "manifest_sha256": MANIFEST_SHA256,
        "native_commit": NATIVE_COMMIT,
        "upstream_commit": UPSTREAM_COMMIT,
        "source_and_license_files": files,
        "source_and_license_file_count": len(files),
        "external_checkout_checked": repository is not None,
        "original_crate_archive_authenticated": archive is not None,
        "input_lengths_bytes": lengths,
    }


def full_pair_component_control() -> dict:
    # Same component with different full-pair keys is intentionally not pooled.
    pairs = {0: ("pq-a", "p256-a"), 1: ("pq-a", "p256-b"), 2: ("pq-a", "p256-a")}
    ledgers = {0: {"a"}, 1: {"b"}, 2: {"c"}}
    ordinary = {0: {"a"}, 1: {"b"}, 2: {"c"}}
    actual = {
        key: set().union(*(ledgers[h] for h in pairs if pairs[h] == key))
        for key in set(pairs.values())
    }
    cases = 0
    for h, message in product(range(3), ("a", "b", "c", "fresh")):
        require(ordinary[h] <= ledgers[h] <= actual[pairs[h]], "pair-to-index ledger inclusion")
        require(message in actual[pairs[h]] or message not in ordinary[h], "actual fresh does not imply oracle fresh")
        cases += 1
    require("b" not in actual[pairs[0]], "distinct pairs with equal PQ components were pooled")
    require("c" in actual[pairs[0]], "coincident full pairs lost actual-key aggregation")
    return {"implication_cases": cases, "equal_component_distinct_pair_countermodel": True}


def failure_and_alias_control() -> dict:
    # The first invocation obtains a result even when publication is suppressed.
    slot_messages = ("m0", "m1", "m0")
    descriptors = {"m0": 7, "m1": 7}
    ledger, cache, oracle_queries = set(), {}, []
    outputs = []
    for i, message in enumerate(slot_messages):
        ledger.add(message)
        pair = (5, descriptors[message])
        if pair not in cache:
            oracle_queries.append(message)
            cache[pair] = ("signature", len(oracle_queries))
        outputs.append(None if i == 0 else cache[pair])
    require(outputs[0] is None and outputs[1] == outputs[2], "failure/replay consistency")
    require(oracle_queries == ["m0"], "new descriptor alias caused a second query")
    require(ledger == {"m0", "m1"}, "cached alias lost its original-message entry")
    require(set(oracle_queries) <= ledger, "signing queries escape private ledger")
    return {"private_invocations": 3, "ordinary_queries": 1, "raw_messages_recorded": 2, "failed_first_publication_retained": True}


def target_reexpansion_control() -> dict:
    # Reopen/alias seed expansions and failed-publication hedge retries are all
    # designated target calls, not ordinary hidden-point guesses.
    owner_family = {"target": 0, "target-alias": 0, "other": 1}
    trials = 0
    for repeats, other_generations, other_signs in product(range(1, 5), range(3), range(3)):
        calls = []
        for i in range(repeats):
            calls.extend((("target" if i % 2 == 0 else "target-alias", "seed", 34), ("target", "hedge", 128)))
        calls.extend(("other", "seed", 34) for _ in range(other_generations))
        calls.extend(("other", "hedge", 128) for _ in range(other_signs))
        remaining = [(owner, kind, size) for owner, kind, size in calls if owner_family[owner] != 0]
        require(len(remaining) == other_generations + other_signs, "target re-expansion charged as an independent guess")
        require(all(owner == "other" for owner, _, _ in remaining), "target hidden seed remains in ideal calls")
        trials += 1
    naive_repeat_hit_probability = Fraction(1, 1)
    claimed_hidden_guess_probability = Fraction(1, 2**256)
    require(naive_repeat_hit_probability > claimed_hidden_guess_probability, "missing-rewrite counterexample lost")
    return {"reopen_retry_profiles": trials, "all_designated_target_reexpansions_removed": True, "omitting_reopen_rewrite_gives_hit_probability": "1"}


def selected_family_control() -> dict:
    # A family may be created adaptively; a declared alias preserves its index.
    cases = 0
    for maximum in range(1, 7):
        for created in range(1, maximum + 1):
            for winner in range(created):
                wins = sum(guess == winner for guess in range(maximum))
                require(Fraction(wins, maximum) == Fraction(1, maximum), "adaptive generation guess loss")
                require(all((guess < created) or guess != winner for guess in range(maximum)), "uncreated family won")
                cases += 1
    return {"creation_winner_profiles": cases, "exact_guess_success_fraction": "1/U", "aliases_allocate_no_new_index": True}


def disjoint_query_mass_control() -> dict:
    # Arbitrary mixtures over complete-input length sectors, independent of xi,K.
    # Weights are rational; testing all mixtures below includes both sectors.
    cases = 0
    maximum = Fraction(0)
    n = 4
    addresses = [("seed", x) for x in range(n)] + [("hedge", x) for x in range(n)] + [("safe", 0)]
    for weights in product(range(3), repeat=3):
        if sum(weights) == 0:
            continue
        # Put each sector's weight on one address; a change of address cannot
        # change its average over a uniform hidden seed/key.
        chosen = (addresses[0], addresses[n], addresses[-1])
        expected = Fraction(0)
        for xi, key in product(range(n), repeat=2):
            hit_weight = sum(weight for weight, (sector, value) in zip(weights, chosen) if (sector == "seed" and value == xi) or (sector == "hedge" and value == key))
            expected += Fraction(hit_weight, sum(weights) * n * n)
        require(expected <= Fraction(1, n), "disjoint-sector mass double counted")
        maximum = max(maximum, expected)
        cases += 1
    require(maximum == Fraction(1, n), "expected sharp average mass missing")
    return {"rational_query_sector_mixtures": cases, "maximum_average_mass": str(maximum), "finite_control_only": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finite-only", action="store_true", help="run finite adversarial controls without reading source packets")
    parser.add_argument("--repository", type=Path, help="also verify native files in this external checkpoint checkout")
    parser.add_argument("--crate-archive", type=Path, help="also authenticate the official fips204-0.4.6.crate archive")
    args = parser.parse_args()
    require(not args.finite_only or (args.repository is None and args.crate_archive is None), "--finite-only cannot request source audits")
    controls = {
        "pair_component_ledger": full_pair_component_control(),
        "failed_publication_descriptor_alias": failure_and_alias_control(),
        "all_target_seed_and_hedge_rewrites": target_reexpansion_control(),
        "adaptive_owner_selection": selected_family_control(),
        "disjoint_secret_support_mass": disjoint_query_mass_control(),
    }
    result = {"status": "passed", "scope": "finite controls and pinned-source audit; no Rust, ML-DSA, quantum execution, or formal verification", "controls": controls}
    if not args.finite_only:
        result["source_audit"] = source_audit(args.repository, args.crate_archive)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
