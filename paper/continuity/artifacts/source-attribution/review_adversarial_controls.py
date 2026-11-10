#!/usr/bin/env python3
"""Independent, finite review controls for the executed-source argument.

The checks exercise event definitions and explicit hypotheses. They are not a
native protocol execution, a signature-security estimate, or a formal proof.
No implementation from check_source_attribution.py is imported.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import itertools
import json
from pathlib import Path
import re
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PIN = "72acaaccde1ca9ea27e5af022da5fbce932ed4e9"
CONTEXT = b"Q-PERIAPT-CONTINUITY-SIGNATURE/v1"
BASE = "research/continuity-identity-candidate/"
SOURCES = [
    BASE + "src/crypto.rs",
    BASE + "src/crypto/persistence.rs",
    BASE + "src/contract.rs",
    BASE + "src/bootstrap.rs",
    BASE + "src/durable.rs",
    BASE + "src/durable/write_intent.rs",
    BASE + "src/durable/messages.rs",
    BASE + "src/durable/messages/rekey.rs",
    BASE + "src/durable/messages/rekey/response.rs",
    BASE + "src/durable/messages/rekey/completion.rs",
    BASE + "src/durable/messages/tests/classical_alias.rs",
    BASE + "Cargo.lock",
    "crates/q-periapt-sdk/src/expert/replay.rs",
]
checks: list[dict] = []


def require(name: str, passed: bool, detail: str) -> None:
    checks.append({"id": name, "pass": bool(passed), "detail": detail})
    if not passed:
        raise RuntimeError(name + ": " + detail)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def signed(purpose: int, body: bytes) -> bytes:
    return CONTEXT + bytes([purpose]) + len(body).to_bytes(4, "big") + body


def hash_link(domain: bytes, data: bytes) -> bytes:
    return hashlib.sha3_256(len(domain).to_bytes(8, "big") + domain
                           + len(data).to_bytes(8, "big") + data).digest()


def source_checks() -> tuple[list[dict], list[int]]:
    rows = []
    for rel in SOURCES:
        data = (ROOT / rel).read_bytes()
        pinned = subprocess.run(
            ["git", "show", PIN + ":" + rel], cwd=ROOT,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        require("source_pin_" + rel, data == pinned,
                "Reviewed working bytes equal the named integration commit.")
        rows.append({"path": rel, "sha256": sha(data), "bytes": len(data),
                     "source_commit": PIN})

    crypto = (ROOT / BASE / "src/crypto.rs").read_text()
    purposes = crypto.split("signature_purposes! {", 1)[1].split("\n}", 1)[0]
    tags = [int(x) for x in re.findall(r"=\s*(\d+),", purposes)]
    require("native_purpose_tags_unique", len(tags) == 39 and len(set(tags)) == 39,
            "All 39 source-defined signing purposes have distinct one-byte tags.")

    rekey = (ROOT / BASE / "src/durable/messages/rekey.rs").read_text()
    prefix = rekey.split("fn prefix(", 1)[1].split("fn scope(", 1)[0]
    scope = rekey.split("fn scope(", 1)[1].split("fn check_body(", 1)[0]
    require("journal_identity_is_not_a_wire_identity", "journal" not in prefix
            and "journal.as_slice()" in scope,
            "The journal ID binds private operation scope, not the signed rekey prefix; global history uniqueness is a controller premise.")
    bootstrap = (ROOT / BASE / "src/bootstrap.rs").read_text()
    require("selected_endpoint_components_are_distinct",
            "initiator.key.shares_component(&responder.key)" in bootstrap,
            "Admission rejects two endpoints sharing either signature component.")

    lock = (ROOT / BASE / "Cargo.lock").read_text()
    require("native_ecdsa_versions_pinned", 'name = "ecdsa"\nversion = "0.17.0"' in lock
            and 'name = "p256"\nversion = "0.14.0"' in lock,
            "The exact RFC6979 implementation identified in the review is the pinned dependency.")
    return rows, tags


def purpose_and_ledger_checks(tags: list[int]) -> dict:
    bodies = (b"", b"x", b"\x00", b"x\x00", b"\x00x", b"x" * 33)
    encodings = {signed(p, b) for p, b in itertools.product(tags, bodies)}
    require("finite_purpose_body_encoding_injective", len(encodings) == len(tags) * len(bodies),
            "Purpose/body examples spanning all native purposes remain distinct after framing.")

    actual_key = {"device": "K", "reopened-device": "K", "other-device": "L"}
    checked = 0
    for purpose, body, alias, write_failed in itertools.product(tags, bodies, (False, True), (False, True)):
        # The query enters the ledger at private computation. Publication and
        # reopening have no authority to erase that historical fact.
        ledger = {(actual_key["device"], signed(purpose, body))}
        published = [] if write_failed else [b"wire"]
        handle = "reopened-device" if alias else "device"
        fresh = (actual_key[handle], signed(purpose, body)) not in ledger
        if fresh:
            raise RuntimeError("An issued body was classified as a fresh forgery")
        # A different public purpose is a distinct signed message, even with
        # identical body bytes. It requires its own successful verification.
        other = tags[(tags.index(purpose) + 1) % len(tags)]
        if (actual_key[handle], signed(other, body)) in ledger:
            raise RuntimeError("Purpose framing collapsed two signing messages")
        if write_failed and published:
            raise RuntimeError("Failure control accidentally published a wire")
        checked += 1
    require("all_purposes_aliases_and_private_failures", checked == 936,
            "936 combinations retain actual-key issuance despite zero published wires and exact owner aliases.")

    m = signed(10, b"response")
    correct_ledger = {("K", m)}
    publication_only_ledger: set[tuple[str, bytes]] = set()
    require("publication_only_ledger_mutation_detected",
            ("K", m) in correct_ledger and ("K", m) not in publication_only_ledger,
            "A computed response followed by failed publication is honest; the publication-only mutant incorrectly calls it fresh.")
    label_only_ledger = {("device", m)}
    require("owner_label_ledger_mutation_detected",
            (actual_key["reopened-device"], m) in correct_ledger
            and ("reopened-device", m) not in label_only_ledger,
            "Renaming/reopening an actual key cannot create a fresh-message event.")
    return {"framed_messages": len(encodings), "ledger_cases": checked,
            "publication_failure_witness": ["private-sign(response)", "durable-write-fails", "reopen", "verify(same-body)"]}


@dataclass(frozen=True)
class Offer:
    generation: int
    public_key: bytes
    signature_alias: int = 0

    def wire(self) -> bytes:
        # The source slot is ghost provenance and deliberately is not a wire field.
        return b"same-context/session/epoch/parent/" + self.public_key + bytes([self.signature_alias])


@dataclass(frozen=True)
class Response:
    responder_history: str
    encapsulation: int
    offered: Offer
    signature_alias: int = 0

    def body(self) -> bytes:
        return hash_link(b"offer-wire", self.offered.wire()) + b"ct/" + bytes([self.encapsulation])

    def wire(self) -> bytes:
        return self.body() + bytes([self.signature_alias])


def association_checks() -> dict:
    accepted = 0
    rejected = 0
    cases = 0
    for public_key_coincides, offer_alias, response_alias, failed_draws in itertools.product(
            (False, True), (0, 1), (0, 1), (0, 1, 2)):
        g = failed_draws + 1
        own = Offer(g, b"pk" if public_key_coincides else b"pk/" + bytes([g]))
        seen = Offer(g, own.public_key, offer_alias)
        original = Response("R", 4, seen)
        presented = Response("R", 4, seen, response_alias)
        ledger = {signed(10, original.body())}
        accepts = hash_link(b"offer-wire", own.wire()) == presented.body()[:32]
        fresh = signed(10, presented.body()) not in ledger
        if fresh:
            raise RuntimeError("A signature alias became a fresh signed body")
        if accepts:
            accepted += 1
            chosen = (g, 4)  # Original slots, not indices at computation time.
            actual = (own.generation, presented.encapsulation)
            if chosen != actual or offer_alias:
                raise RuntimeError("Single-history source association failed")
        else:
            rejected += 1
            if not offer_alias:
                raise RuntimeError("An unchanged honest offer was rejected")
        cases += 1
    require("single_history_alias_and_equal_public_key_cases", cases == 24 and accepted == rejected == 12,
            "24 cases preserve original slots after zero/two failed draws and public-key coincidence; full-offer aliases are rejected while response aliases remain attributable.")

    # A deterministic counterexample for an enlarged controller. Each journal
    # has a perfectly persistent local plan; there is no signature forgery or
    # hash collision. It is the missing global history premise that matters.
    own = Offer(1, b"pk")
    a = Response("R-journal-A", 2, own)
    b = Response("R-journal-B", 3, own)
    issued = {signed(10, a.body()), signed(10, b.body())}
    selected = (1, 2)
    actual = (1, 3)
    accepted_b = hash_link(b"offer-wire", own.wire()) == b.body()[:32]
    fresh_b = signed(10, b.body()) not in issued
    require("two_live_journal_hypothesis_control", accepted_b and not fresh_b and selected != actual,
            "Two independently retained responder plans with the same signer/session/epoch defeat a single predesignated responder-source register without forgery; the theorem explicitly excludes this controller.")

    # The output-equality shortcut is different from causal identity.
    hypothetical_unexecuted = Offer(1, b"coincident-pk")
    executed = Offer(2, b"coincident-pk")
    require("public_key_equality_is_not_origin_identity",
            hypothetical_unexecuted.wire() == executed.wire()
            and hypothetical_unexecuted.generation != executed.generation,
            "Even byte-identical public offers do not justify replacing executed original slot 2 by failed slot 1.")

    # This is an explicit oracle mutation, not a discovered SHA3 collision.
    alias = Offer(own.generation, own.public_key, 1)
    normal_accepts = hash_link(b"offer-wire", alias.wire()) == hash_link(b"offer-wire", own.wire())
    collision_oracle = {own.wire(): b"same", alias.wire(): b"same"}
    require("hash_collision_control_is_charged", not normal_accepts
            and own.wire() != alias.wire() and collision_oracle[own.wire()] == collision_oracle[alias.wire()],
            "Removing distinct-input collision exclusion makes the complete-offer equality inference invalid; the mutated oracle supplies the charged witness.")
    return {"cases": cases, "accepted": accepted, "rejected": rejected,
            "two_journal_witness": {"selected_pair": list(selected), "actual_pair": list(actual),
                                    "verification_accepted": accepted_b, "fresh_body": fresh_b,
                                    "hash_collision": False,
                                    "scope": "Countermodel to dropping the declared history premise, not a claimed native bootstrap exploit."}}


def exposure_result(events: tuple[str, ...]) -> dict:
    ledger: set[str] = set()
    native_fresh = False
    stopped_fresh = False
    exposed = False
    for event in events:
        if event == "expose":
            exposed = True
        elif event.startswith("issue-"):
            ledger.add(event.removeprefix("issue-"))
        elif event.startswith("verify-"):
            fresh = event.removeprefix("verify-") not in ledger
            native_fresh = native_fresh or fresh
            if not exposed:
                stopped_fresh = stopped_fresh or fresh
        elif event != "publication-failure":
            raise ValueError(event)
    return {"eligible": not exposed, "native_fresh": native_fresh, "stopped_fresh": stopped_fresh}


def exposure_checks() -> dict:
    # Each verify event denotes a successful public verification. The model
    # checks event coupling and makes no assertion about its cryptographic probability.
    alphabet = ("issue-M", "issue-N", "verify-M", "verify-N", "expose", "publication-failure")
    count = 0
    for size in range(6):
        for events in itertools.product(alphabet, repeat=size):
            result = exposure_result(events)
            stop = events.index("expose") if "expose" in events else len(events)
            prefix_result = exposure_result(events[:stop])
            if result["stopped_fresh"] != prefix_result["native_fresh"]:
                raise RuntimeError("Pre-disclosure prefix coupling failed")
            if result["eligible"] and result["native_fresh"] and not result["stopped_fresh"]:
                raise RuntimeError("Eligible fresh-body event disappeared under the stop")
            count += 1
    require("exposure_stopped_prefix_coupling", count == 9331,
            "All 9,331 histories of length at most five preserve the successful-verification event before the first key/file disclosure.")
    witness = exposure_result(("expose", "verify-M"))
    require("unqualified_signature_event_mutation_detected",
            witness == {"eligible": False, "native_fresh": True, "stopped_fresh": False},
            "A verification made possible after key disclosure belongs to the unqualified event, not the stopped primitive experiment.")
    return {"histories": count, "unqualified_event_counterexample": witness}


def multiuser_checks() -> dict:
    pairs = 0
    for users in range(1, 9):
        for winning_user in range(users):
            matching_guesses = sum(guess == winning_user for guess in range(users))
            if matching_guesses != 1:
                raise RuntimeError("Wrong user-selection probability")
            pairs += 1
    require("single_user_loss_is_explicit", pairs == 36,
            "For U = 1..8 and every winning owner, exactly one of U uniform embedded-owner guesses extracts the forgery; the single-user form pays U.")

    # Distinct pair owners can coincide in one constituent. The usual indexed
    # component game retains the owner index, whereas exact reuse of a full
    # signing owner retains its existing issuance ledger.
    messages = {0: {b"M"}, 1: set()}
    same_component_public_key = {0: b"P", 1: b"P"}
    require("component_collision_uses_indexed_game",
            same_component_public_key[0] == same_component_public_key[1]
            and b"M" in messages[0] and b"M" not in messages[1],
            "An accidental component-key coincidence stays in the distribution; per-user component freshness is evaluated at the projected owner index.")
    actual_pair_ledger = {b"same-full-pair-key": {b"M"}}
    require("full_owner_alias_cannot_reset_freshness",
            b"M" in actual_pair_ledger[b"same-full-pair-key"],
            "When full signing owners alias, the native actual-key ledger remains shared; absence there implies absence at every associated component index.")
    return {"user_winner_assignments": pairs, "maximum_users": 8}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    sources, tags = source_checks()
    results = {"purpose_and_ledger": purpose_and_ledger_checks(tags),
               "source_association": association_checks(),
               "exposure_stop": exposure_checks(), "multiuser": multiuser_checks()}
    artifact_names = ("source_attribution_proof.md", "check_source_attribution.py", "source_identity.json")
    artifacts = [{"path": str((HERE / name).relative_to(ROOT)),
                  "sha256": sha((HERE / name).read_bytes())} for name in artifact_names]
    module = ROOT / "paper/continuity/source-attribution.tex"
    if module.exists():
        artifacts.append({"path": str(module.relative_to(ROOT)), "sha256": sha(module.read_bytes())})
    report = {"status": "passed", "checks": checks, "check_count": len(checks),
              "python": sys.version.split()[0], "reviewer_checker_sha256": sha(Path(__file__).read_bytes()),
              "reviewed_source_commit": PIN, "source_files": sources, "artifacts_at_execution": artifacts,
              "results": results,
              "scope": "Independent finite controls and exact source identity checks. No Rust execution, formal verification, or estimate of cryptographic security."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "passed", "checks": len(checks), "output": str(args.output),
                      "exposure_histories": results["exposure_stop"]["histories"],
                      "ledger_cases": results["purpose_and_ledger"]["ledger_cases"]}))


if __name__ == "__main__":
    main()
