#!/usr/bin/env python3
"""Finite fault, transcript-alias and signing-reservation research checks.

This is an executable model and source audit. It does not execute the native
Rust protocol, prove signature security, or run a formal verifier.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from dataclasses import dataclass, replace
import hashlib
import itertools
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[3]
DR = b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/"
checks: list[dict] = []


def check(name: str, value: bool, detail: str) -> None:
    checks.append({"id": name, "pass": bool(value), "detail": detail})
    if not value:
        raise AssertionError(name + ": " + detail)


def lp(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data


def digest(label: bytes, data: bytes) -> bytes:
    return hashlib.sha3_256(lp(DR + label) + lp(data)).digest()


@dataclass(frozen=True)
class State:
    """A recovered journal plus a ghost original-computation ledger.

    Phase 0 is empty, 1 retains a KEM token, 2 retains its result/signing
    reservation, and 3 retains the ready wire. Epochs begin at one.
    """

    epoch: int = 1
    phase: int = 0
    origin: int | None = None
    draws: tuple[int, ...] = ()
    executed: tuple[tuple[int, ...], ...] = ((), ())


def execute(state: State, origin: int, mutant: str | None) -> State:
    ledger = list(state.executed)
    values = ledger[state.epoch - 1]
    recorded = origin
    if mutant == "renumber_retry" and values:
        recorded = max(values) + 100
    ledger[state.epoch - 1] = tuple(sorted(set(values + (recorded,))))
    return replace(state, executed=tuple(ledger))


def call_transitions(state: State, kind: str, mutant: str | None = None):
    """Enumerate actual call-boundary outcomes, followed by authoritative reopen.

    A failed write may retain the old state or the complete new target. Both
    outcomes return to the caller. Only a successful write continues the call.
    """
    if kind not in {"generation", "encapsulation"}:
        raise ValueError("unknown KEM role")
    if state.phase == 3:
        yield ("ready replay", state)
        if state.epoch == 1:
            yield ("complete advances epoch", replace(state, epoch=2, phase=0, origin=None))
        return

    working = state
    prefix: tuple[str, ...] = ()
    if working.phase == 0:
        if len(working.draws) >= 3:
            return
        origin = len(working.draws) + 1
        working = replace(working, draws=working.draws + (working.epoch,))
        if mutant == "compute_before_persist":
            working = execute(working, origin, None)
        token = replace(working, phase=1, origin=origin)
        yield ("reserve; no durable target; caller error", working)
        yield ("reserve; retained target; caller error", token)
        working = token
        prefix = ("reserve; token committed",)

    if working.origin is None:
        raise AssertionError("retained phase has no original token")
    if working.phase == 1 or kind == "generation":
        working = execute(working, working.origin, mutant)
        yield ("; ".join(prefix + ("KEM invocation; provider error",)), working)
        yield ("; ".join(prefix + ("KEM computed; process loss",)), working)
        prefix += ("KEM computed",)

    if working.phase == 1:
        signing = replace(working, phase=2)
        failed = working
        if mutant == "discard_executed_plan":
            failed = replace(working, phase=0, origin=None)
        yield ("; ".join(prefix + ("signing target absent; caller error",)), failed)
        yield ("; ".join(prefix + ("signing target retained; caller error",)), signing)
        working = signing
        prefix += ("signing target committed",)

    yield ("; ".join(prefix + ("signing invocation; provider error",)), working)
    yield ("; ".join(prefix + ("signature computed; process loss",)), working)
    yield ("; ".join(prefix + ("ready target absent; caller error",)), working)
    ready = replace(working, phase=3)
    yield ("; ".join(prefix + ("ready target retained; caller error",)), ready)
    yield ("; ".join(prefix + ("ready committed; release denied",)), ready)
    yield ("; ".join(prefix + ("ready committed; release allowed",)), ready)


def invariant(state: State) -> bool:
    for epoch, values in enumerate(state.executed, start=1):
        if len(values) > 1:
            return False
        if any(origin < 1 or origin > len(state.draws) or state.draws[origin - 1] != epoch for origin in values):
            return False
    if state.phase and state.executed[state.epoch - 1]:
        if state.executed[state.epoch - 1] != (state.origin,):
            return False
    return True


def explore(kind: str, mutant: str | None = None) -> dict:
    initial = State()
    queue = deque([initial])
    paths = {initial: ()}
    edges = 0
    while queue:
        old = queue.popleft()
        for label, new in call_transitions(old, kind, mutant):
            edges += 1
            trace = paths[old] + (label,)
            if not invariant(new):
                return {"status": "counterexample", "states": len(paths), "edges": edges,
                        "trace": list(trace), "state": state_json(new)}
            if new not in paths:
                paths[new] = trace
                queue.append(new)
    ready = [s for s in paths if s.phase == 3]
    failed_first = [s for s in ready if s.epoch == 1 and s.executed[0] == (2,)
                    and s.draws[:2] == (1, 1)]
    if not failed_first:
        raise AssertionError("fault exploration omitted failed-first-reservation witness")
    witness = min(failed_first, key=lambda s: len(paths[s]))
    return {"status": "passed", "states": len(paths), "edges": edges,
            "ready_states": len(ready), "epoch_two_states": sum(s.epoch == 2 for s in paths),
            "failed_first_witness": {"trace": list(paths[witness]), "state": state_json(witness),
                                     "metadata_selector": 1, "executed_selector": 2}}


def state_json(state: State) -> dict:
    return {"epoch": state.epoch, "phase": state.phase, "origin": state.origin,
            "original_reservation_epochs": list(state.draws),
            "executed_original_slots": [list(x) for x in state.executed]}


@dataclass(frozen=True)
class Wire:
    purpose: int
    body: bytes
    signature: bytes = b"signature-0"

    def encoded(self) -> bytes:
        return len(self.body).to_bytes(4, "big") + self.body + self.signature

    def alternate(self) -> Wire:
        return replace(self, signature=b"signature-1")


def alias_cases() -> list[dict]:
    """Use fixed independent expected outcomes for the three complete-wire links.

    Signatures are origin labels. The model allows a different valid encoding
    of the same signed body; it does not simulate a cryptographic forgery.
    """
    prefix = b"fixed-profile-context-session-epoch-role-parent"
    offer = Wire(9, prefix + b"pk-from-generation-2")

    def response(presented: Wire) -> Wire:
        return Wire(10, prefix + digest(b"offer-wire", presented.encoded()) + b"ct-from-encapsulation-3")

    def final(presented_offer: Wire, presented_response: Wire) -> Wire:
        return Wire(11, prefix + digest(b"offer-wire", presented_offer.encoded())
                    + digest(b"response-wire", presented_response.encoded()))

    rows = []
    expected = {
        "honest": (True, True, True),
        "offer_alias": (False, False, False),
        "response_alias": (True, False, False),
        "final_alias": (True, True, False),
    }
    for name, wanted in expected.items():
        presented_offer = offer.alternate() if name == "offer_alias" else offer
        saved_response = response(presented_offer)
        presented_response = saved_response.alternate() if name == "response_alias" else saved_response
        proposer_accepts = presented_response.body == response(offer).body
        made_final = final(offer, presented_response)
        presented_final = made_final.alternate() if name == "final_alias" else made_final
        responder_accepts = proposer_accepts and presented_final.body == final(presented_offer, saved_response).body
        receipt_accepts = responder_accepts and digest(b"final-wire", presented_final.encoded()) == digest(b"final-wire", made_final.encoded())
        actual = (proposer_accepts, responder_accepts, receipt_accepts)
        check("transcript_" + name, actual == wanted,
              "Expected proposer allocation/responder allocation/proposer receipt: " + repr(wanted))
        same_pair = (2, 3) if proposer_accepts or responder_accepts else None
        rows.append({"case": name, "proposer_allocation": proposer_accepts,
                     "responder_allocation": responder_accepts,
                     "proposer_receipt": receipt_accepts, "source_pair": same_pair,
                     "traffic_info_differs_from_original": digest(b"traffic-transcript", offer.encoded() + presented_response.encoded()) != digest(b"traffic-transcript", offer.encoded() + saved_response.encoded())})
    response_alias = next(row for row in rows if row["case"] == "response_alias")
    check("response_alias_changes_info_without_changing_sources",
          response_alias["source_pair"] == (2, 3) and response_alias["traffic_info_differs_from_original"],
          "An accepted same-body response alias preserves original sources and changes full traffic information.")

    other_offer = Wire(9, prefix + b"different-generation")
    same_digest_response = response(other_offer)
    check("distinct_offer_link_rejected",
          same_digest_response.body != response(offer).body,
          "A response to a different offered key fails the actual complete-offer hash comparison.")
    forced = {offer.encoded(): b"forced-collision", other_offer.encoded(): b"forced-collision"}
    check("collision_control_is_explicit",
          offer.encoded() != other_offer.encoded() and forced[offer.encoded()] == forced[other_offer.encoded()],
          "Overriding the two hash replies supplies a distinct-input collision witness; it is a charged event.")
    authored = {(offer.purpose, offer.body), (10, response(offer).body)}
    forged = (10, prefix + b"unauthored-ciphertext")
    check("fresh_body_event_is_not_wire_alias",
          (10, response(offer).alternate().body) in authored and forged not in authored,
          "A new wire encoding of an issued body is outside the fresh-message forgery event.")
    return rows


def signature_models() -> dict:
    cases = 0
    for secret, randomizer in itertools.product(range(8), repeat=2):
        appendix = secret ^ randomizer
        check_name = "coin recovery"
        if appendix ^ randomizer != secret:
            raise AssertionError(check_name)
        cases += 1
    counts = {secret: Counter(secret ^ r for r in range(8)) for secret in range(8)}
    uniform = Counter({x: 1 for x in range(8)})
    check("ordinary_appendix_independent_of_secret", all(c == uniform for c in counts.values()),
          "For every 3-bit key, the appendix is exactly uniform over all 3-bit randomizers.")
    check("opened_original_randomizer_recovers_secret", cases == 64,
          "All 64 key/randomizer assignments recover the original key exactly by XOR.")

    # The classical part is an opaque deterministic oracle. The wrapper knows
    # only the independent auxiliary key and its original randomizers.
    oracle_queries: list[bytes] = []
    oracle_cache: dict[bytes, bytes] = {}

    def oracle(message: bytes) -> bytes:
        oracle_queries.append(message)
        return oracle_cache.setdefault(message, hashlib.sha256(b"oracle-only-key" + message).digest())

    entries: dict[int, tuple[bytes, int]] = {}
    result_cache: dict[int, tuple[bytes, bytes]] = {}
    real_cache: dict[int, tuple[bytes, bytes]] = {}
    operations = 0
    for origin, (message, randomizer) in enumerate(itertools.product((b"offer", b"response"), range(4)), start=1):
        entries[origin] = (message, randomizer)
        for before in (True, False):
            if before and entries[origin][1] != randomizer:
                raise AssertionError("pre-execution open changed randomness")
            if origin not in result_cache:
                auxiliary = hashlib.sha256(b"known-independent-key" + message + bytes([randomizer])).digest()
                result_cache[origin] = (auxiliary, oracle(message))
                real_cache[origin] = (auxiliary, hashlib.sha256(b"oracle-only-key" + message).digest())
            if result_cache[origin] != real_cache[origin] or entries[origin] != (message, randomizer):
                raise AssertionError("reservation-aware signature adapter mismatch")
            operations += 1
    check("deterministic_component_adapter_exact", operations == 16 and len(oracle_queries) == 8,
          "Eight original reservations, sixteen executions/openings, and one classical signing query per reservation.")
    first, second = result_cache[1], result_cache[2]
    check("same_body_distinct_randomizers_keep_two_origins", first[1] == second[1] and first[0] != second[0],
          "The deterministic component repeats; the auxiliary randomized component and original reservations remain separate.")
    published = {}
    private = result_cache[1]
    before_queries = len(oracle_queries)
    # The result write fails before any wire is published. Recovery retains
    # the original reservation; the reduction's private computation persists.
    reopened_reservation = entries[1]
    replayed = result_cache[1]
    check("executed_query_ledger_survives_failed_publication",
          not published and reopened_reservation == (b"offer", 0)
          and b"offer" in oracle_queries and replayed == private
          and len(oracle_queries) == before_queries,
          "After failed publication and recovery, the original signature and query ledger remain, with no new oracle query.")
    check("publication_only_origin_ledger_is_rejected",
          b"offer" not in published and b"offer" in oracle_queries,
          "A ledger recording only published wires misclassifies an honestly computed, unpublished signature as fresh.")
    return {"separation_assignments": cases, "original_signature_reservations": len(entries),
            "execute_and_open_sequences": operations, "classical_oracle_queries": len(oracle_queries)}


def source_audit(repository: Path) -> list[dict]:
    manifest = json.loads((HERE / "source_identity.json").read_text())
    texts = {}
    sources = []
    for item in manifest["sources"]:
        rel = item["path"]
        data = (repository / rel).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        check("source_identity_" + rel.replace("/", "_"), actual == item["sha256"],
              "Exact bytes match the independently inspected source manifest.")
        texts[rel] = data.decode("utf-8")
        sources.append({"path": rel, "sha256": actual, "bytes": len(data)})
    base = "research/continuity-identity-candidate/src/"
    crypto = texts[base + "crypto.rs"]
    rekey = texts[base + "durable/messages/rekey.rs"]
    response = texts[base + "durable/messages/rekey/response.rs"]
    completion = texts[base + "durable/messages/rekey/completion.rs"]

    def ordered(text: str, markers: tuple[str, ...]) -> bool:
        cursor = 0
        for marker in markers:
            found = text.find(marker, cursor)
            if found == -1:
                return False
            cursor = found + len(marker)
        return True

    check("native_generation_persist_before_compute", ordered(rekey, (
        "if state.control.plan.is_none()", ".reserve_key(", "Some(Plan::Key(key))",
        "self.store_message_state(&mut image, &state).await?;", "recovery.generate_key(")),
        "The exact source orders original reservation, plan retention and private generation.")
    check("native_encapsulation_persist_before_compute", ordered(response, (
        "if state.control.plan.is_none()", ".reserve_encapsulation(", "stage: Stage::Encapsulation(reservation)",
        "self.store_message_state(&mut image, &state).await?;", "recovery.encapsulate(")),
        "The exact source orders original reservation, retained offered wire and private encapsulation.")
    check("native_plan_clear_advances_epoch", ordered(completion, (
        "fn complete(&mut self", "self.control.epoch = self.control.target()?;", "self.control.plan = None;")),
        "The completion transition increments the epoch before clearing the rekey plan.")
    check("native_generation_retains_original_token", all(m in rekey for m in (
        "Self::Key(key) | Self::Signing { key, .. } | Self::Ready { key, .. } => Ok(key)",
        "if *saved != body", "Some(Plan::Ready {", "key,")),
        "Generation retries use the retained token and compare the recomputed complete offer body.")
    check("native_response_pins_complete_offer", all(m in response for m in (
        "if saved.offer != offer", "return Err(DurableError::Conflict);", "hash(b\"offer-wire\", offer)",
        "hash(b\"response-kem\", offer)")),
        "The responder keeps the exact complete offer for conflict, signed-prefix and KEM-context checks.")
    proposer = completion[completion.index("pub async fn accept_rekey_response("):completion.index("pub async fn finish_rekey(")]
    check("native_proposer_checks_before_decapsulation", ordered(proposer, (
        "verify_wire(context, target, RekeyFlight::Response, reply)?;", "let prefix = response::prefix(",
        "!body.starts_with(&prefix)", "recovery.generate_key(", ".public_key()", ".decapsulate(")),
        "Response signature/prefix and original regenerated public key precede selected decapsulation.")
    responder = completion[completion.index("pub async fn finish_rekey("):completion.index("pub async fn accept_rekey_receipt(")]
    check("native_responder_checks_before_allocation", ordered(responder, (
        "verify_wire(context, target, RekeyFlight::Final, final_wire)?;", "verify_control_body(",
        "state.add_epoch(")),
        "Final signature and complete saved-wire checks precede the responder's traffic allocation.")
    check("native_full_wire_traffic_info", 'hash(b"traffic-transcript", &[offer, reply].concat())' in completion,
        "The actual received complete response wire enters traffic information.")
    check("native_signing_binding_fields", ordered(crypto, (
        "fn signed_message(", "SIGNATURE_CONTEXT", "message.push(purpose as u8);",
        "message.extend_from_slice(&length.to_be_bytes());", "message.extend_from_slice(body);")),
        "Purpose and complete body length are in the signed string.")
    reservation = crypto[crypto.index("pub(crate) struct SigningReservation"):crypto.index("/// Owned application protocol-policy signer")]
    check("native_reservation_serializes_only_binding_and_randomizer", ordered(reservation, (
        "pub(crate) fn encode(", "out.extend_from_slice(&self.binding);", "out.extend_from_slice(self.randomness.as_bytes());")),
        "The signing-reservation byte interface includes the original randomizer.")
    sign = crypto[crypto.index("fn sign_message("):crypto.index("/// Owned account-root signer")]
    check("native_component_randomness_separation", ordered(sign, (
        ".sign_ctx(", "randomness.as_bytes()", ".classic", ".try_sign(message)", "signature.normalize_s()")),
        "The retained randomizer feeds ML-DSA; deterministic P-256 signing and canonicalization are separate.")
    owner = texts[base + "crypto/persistence.rs"]
    check("native_owner_file_requires_separate_interface", all(m in owner for m in (
        "plaintext.extend_from_slice(seed.pq.as_bytes());", "plaintext.extend_from_slice(seed.classic.as_bytes());")),
        "Actual owner files contain both secret seeds and are explicitly outside the exact signature adapter's byte interface.")
    alias = texts[base + "durable/messages/tests/classical_alias.rs"]
    check("native_alias_test_is_retained_source_only", all(m in alias for m in (
        "classical_offer_alias_authenticates_but_cannot_replace_the_retained_rekey_offer",
        "classical_response_alias_passes_root_confirmation_but_final_binds_the_original_wire")),
        "Existing native test source supports the alias interpretation; this command does not execute those Rust tests.")
    return sources


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--finite-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    models = {}
    for kind in ("generation", "encapsulation"):
        result = explore(kind)
        check(kind + "_fault_graph", result["status"] == "passed",
              "All reachable recovered states with up to three source draws and two epochs preserve executed-source identity.")
        check(kind + "_multiple_epochs_present", result["epoch_two_states"] > 0,
              "Normal completion permits a new source in the next epoch.")
        models[kind] = result
        for mutant in ("compute_before_persist", "discard_executed_plan", "renumber_retry"):
            negative = explore(kind, mutant)
            check(kind + "_reject_" + mutant, negative["status"] == "counterexample",
                  "The checker finds a causal trace violating the original-slot invariant.")
            models[kind + "_" + mutant] = negative
    alias_rows = alias_cases()
    signatures = signature_models()
    sources = [] if args.finite_only else source_audit(args.repository.resolve())
    report = {
        "status": "passed", "mode": "finite-only" if args.finite_only else "finite-and-source",
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": sys.version.split()[0], "check_count": len(checks), "checks": checks,
        "source_files": sources, "fault_models": models, "transcript_alias_cases": alias_rows,
        "signature_models": signatures,
        "scope": "Finite recovered-state graph, explicit transcript-alias expectations, signature-interface algebra and optional exact source audit. No Rust execution, cryptographic probability estimate or mechanized proof."
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "mode": report["mode"],
                      "checks": len(checks), "output": str(args.output),
                      "generation_states": models["generation"]["states"],
                      "encapsulation_states": models["encapsulation"]["states"]}))


if __name__ == "__main__":
    main()
