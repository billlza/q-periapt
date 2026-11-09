#!/usr/bin/env python3
"""Finite controls for native online selection, stops and original ledgers.

These are executable finite-interface checks. They do not execute Rust or
instantiate the cryptographic security reductions in the manuscript.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def require(condition: bool, label: str) -> None:
    if not condition:
        raise ValueError(label)


@dataclass
class StepLedger:
    # Designated before this ledger executes its first private chain call.
    target: tuple[str, int] = ("a", 1)
    # Both endpoint names resolve to the original material handle.
    aliases: dict[str, str] = field(default_factory=lambda: {
        "sender-a": "a", "receiver-a": "a", "sender-b": "b"})
    seen: dict[tuple[str, int, int], int] = field(default_factory=dict)
    marked: tuple[str, int, int] | None = None
    calls: list[tuple[str, int, int]] = field(default_factory=list)

    def compute(self, endpoint: str, direction: int, index: int,
                mark: bool, lifetime: int = 3) -> bool:
        identity = (self.aliases[endpoint], direction, index)
        accepted = (mark and identity[:2] == self.target and self.marked is None
                    and identity not in self.seen and index < lifetime)
        if accepted:
            self.marked = identity
        if identity not in self.seen:
            self.seen[identity] = len(self.calls)
        self.calls.append(identity)
        return accepted


def allocation_controls() -> dict:
    # Failed receive attempts are still actual private calls; their public
    # native counter may roll back, whereas the list below is historical.
    actions = [
        ("sender-a", 1, 0, "send"),
        ("receiver-a", 1, 0, "receive-error"),
        ("receiver-a", 1, 1, "skipped-error"),
        ("sender-a", 1, 1, "send-retry"),
        ("sender-b", 1, 0, "other-material"),
        ("sender-a", 2, 0, "opposite-direction"),
    ]
    traces = 0
    decisions = 0
    rejected_prior = 0
    rejected_other = 0
    targets = [("a", 1), ("b", 1), ("a", 2)]
    for target in targets:
        for trace in itertools.product(actions, repeat=4):
            # The material/direction is fixed before the trace. Enumerate
            # every attempted step-marking position, including no mark.
            for selected_position in range(-1, len(trace)):
                ledger = StepLedger(target=target)
                first_positions = {}
                canonical_history = []
                for position, (endpoint, direction, index, _) in enumerate(trace):
                    canonical = ("b" if endpoint == "sender-b" else "a", direction, index)
                    canonical_history.append(canonical)
                    first_positions.setdefault(canonical, position)
                    attempt = position == selected_position
                    matching = canonical[:2] == target
                    first = canonical_history.index(canonical) == position
                    expected = attempt and matching and first
                    actual = ledger.compute(endpoint, direction, index, attempt)
                    require(actual == expected, "online marking differs from independent history search")
                    rejected_prior += int(attempt and matching and not first)
                    rejected_other += int(attempt and not matching)
                    decisions += 1
                require(ledger.seen == first_positions, "original computation index changed after retry")
                traces += 1

    # Concrete counterexample to rolling back the proof ledger with a failed
    # transaction: the receiver has already evaluated index 1 privately.
    seen_before_failure = [("a", 1, 0), ("a", 1, 1)]
    correct = ("a", 1, 1) not in seen_before_failure
    rolled_back = ("a", 1, 1) not in []
    require(not correct and rolled_back, "failed-receive rollback counterexample")
    # Collapsing material identities would reject a genuinely fresh target.
    require(("b", 1, 0) not in [("a", 1, 0)] and (1, 0) in [(1, 0)],
            "epoch-only identity counterexample")
    other_target = StepLedger(target=("b", 1))
    require(not other_target.compute("sender-a", 1, 0, True), "other material cannot mark")
    require(other_target.compute("sender-b", 1, 0, True), "predesignated material remains fresh")
    selected = StepLedger(target=("a", 1))
    require(not selected.compute("sender-a", 2, 0, True), "other direction cannot mark")
    require(("a", 2, 0) in selected.seen, "nonselected computation omitted from ledger")
    bounded = StepLedger()
    require(not bounded.compute("sender-a", 1, 3, True, 3), "fixed lifetime boundary")
    bounded = StepLedger()
    require(bounded.compute("receiver-a", 1, 1, True), "receive-first online mark")
    require(not bounded.compute("sender-a", 1, 1, True), "second alias cannot remark")
    require(not bounded.compute("sender-a", 1, 2, True), "mark remains unique")
    return {"traces_with_mark_choices": traces, "first_call_decisions": decisions,
            "predesignated_material_direction_targets": len(targets),
            "prior_computation_mark_attempts_rejected": rejected_prior,
            "nonselected_material_or_direction_marks_rejected": rejected_other,
            "failed_receive_rollback_counterexample": True,
            "material_collapse_counterexample": True,
            "receive_first_mark_and_exact_aliases": True,
            "lifetime_and_unique_mark_controls": True}


def stop_and_score_controls() -> dict:
    # Independent enumeration of the temporal statement used in the proof.
    # A copy's new seal time does not alter its original version save time.
    temporal = 0
    partition = 0
    for reserve_g, reserve_a, cut, saved, same_session in itertools.product(
            range(1, 4), range(1, 4), range(5), range(5), [False, True]):
        eligible = cut < reserve_g and cut < reserve_a and not (same_session and cut < saved)
        free_stop = same_session and (reserve_g <= saved or reserve_a <= saved)
        require(not (eligible and free_stop), "origin stop removed an eligible candidate")
        temporal += 1

    # This is the exact native partition for both a signed score and an
    # event bit. A candidate's ideal comparison is deliberately not used.
    for eligible, attributed, selected, bad, charged0, charged1, sign in itertools.product(
            [False, True], [False, True], [0, 1], [False, True],
            [False, True], [False, True], [-1, 1]):
        charged = [charged0, charged1]
        for score in [sign, int(bad)]:
            original = int(eligible) * score
            residual_attr = int(eligible and not attributed) * score
            residual_projection = int(eligible and attributed and charged[selected]) * score
            candidates = sum(int(eligible and attributed and selected == j and not charged[j]) * score
                             for j in range(2))
            require(original == residual_attr + residual_projection + candidates,
                    "native score localization identity")
            partition += 1

    cut = 3
    old_version_save = 2
    resealed_at = 8
    require(old_version_save <= cut < resealed_at, "old-copy resealing control")
    target_version_save = 4
    contains_available_successor = True
    require(contains_available_successor and target_version_save > cut,
            "complete record retains original acquisition scope")
    # A free stop for candidate a must not stop candidate b's separate run.
    candidate_a = {"session": "a", "reservation": 2}
    candidate_b = {"session": "b", "reservation": 4}
    acquired = {"session": "a", "save": 3}
    stops = [acquired["session"] == c["session"] and c["reservation"] <= acquired["save"]
             for c in [candidate_a, candidate_b]]
    require(stops == [True, False], "candidate-local acquisition scope")
    return {"temporal_assignments": temporal, "signed_and_boolean_partition_checks": partition,
            "old_version_reseal_uses_original_time": True,
            "available_successor_does_not_declassify_complete_record": True,
            "candidate_local_stop_counterexample": True}


def private_origin_controls() -> dict:
    # Actual operation order from send_message: first durable SendPlan, then
    # step/encrypt, then durable outbox. Failure branches preserve that order.
    histories = []
    for first_persist, second_persist in itertools.product([False, True], repeat=2):
        if not first_persist and second_persist:
            continue  # No second write is reached after a failed first write.
        retained_plan = None
        encryption_ledger = {}
        original = ("material-a", 1, 1)
        intent = (b"payload", b"common-ad")
        if first_persist:
            retained_plan = intent
            encryption_ledger[original] = (retained_plan, b"exact-ciphertext")
        if first_persist and not second_persist:
            # Reopen the earlier retained plan. The exact retry consumes
            # the cached private encryption before its durable outcome.
            require(retained_plan == encryption_ledger[original][0], "retained send intent changed")
            require(retained_plan != (b"different", b"common-ad"), "different intent must conflict")
            require(encryption_ledger[original][1] == b"exact-ciphertext", "private encryption retry")
        require(len(encryption_ledger) == int(first_persist), "encryption before durable reservation")
        histories.append({"reservation_persisted": first_persist,
                          "outbox_persisted": first_persist and second_persist,
                          "original_encryptions": len(encryption_ledger)})

    # Earliest target computation can be a receive. Its authentication event
    # is historical; a later honest encryption of the same pair cannot erase
    # the earlier fresh installation.
    encryptions = set()
    pair = (b"ad", b"ciphertext")
    recorded_bad = pair not in encryptions
    encryptions.add(pair)
    retrospective_bad = pair not in encryptions
    require(recorded_bad and not retrospective_bad, "late encryption erases historical forgery")
    # The experiment's one challenge stays attached to its accepted original
    # send even if the final selector supplies another same-index material.
    accepted = ("material-a", 1, 1, "send-origin")
    substitute = ("material-b", 1, 1, "send-origin")
    require(accepted != substitute, "challenge origin transferred across materials")
    return {"send_failure_histories": histories,
            "receive_before_encryption_integrity_witness": True,
            "retrospective_integrity_ledger_counterexample": True,
            "challenge_material_origin_retained": True}


def source_controls() -> dict:
    identity = json.loads((ROOT / "source_identity.json").read_text())
    for entry in identity["files"]:
        data = (ROOT / entry["snapshot"]).read_bytes()
        require(hashlib.sha256(data).hexdigest() == entry["sha256"], "source SHA-256")
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                == entry["git_blob_sha1"], "source Git blob")
    messages = (ROOT / "sources/messages.rs.txt").read_text()
    traffic = (ROOT / "sources/traffic.rs.txt").read_text()
    send = messages.split("pub async fn send_message(", 1)[1].split("pub async fn message_status(", 1)[0]
    native_step = messages.split("fn step(", 1)[1].split("\n}", 1)[0]
    send_input = traffic.split("fn send_input(", 1)[1].split("pub(super) fn receive(", 1)[0]
    receive = traffic.split("pub(super) fn receive(", 1)[1]
    anchors = {
        "pending_plan_before_first_persist": send.index("traffic.pending = Some(SendPlan") < send.index("self.persist(&mut image).await?;"),
        "first_persist_before_send_computation": send.index("self.persist(&mut image).await?;") < send.index(".send(id, plaintext, associated_data)?;"),
        "pending_id_and_payload_binding": all(s in send_input for s in ["plan.id != id", "plan.plaintext.as_slice() != plaintext", "plan.ad != ad"]),
        "pending_check_before_step": send_input.index("plan.id != id") < send_input.index("step(&self.send, self.sent)?"),
        "step_before_encryption": send_input.index("step(&self.send, self.sent)?") < send_input.index("encrypt_inout_detached("),
        "outbox_and_counter_after_encryption": send_input.index("encrypt_inout_detached(") < send_input.index("self.send = next;\n        self.sent += 1;"),
        "outbox_reuse_before_fresh_step": send_input.index("Ok(saved.wire.as_slice())") < send_input.index("step(&self.send, self.sent)?"),
        "directional_role_swap": "(a, b, ack_a, ack_b)" in traffic and "(b, a, ack_b, ack_a)" in traffic,
        "receiver_computes_skipped_steps": "while self.received < header.index" in receive and "self.skipped.insert(self.received, message);" in receive,
        "receiver_step_before_authentication": receive.index("step(&self.receive, self.received)?") < receive.index("decrypt_inout_detached("),
        "receiver_drops_error_candidate": "Candidate state is transaction-private and dropped on any error." in receive,
        "receiver_reuses_retained_skipped_key": "self.skipped\n                .remove(&header.index)" in receive,
        "zero_salt_extract": "Hkdf::<Sha256>::new(None, seed.as_bytes())" in native_step,
        "fixed_width_chain_index": "index.to_be_bytes()" in native_step,
        "reserved_index_rejected": "index == u64::MAX" in native_step,
        "two_chain_output_blocks": "ZeroizingBytes::<64>::zeroed()" in native_step,
        "zero_message_nonce": traffic.count("&Nonce::from([0; 12])") == 2,
        "exact_public_resume": "return Ok(saved.wire.clone());" in messages,
    }
    require(all(anchors.values()), "native source-order anchor failed")
    return {"files": len(identity["files"]), "anchors": anchors,
            "current_source_commit": identity["inspected_commit"],
            "all_match_original_paper_source": all(e["matches_paper_pin"] for e in identity["files"])}


def main() -> None:
    result = {"schema": "qperiapt-native-online-chain-controls/1", "status": "passed",
              "allocation": allocation_controls(), "localization": stop_and_score_controls(),
              "private_origins": private_origin_controls(), "sources": source_controls(),
              "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "scope": "Finite source-order, alias/mark, candidate-stop, native-partition and historical-event controls. Rust, a formal verifier and native workload benchmarks are not executed by this checker; the complete result is proved in the accompanying manuscript."}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
