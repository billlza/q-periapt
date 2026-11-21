"""Finite event models for exact-output selection and retry admission.

The two values A and B are distinguishable (wire, successor) pairs for one
fixed public operation slot. All actions are abstract. No keys, providers,
network clients or storage adapters are used.
"""

from collections import deque
from dataclasses import dataclass, replace
from enum import Enum, IntFlag, auto
import json


class Value(IntFlag):
    NONE = 0
    A = 1
    B = 2


VALUES = (Value.A, Value.B)


class Rule(Enum):
    CANDIDATE = auto()
    BARE_OUTPUT = auto()
    SLOT_ONLY_RECEIPT = auto()
    DECIDE_FROM_RAM = auto()
    ONE_DECISION_PER_ATTEMPT = auto()
    HISTORICAL_AUTHORITY = auto()
    SHARED_RECEIPT_SIGNER = auto()
    UNFENCED_ABSENCE = auto()
    RETRY_ON_UNKNOWN = auto()


@dataclass(frozen=True)
class OutputState:
    sampled: Value = Value.NONE       # history only, never becomes a recovery input
    ram: Value = Value.NONE
    prepared: Value = Value.NONE       # durable exact wire AND successor, retrievable by slot
    decided: Value = Value.NONE        # independent durable compare-and-set, survives client loss
    receipts: Value = Value.NONE       # independently verifiable, tied to the chosen wire
    observable: Value = Value.NONE     # public bytes seen through release or a RAM observation
    exposed: Value = Value.NONE        # observed contribution/successor origins, history only
    accepted: Value = Value.NONE       # records each distinct peer acceptance for the slot
    authorized: bool = True


def output_steps(s, rule):
    if s.authorized:
        yield "revoke", replace(s, authorized=False)
    if s.ram:
        yield "lose volatile state", replace(s, ram=Value.NONE)
    for v in VALUES:
        if s.authorized and not s.decided and not (s.sampled & v):
            yield f"compute {v.name}", replace(s, sampled=s.sampled | v, ram=s.ram | v)
        if s.ram & v:
            yield f"observe volatile pair {v.name}", replace(
                s, observable=s.observable | v, exposed=s.exposed | v)
            yield f"persist wire and successor {v.name}", replace(s, prepared=s.prepared | v)
        if s.prepared & v:
            yield f"observe readable prepared pair {v.name}", replace(
                s, observable=s.observable | v, exposed=s.exposed | v)
        available = s.prepared | (s.ram if rule is Rule.DECIDE_FROM_RAM else Value.NONE)
        if s.authorized and available & v and (not s.decided or rule is Rule.ONE_DECISION_PER_ATTEMPT):
            yield f"decide {v.name}", replace(s, decided=s.decided | v)
        if s.decided & v:
            yield f"obtain receipt {v.name}", replace(s, receipts=s.receipts | v)
            if s.authorized and s.prepared & v:
                yield f"release stored output {v.name}", replace(s, observable=s.observable | v)
        if rule is Rule.SHARED_RECEIPT_SIGNER and s.ram & v:
            yield f"issue receipt in exposed domain {v.name}", replace(s, receipts=s.receipts | v)
        if not (s.observable & v) or s.accepted & v:
            continue
        eligible = bool(s.receipts & v)
        if rule is Rule.BARE_OUTPUT:
            eligible = True
        elif rule is Rule.SLOT_ONLY_RECEIPT:
            eligible = bool(s.receipts)
        if eligible and (s.authorized or rule is Rule.HISTORICAL_AUTHORITY):
            yield f"peer accepts {v.name}", replace(s, accepted=s.accepted | v)


def output_violation(before, after):
    if after.decided == (Value.A | Value.B):
        return "two decisions for one original slot"
    if after.decided & ~after.prepared and not after.ram:
        return "decided output or successor unavailable after crash"
    newly_accepted = after.accepted & ~before.accepted
    if newly_accepted & ~after.decided:
        return "peer accepted an undecided output"
    if newly_accepted and not before.authorized:
        return "new acceptance after revocation"
    return None


class Client(Enum):
    ORIGINAL = auto()
    UNKNOWN_A = auto()
    ABSENCE_CONFIRMED = auto()
    UNKNOWN_B = auto()
    RECOVERED_A = auto()
    RECOVERED_B = auto()


@dataclass(frozen=True)
class RetryState:
    client: Client = Client.ORIGINAL
    pending: Value = Value.NONE         # delayed requests can outlive a process
    winner: Value = Value.NONE
    fenced_a: bool = False
    absence_returned: bool = False


def retry_steps(s, rule):
    if s.client is Client.ORIGINAL:
        yield "submit A, outcome unknown", replace(s, pending=Value.A, client=Client.UNKNOWN_A)
    for v in VALUES:
        if not (s.pending & v):
            continue
        remainder = s.pending & ~v
        yield f"lose request {v.name}", replace(s, pending=remainder)
        if not s.winner and (v is Value.B or not s.fenced_a):
            yield f"commit {v.name}, no reply", replace(s, pending=remainder, winner=v)
    if s.client in (Client.UNKNOWN_A, Client.UNKNOWN_B) and s.winner:
        done = Client.RECOVERED_A if s.winner is Value.A else Client.RECOVERED_B
        yield f"recover exact {s.winner.name} by original slot", replace(s, client=done)
    if s.client is Client.UNKNOWN_A:
        if not s.winner:
            yield "resolve absence", replace(s, client=Client.ABSENCE_CONFIRMED,
                                             fenced_a=rule is not Rule.UNFENCED_ABSENCE,
                                             absence_returned=True)
        if rule is Rule.RETRY_ON_UNKNOWN:
            yield "start B on timeout", replace(s, client=Client.UNKNOWN_B, pending=s.pending | Value.B)
    if s.client is Client.ABSENCE_CONFIRMED:
        yield "start B in the same slot", replace(s, client=Client.UNKNOWN_B, pending=s.pending | Value.B)


def retry_violation(before, after):
    if after.absence_returned and after.winner is Value.A:
        return "old request committed after negative resolution"
    if after.client is Client.UNKNOWN_B and not before.absence_returned:
        return "new attempt without negative resolution"
    return None


def explore(initial, steps, violation, rule):
    parents = {initial: None}
    queue = deque([initial])
    transitions = 0
    while queue:
        state = queue.popleft()
        for event, target in steps(state, rule):
            transitions += 1
            failure = violation(state, target)
            if failure:
                path = [event]
                while parents[state] is not None:
                    state, incoming = parents[state]
                    path.append(incoming)
                return parents, transitions, {"property": failure, "events": path[::-1]}
            if target not in parents:
                parents[target] = (state, event)
                queue.append(target)
    return parents, transitions, None


OUTPUT_CONTROLS = {
    Rule.BARE_OUTPUT: "peer accepted an undecided output",
    Rule.SLOT_ONLY_RECEIPT: "peer accepted an undecided output",
    Rule.DECIDE_FROM_RAM: "decided output or successor unavailable after crash",
    Rule.ONE_DECISION_PER_ATTEMPT: "two decisions for one original slot",
    Rule.HISTORICAL_AUTHORITY: "new acceptance after revocation",
    Rule.SHARED_RECEIPT_SIGNER: "peer accepted an undecided output",
}
RETRY_CONTROLS = {
    Rule.UNFENCED_ABSENCE: "old request committed after negative resolution",
    Rule.RETRY_ON_UNKNOWN: "new attempt without negative resolution",
}


def run():
    report = {}
    for name, initial, steps, violation, controls in (
        ("output", OutputState(), output_steps, output_violation, OUTPUT_CONTROLS),
        ("retry", RetryState(), retry_steps, retry_violation, RETRY_CONTROLS),
    ):
        reached, transitions, failure = explore(initial, steps, violation, Rule.CANDIDATE)
        if failure:
            raise RuntimeError(f"candidate {name}: {failure}")
        if name == "output":
            for v in VALUES:
                # A decision survives loss of RAM and can actually be accepted.
                if not any(not s.ram and s.accepted == v and s.decided == v for s in reached):
                    raise RuntimeError(f"missing useful acceptance of {v.name}")
            if not any(s.observable == (Value.A | Value.B) and not s.decided for s in reached):
                raise RuntimeError("both speculative wire values must be observable before selection")
            if not any(s.exposed == Value.A and s.accepted == Value.A for s in reached):
                raise RuntimeError("receipt validation must preserve the winning origin's disclosure")
            if not any(s.exposed == Value.A and s.accepted == Value.B for s in reached):
                raise RuntimeError("the model must distinguish the losing and winning origins")
        else:
            for done in (Client.RECOVERED_A, Client.RECOVERED_B):
                if not any(s.client is done for s in reached):
                    raise RuntimeError(f"missing original-operation recovery through {done.name}")
        examples = {}
        for rule, expected in controls.items():
            _, _, example = explore(initial, steps, violation, rule)
            if example is None or example["property"] != expected:
                raise RuntimeError(f"control {rule.name}: expected {expected}, got {example}")
            examples[rule.name] = example
        report[name] = {"reachable_states": len(reached), "transitions_examined": transitions,
                        "finite_candidate_violations": 0, "negative_controls": examples}
    return report


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
