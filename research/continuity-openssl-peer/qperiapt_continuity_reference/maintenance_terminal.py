"""Common exact-image/terminal/ACK/cleanup sequence for typed G and R owners."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from typing import Callable
from .local_authority_control import Control, write
from .local_renewal_protocol import Proposal as CredentialProposal
from .local_renewal_intent import Intent as CredentialIntent
from .roster_protocol import Proposal as RosterProposal
from .roster_intent import Intent as RosterIntent
from .wire import require


@dataclass(frozen=True)
class Transition:
    proposal: CredentialProposal | RosterProposal
    terminal: Control
    completed: Control
    acknowledgement: int
    read_intent: Callable[[], CredentialIntent | RosterIntent | None]
    label: str


def finish(journal, snapshot, intent, outcome, transition):
    require(outcome in ("Applied", "Closed"), "maintenance has no exact terminal result")
    p = transition.proposal
    if outcome == "Applied":
        if snapshot.digest != p.target.digest:
            require(intent is not None and snapshot.digest == p.expected.digest
                    and snapshot.revision == p.expected.revision, "missing original applied target")
            journal._admit().publish("head", intent.target)
            snapshot = journal._decode(intent.target)
        require(snapshot.revision == p.target.revision, "applied target revision differs")
    else:
        require(snapshot.digest == p.expected.digest and snapshot.revision == p.expected.revision,
                "closed target was installed")
    journal._query(snapshot)
    write(journal, transition.terminal)
    journal._admit().observe(transition.label + ":terminal-durable")
    require(p.exchange(journal.client, transition.acknowledgement) in ("Acknowledged", "Unavailable"),
            "maintenance terminal acknowledgement")
    journal._admit().observe(transition.label + ":acknowledged")
    if journal._admit().read("intent") is not None:
        require(transition.read_intent() == intent, "another intent replaced terminal maintenance")
        journal._admit().remove_intent()
    write(journal, transition.completed)
    journal._admit().observe(transition.label + ":completed")
    return outcome
