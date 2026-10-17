"""Compose a pinned certificate's proofs without retaining every proof state.

Tamarin admits earlier reuse declarations as premises even when their proof is
incomplete. Each individual replay is therefore conditional. Acceptance requires
all original universal properties and their complete acyclic dependency graph.
Source lemmas are rejected here because their global scope needs another graph.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from continuity_recovery_profiles import Certificate

_DECLARATION = re.compile(
    r'(?ms)^lemma\s+(\w+)(?:\s+\[([^\]]+)\])?:\s*'
    r'(all-traces|exists-trace)?\s*"([^\"]*)"'
)


class CompositionError(ValueError):
    """The original conjunction has not been established by the supplied parts."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompositionError(message)


@dataclass(frozen=True)
class ProofNode:
    name: str
    dependencies: tuple[str, ...]
    data: bytes
    source_sha256: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def plan(data: bytes, case: Certificate) -> tuple[ProofNode, ...]:
    """Restrict a reviewed exported certificate to one unchanged proof per part."""
    require(hashlib.sha256(data).hexdigest() == case.sha256, "source certificate differs")
    text = data.decode("utf-8", errors="strict")
    declarations = list(_DECLARATION.finditer(text))
    names = [match.group(1) for match in declarations]
    expected = case.expected_results()
    require(len(names) == len(set(names)) and set(names) == set(expected),
            "certificate declaration inventory differs")
    require(case.verified and set(case.verified) == set(case.all_traces),
            "composition requires every universal property")
    attributes = [{value.strip() for value in (match.group(2) or "").split(",")}
                  for match in declarations]
    require(all("sources" not in values for values in attributes),
            "global source lemmas cannot use this composition")
    for match, values in zip(declarations, attributes):
        mode = match.group(3) or "all-traces"
        require(mode == expected[match.group(1)][0], "declaration quantifier differs")
        require("reuse" not in values or mode == "all-traces", "existential reuse declaration")
    selected = tuple(name for name in names if name in case.verified)
    # The catalog lists properties; dependency order comes from the pinned source.
    require(len(selected) == len(case.verified), "universal declaration inventory differs")
    end = re.search(r"\nend\s*\Z", text)
    require(end is not None, "certificate has no final theory boundary")
    prefix = text[:declarations[0].start()]
    originals = [match.group() for match in declarations]
    nodes = []
    for name in selected:
        index = names.index(name)
        dependencies = tuple(names[prior] for prior in range(index) if "reuse" in attributes[prior])
        require(set(dependencies) <= set(selected[:selected.index(name)]),
                "dependency is missing or not earlier in source order")
        parts = [prefix]
        for position, match in enumerate(declarations):
            stop = declarations[position + 1].start() if position + 1 < len(declarations) else end.start()
            parts.append(text[match.start():stop] if match.group(1) == name
                         else match.group() + "\nby sorry\n\n")
        generated = "".join(parts) + "\nend\n"
        require([match.group() for match in _DECLARATION.finditer(generated)] == originals,
                "composition changed a theorem declaration")
        nodes.append(ProofNode(name, dependencies, generated.encode("utf-8"), case.sha256))
    return tuple(nodes)


def combine(data: bytes, records: dict, case: Certificate) -> dict[str, int]:
    """Discharge the conditional premises in strict source order, without cycles."""
    nodes = plan(data, case)
    require(set(records) == set(case.verified), "incomplete theorem graph")
    verified = {}
    for node in nodes:
        record = records[node.name]
        require(isinstance(record, dict), "malformed conditional record")
        require(node.source_sha256 == case.sha256
                and record.get("source_certificate_sha256") == case.sha256,
                "composition uses a different source certificate")
        require(record.get("dependencies") == list(node.dependencies)
                and set(node.dependencies) <= verified.keys(),
                "dependency graph is not closed in source order")
        require(record.get("input_sha256") == node.sha256, "conditional input differs")
        result = record.get("result")
        require(isinstance(result, dict) and type(result.get("returncode")) is int
                and result["returncode"] == 0 and isinstance(result.get("verified"), dict)
                and set(result["verified"]) == {node.name},
                "conditional proof did not verify exactly its property")
        steps = result["verified"][node.name]
        require(type(steps) is int and steps > 0, "invalid proof step count")
        verified[node.name] = steps
    return verified
