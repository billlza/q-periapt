"""Require macro coverage in the compilation target that enables the source.

The complete raw macro census remains observable. A compiler-only export-name
attribute is not executable AST, while a macro in an inactive module needs an
expansion in a profile that actually compiles that module. Neither case permits
an expanded peer profile to hide a failure in the current active source.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
import re

from codeql_rust_quality import CodeQLRustQualityError


@dataclass(frozen=True)
class MacroCall:
    path: str
    line: int
    column: int
    description: str
    expanded: bool
    context: str

    @property
    def site(self) -> tuple[str, int, int, str]:
        return self.path, self.line, self.column, self.description

    @property
    def key(self) -> tuple[str, int, int, str, str]:
        return (*self.site, self.context)


@dataclass(frozen=True)
class MacroProfile:
    target: str
    source_sha256: Mapping[str, str]
    compiled_sources: frozenset[str]
    calls: tuple[MacroCall, ...]
    source_macro_count: int
    unresolved_macro_count: int


def parse_macro_calls(rows: Sequence[Sequence[object]]) -> tuple[MacroCall, ...]:
    calls = []
    for row in rows:
        if not (
            len(row) == 7
            and isinstance(row[0], str)
            and type(row[1]) is int and row[1] > 0
            and type(row[2]) is int and row[2] > 0
            and isinstance(row[3], str) and bool(row[3])
            and row[4] in ("expanded", "unresolved")
            and row[5] in ("code", "export_name")
            and isinstance(row[6], dict)
            and row[6].get("label") == row[3]
        ):
            raise CodeQLRustQualityError("macro census contains a malformed entity row")
        path = PurePosixPath(row[0])
        if (path.is_absolute() or ".." in path.parts
                or path.as_posix() != row[0] or path.suffix != ".rs"):
            raise CodeQLRustQualityError("macro census path is not canonical Rust source")
        # Distinct macro entities can have identical source locations and labels.
        # Preserve their multiplicity and reconcile it with the raw metric below.
        calls.append(MacroCall(row[0], row[1], row[2], row[3],
                               row[4] == "expanded", row[5]))
    return tuple(calls)


def validate_macro_profiles(profiles: Sequence[MacroProfile]) -> dict[str, dict[str, int]]:
    if (len(profiles) < 2 or any(not isinstance(p.target, str) or not p.target
                                 for p in profiles)
            or len({p.target for p in profiles}) != len(profiles)):
        raise CodeQLRustQualityError("macro coverage requires distinct compilation targets")
    source = dict(profiles[0].source_sha256)
    if not source or any(not isinstance(value, str)
                         or re.fullmatch(r"[0-9a-f]{64}", value) is None
                         for value in source.values()):
        raise CodeQLRustQualityError("macro coverage requires source byte identities")
    for profile in profiles:
        if dict(profile.source_sha256) != source:
            raise CodeQLRustQualityError("macro profiles do not use the same source bytes")
        if not profile.compiled_sources or not profile.compiled_sources <= source.keys():
            raise CodeQLRustQualityError("compiled source inventory is empty or outside the source")
        if any(call.path not in source for call in profile.calls):
            raise CodeQLRustQualityError("macro census contains untracked source")
        if (type(profile.source_macro_count) is not int or profile.source_macro_count <= 0
                or len(profile.calls) != profile.source_macro_count):
            raise CodeQLRustQualityError("macro entity count differs from the raw metric")
        if (type(profile.unresolved_macro_count) is not int
                or sum(not call.expanded for call in profile.calls)
                != profile.unresolved_macro_count):
            raise CodeQLRustQualityError("unresolved macro count differs from the raw metric")

    covered = {profile.target: {call.key for call in profile.calls
                               if call.expanded or (call.context == "export_name"
                                                    and call.path in profile.compiled_sources)}
               for profile in profiles}
    unresolved_code = {profile.target: {call.key for call in profile.calls
                                       if not call.expanded and call.context == "code"}
                       for profile in profiles}
    result = {}
    failures = []
    for profile in profiles:
        counts: Counter[str] = Counter({"expanded": 0, "compiler_export_metadata": 0,
                                       "inactive_with_compiled_peer": 0})
        for call in profile.calls:
            if call.expanded:
                counts["expanded"] += 1
                continue
            if call.path in profile.compiled_sources:
                if call.context == "export_name":
                    counts["compiler_export_metadata"] += 1
                else:
                    failures.append((profile.target, call.site, "active macro has no expansion"))
                continue
            peers = [peer for peer in profiles if peer.target != profile.target
                     and call.path in peer.compiled_sources]
            if any(call.key in covered[peer.target]
                   and call.key not in unresolved_code[peer.target] for peer in peers):
                counts["inactive_with_compiled_peer"] += 1
            else:
                failures.append((profile.target, call.site, "no compiled peer covers the macro context"))
        result[profile.target] = dict(counts)
    if failures:
        raise CodeQLRustQualityError(
            f"target-specific macro coverage has {len(failures)} failure(s): {failures[:8]}"
        )
    return result
