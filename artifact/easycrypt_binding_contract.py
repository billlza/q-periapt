#!/usr/bin/env python3
"""Check the reviewed assumptions and theorem statements, then let EasyCrypt prove them.

This deliberately narrow declaration inventory is not an EasyCrypt parser or a
proof checker. The mandatory compiler lane remains responsible for proof bodies.
Definitions, standard-library axioms and implementation correspondence still need
review; this gate catches added assumptions and removed/changed named claims.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE_NAMES = ("BindingViaCR.ec", "JRejectionCountermodel.ec")
NAME = r"[A-Za-z_][A-Za-z0-9_']*"


class ContractError(ValueError):
    """The source no longer matches the reviewed proof contract."""


def strip_comments(source: str) -> str:
    """Remove nested EasyCrypt comments without joining adjacent code tokens."""
    result: list[str] = []
    depth = 0
    index = 0
    while index < len(source):
        pair = source[index:index + 2]
        if pair == "(*":
            depth += 1
            result.append("  ")
            index += 2
        elif pair == "*)":
            if depth == 0:
                raise ContractError("unmatched comment terminator")
            depth -= 1
            result.append("  ")
            index += 2
        else:
            char = source[index]
            result.append(char if depth == 0 or char == "\n" else " ")
            index += 1
    if depth:
        raise ContractError("unterminated comment")
    return "".join(result)


def inventory(source: str) -> dict[str, object]:
    if len(source.encode("utf-8")) > 256 * 1024:
        raise ContractError("proof source exceeds inventory bound")
    code = strip_comments(source)
    if '"' in code:
        raise ContractError("string literals need explicit inventory-parser review")
    if re.search(r"\b(admit|sorry|abort|axiomatized|declare|clone|include)\b", code):
        raise ContractError("unreviewed assumption, dependency or proof escape")
    def normalize(value: str) -> str:
        return " ".join(value.split())

    imports = re.findall(r"(?m)^\s*(require\s+import\s+[^.]+\.)", code)
    if len(re.findall(r"\b(require|import)\b", code)) != 2 * len(imports):
        raise ContractError("unrecognized import syntax")
    result: dict[str, object] = {"imports": [normalize(value) for value in imports]}
    for keyword, ending in (("axiom", r"\.(?=\s*(?:\n|$))"),
                            ("lemma", r"\.\s*proof\.")):
        count = len(re.findall(rf"\b{keyword}\b", code))
        if count > 128:
            raise ContractError("too many proof declarations")
        pattern = rf"(?ms)^\s*({keyword}\s+({NAME})\b.*?)" + ending
        matches = list(re.finditer(pattern, code))
        if len(matches) != count:
            raise ContractError(f"unrecognized {keyword} declaration")
        declarations: dict[str, str] = {}
        for match in matches:
            name = match.group(2)
            if name in declarations:
                raise ContractError(f"duplicate {keyword}: {name}")
            declarations[name] = normalize(match.group(1)) + "."
        result[keyword + "s"] = declarations
    return result


def verify(sources: dict[str, str], contract: object) -> dict[str, int]:
    if not isinstance(contract, dict) or set(contract) != {"schema_version", "sources", "assumption_notes"}:
        raise ContractError("invalid proof contract schema")
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise ContractError("unsupported proof contract version")
    expected = contract["sources"]
    if not isinstance(expected, dict) or set(expected) != set(SOURCE_NAMES) or set(sources) != set(SOURCE_NAMES):
        raise ContractError("proof source set differs")
    if not isinstance(contract["assumption_notes"], dict):
        raise ContractError("missing assumption scope notes")
    counts = {"sources": len(sources), "axioms": 0, "lemmas": 0}
    for name in SOURCE_NAMES:
        actual = inventory(sources[name])
        if actual != expected[name]:
            raise ContractError(f"reviewed declarations differ: {name}")
        counts["axioms"] += len(actual["axioms"])
        counts["lemmas"] += len(actual["lemmas"])
    return counts


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate contract key: {key}")
        result[key] = value
    return result


def main() -> int:
    directory = ROOT / "formal" / "easycrypt"
    try:
        contract_path = directory / "BindingContract.json"
        if contract_path.stat().st_size > 128 * 1024:
            raise ContractError("proof contract exceeds bound")
        contract = json.loads(contract_path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_keys)
        sources = {}
        for name in SOURCE_NAMES:
            path = directory / name
            if path.stat().st_size > 256 * 1024:
                raise ContractError("proof source exceeds bound")
            sources[name] = path.read_text(encoding="utf-8")
        counts = verify(sources, contract)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"EASYCRYPT_BINDING_CONTRACT_FAIL: {error}")
        return 1
    print("EASYCRYPT_BINDING_CONTRACT_PASS " + json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
