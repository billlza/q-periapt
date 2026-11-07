"""Complete declaration and compiled-layout checks for the unpublished C owner.

The snapshot is an explicit review surface, not a product-admission receipt.
Whitespace and comments are immaterial; all other header tokens are retained.
Actual C and Rust compilers independently supply the target's record layouts.
"""
from __future__ import annotations

from pathlib import Path
import re

from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk

CONTRACT = "abi/qpc-owner-v1.json"
TEST = "abi_contract::declared_c_types_match_native_owners"
PREFIX = "QPC_ABI "
NATIVE_PREFIX = "QPC_ABI_NATIVE "
FUNCTION_PREFIX = "QPC_ABI_FUNCTION "
DIRECTIVES = ["#ifndef QPC_OWNER_V1_H", "#define QPC_OWNER_V1_H",
              "#include <stddef.h>", "#include <stdint.h>",
              "#ifdef __cplusplus", "#endif", "#ifdef __cplusplus", "#endif", "#endif"]


def declarations(header: str) -> list[str]:
    """Admit this closed header grammar; do not silently strip attributes/macros."""
    sdk.require(type(header) is str and len(header) <= 128 * 1024,
                "C ABI header is not bounded text")
    text = re.sub(r"/\*.*?\*/|//[^\n]*", " ", header, flags=re.S)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    sdk.require([line for line in lines if line.startswith("#")] == DIRECTIVES,
                "C ABI header preprocessing differs")
    text = "\n".join(line for line in lines if not line.startswith("#"))
    sdk.require(text.count('extern "C" {') == 1
                and re.search(r"\n}\s*$", text) is not None,
                "C ABI language-linkage wrapper differs")
    text = text.replace('extern "C" {', "", 1)
    text = re.sub(r"\n}\s*$", "", text)
    tokens = re.findall(r"[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[{}()\[\]*,;=]", text)
    sdk.require("".join(tokens) == re.sub(r"\s+", "", text),
                "C ABI header contains an unsupported token")
    rows, current, depth = [], [], 0
    for token in tokens:
        current.append(token)
        depth += (token == "{") - (token == "}")
        sdk.require(depth in (0, 1), "C ABI declaration nesting differs")
        if token == ";" and depth == 0:
            rows.append(" ".join(current))
            current = []
    sdk.require(not current and depth == 0 and rows, "C ABI header is incomplete")
    return rows


def record_fields(declaration: str) -> tuple[str, list[str]]:
    match = re.fullmatch(r"typedef struct \{ (.+) \} (qpc_[a-z0-9_]+) ;", declaration)
    sdk.require(match is not None, "C ABI record declaration differs")
    fields = []
    for item in match[1].split(" ; "):
        item = item.removesuffix(" ;")
        declared = re.fullmatch(r"(?:const )?(?:u?int(?:8|16|32|64)_t|size_t|qpc_[a-z0-9_]+) (.+)", item)
        sdk.require(declared is not None, "C ABI record field type differs")
        for part in declared[1].split(" , "):
            name = re.fullmatch(r"(?:\* )?([a-z][a-z0-9_]*)(?: \[ [0-9]+ \])?", part)
            sdk.require(name is not None, "C ABI record field shape differs")
            fields.append(name[1])
    sdk.require(len(set(fields)) == len(fields) and fields, "C ABI duplicate or empty fields")
    return match[2], fields


def declared_type(declaration: str, constants: dict, *, parameter: bool) -> str:
    match = re.fullmatch(r"(const )?(u?int(?:8|16|32|64)_t|size_t|void|qpc_[a-z0-9_]+) (\* )?[a-z][a-z0-9_]*(?: \[ ([0-9]+|QPC_[A-Z0-9_]+) \])?", declaration)
    sdk.require(match is not None, "C ABI type is outside the reviewed grammar")
    const, base, pointer, extent = match.groups()
    sdk.require(not (pointer and extent) and (not const or pointer or extent)
                and (base != "void" or pointer), "C ABI declarator shape differs")
    if base == "size_t":
        base = "usize"
    elif base == "void":
        base = "core::ffi::c_void"
    elif base.endswith("_t"):
        base = ("u" if base.startswith("u") else "i") + re.search(r"[0-9]+", base)[0]
    if extent:
        value = int(extent) if extent.isdigit() else constants.get(extent)
        sdk.require(type(value) is int and 0 < value <= 1024 * 1024, "C ABI array extent differs")
        base = f"[{base};{value}]"
    if pointer or (parameter and extent):
        base = ("*const" if const else "*mut") + base
    return base


def load(consumer: Path) -> dict:
    data = sdk.snapshot(consumer / CONTRACT, maximum=256 * 1024).data
    document = parse_strict_json_bytes(data, label="Continuity C ABI review snapshot")
    sdk.require(type(document) is dict and set(document) == {
        "schema_version", "abi", "package_version", "frozen_product_contract", "declarations"},
        "C ABI snapshot fields differ")
    sdk.require(type(document["schema_version"]) is int and document["schema_version"] == 1
                and document["abi"] == "qpc-owner/1" and document["package_version"] == "0.0.0"
                and document["frozen_product_contract"] is False,
                "C ABI snapshot identity or admission claim differs")
    expected = document["declarations"]
    sdk.require(type(expected) is list and expected
                and all(type(row) is str for row in expected), "C ABI declarations differ")
    observed = declarations(sdk.snapshot(consumer / "qpc_owner.h", maximum=128 * 1024).data.decode())
    sdk.require(observed == expected, "C ABI header differs from the reviewed declaration snapshot")
    records, functions, callbacks, constants, record_declarations = {}, {}, {}, {}, {}
    for row in expected:
        if row.startswith("typedef struct "):
            name, fields = record_fields(row)
            sdk.require(name not in records, "C ABI duplicate record")
            records[name] = fields
            record_declarations[name] = row
        elif match := re.fullmatch(r"int32_t (qpc_[a-z0-9_]+) \( (.+) \) ;", row):
            sdk.require(match[1] not in functions, "C ABI duplicate function")
            functions[match[1]] = match[2]
        elif match := re.fullmatch(r"typedef int32_t \( \* (qpc_[a-z0-9_]+) \) \( (.+) \) ;", row):
            sdk.require(match[1] not in callbacks, "C ABI duplicate callback")
            callbacks[match[1]] = match[2]
        elif match := re.fullmatch(r"enum \{ (.+) \} ;", row):
            for item in match[1].split(" , "):
                value = re.fullmatch(r"(QPC_[A-Z0-9_]+) = ([0-9]+)", item)
                sdk.require(value is not None and value[1] not in constants,
                            "C ABI constant declaration differs")
                constants[value[1]] = int(value[2])
        else:
            raise ValueError("C ABI declaration is outside the reviewed grammar")
    from continuity_c_consumer import EXPORTS
    sdk.require(set(functions) == EXPORTS, "C ABI declarations and export census differ")
    sdk.require(set(callbacks) == {"qpc_commit_v1"}, "C ABI callback set differs")
    field_types = {}
    for name, row in record_declarations.items():
        types = []
        for item in row.split("{ ", 1)[1].rsplit(" }", 1)[0].split(" ; "):
            field = re.fullmatch(r"((?:const )?\w+) (.+)", item.removesuffix(" ;"))
            sdk.require(field is not None, "C ABI record field differs")
            types.extend(declared_type(field[1] + " " + part, constants, parameter=False)
                         for part in field[2].split(" , "))
        field_types[name] = dict(zip(records[name], types, strict=True))
    signatures = {name: ["i32", *(declared_type(part, constants, parameter=True)
                                  for part in arguments.split(" , "))]
                  for name, arguments in (functions | callbacks).items()}
    return {"records": records, "functions": functions, "callbacks": callbacks,
            "constants": constants, "field_types": field_types, "signatures": signatures}


def c_probe(contract: dict) -> bytes:
    lines = ['/* SPDX-License-Identifier: Apache-2.0 OR MIT */',
             '#include "qpc_owner.h"', '#include <stdio.h>']
    # Volatile loads retain every address relocation even under optimization;
    # this checks actual linkage without invoking any lifecycle operation.
    for name, arguments in contract["functions"].items():
        lines.append(f"static int32_t (*volatile probe_{name})({arguments}) = {name};")
    lines.append("int main(void) {")
    for name in contract["functions"]:
        lines.append(f"    if (probe_{name} == NULL) return 1;")
    lines.append('    printf("QPC_ABI target %zu %zu\\n", sizeof(size_t), _Alignof(size_t));')
    for name, signature in contract["signatures"].items():
        lines.append(f'    puts("QPC_ABI_FUNCTION {name} {" ".join(signature)}");')
    for name in contract["callbacks"]:
        lines.append(f'    printf("QPC_ABI {name} %zu %zu\\n", sizeof({name}), _Alignof({name}));')
    for name, fields in contract["records"].items():
        lines.append(f'    printf("QPC_ABI {name} %zu %zu", sizeof({name}), _Alignof({name}));')
        for field in fields:
            kind = contract["field_types"][name][field]
            lines.append(f'    printf(" {field}:%zu:%zu:{kind}", offsetof({name}, {field}), sizeof((({name} *)0)->{field}));')
        lines.append('    putchar(\'\\n\');')
    lines.extend(["    return 0;", "}", ""])
    return "\n".join(lines).encode()


def layouts(stdout: bytes, contract: dict, *, rust: bool) -> dict:
    sdk.require(len(stdout) <= 1024 * 1024, "C ABI probe output exceeds its bound")
    text = stdout.decode("ascii")
    if rust:
        # The libtest progress prefix shares its line with the first print.
        identity = f"test {TEST} ... "
        sdk.require(text.count(identity) == 1, "Rust ABI test identity is absent or duplicated")
        text = text.replace(identity, "", 1)
        lines = [line for line in text.splitlines() if line]
        sdk.require(len(lines) >= 4 and lines[0] == "running 1 test" and lines[-2] == "ok"
                    and re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s", lines[-1]),
                    "Rust ABI contract did not execute exactly one completed test")
        lines = lines[1:-2]
    else:
        lines = text.splitlines()
        sdk.require(text.endswith("\n"), "C ABI probe output is incomplete")
    result, native_types, signatures = {}, {}, {}
    for line in lines:
        parts = line.split()
        if line.startswith(NATIVE_PREFIX):
            sdk.require(rust and len(parts) == 3 and parts[1] not in native_types,
                        "C ABI native type inventory is duplicated or unexpected")
            native_types[parts[1]] = parts[2]
            continue
        if line.startswith(FUNCTION_PREFIX):
            sdk.require(len(parts) >= 4 and parts[1] not in signatures
                        and parts[1] in contract["signatures"]
                        and len(parts[2:]) == len(contract["signatures"][parts[1]]),
                        "C ABI signature inventory differs")
            signatures[parts[1]] = parts[2:]
            continue
        sdk.require(line.startswith(PREFIX), "C ABI probe has unexpected output")
        sdk.require(len(parts) >= 4 and parts[1] not in result
                    and all(re.fullmatch(r"[1-9][0-9]*", p) for p in parts[2:4]),
                    "C ABI layout identity, size or alignment differs")
        name, size, alignment = parts[1], int(parts[2]), int(parts[3])
        sdk.require(size <= 1024 * 1024 and alignment <= 16 and alignment & (alignment - 1) == 0
                    and size % alignment == 0, "C ABI layout exceeds its shape bounds")
        fields = {}
        for part in parts[4:]:
            match = re.fullmatch(r"([a-z][a-z0-9_]*):([0-9]+):([1-9][0-9]*):(.+)", part)
            sdk.require(match is not None and match[1] not in fields, "C ABI duplicate or malformed layout field")
            offset, width = int(match[2]), int(match[3])
            sdk.require(offset + width <= size, "C ABI field exceeds its record")
            sdk.require(not fields or offset >= max(row["offset"] + row["bytes"] for row in fields.values()),
                        "C ABI fields overlap or are out of order")
            fields[match[1]] = {"offset": offset, "bytes": width, "type": match[4]}
        sdk.require(list(fields) == contract["records"].get(name, []), "C ABI field inventory or order differs")
        result[name] = {"bytes": size, "alignment": alignment, "fields": fields}
    sdk.require(set(result) == {"target", *contract["callbacks"], *contract["records"]},
                "C ABI compiled layout inventory is incomplete or unexpected")
    sdk.require(result["target"]["bytes"] in (4, 8), "C ABI target width differs")
    sdk.require(set(signatures) == set(contract["signatures"]), "C ABI function signatures are incomplete")
    sdk.require(set(native_types) == ({*contract["records"], *contract["callbacks"]} if rust else set()),
                "C ABI native record identities are incomplete")
    return {"layouts": result, "native_types": native_types, "signatures": signatures}


def compare(c: dict, native: dict, contract: dict) -> None:
    def translate(kind):
        return re.sub(r"qpc_[a-z0-9_]+", lambda match: native["native_types"][match[0]], kind)
    for name, row in c["layouts"].items():
        other = native["layouts"][name]
        sdk.require((row["bytes"], row["alignment"]) == (other["bytes"], other["alignment"]),
                    "C and Rust compiled owner ABI layouts differ")
        for field, value in row["fields"].items():
            sdk.require(value["type"] == contract["field_types"][name][field],
                        "C compiled field type descriptor differs from its declaration")
            sdk.require(dict(value, type=translate(value["type"])) == other["fields"][field],
                        f"C and Rust compiled field types or layouts differ: {name}.{field}")
    sdk.require(c["signatures"] == contract["signatures"], "C compiled signature descriptor differs from its declaration")
    for name, signature in c["signatures"].items():
        for c_type, rust_type in zip(signature, native["signatures"][name], strict=True):
            expected = translate(c_type)
            # A C parameter array decays to a pointer. Preserve exact extents
            # when Rust also uses a pointer-to-array; never erase a mismatched one.
            array = re.fullmatch(r"(\*(?:const|mut))\[([^\[\]]+);[0-9]+\]", expected)
            sdk.require(expected == rust_type or (array is not None and array[1] + array[2] == rust_type),
                        f"C and Rust compiled function or callback types differ: {name}")


def qualify(consumer: Path, installed: Path, cc: Path, platform_flags: list[str],
            profile: str, unit_test: Path, run, *, darwin: bool, runtime: dict,
            filename: str) -> dict:
    from continuity_c_consumer import verify_linkage
    contract = load(consumer)
    source = installed / "qpc-abi-contract.c"
    with source.open("xb") as stream:
        stream.write(c_probe(contract))
    executable = installed / "qpc-abi-contract"
    run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         *(["-O2"] if profile == "release" else ["-O0", "-g"]), str(source), "-I", str(consumer),
         "-L", str(installed), "-lq_periapt_continuity_c_consumer",
         "-Wl,-rpath," + ("@loader_path" if darwin else "$ORIGIN"), "-o", str(executable)],
        "abi-contract-compile-" + profile)
    if darwin:
        dependencies = run(["/usr/bin/otool", "-L", str(executable)], "abi-contract-dependencies-" + profile).decode()
        loader = run(["/usr/bin/otool", "-l", str(executable)], "abi-contract-loader-" + profile).decode()
    else:
        dependencies = run(["/usr/bin/readelf", "-d", str(executable)], "abi-contract-dependencies-" + profile).decode()
        loader = dependencies
    verify_linkage(dependencies, loader, filename, darwin=darwin)
    files = {"executable": executable, "library": installed / filename,
             "rust_test": unit_test, "header": consumer / "qpc_owner.h",
             "contract": consumer / CONTRACT, "probe": source}
    before = {name: sdk.snapshot(path, maximum=256 * 1024**2).sha256 for name, path in files.items()}
    c = layouts(run([str(executable)], "abi-contract-c-" + profile, runtime=runtime), contract, rust=False)
    native = layouts(run([str(unit_test), "--exact", TEST, "--nocapture", "--test-threads=1"],
                         "abi-contract-rust-" + profile, runtime=runtime), contract, rust=True)
    compare(c, native, contract)
    sdk.require(before == {name: sdk.snapshot(path, maximum=256 * 1024**2).sha256 for name, path in files.items()},
                "C ABI qualification inputs changed")
    return {"completed": True, "abi": "qpc-owner/1", "identities": before,
            "exports": len(contract["functions"]), "records": len(contract["records"]),
            "callbacks": len(contract["callbacks"]), "constants": len(contract["constants"]),
            "layouts": c["layouts"], "signatures": c["signatures"], "native_types": native["native_types"],
            "frozen_product_contract": False, "release_claim_eligible": False,
            "scope": "installed shared-library linkage and same-source native C/Rust type and layout agreement; not lifecycle or product ABI 2 admission"}
