"""The CBOM's row set against the backend declarations in `q-periapt-backends`.

`crates/q-periapt-cli` derives every CBOM row from a backend it names, so a
backend that is removed or renamed breaks that crate's build or its own guard,
`crates/q-periapt-cli/tests/cbom_inventory.rs`.  Neither catches the opposite
drift.  A backend *added* to `q-periapt-backends` still compiles, is simply
absent from the inventory, and appears in no hand-written list -- so nothing
fails and a released CBOM quietly omits an algorithm the suite ships.

This is the independent enumeration that does catch it.  It reads the backend
declarations out of the backends crate's own source and requires every one of
them to be accounted for by a CBOM row, or by a stated reason it needs none.  A
new backend fails here until the inventory answers for it.  The guard cannot
live in the CLI's own test file: that file ships to crates.io, where the sibling
crate's source is not on disk.

Caught:

* a backend the crate declares -- by a plain trait impl or through one of its
  declaration macros -- that no row accounts for, and a row whose backend is
  gone: the comparison runs in both directions;
* a backend that moves onto or off the off-by-default `slh-dsa` feature gate;
  the gate is read from the module declarations, not assumed;
* a declaration form this scan cannot read, and a source file no module
  declaration covers: both leave the table with an entry no declaration backs,
  which fails.

Not caught: a backend implemented in some other crate the CLI links, or emitted
by a procedural macro.  Nothing here reads outside this crate's own source.
"""

from __future__ import annotations

import pathlib
import re
import unittest

import package_bom


ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKENDS_SRC = ROOT / "crates" / "q-periapt-backends" / "src"
BACKENDS_LIB = BACKENDS_SRC / "lib.rs"
MAX_SOURCE_BYTES = 4 * 1024 * 1024

# Traits whose implementors are shipped cryptographic backends. A type that
# implements one of these is an algorithm the suite offers, so the CBOM owes it
# a row or a stated reason.
BACKEND_TRAITS = ("Kem", "Signer", "Verifier", "Xof256")

DEFAULT_GATE = "default"
SLH_DSA_GATE = "slh-dsa"

# Every backend the crate declares, the feature gate it sits behind, and the
# CBOM row(s) it accounts for. The left-hand side is read from the source by
# `declared_backends()`; this is the right-hand side, and the two must agree
# exactly.
BACKEND_CBOM_ROWS: dict[str, tuple[str, tuple[str, ...]]] = {
    "MlKem512": (DEFAULT_GATE, ("ML-KEM-512",)),
    "MlKem768": (DEFAULT_GATE, ("ML-KEM-768",)),
    "MlKem1024": (DEFAULT_GATE, ("ML-KEM-1024",)),
    # The same FIPS 203 parameter set behind the X-Wing seed key format
    # ("ML-KEM-768(seed-dk)"), so it is the ML-KEM-768 row rather than a further
    # asset. It is also where the suite's own SHAKE-256 use lives: it expands
    # the 32-byte seed into the FIPS 203 (d || z) key-generation seed.
    "MlKem768XWingSeed": (DEFAULT_GATE, ("ML-KEM-768", "SHAKE-256")),
    "X25519": (DEFAULT_GATE, ("X25519",)),
    "MlDsa44": (DEFAULT_GATE, ("ML-DSA-44",)),
    "MlDsa65": (DEFAULT_GATE, ("ML-DSA-65",)),
    "MlDsa87": (DEFAULT_GATE, ("ML-DSA-87",)),
    # The combiner sponge: `squeeze32` returns the SHA3-256 digest of the
    # transcript. It reports no algorithm identifier of its own, which is why
    # the CBOM writes that row's name out rather than deriving it.
    "Sha3_256Xof": (DEFAULT_GATE, ("SHA3-256",)),
    "SlhDsaSha2_128s": (SLH_DSA_GATE, ("SLH-DSA-SHA2-128s",)),
    "SlhDsaSha2_192s": (SLH_DSA_GATE, ("SLH-DSA-SHA2-192s",)),
    "SlhDsaSha2_256s": (SLH_DSA_GATE, ("SLH-DSA-SHA2-256s",)),
}

# The rows the `slh-dsa` feature adds, in the order the CLI emits them.
SLH_DSA_ROWS = frozenset(
    {"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s"}
)

MODULE_DECLARATION = re.compile(
    r"^(?:#\[cfg\((?P<cfg>[^\n]*)\)\]\n)?(?:pub\s+)?mod\s+(?P<name>\w+)\s*;",
    re.MULTILINE,
)
TRAIT_IMPLEMENTATION = re.compile(
    r"\bimpl\s+(?:" + "|".join(BACKEND_TRAITS) + r")\s+for\s+(\$?\w+)"
)
MACRO_DEFINITION = re.compile(r"\bmacro_rules!\s+(\w+)")
INCLUDE_DIRECTIVE = re.compile(r'\binclude!\(\s*"(?P<target>[^"\n]+)"\s*\)')
RAW_STRING_OPENER = re.compile(r'r(?P<hashes>#*)"')


class BackendInventoryError(AssertionError):
    """The backends crate's source cannot be enumerated as this guard requires."""


def rust_source_without_comments(source: str, *, mask_strings: bool = True) -> str:
    """Blank comments, and string literals unless asked to keep them.

    Offsets are preserved so a match's position still locates the declaration
    that produced it. Char literals are left alone: `&'static str` would
    otherwise read as an unterminated literal. `mask_strings=False` keeps the
    literals a `#[cfg(feature = "...")]` attribute is written with.
    """

    masked: list[str] = []
    cursor = 0
    length = len(source)
    while cursor < length:
        if source.startswith("//", cursor):
            end = source.find("\n", cursor)
            end = length if end == -1 else end
        elif source.startswith("/*", cursor):
            depth = 0
            end = cursor
            while end < length:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                    if depth == 0:
                        break
                else:
                    end += 1
            if depth != 0:
                raise BackendInventoryError("unterminated block comment in backend source")
        elif mask_strings and (
            opener := RAW_STRING_OPENER.match(source, cursor)
        ) is not None:
            terminator = '"' + opener.group("hashes")
            found = source.find(terminator, opener.end())
            if found == -1:
                raise BackendInventoryError("unterminated raw string in backend source")
            end = found + len(terminator)
        elif mask_strings and source[cursor] == '"':
            end = cursor + 1
            while end < length:
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == '"':
                    end += 1
                    break
                end += 1
            else:
                raise BackendInventoryError("unterminated string literal in backend source")
        else:
            masked.append(source[cursor])
            cursor += 1
            continue
        masked.extend(
            "\n" if character == "\n" else " " for character in source[cursor:end]
        )
        cursor = end
    return "".join(masked)


def read_source(path: pathlib.Path, *, mask_strings: bool = True) -> str:
    """Read one Rust source file with its comments blanked."""

    if path.is_symlink() or not path.is_file():
        raise BackendInventoryError(f"{path} is not a regular file")
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise BackendInventoryError(f"{path} exceeds the byte limit")
    return rust_source_without_comments(
        path.read_text(encoding="utf-8"), mask_strings=mask_strings
    )


def included_files(path: pathlib.Path) -> set[pathlib.Path]:
    """The sibling sources `path` pulls in with `include!`, which declare no
    module of their own."""

    included = set()
    for match in INCLUDE_DIRECTIVE.finditer(read_source(path, mask_strings=False)):
        target = (path.parent / match.group("target")).resolve()
        if target.parent != BACKENDS_SRC:
            raise BackendInventoryError(f"{path.name} includes a file outside the crate")
        included.add(target)
    return included


def module_gates() -> dict[pathlib.Path, str]:
    """Every source file that ships, mapped to the feature gate it sits behind.

    The gate is the module declaration's own `cfg`, so a backend that moves onto
    or off the `slh-dsa` feature moves with it. Test-only modules are dropped:
    they ship in no build. An unrecognised `cfg` is refused rather than guessed.

    Every `.rs` file in the crate must be reached, as a declared module or
    through an `include!` from one. A file reached by neither could declare a
    backend this guard would never see, so it is an error rather than an
    omission.
    """

    gates = {BACKENDS_LIB: DEFAULT_GATE}
    covered = {BACKENDS_LIB}
    for match in MODULE_DECLARATION.finditer(
        read_source(BACKENDS_LIB, mask_strings=False)
    ):
        path = BACKENDS_SRC / f"{match.group('name')}.rs"
        covered.add(path)
        cfg = (match.group("cfg") or "").strip()
        if "test" in cfg:
            continue
        if not cfg:
            gates[path] = DEFAULT_GATE
        elif cfg == 'feature = "slh-dsa"':
            gates[path] = SLH_DSA_GATE
        else:
            raise BackendInventoryError(
                f"module {match.group('name')} has an unrecognised gate: {cfg}"
            )
    pending = list(covered)
    while pending:
        for included in included_files(pending.pop()):
            if included not in covered:
                covered.add(included)
                pending.append(included)
    for path, gate in list(gates.items()):
        for included in included_files(path):
            gates.setdefault(included, gate)
    present = set(BACKENDS_SRC.glob("*.rs"))
    if present - covered:
        raise BackendInventoryError(
            "source files no module declaration or include! reaches: "
            f"{sorted(path.name for path in present - covered)}"
        )
    return gates


def declared_backends() -> dict[str, str]:
    """Every backend type the crate declares, mapped to its feature gate.

    Two declaration forms exist and both are read: a plain `impl <trait> for
    <type>`, and the crate's declaration macros, whose bodies implement the
    trait for a `$name` the invocations supply. Macro names are discovered from
    the bodies that implement a backend trait, so a *new* declaration macro is
    followed too.
    """

    backends: dict[str, str] = {}
    macros: dict[str, str] = {}
    gates = module_gates()
    sources = {path: read_source(path) for path in gates}
    for path, gate in gates.items():
        source = sources[path]
        for match in TRAIT_IMPLEMENTATION.finditer(source):
            name = match.group(1)
            if not name.startswith("$"):
                backends[name] = gate
                continue
            definitions = [
                definition
                for definition in MACRO_DEFINITION.finditer(source)
                if definition.start() < match.start()
            ]
            if not definitions:
                raise BackendInventoryError(
                    f"{path.name} implements a backend trait for {name} outside a macro"
                )
            macros[definitions[-1].group(1)] = gate
    for macro, gate in macros.items():
        invocation = re.compile(rf"^\s*{re.escape(macro)}!\(\s*(\w+)\s*,", re.MULTILINE)
        found = False
        for path, source in sources.items():
            for match in invocation.finditer(source):
                backends[match.group(1)] = gate
                found = True
        if not found:
            raise BackendInventoryError(f"macro {macro} declares a backend but is never invoked")
    if not macros or not backends:
        raise BackendInventoryError("the backend scan found nothing, so it proves nothing")
    return backends


class CbomBackendInventoryTests(unittest.TestCase):
    def test_every_declared_backend_is_accounted_for_by_the_inventory(self) -> None:
        declared = declared_backends()
        self.assertEqual(
            {name: gate for name, (gate, _) in BACKEND_CBOM_ROWS.items()},
            declared,
            "the backends crate and the CBOM inventory disagree about what ships: a "
            "backend added here needs a CBOM row in crates/q-periapt-cli/src/lib.rs "
            "and an entry above, or a stated reason it needs none",
        )

    def test_the_default_backends_produce_the_packaged_asset_inventory(self) -> None:
        rows = {
            row
            for gate, names in BACKEND_CBOM_ROWS.values()
            if gate == DEFAULT_GATE
            for row in names
        }
        self.assertEqual(package_bom.EXPECTED_CRYPTO_ASSETS, frozenset(rows))

    def test_the_feature_gated_backends_produce_exactly_the_slh_dsa_rows(self) -> None:
        rows = {
            row
            for gate, names in BACKEND_CBOM_ROWS.values()
            if gate == SLH_DSA_GATE
            for row in names
        }
        self.assertEqual(SLH_DSA_ROWS, frozenset(rows))
        self.assertEqual(frozenset(), SLH_DSA_ROWS & package_bom.EXPECTED_CRYPTO_ASSETS)

    def test_the_scan_reads_both_declaration_forms(self) -> None:
        # Non-vacuity: the plain-impl path and the macro path must each still
        # find something, or a silent parse failure would look like agreement.
        declared = declared_backends()
        self.assertIn("X25519", declared)
        self.assertIn("MlKem768", declared)
        self.assertEqual(SLH_DSA_GATE, declared["SlhDsaSha2_128s"])


if __name__ == "__main__":
    unittest.main()
