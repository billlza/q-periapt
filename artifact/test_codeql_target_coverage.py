from __future__ import annotations

import dataclasses
import unittest

from codeql_rust_quality import CodeQLRustQualityError
from codeql_target_coverage import MacroCall, MacroProfile, parse_macro_calls, validate_macro_profiles


SOURCES = {"src/native.rs": "1" * 64, "src/web.rs": "2" * 64}


def call(path: str, expanded: bool, *, context: str = "code", line: int = 3) -> MacroCall:
    return MacroCall(path, line, 5, "format!...", expanded, context)


def profile(target: str, compiled: str, calls: list[MacroCall]) -> MacroProfile:
    return MacroProfile(target, dict(SOURCES), frozenset({compiled}), tuple(calls),
                        len(calls), sum(not item.expanded for item in calls))


def valid_pair() -> list[MacroProfile]:
    return [
        profile("native", "src/native.rs", [call("src/native.rs", True), call("src/web.rs", False)]),
        profile("wasm", "src/web.rs", [call("src/native.rs", False), call("src/web.rs", True)]),
    ]


class TargetMacroCoverageTests(unittest.TestCase):
    def test_disjoint_compilation_targets_account_for_every_macro(self) -> None:
        result = validate_macro_profiles(valid_pair())
        for target in ("native", "wasm"):
            self.assertEqual(result[target], {"expanded": 1, "compiler_export_metadata": 0,
                                               "inactive_with_compiled_peer": 1})

    def test_active_failure_is_not_hidden_by_successful_peer(self) -> None:
        # Both targets compile the same source; the second target expands it.
        native = profile("native", "src/native.rs", [call("src/native.rs", False)])
        wasm = profile("wasm", "src/native.rs", [call("src/native.rs", True)])
        with self.assertRaisesRegex(CodeQLRustQualityError, "active macro has no expansion"):
            validate_macro_profiles([native, wasm])

    def test_peer_expansion_without_actual_compilation_is_insufficient(self) -> None:
        pair = valid_pair()
        pair[1] = profile("wasm", "src/native.rs", [call("src/web.rs", True)])
        with self.assertRaisesRegex(CodeQLRustQualityError, "no compiled peer covers"):
            validate_macro_profiles(pair)

    def test_macro_missing_from_peer_remains_an_error(self) -> None:
        pair = valid_pair()
        pair[1] = profile("wasm", "src/web.rs", [call("src/native.rs", False)])
        with self.assertRaisesRegex(CodeQLRustQualityError, "no compiled peer covers"):
            validate_macro_profiles(pair)

    def test_uncompiled_context_cannot_qualify_itself_as_export_metadata(self) -> None:
        pair = [profile("native", "src/native.rs", [call("src/web.rs", False, context="export_name")]),
                profile("wasm", "src/native.rs", [call("src/web.rs", False, context="export_name")])]
        with self.assertRaisesRegex(CodeQLRustQualityError, "no compiled peer covers"):
            validate_macro_profiles(pair)

    def test_export_metadata_is_observed_separately_after_compilation(self) -> None:
        # The real compiler/CodeQL control has an unexpanded export-name value,
        # a correct exported symbol, and a complete parameter-to-return flow.
        pair = [profile("native", "src/native.rs", [call("src/native.rs", False, context="export_name")]),
                profile("wasm", "src/native.rs", [call("src/native.rs", False, context="export_name")])]
        result = validate_macro_profiles(pair)
        self.assertEqual(result["native"]["compiler_export_metadata"], 1)
        self.assertEqual(result["wasm"]["compiler_export_metadata"], 1)

    def test_attribute_context_cannot_cover_executable_macro_at_same_location(self) -> None:
        native = profile("native", "src/native.rs", [call("src/web.rs", False)])
        wasm = profile("wasm", "src/web.rs", [call("src/web.rs", False, context="export_name")])
        with self.assertRaisesRegex(CodeQLRustQualityError, "no compiled peer covers"):
            validate_macro_profiles([native, wasm])

    def test_duplicate_location_does_not_hide_an_unresolved_entity(self) -> None:
        pair = valid_pair()
        pair[1] = profile("wasm", "src/web.rs", [*pair[1].calls, call("src/web.rs", False)])
        with self.assertRaisesRegex(CodeQLRustQualityError, "active macro has no expansion"):
            validate_macro_profiles(pair)

    def test_all_source_bytes_must_match_even_for_files_without_calls(self) -> None:
        pair = valid_pair()
        changed = dict(SOURCES, **{"src/native.rs": "3" * 64})
        pair[1] = dataclasses.replace(pair[1], source_sha256=changed)
        with self.assertRaisesRegex(CodeQLRustQualityError, "same source bytes"):
            validate_macro_profiles(pair)

    def test_missing_or_duplicate_target_is_rejected(self) -> None:
        pair = valid_pair()
        for invalid in (pair[:1], [pair[0], pair[0]]):
            with self.subTest(profiles=len(invalid)), self.assertRaisesRegex(
                CodeQLRustQualityError, "distinct compilation targets"
            ):
                validate_macro_profiles(invalid)

    def test_missing_or_untracked_compiler_inputs_are_rejected(self) -> None:
        pair = valid_pair()
        for compiled in (frozenset(), frozenset({"elsewhere.rs"})):
            with self.subTest(compiled=compiled), self.assertRaisesRegex(
                CodeQLRustQualityError, "compiled source inventory"
            ):
                validate_macro_profiles([dataclasses.replace(pair[0], compiled_sources=compiled), pair[1]])

    def test_metrics_cannot_omit_entities_or_unresolved_calls(self) -> None:
        pair = valid_pair()
        for changes in ({"source_macro_count": 1}, {"source_macro_count": True},
                        {"unresolved_macro_count": 0}, {"unresolved_macro_count": True}):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                CodeQLRustQualityError, "count differs"
            ):
                validate_macro_profiles([dataclasses.replace(pair[0], **changes), pair[1]])

    def test_macro_census_preserves_distinct_entities_at_identical_locations(self) -> None:
        row = ["src/native.rs", 3, 5, "format!...", "expanded", "code", {"label": "format!..."}]
        self.assertEqual(len(parse_macro_calls([row, row])), 2)

    def test_malformed_locations_contexts_and_entity_labels_are_rejected(self) -> None:
        row = ["src/native.rs", 3, 5, "format!...", "expanded", "code", {"label": "format!..."}]
        for index, value in ((0, "../escape.rs"), (0, "/absolute.rs"), (1, True), (2, 0),
                             (3, ""), (4, "unknown"), (5, "safe"), (6, {"label": "other"})):
            changed = list(row); changed[index] = value
            with self.subTest(index=index, value=value), self.assertRaises(CodeQLRustQualityError):
                parse_macro_calls([changed])


if __name__ == "__main__":
    unittest.main()
