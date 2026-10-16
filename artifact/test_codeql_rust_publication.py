from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import codeql_rust_publication as publication
import codeql_rust_quality as quality
from codeql_target_coverage import validate_macro_profiles
from test_codeql_rust_profile import sarif


class RustPublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "source"
        (self.root / "src").mkdir(parents=True)
        self.sources = {}
        for name in ("native", "web"):
            path = self.root / "src" / (name + ".rs")
            path.write_text("pub fn operation() {}\n")
            self.sources[path.relative_to(self.root).as_posix()] = self.digest(path)
        self.artifacts = self.base / "artifacts"
        self.artifacts.mkdir()
        original = Path(__file__).resolve().parent
        shutil.copytree(original / "codeql-rust-quality", self.root / "artifact/codeql-rust-quality")
        shutil.copyfile(original / "codeql_rust_queries.json", self.root / "artifact/codeql_rust_queries.json")
        self.inventory = self.read(self.root / "artifact/codeql_rust_queries.json")["queries"]
        self.paths = {}
        for name, own, other in (("native", "native", "web"), ("wasm", "web", "native")):
            directory = self.artifacts / ("codeql-rust-profile-" + name + "-1")
            directory.mkdir()
            metrics = {key: 0 for key in quality.EXPECTED_METRICS}
            metrics.update(extracted_files=2, successfully_extracted_files=2,
                           source_macro_calls=2, unresolved_source_macro_calls=1, source_format_args=1)
            rows = [[f"src/{own}.rs", 3, 5, "format!...", "expanded", "code", {"label": "format!..."}],
                    [f"src/{other}.rs", 3, 5, "format!...", "unresolved", "code", {"label": "format!..."}]]
            self.write(directory / "MacroCalls.json", rows)
            self.write(directory / "ExtractedPaths.json", [[path] for path in sorted(self.sources)])
            self.write(directory / "Metrics.json", list(map(list, metrics.items())))
            self.write(directory / "QUERY_INVENTORY.json", self.inventory)
            self.write(directory / "results.sarif", sarif(name))
            profile = {"schema": 1, "profile": name, "target": publication.TARGETS[name],
                       "source_commit": "a" * 40, "run_id": "123", "run_attempt": "1",
                       "codeql_version": publication.VERSION, "compiler": publication.COMPILER,
                       "source_sha256": self.sources, "compiled_sources": {f"src/{own}.rs": self.sources[f"src/{own}.rs"]},
                       "metrics": metrics, "macro_census_sha256": self.digest(directory / "MacroCalls.json"),
                       "extracted_paths_sha256": self.digest(directory / "ExtractedPaths.json"),
                       "quality_queries_sha256": {p.name: self.digest(p) for p in (self.root / "artifact/codeql-rust-quality").glob("*.ql")},
                       "quality_pack_sha256": self.digest(self.root / "artifact/codeql-rust-quality/qlpack.yml"),
                       "quality_lock_sha256": self.digest(self.root / "artifact/codeql-rust-quality/codeql-pack.lock.yml"),
                       "active_target_quality_passed": True, "paired_target_quality_passed": False}
            self.write(directory / "PROFILE.json", profile)
            self.write(directory / "ANALYSIS.json", {"completed": True, "codeql_version": publication.VERSION,
                       "query_pack": publication.QUERY_VERSION, "upload_performed": False,
                       "profile_sha256": self.digest(directory / "PROFILE.json"),
                       "query_inventory_sha256": self.digest(directory / "QUERY_INVENTORY.json"),
                       "query_result_sha256": {path: "b" * 64 for path in self.inventory},
                       "sarif_sha256": self.digest(directory / "results.sarif")})
            self.paths[name] = directory
        patch = mock.patch.object(quality, "tracked_rust_paths", return_value=frozenset(self.sources))
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def read(path):
        return json.loads(path.read_text())

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value))

    def validate(self, name):
        return publication.validate_profile_artifact(self.paths[name], name, self.root, "a" * 40, "123", 1)

    def rebind_profile(self, name, value):
        directory = self.paths[name]
        self.write(directory / "PROFILE.json", value)
        analysis = self.read(directory / "ANALYSIS.json")
        analysis["profile_sha256"] = self.digest(directory / "PROFILE.json")
        self.write(directory / "ANALYSIS.json", analysis)

    def test_both_completed_profiles_are_required(self) -> None:
        selected = publication.latest_profile_directories(self.artifacts, 1)
        self.assertEqual(selected, self.paths)
        result = validate_macro_profiles([self.validate("native"), self.validate("wasm")])
        self.assertEqual(result[publication.TARGETS["native"]]["inactive_with_compiled_peer"], 1)
        shutil.rmtree(self.paths["wasm"])
        with self.assertRaisesRegex(ValueError, "both native and WASM"):
            publication.latest_profile_directories(self.artifacts, 1)

    def test_latest_failed_attempt_cannot_fall_back_to_old_success(self) -> None:
        newer = self.artifacts / "codeql-rust-profile-native-2"
        newer.mkdir()
        selected = publication.latest_profile_directories(self.artifacts, 2)
        self.assertEqual(selected["native"], newer)
        with self.assertRaises(ValueError):
            publication.validate_profile_artifact(newer, "native", self.root, "a" * 40, "123", 2)

    def test_future_attempt_is_rejected(self) -> None:
        (self.artifacts / "codeql-rust-profile-native-2").mkdir()
        with self.assertRaisesRegex(ValueError, "future"):
            publication.latest_profile_directories(self.artifacts, 1)

    def test_run_source_tool_and_compiler_identity_are_bound(self) -> None:
        original = self.read(self.paths["native"] / "PROFILE.json")
        for key, value in (("run_id", "124"), ("source_commit", "b" * 40),
                           ("compiler", "1.97.0"), ("target", publication.TARGETS["wasm"])):
            changed = dict(original); changed[key] = value
            self.rebind_profile("native", changed)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate("native")
        self.rebind_profile("native", original)

    def test_changed_source_is_rejected(self) -> None:
        (self.root / "src/native.rs").write_text("changed source\n")
        with self.assertRaisesRegex(ValueError, "source bytes"):
            self.validate("native")

    def test_changed_quality_query_is_rejected(self) -> None:
        (self.root / "artifact/codeql-rust-quality/MacroCalls.ql").write_text("changed query\n")
        with self.assertRaisesRegex(ValueError, "quality query bytes"):
            self.validate("native")

    def test_sarif_corruption_or_query_result_omission_is_rejected(self) -> None:
        directory = self.paths["native"]
        analysis = self.read(directory / "ANALYSIS.json")
        del analysis["query_result_sha256"]["queries/summary/SummaryStats.ql"]
        self.write(directory / "ANALYSIS.json", analysis)
        with self.assertRaisesRegex(ValueError, "census is incomplete"):
            self.validate("native")
        analysis["query_result_sha256"]["queries/summary/SummaryStats.ql"] = "b" * 64
        self.write(directory / "ANALYSIS.json", analysis)
        (directory / "results.sarif").write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "SARIF differs"):
            self.validate("native")

    def test_completed_marker_cannot_override_active_macro_failure(self) -> None:
        directory = self.paths["native"]
        rows = self.read(directory / "MacroCalls.json")
        rows[0][4] = "unresolved"
        self.write(directory / "MacroCalls.json", rows)
        profile = self.read(directory / "PROFILE.json")
        profile["metrics"]["unresolved_source_macro_calls"] = 2
        self.write(directory / "Metrics.json", list(map(list, profile["metrics"].items())))
        profile["macro_census_sha256"] = self.digest(directory / "MacroCalls.json")
        self.rebind_profile("native", profile)
        with self.assertRaisesRegex(ValueError, "active macro has no expansion"):
            self.validate("native")

    def test_stale_compiled_source_hash_is_rejected(self) -> None:
        profile = self.read(self.paths["native"] / "PROFILE.json")
        profile["compiled_sources"]["src/native.rs"] = "f" * 64
        self.rebind_profile("native", profile)
        with self.assertRaisesRegex(ValueError, "compiler source identity"):
            self.validate("native")


if __name__ == "__main__":
    unittest.main()
