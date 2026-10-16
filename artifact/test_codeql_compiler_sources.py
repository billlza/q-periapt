from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from codeql_compiler_sources import collect_compiled_sources
from codeql_rust_quality import CodeQLRustQualityError


class CompilerSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name).resolve()
        self.root = base / "source"
        self.cwd = self.root / "crates" / "example"
        (self.cwd / "src").mkdir(parents=True)
        (self.cwd / "src/lib.rs").write_text("mod enabled;\n")
        (self.cwd / "src/enabled.rs").write_text("pub fn run() {}\n")
        (self.cwd / "src/inactive.rs").write_text("pub fn unused() {}\n")
        self.target = base / "build" / "debug" / "deps"
        self.target.mkdir(parents=True)
        self.depfile = self.target / "example-123.d"
        self.depfile.write_text("output.rmeta: src/lib.rs src/enabled.rs\n\nsrc/lib.rs:\n")
        self.tracked = {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in self.root.rglob("*.rs")}
        self.artifact = {"reason": "compiler-artifact",
                         "target": {"src_path": str(self.cwd / "src/lib.rs"), "kind": ["lib"]},
                         "filenames": [str(self.target / "libexample-123.rmeta")]}

    def events(self, *events: object) -> bytes:
        return b"".join(json.dumps(event).encode() + b"\n" for event in events)

    def collect(self, *events: object) -> dict[str, str]:
        return collect_compiled_sources(self.root, self.cwd, self.events(*events), self.tracked)

    def success(self) -> dict[str, str]:
        return self.collect(self.artifact, {"reason": "build-finished", "success": True})

    def test_actual_artifact_depfile_selects_enabled_sources(self) -> None:
        # A stale depfile is intentionally present in the same shared target dir.
        (self.target / "unrelated.d").write_text("out: src/inactive.rs\n")
        result = self.success()
        self.assertEqual(set(result), {"crates/example/src/lib.rs", "crates/example/src/enabled.rs"})

    def test_cargo_workspace_cwd_is_required_for_relative_dependencies(self) -> None:
        with self.assertRaisesRegex(CodeQLRustQualityError, "dependencies"):
            collect_compiled_sources(self.root, self.root,
                                     self.events(self.artifact, {"reason": "build-finished", "success": True}),
                                     self.tracked)

    def test_absolute_and_escaped_space_dependencies_are_retained(self) -> None:
        additional = self.cwd / "src/with space.rs"
        additional.write_text("pub fn spaces() {}\n")
        relative = additional.relative_to(self.root).as_posix()
        self.tracked[relative] = hashlib.sha256(additional.read_bytes()).hexdigest()
        escaped = str(additional).replace(" ", "\\ ")
        self.depfile.write_text(f"output.rmeta: {self.cwd / 'src/lib.rs'} \\\n {escaped}\n")
        self.assertEqual(set(self.success()), {"crates/example/src/lib.rs", relative})

    def test_source_change_after_compile_cannot_qualify(self) -> None:
        (self.cwd / "src/enabled.rs").write_text("pub fn changed() {}\n")
        with self.assertRaisesRegex(CodeQLRustQualityError, "source bytes differ"):
            self.success()

    def test_missing_depfile_does_not_fall_back_to_crate_root_only(self) -> None:
        self.depfile.unlink()
        with self.assertRaisesRegex(CodeQLRustQualityError, "depfile"):
            self.success()

    def test_wrong_crate_depfile_cannot_supply_active_sources(self) -> None:
        self.depfile.write_text("output.rmeta: src/inactive.rs src/enabled.rs\n")
        with self.assertRaisesRegex(CodeQLRustQualityError, "uniquely bind"):
            self.success()

    def test_failure_warning_and_truncated_stream_are_rejected(self) -> None:
        invalid = [
            [self.artifact],
            [self.artifact, {"reason": "build-finished", "success": False}],
            [self.artifact, {"reason": "compiler-message", "message": {"level": "warning"}},
             {"reason": "build-finished", "success": True}],
            [self.artifact, {"reason": "build-finished", "success": True},
             {"reason": "build-finished", "success": True}],
        ]
        for events in invalid:
            with self.subTest(events=events), self.assertRaises(CodeQLRustQualityError):
                self.collect(*events)

    def test_untracked_rust_dependency_is_not_silently_discarded(self) -> None:
        hidden = self.cwd / "src/untracked.rs"
        hidden.write_text("pub fn hidden() {}\n")
        self.depfile.write_text("out: src/lib.rs src/untracked.rs\n")
        with self.assertRaisesRegex(CodeQLRustQualityError, "untracked Rust source"):
            self.success()

    def test_build_script_depfile_is_bound_by_the_crate_source(self) -> None:
        self.artifact["target"]["kind"] = ["custom-build"]
        self.artifact["filenames"] = [str(self.target / "build-script-build")]
        self.assertEqual(len(self.success()), 2)


if __name__ == "__main__":
    unittest.main()
