"""Keep candidate authority isolated except for the explicit private browser owner."""

import json
from pathlib import Path
import tomllib
import unittest

from artifact.bounded_process import capture_output
from rust_sdk_profile import classify, validate_browser_candidate_dependency

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "research/continuity-identity-candidate"
NAME = "q-periapt-continuity-identity-candidate"


def metadata(manifest: Path) -> dict:
    result = capture_output(
        ["cargo", "metadata", "--manifest-path", str(manifest), "--locked",
         "--format-version", "1", "--no-deps"],
        timeout_seconds=60, maximum_stdout_bytes=1024 * 1024,
        maximum_stderr_bytes=65536,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode())
    return json.loads(result.stdout)


class ContinuityIdentityIsolationTests(unittest.TestCase):
    def test_candidate_has_a_separate_unpublished_workspace_and_lock(self):
        candidate = metadata(CANDIDATE / "Cargo.toml")
        self.assertEqual(Path(candidate["workspace_root"]), CANDIDATE)
        self.assertEqual(len(candidate["workspace_members"]), 1)
        package, = candidate["packages"]
        self.assertEqual(package["name"], NAME)
        self.assertEqual(package["publish"], [])
        self.assertNotIn("q-periapt-continuity-model", {
            dependency["name"] for dependency in package["dependencies"]
        })
        for dependency in package["dependencies"]:
            if dependency["name"].startswith("q-periapt"):
                self.assertEqual(dependency["req"], "=0.2.0")
        lock = tomllib.loads((CANDIDATE / "Cargo.lock").read_text())
        self.assertIn(NAME, {package["name"] for package in lock["package"]})

    def test_only_the_private_browser_owner_can_compose_candidate_authority(self):
        sdk = metadata(ROOT / "Cargo.toml")
        classify(sdk)
        edges = []
        for package in sdk["packages"]:
            self.assertNotEqual(package["name"], NAME)
            for dependency in package["dependencies"]:
                if dependency["name"] == NAME:
                    validate_browser_candidate_dependency(package["name"], dependency)
                    self.assertEqual(package["publish"], [])
                    self.assertEqual(package["features"], {"browser-continuity": [
                        "dep:q-periapt-continuity-identity-candidate", "dep:wasm-bindgen-futures",
                    ]})
                    edges.append(package["name"])
                    continue
                if dependency.get("path"):
                    self.assertNotEqual(Path(dependency["path"]).resolve(), CANDIDATE)
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        self.assertEqual(edges, ["q-periapt-sdk-wasm"])
        candidate, = [package for package in lock["package"] if package["name"] == NAME]
        self.assertEqual(candidate["version"], "0.0.0")
        self.assertNotIn("source", candidate)
        self.assertNotIn("checksum", candidate)


if __name__ == "__main__":
    unittest.main(warnings="error")
