"""Profile joins reject missing, unfinished, mixed-source and mislabeled runs."""
import argparse
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest

import continuity_package as package
import continuity_profiles as profiles

COMMIT = "a1" * 20
SOURCES = {"rust_workspace_sha256": "b2" * 32, "files": {"fixture.rs": "c3" * 32}}


def partition(consumer, profile):
    language, field = profiles.CONSUMERS[consumer]
    # These are deliberately small join-contract fixtures, not runtime evidence.
    scoped = {"completed": False, "partition_completed": True,
              "build_profiles": [profile], "release_claim_eligible": False}
    result = {
        "schema_version": 1, "kind": "qperiapt.continuity_candidate_package_partition",
        "completed": False, "partition_completed": True, "sources_unchanged": True,
        "source_commit": COMMIT, "source_inputs": copy.deepcopy(SOURCES),
        "build_profiles": [profile], "requested_consumers": ["Rust", "C", language],
        "host_os": "Darwin", "host_arch": "arm64", "publication_performed": False,
        "release_claim_eligible": False, "rust_report_sha256": "d4" * 32,
        "rustc": "rustc 1.98.1 (48a229cea 2026-09-01)\nbinary: rustc\n",
        "execution": {profile: {"fixture": "Rust"}},
        "c_consumer": dict(scoped, execution={profile: {"fixture": "C"}}),
        field: dict(scoped, profiles={profile: {"fixture": language}}),
    }
    if consumer == "swift":
        result["apple_package"] = {"completed": True}
        result[field]["minimum_root"] = {"completed": True}
    return result


class ProfileSelectionTests(unittest.TestCase):
    def test_only_canonical_nonempty_build_profiles_are_accepted(self):
        for selected in (("debug",), ("release",), ("debug", "release")):
            self.assertEqual(profiles.validate_profiles(selected), selected)
        for selected in ((), ("release", "debug"), ("debug", "debug"), ("debug", "unknown"),
                         ("unknown",), "debug", ["debug"], None):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                profiles.validate_profiles(selected)

    def test_partial_native_cannot_satisfy_a_full_or_different_foreign_request(self):
        native = partition("kotlin", "debug")["c_consumer"]
        profiles.require_native(native, ("debug",))
        full = native | {"completed": True, "build_profiles": list(profiles.PROFILES),
                         "execution": {p: {"fixture": "C"} for p in profiles.PROFILES}}
        profiles.require_native(full, profiles.PROFILES)
        for selected in (("release",), profiles.PROFILES):
            with self.subTest(selected=selected), self.assertRaisesRegex(ValueError, "profiles"):
                profiles.require_native(native, selected)
        for updates in ({"completed": True}, {"completed": 0}, {"partition_completed": False}, {"execution": {}},
                        {"execution": {"debug": {}}}, {"build_profiles": ["debug", "release"]}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                profiles.require_native(native | updates, ("debug",))

    def test_partition_flags_reject_omitted_or_multiple_foreign_consumers_before_io(self):
        base = dict(build_profile="debug", with_c_consumer=True, with_swift_consumer=False,
                    with_kotlin_consumer=True, with_android_jni_consumer=False, with_apple_package=False)
        for updates in ({"with_c_consumer": False}, {"with_kotlin_consumer": False},
                        {"with_android_jni_consumer": True}, {"with_apple_package": True},
                        {"with_kotlin_consumer": False, "with_swift_consumer": True}):
            with self.subTest(updates=updates), self.assertRaisesRegex(ValueError, "profile partition"):
                package.qualify(argparse.Namespace(**(base | updates)))

    def test_ci_preserves_all_six_profiles_and_requires_the_join_after_failures(self):
        workflow = (package.ROOT / ".github/workflows/ci.yml").read_text()
        def job(name):
            match = re.search(r"(?ms)^  " + re.escape(name) + r":\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)", workflow)
            self.assertIsNotNone(match, name)
            return match.group(1)
        producer = job("continuity-installed-swift")
        consumer_match = re.search(r"^        consumer: \[(.*?)\]$", producer, re.MULTILINE)
        profile_match = re.search(r"^        profile: \[(.*?)\]$", producer, re.MULTILINE)
        self.assertIsNotNone(consumer_match); self.assertIsNotNone(profile_match)
        self.assertEqual(consumer_match[1].split(", "), list(profiles.CONSUMERS))
        self.assertEqual(profile_match[1].split(", "), list(profiles.PROFILES))
        self.assertIn("      fail-fast: false\n", producer)
        self.assertIn("    timeout-minutes: 330\n", producer)
        self.assertIn('            --build-profile "$CONTINUITY_BUILD_PROFILE"', producer)
        self.assertIn("          CONTINUITY_BUILD_PROFILE: ${{ matrix.profile }}\n", producer)
        self.assertIn("          name: continuity-installed-${{ matrix.consumer }}-${{ matrix.profile }}\n", producer)
        join = job("continuity-installed-coverage")
        self.assertIn("    needs: continuity-installed-swift\n", join)
        self.assertIn("    if: ${{ !cancelled() }}\n", join)
        self.assertIn("          pattern: continuity-installed-*-*\n", join)
        self.assertIn("          merge-multiple: false\n", join)
        self.assertIn("artifact/continuity_profiles.py", join)
        self.assertIn('            --source-commit "$EXPECTED_COMMIT"', join)
        self.assertNotIn("continue-on-error:", producer + join)
        self.assertNotIn("|| true", producer + join)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for consumer in profiles.CONSUMERS:
            for profile in profiles.PROFILES:
                self.write(consumer, profile, partition(consumer, profile))

    def path(self, consumer="kotlin", profile="release"):
        return self.root / f"continuity-installed-{consumer}-{profile}" / "CONTINUITY_PACKAGE.json"

    def write(self, consumer, profile, value):
        path = self.path(consumer, profile)
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(value))

    def verify(self):
        return profiles.verify_partitions(self.root, source_commit=COMMIT, source_inputs=SOURCES)

    def test_complete_union_retains_each_report_identity_without_claiming_release(self):
        result = self.verify()
        self.assertTrue(result["completed"])
        self.assertFalse(result["release_claim_eligible"])
        self.assertEqual(result["build_profiles"], ["debug", "release"])
        self.assertEqual(len(result["partitions"]), 6)
        self.assertEqual(len({r["report_sha256"] for r in result["partitions"].values()}), 6)

    def test_missing_extra_or_duplicate_profile_is_rejected(self):
        removed = self.path()
        saved = removed.read_bytes()
        removed.unlink(); removed.parent.rmdir()
        with self.assertRaisesRegex(ValueError, "partition set"):
            self.verify()
        removed.parent.mkdir(); removed.write_bytes(saved)
        extra = self.root / "continuity-installed-kotlin-extra"
        extra.mkdir()
        with self.assertRaisesRegex(ValueError, "partition set"):
            self.verify()
        extra.rmdir()
        removed.write_bytes(self.path("kotlin", "debug").read_bytes())
        with self.assertRaisesRegex(ValueError, "profiles"):
            self.verify()

    def test_interrupted_or_success_shaped_partial_report_cannot_pass(self):
        original = partition("kotlin", "release")
        for patch in ({"partition_completed": False}, {"partition_completed": 1}, {"completed": True},
                      {"schema_version": True},
                      {"completed": 0}, {"sources_unchanged": False}, {"failure": "cancelled"},
                      {"release_claim_eligible": True}, {"publication_performed": True},
                      {"kind": "qperiapt.continuity_candidate_package"}):
            with self.subTest(patch=patch):
                self.write("kotlin", "release", original | patch)
                with self.assertRaisesRegex(ValueError, "unfinished|claim"):
                    self.verify()

    def test_source_archive_compiler_platform_and_language_substitution_is_rejected(self):
        original = partition("kotlin", "release")
        for patch in ({"source_commit": "00" * 20}, {"source_inputs": {}},
                      {"rust_report_sha256": "00" * 32}, {"rust_report_sha256": None},
                      {"rustc": "rustc 1.90.0\n"}, {"rustc": original["rustc"] + "different\n"},
                      {"host_arch": "x86_64"}, {"host_os": "Linux"},
                      {"requested_consumers": ["Rust", "C", "Swift"]},
                      {"swift_consumer": original["kotlin_consumer"]}):
            with self.subTest(patch=patch):
                self.write("kotlin", "release", original | patch)
                with self.assertRaises(ValueError): self.verify()

    def test_missing_native_foreign_or_profile_execution_is_rejected(self):
        original = partition("kotlin", "release")
        for field in ("execution", "c_consumer", "kotlin_consumer"):
            value = copy.deepcopy(original); del value[field]
            self.write("kotlin", "release", value)
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify()
        for field, key in (("c_consumer", "execution"), ("kotlin_consumer", "profiles")):
            for updates in ({"completed": True}, {"partition_completed": False}, {"build_profiles": ["debug"]}, {key: {}},
                            {key: {"debug": {"fixture": True}, "release": {"fixture": True}}}):
                value = copy.deepcopy(original); value[field].update(updates)
                self.write("kotlin", "release", value)
                with self.subTest(field=field, updates=updates), self.assertRaises(ValueError): self.verify()

    def test_swift_requires_apple_package_and_minimum_compiler(self):
        for field in ("apple_package", "minimum_root"):
            for completed in (False, None, 1):
                value = partition("swift", "debug")
                destination = value if field == "apple_package" else value["swift_consumer"]
                destination[field] = {"completed": completed}
                self.write("swift", "debug", value)
                with self.subTest(field=field, completed=completed), self.assertRaisesRegex(ValueError, "Swift"):
                    self.verify()

    def test_symlink_report_and_duplicate_json_keys_are_rejected(self):
        path = self.path(); original = path.read_bytes()
        path.unlink(); path.symlink_to(self.path("kotlin", "debug"))
        with self.assertRaises(ValueError): self.verify()
        path.unlink(); path.write_bytes(b'{"completed":false,' + original[1:])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
