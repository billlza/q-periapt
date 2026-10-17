"""Transport boundary tests; native SDK execution is the separate CI gate."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import android_sdk_runtime_replay as replay
from android_agp_consumer_contract import AndroidAgpConsumerError, SDK_PROFILES, export_file_names, flat_sdk_export_files
from evidence_io import EvidenceIOError


class AndroidSdkRuntimeReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "target").mkdir()
        patch = mock.patch.object(replay, "ROOT", self.root)
        patch.start()
        self.addCleanup(patch.stop)
        self.runs = self.root / "target/qperiapt-android-device-smoke-runs"
        self.arguments = dict(runtime_profile="api35-16k", sdk=self.root / "sdk",
                              source_commit="1" * 40, aar_sha256="2" * 64,
                              manifest_sha256="3" * 64)

    def exports(self) -> dict[str, Path]:
        result = {}
        for number, profile in enumerate(sorted(SDK_PROFILES), 1):
            run_id = f"{number:032x}"
            directory = self.runs / run_id / "proof/agp-evidence"
            for relative in export_file_names("emulator", profile):
                path = directory / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                data = (profile + ":" + relative).encode()
                if relative == "proof.json":
                    data = json.dumps({"run_id": run_id, "consumer": {"profile": profile}}).encode()
                path.write_bytes(data)
                path.chmod(0o644)
            result[profile] = directory
        return result

    def test_stage_checks_restored_bytes_and_all_independent_pins(self) -> None:
        original = self.exports()

        def verify(root: Path, directory: Path, **expected: object) -> dict:
            profile = expected["expected_profile"]
            self.assertEqual(root, self.root)
            self.assertNotEqual(directory, original[profile])
            self.assertEqual(expected, dict(expected_profile=profile,
                expected_source_commit="1" * 40, expected_aar_sha256="2" * 64,
                expected_aar_manifest_sha256="3" * 64, sdk=self.root / "sdk",
                expected_device_abi="x86_64", expected_runtime_profile="api35-16k"))
            for relative in export_file_names("emulator", profile):
                self.assertEqual((directory / relative).read_bytes(), (original[profile] / relative).read_bytes())
            return {"profile": profile}

        with mock.patch.object(replay, "verify_exported_profile", side_effect=verify) as verifier:
            result = replay.run("stage", **self.arguments)
        self.assertTrue(result["completed"])
        self.assertEqual(verifier.call_count, 2)
        flat = self.root / "target/android-sdk-runtime-export-api35-16k"
        self.assertEqual(len(list(flat.iterdir())), 56)
        for leaf, (profile, relative) in flat_sdk_export_files().items():
            self.assertEqual((flat / leaf).read_bytes(), (original[profile] / relative).read_bytes())

    def test_run_selection_rejects_extra_attempts_and_duplicate_profiles(self) -> None:
        original = self.exports()
        extra = self.runs / ("f" * 32)
        extra.mkdir()
        with self.assertRaisesRegex(AndroidAgpConsumerError, "exactly two runs"):
            replay.select_exports(self.runs)
        extra.rmdir()
        profiles = sorted(original)
        proof_path = original[profiles[1]] / "proof.json"
        proof = json.loads(proof_path.read_text())
        proof["consumer"]["profile"] = profiles[0]
        proof_path.write_text(json.dumps(proof))
        with self.assertRaisesRegex(AndroidAgpConsumerError, "duplicated"):
            replay.select_exports(self.runs)

    def test_extra_public_file_is_rejected_before_sdk_execution(self) -> None:
        original = self.exports()
        (next(iter(original.values())) / "extra.txt").write_text("unadmitted")
        with mock.patch.object(replay, "verify_exported_profile") as verifier:
            with self.assertRaisesRegex(AndroidAgpConsumerError, "extras"):
                replay.run("stage", **self.arguments)
        verifier.assert_not_called()

    def test_sdk_tool_failure_is_recorded_and_propagated(self) -> None:
        self.exports()
        with mock.patch.object(replay, "verify_exported_profile", side_effect=AndroidAgpConsumerError("SDK tool identity differs")):
            with self.assertRaisesRegex(AndroidAgpConsumerError, "SDK tool identity differs"):
                replay.run("stage", **self.arguments)
        report = json.loads((self.root / "target/android-sdk-runtime-stage-api35-16k/REPORT.json").read_text())
        self.assertFalse(report["completed"])
        self.assertEqual(report["profiles"], [])
        self.assertEqual(report["failure"]["message"], "SDK tool identity differs")

    def test_verify_refuses_original_run_or_aar_directories(self) -> None:
        for path in (self.runs, self.root / "target/qperiapt-android-aar"):
            with self.subTest(path=path.name):
                path.mkdir()
                with self.assertRaisesRegex(AndroidAgpConsumerError, "directories to be absent"):
                    replay.run("verify", **self.arguments)
                path.rmdir()

    def test_second_profile_failure_never_completes_the_pair(self) -> None:
        self.exports()
        with mock.patch.object(replay, "verify_exported_profile", side_effect=[
            {"profile": "agp_sdk_full_release"}, AndroidAgpConsumerError("second APK failed")
        ]):
            with self.assertRaisesRegex(AndroidAgpConsumerError, "second APK failed"):
                replay.run("stage", **self.arguments)
        report = json.loads((self.root / "target/android-sdk-runtime-stage-api35-16k/REPORT.json").read_text())
        self.assertFalse(report["completed"])
        self.assertEqual(report["profiles"], [{"profile": "agp_sdk_full_release"}])
        self.assertEqual(report["failure"]["message"], "second APK failed")

    def test_restore_rejects_extra_file_mode_links_and_symlinks(self) -> None:
        self.exports()
        with mock.patch.object(replay, "verify_exported_profile", return_value={}):
            replay.run("stage", **self.arguments)
        flat = self.root / "target/android-sdk-runtime-export-api35-16k"
        source = next(iter(flat.iterdir()))
        data = source.read_bytes()
        extra = flat / "extra.txt"
        extra.write_text("extra")
        with self.assertRaisesRegex(AndroidAgpConsumerError, "file set"):
            replay.restore(flat, self.root / "target/extra", "api35-16k")
        extra.unlink()
        source.chmod(0o600)
        with self.assertRaisesRegex(AndroidAgpConsumerError, "mode-0644"):
            replay.restore(flat, self.root / "target/mode", "api35-16k")
        source.chmod(0o644)
        hardlink = self.root / "hardlink"
        os.link(source, hardlink)
        with self.assertRaises((AndroidAgpConsumerError, EvidenceIOError)):
            replay.restore(flat, self.root / "target/link", "api35-16k")
        hardlink.unlink()
        source.unlink()
        source.symlink_to(self.root / "absent")
        with self.assertRaisesRegex(AndroidAgpConsumerError, "non-regular"):
            replay.restore(flat, self.root / "target/symlink", "api35-16k")
        source.unlink()
        source.write_bytes(data)
        source.chmod(0o644)
        self.assertEqual(set(replay.restore(flat, self.root / "target/valid", "api35-16k")), SDK_PROFILES)

    def test_verify_uses_only_transported_closures(self) -> None:
        self.exports()
        with mock.patch.object(replay, "verify_exported_profile", return_value={}) as verifier:
            replay.run("stage", **self.arguments)
            shutil.rmtree(self.runs)  # This test owns these synthetic fixtures.
            spec = replay.ANDROID_SDK_RUNTIME_REPLAY_PROFILES["api35-16k"]
            shutil.copytree(self.root / "target/android-sdk-runtime-export-api35-16k", self.root / spec.destination)
            result = replay.run("verify", **self.arguments)
        self.assertTrue(result["completed"])
        self.assertEqual(verifier.call_count, 4)
        self.assertFalse(self.runs.exists())


if __name__ == "__main__":
    unittest.main()
