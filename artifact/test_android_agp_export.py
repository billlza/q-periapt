"""Portable profile verification with real schema/IO and one explicit SDK mock."""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import android_agp_consumer as consumer
import android_agp_test_fixture as fixture
import android_device_proof as runtime
from test_android_elf import zip_bytes


class AgpExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="qperiapt-agp-export-test-")
        cls.directory = pathlib.Path(cls.temporary.name).resolve()
        cls.pair = fixture.create_agp_fixture_pair(cls.directory)
        cls.exports = {}
        cls.projections = {}
        with mock.patch.object(
            consumer, "run_sdk_tool", side_effect=fixture.sdk_runner
        ):
            for name, profile in cls.pair.profiles.items():
                cls.projections[name] = consumer.validate_completed_profile(
                    profile.root, profile.proof, sdk=profile.sdk, **profile.expected
                )
                files = consumer.profile_evidence_files(
                    profile.root, profile.proof, sdk=profile.sdk
                )
                exported = cls.directory / name
                for relative, source in files.items():
                    destination = exported / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
                    destination.chmod(0o644)
                cls.exports[name] = exported
        # No original runtime evidence or selected AAR remains available at its old path.
        (cls.pair.root / "target" / runtime.ANDROID_RUNS_ROOT_LEAF).rename(
            cls.directory / "retired-runs"
        )
        cls.pair.aar.parent.rename(cls.directory / "retired-aar")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def verify(self, profile: str, directory: pathlib.Path) -> dict[str, object]:
        selected = self.pair.profiles[profile]
        with mock.patch.object(
            consumer, "run_sdk_tool", side_effect=fixture.sdk_runner
        ):
            return consumer.verify_exported_profile(
                selected.root, directory, sdk=selected.sdk, **selected.expected
            )

    def test_pair_reverifies_after_both_original_runs_and_aar_are_moved_away(
        self,
    ) -> None:
        values = []
        for name, profile in self.pair.profiles.items():
            self.assertFalse(profile.proof.exists())
            self.assertFalse(self.pair.aar.exists())
            result = self.verify(name, self.exports[name])
            self.assertEqual(result, self.projections[name])
            values.append(result)
        self.assertEqual(values[0]["source_commit"], values[1]["source_commit"])
        self.assertEqual(
            values[0]["source_tree_sha256"], values[1]["source_tree_sha256"]
        )
        self.assertEqual(values[0]["aar_sha256"], values[1]["aar_sha256"])
        self.assertNotEqual(values[0]["run_id"], values[1]["run_id"])

    def test_self_consistent_hashes_cannot_replace_signature_alignment_or_binary_dumps(
        self,
    ) -> None:
        cases = {
            "unsigned": "rejected unsigned APK",
            "unaligned": "rejected unaligned APK",
            "dexdump": "archived DEX dump differs",
            "manifest_dump": "archived manifest dump differs",
        }
        for profile in self.pair.profiles:
            for mutation, expected_failure in cases.items():
                with self.subTest(profile=profile, mutation=mutation):
                    changed = self.directory / (profile + "-" + mutation)
                    shutil.copytree(self.exports[profile], changed)
                    proof_path = changed / "proof.json"
                    proof = json.loads(proof_path.read_bytes())
                    build_path = changed / "build/receipt.json"
                    build = json.loads(build_path.read_bytes())
                    if mutation in {"unsigned", "unaligned"}:
                        selected_apk = (
                            changed
                            / "runtime"
                            / runtime.bundle_file_paths(proof)["smoke_apk"]
                        )
                        entries = consumer._apk_entries(selected_apk)
                        if mutation == "unsigned":
                            del entries["META-INF/QPERIAPT.RSA"]
                        else:
                            entries["alignment.fixture"] = b"4096"
                        payload = zip_bytes(entries)
                        selected_apk.write_bytes(payload)
                        if mutation == "unaligned":
                            for key in ("apk", "agp_apk"):
                                unsigned = (
                                    changed / "build" / consumer.BUILD_FILE_NAMES[key]
                                )
                                unsigned_entries = consumer._apk_entries(unsigned)
                                unsigned_entries["alignment.fixture"] = b"4096"
                                unsigned.write_bytes(zip_bytes(unsigned_entries))
                                build["files"][key] = fixture.record(unsigned)
                        proof["artifacts"]["smoke_apk_sha256"] = hashlib.sha256(
                            payload
                        ).hexdigest()
                    else:
                        path = changed / "build" / consumer.BUILD_FILE_NAMES[mutation]
                        original = path.read_bytes()
                        replacement = (
                            original.replace(b"Processing ", b"Forged Processing ", 1)
                            if mutation == "dexdump"
                            else original.replace(b"line=1", b"line=99", 1)
                        )
                        self.assertNotEqual(original, replacement)
                        path.write_bytes(replacement)
                        build["files"][mutation] = fixture.record(path)
                    build_path.write_bytes(fixture.json_bytes(build))
                    proof["consumer"]["build_receipt"] = fixture.record(
                        build_path, proof["consumer"]["build_receipt"]["path"]
                    )
                    proof_path.write_bytes(fixture.json_bytes(proof))
                    with self.assertRaisesRegex(
                        consumer.AndroidAgpConsumerError, expected_failure
                    ):
                        self.verify(profile, changed)

    def test_missing_and_extra_files_and_wrong_profile_are_rejected(self) -> None:
        for profile in self.pair.profiles:
            other = (
                "agp_minimal_release"
                if profile == "agp_full_release"
                else "agp_full_release"
            )
            with self.assertRaises(consumer.AndroidAgpConsumerError):
                self.verify(other, self.exports[profile])
            for mutation in ("missing", "extra"):
                changed = self.directory / (profile + "-" + mutation)
                shutil.copytree(self.exports[profile], changed)
                if mutation == "missing":
                    (changed / "instrumentation.txt").unlink()
                else:
                    (changed / "unexpected.txt").write_text("unexpected")
                with self.assertRaisesRegex(
                    consumer.AndroidAgpConsumerError,
                    "closure is missing files or contains extras",
                ):
                    self.verify(profile, changed)

    def test_export_rechecks_original_prepared_and_signed_payloads_after_rehash(self):
        for profile in self.pair.profiles:
            for mutation, expected_failure in (
                ("original-metadata", "differs from the pinned producer"),
                ("prepared-payload", "beyond the fixed app metadata removal"),
                ("signed-payload", "beyond signature entries"),
                ("delta-receipt", "receipt differs from the complete APK delta"),
                ("delta-float", "byte count must be an exact integer"),
            ):
                with self.subTest(profile=profile, mutation=mutation):
                    changed = self.directory / (profile + "-" + mutation)
                    shutil.copytree(self.exports[profile], changed)
                    proof_path = changed / "proof.json"
                    proof = json.loads(proof_path.read_bytes())
                    build_path = changed / "build/receipt.json"
                    build = json.loads(build_path.read_bytes())
                    if mutation == "delta-float":
                        build["signing_input"]["removed"][consumer.APP_METADATA_ENTRY][
                            "bytes"
                        ] = 56.0
                    elif mutation == "delta-receipt":
                        build["signing_input"]["removed"][consumer.APP_METADATA_ENTRY][
                            "sha256"
                        ] = ("a" * 64)
                    elif mutation == "signed-payload":
                        apk = (
                            changed
                            / "runtime"
                            / runtime.bundle_file_paths(proof)["smoke_apk"]
                        )
                        entries = consumer._apk_entries(apk)
                        entries["unexpected-resource.bin"] = b"unrecorded payload"
                        apk.write_bytes(zip_bytes(entries))
                        proof["artifacts"]["smoke_apk_sha256"] = fixture.digest(apk)
                    else:
                        key = "agp_apk" if mutation == "original-metadata" else "apk"
                        apk = changed / "build" / consumer.BUILD_FILE_NAMES[key]
                        entries = consumer._apk_entries(apk)
                        if mutation == "original-metadata":
                            entries[consumer.APP_METADATA_ENTRY] = (
                                b"unexpected producer"
                            )
                        else:
                            entries["unexpected-resource.bin"] = b"unrecorded payload"
                        apk.write_bytes(zip_bytes(entries))
                        build["files"][key] = fixture.record(apk)
                    build_path.write_bytes(fixture.json_bytes(build))
                    proof["consumer"]["build_receipt"] = fixture.record(
                        build_path, proof["consumer"]["build_receipt"]["path"]
                    )
                    proof_path.write_bytes(fixture.json_bytes(proof))
                    with self.assertRaisesRegex(
                        consumer.AndroidAgpConsumerError, expected_failure
                    ):
                        self.verify(profile, changed)


if __name__ == "__main__":
    unittest.main()
