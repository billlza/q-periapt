"""Movable r2 envelopes around complete synthetic AGP consumer closures.

Only the fixed SDK command boundary uses its binary-inspecting fixture oracle.
These are verifier tests, not evidence of a real ART run. The nested canonical
runtime archive is opaque here: its existing deep verifier remains the next
explicit platform-distribution gate.
"""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import android_agp_consumer as agp
import android_agp_test_fixture as fixture
import android_maintenance_bundle as bundle
from deterministic_archive import create_zip


class AndroidMaintenanceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = pathlib.Path(self.temporary.name).resolve()
        self.pair = fixture.create_agp_fixture_pair(self.work / "inputs")
        self.stage = self.work / "archive-input"
        self.stage.mkdir(mode=0o700)
        self.canonical = b"opaque input for the separate canonical runtime verifier\n"
        canonical = self.stage / "canonical/runtime-evidence-v2.zip"
        fixture.write(canonical, self.canonical)
        files = {"canonical/runtime-evidence-v2.zip": self._record(canonical)}
        consumers = {}
        with mock.patch.object(agp, "run_sdk_tool", side_effect=fixture.sdk_runner):
            for profile, selected in self.pair.profiles.items():
                projection = agp.validate_completed_profile(
                    selected.root, selected.proof, sdk=selected.sdk, **selected.expected
                )
                exported = agp.profile_evidence_files(
                    selected.root, selected.proof, sdk=selected.sdk
                )
                for name, path in exported.items():
                    relative = f"consumers/{profile}/{name}"
                    destination = self.stage / relative
                    fixture.write(destination, path.read_bytes())
                    files[relative] = self._record(destination)
                consumers[profile] = {
                    "proof_path": f"consumers/{profile}/proof.json",
                    "projection": projection,
                }
        aar_manifest = json.loads(self.pair.aar_manifest.read_bytes())
        self.manifest = {
            "schema_version": 3,
            "kind": "qperiapt.android_runtime_evidence_bundle",
            "profile": "maintenance-r2",
            "git_commit": aar_manifest["git_commit"],
            "source_date_epoch": aar_manifest["source_date_epoch"],
            "source_tree_sha256": aar_manifest["source_tree_sha256"],
            "aar_sha256": fixture.digest(self.pair.aar),
            "aar_manifest_sha256": fixture.digest(self.pair.aar_manifest),
            "files": files,
            "agp_consumers": consumers,
        }
        self.expected = {
            "expected_aar_sha256": self.manifest["aar_sha256"],
            "expected_aar_manifest_sha256": self.manifest["aar_manifest_sha256"],
            "expected_source_commit": self.manifest["git_commit"],
            "expected_source_tree_sha256": self.manifest["source_tree_sha256"],
            "expected_source_epoch": self.manifest["source_date_epoch"],
        }

    @staticmethod
    def _record(path: pathlib.Path) -> dict[str, object]:
        return {"bytes": path.stat().st_size, "sha256": fixture.digest(path)}

    def _archive(self, name: str) -> pathlib.Path:
        fixture.write(self.stage / "MANIFEST.json", fixture.json_bytes(self.manifest))
        archive = self.work / f"{name}.zip"
        create_zip(
            self.stage,
            archive,
            root_name="qperiapt-android-runtime-evidence-v3",
            mtime=self.manifest["source_date_epoch"],
            limits=bundle.BUNDLE_LIMITS,
        )
        return archive

    def _verify(self, archive: pathlib.Path, name: str, **expected):
        return bundle.verify_and_extract(
            root=self.pair.root,
            bundle=archive,
            destination=self.work / name,
            expected_bundle_sha256=fixture.digest(archive),
            sdk=self.pair.sdk,
            **(self.expected | expected),
        )

    def _hide_private_inputs(self) -> None:
        first = next(iter(self.pair.profiles.values()))
        first.proof.parents[2].rename(self.work / "retained-private-runs")
        self.pair.aar.rename(self.work / "retained-original.aar")
        self.pair.aar_manifest.rename(self.work / "retained-aar-manifest.json")
        for profile in self.pair.profiles.values():
            self.assertFalse(profile.proof.exists())
        self.assertFalse(self.pair.aar.exists())
        self.assertFalse(self.pair.aar_manifest.exists())

    def test_complete_export_revalidates_after_all_original_runs_and_aar_are_unavailable(
        self,
    ) -> None:
        archive = self._archive("downloaded")
        self._hide_private_inputs()
        with mock.patch.object(
            agp, "run_sdk_tool", side_effect=fixture.sdk_runner
        ) as sdk:
            verified = self._verify(archive, "new-download-root")
        self.assertEqual(self.canonical, verified.runtime_bundle.read_bytes())
        self.assertEqual(
            hashlib.sha256(self.canonical).hexdigest(), verified.runtime_bundle_sha256
        )
        self.assertEqual(fixture.digest(archive), verified.archive_sha256)
        self.assertEqual(self.manifest["agp_consumers"], verified.consumers)
        tools = [call.args[0].name for call in sdk.call_args_list]
        for tool in ("apksigner", "zipalign", "dexdump", "aapt2"):
            self.assertEqual(2, tools.count(tool), tool)
        self.assertEqual(
            ["runtimeVersionOnly"],
            verified.consumers["agp_minimal_release"]["projection"]["passed_tests"],
        )

    def test_consistent_outer_inventory_cannot_omit_a_required_consumer_file(
        self,
    ) -> None:
        relative = "consumers/agp_minimal_release/build/receipt.json"
        (self.stage / relative).unlink()
        self.manifest["files"].pop(relative)
        archive = self._archive("partial")
        self._hide_private_inputs()
        with mock.patch.object(agp, "run_sdk_tool", side_effect=fixture.sdk_runner):
            with self.assertRaises(bundle.AndroidMaintenanceBundleError):
                self._verify(archive, "partial-download")

    def test_coherently_rehashed_cross_profile_build_receipt_is_rejected(self) -> None:
        full = self.stage / "consumers/agp_full_release/build/receipt.json"
        relative = "consumers/agp_minimal_release/build/receipt.json"
        destination = self.stage / relative
        fixture.write(destination, full.read_bytes())
        self.manifest["files"][relative] = self._record(destination)
        proof_relative = "consumers/agp_minimal_release/proof.json"
        proof_path = self.stage / proof_relative
        proof = json.loads(proof_path.read_bytes())
        proof["consumer"]["build_receipt"].update(self._record(destination))
        fixture.write(proof_path, fixture.json_bytes(proof))
        self.manifest["files"][proof_relative] = self._record(proof_path)
        self.manifest["agp_consumers"]["agp_minimal_release"]["projection"].update(
            proof_sha256=fixture.digest(proof_path),
            build_receipt_sha256=fixture.digest(destination),
        )
        archive = self._archive("spliced")
        self._hide_private_inputs()
        with mock.patch.object(agp, "run_sdk_tool", side_effect=fixture.sdk_runner):
            with self.assertRaises(bundle.AndroidMaintenanceBundleError):
                self._verify(archive, "spliced-download")

    def test_actual_sdk_rejection_of_second_apk_is_not_replaced_by_first_success(
        self,
    ) -> None:
        archive = self._archive("sdk-failure")

        def sdk(tool, arguments):
            if tool.name == "dexdump" and pathlib.Path(
                arguments[-1]
            ).read_bytes().endswith(b"minimal"):
                raise agp.AndroidAgpConsumerError("selected minimal DEX was rejected")
            return fixture.sdk_runner(tool, arguments)

        with mock.patch.object(agp, "run_sdk_tool", side_effect=sdk):
            with self.assertRaisesRegex(
                bundle.AndroidMaintenanceBundleError, "minimal DEX"
            ):
                self._verify(archive, "sdk-failed-download")

    def test_source_revision_and_extra_archive_entries_fail_before_sdk_replay(
        self,
    ) -> None:
        original = copy.deepcopy(self.manifest)
        for index, changes in enumerate(
            (
                {"schema_version": 2},
                {"profile": "stable"},
                {"git_commit": "0" * 40},
                {"source_tree_sha256": "0" * 64},
                {"aar_sha256": "0" * 64},
            )
        ):
            self.manifest = original | changes
            archive = self._archive(f"identity-{index}")
            with mock.patch.object(
                agp,
                "run_sdk_tool",
                side_effect=AssertionError("invalid envelope reached SDK"),
            ):
                with self.assertRaises(bundle.AndroidMaintenanceBundleError):
                    self._verify(archive, f"identity-download-{index}")
        self.manifest = original
        fixture.write(self.stage / "unrecorded.txt", b"unexpected\n")
        archive = self._archive("extra")
        with mock.patch.object(
            agp, "run_sdk_tool", side_effect=AssertionError("extra entry reached SDK")
        ):
            with self.assertRaises(bundle.AndroidMaintenanceBundleError):
                self._verify(archive, "extra-download")

    def test_signing_tools_must_select_the_same_explicit_sdk(self) -> None:
        tools = self.pair.sdk / "build-tools/36.0.0"
        self.assertEqual(
            self.pair.sdk,
            bundle.android_sdk_for_tools(tools / "apksigner", tools / "zipalign"),
        )
        other = self.work / "other-sdk/build-tools/36.0.0/zipalign"
        fixture.write(other, b"different tool\n")
        with self.assertRaises(bundle.AndroidMaintenanceBundleError):
            bundle.android_sdk_for_tools(tools / "apksigner", other)


if __name__ == "__main__":
    unittest.main()
