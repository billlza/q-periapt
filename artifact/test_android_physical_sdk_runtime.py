"""Physical SDK admission/proof boundaries; these fixtures are not device execution."""
import copy
import json
import tempfile
from unittest import mock
import os
from pathlib import Path
import subprocess
import sys
import unittest

import android_agp_consumer as consumer
import android_agp_consumer_contract as contract
import android_agp_test_fixture as fixture
import android_device_proof as proof
import android_runtime_profile as profiles
from test_android_agp_consumer import projection
import test_android_device_proof as device_fixtures


class PhysicalSDKAdmissionTests(unittest.TestCase):
    def test_explicit_physical_projection_cannot_replace_any_emulator_or_legacy_profile(self):
        target = {"kind": "physical", "abi": "arm64-v8a", "sdk": 36, "page_size": 4096}
        for name in contract.SDK_PROFILES:
            expected = dict(expected_profile=name, expected_aar_sha256="b" * 64,
                expected_aar_manifest_sha256="b" * 64, expected_source_commit="c" * 40,
                expected_device_abi="arm64-v8a", expected_runtime_profile=profiles.PHYSICAL_RUNTIME_PROFILE)
            value = projection(name)
            value["runtime_target"] = target
            self.assertEqual(contract.validate_profile_projection(value, **expected), value)
            for field, other in (("kind", "emulator"), ("abi", "x86_64"), ("sdk", 35),
                                 ("sdk", 36.0), ("page_size", 16384), ("page_size", 4096.0)):
                changed = copy.deepcopy(value)
                changed["runtime_target"][field] = other
                with self.subTest(field=field), self.assertRaises(contract.AndroidAgpConsumerError):
                    contract.validate_profile_projection(changed, **expected)
            for other in ("api35-16k", "api23-4k"):
                with self.assertRaises(contract.AndroidAgpConsumerError):
                    contract.validate_profile_projection(value, **{**expected, "expected_runtime_profile": other})
            with self.assertRaises(contract.AndroidAgpConsumerError):
                contract.runtime_target(name, "x86_64", profiles.PHYSICAL_RUNTIME_PROFILE)
        for legacy in contract.PROFILES:
            with self.assertRaises(contract.AndroidAgpConsumerError):
                contract.runtime_target(legacy, "arm64-v8a", profiles.PHYSICAL_RUNTIME_PROFILE)
        # Owned AVD launch and recovery retain their original, closed two profiles.
        self.assertEqual(set(profiles.RUNTIME_PROFILES), {"api35-16k", "api23-4k"})
        with self.assertRaises(ValueError):
            profiles.runtime_profile(profiles.PHYSICAL_RUNTIME_PROFILE)
        with self.assertRaises(ValueError):
            profiles.owned_avd_profile("macos-account", "arm64-v8a", profiles.PHYSICAL_RUNTIME_PROFILE)

    def test_physical_metadata_requires_independent_exact_expectations(self):
        value = device_fixtures.AndroidDeviceProofProvenanceTests.physical_release_device_proof()
        expected = dict(expected_device_kind="physical", expected_device_abi="arm64-v8a",
            expected_page_size=4096, expected_device_sdk=36, require_release_mode=True,
            expected_runtime_profile=profiles.PHYSICAL_RUNTIME_PROFILE)
        proof.verify_device_metadata(value, **expected)
        for name, other in (("expected_device_kind", ""), ("expected_device_kind", "emulator"),
                            ("expected_device_abi", ""), ("expected_device_abi", "x86_64"),
                            ("expected_page_size", None), ("expected_page_size", 16384),
                            ("expected_device_sdk", None), ("expected_device_sdk", 35)):
            with self.subTest(expected=name), self.assertRaises(SystemExit):
                proof.verify_device_metadata(value, **{**expected, name: other})
        for name, other in (("kind", "emulator"), ("abi", "x86_64"), ("page_size", 16384), ("sdk", 35)):
            changed = copy.deepcopy(value)
            changed["device"][name] = other
            with self.subTest(observed=name), self.assertRaises(SystemExit):
                proof.verify_device_metadata(changed, **expected)
        changed = copy.deepcopy(value)
        changed['emulator_control'] = {}
        with self.assertRaisesRegex(SystemExit, 'emulator_control to null'):
            proof.verify_emulator_control(changed, require_release_mode=True)

    def test_real_shell_admission_binds_kind_boot_mode_and_shape_before_lane_creation(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / 'artifact/android-device-smoke.sh').read_text()
        start = source.index('ANDROID_CONSUMER_PROFILE=')
        end = source.index('# Hold one host/account-scoped', start)
        prefix = 'set -eu\nROOT=$QPERIAPT_TEST_ROOT\n. "$ROOT/artifact/python-env.sh"\n'
        block = prefix + source[start:end] + '\nprintf "%s\\n" "$ANDROID_PROFILE_SELECTION"\n'
        selected = dict(QPERIAPT_TEST_ROOT=str(root), QPERIAPT_ANDROID_RELEASE_MODE='1',
            QPERIAPT_ANDROID_CONSUMER_PROFILE='agp_sdk_full_release', QPERIAPT_ANDROID_RUNTIME_PROFILE=profiles.PHYSICAL_RUNTIME_PROFILE,
            QPERIAPT_ANDROID_EXPECT_DEVICE_KIND='physical', QPERIAPT_ANDROID_BOOT_AVD='0',
            QPERIAPT_ANDROID_EXPECT_ABI='arm64-v8a', QPERIAPT_ANDROID_EXPECT_SDK='36',
            QPERIAPT_ANDROID_EXPECT_PAGE_SIZE='4096', QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE='0')
        clean = {k:v for k,v in os.environ.items() if not k.startswith('QPERIAPT_')}
        # Keep the executing test runtime explicit: hosted Python may live
        # outside the bootstrap's system fallback paths. Only device selectors
        # are reset; this must not replace the selected CPython with an older one.
        clean['QPERIAPT_PYTHON'] = sys.executable
        for profile in contract.SDK_PROFILES:
            result = subprocess.run(['sh','-c',block], env={**clean,**selected,'QPERIAPT_ANDROID_CONSUMER_PROFILE':profile},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b'sdk-020:36:4096:page-size:device-time\n')
        for key, value in (('QPERIAPT_ANDROID_RELEASE_MODE','0'),('QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE','1'),
                           ('QPERIAPT_ANDROID_BOOT_AVD','1'),('QPERIAPT_ANDROID_EXPECT_DEVICE_KIND','emulator'),
                           ('QPERIAPT_ANDROID_EXPECT_DEVICE_KIND','any'),('QPERIAPT_ANDROID_EXPECT_ABI','x86_64'),
                           ('QPERIAPT_ANDROID_EXPECT_SDK','35'),('QPERIAPT_ANDROID_EXPECT_SDK',''),
                           ('QPERIAPT_ANDROID_EXPECT_PAGE_SIZE','16384'),('QPERIAPT_ANDROID_EXPECT_PAGE_SIZE',''),
                           ('QPERIAPT_ANDROID_RUNTIME_PROFILE','api35-16k'),
                           ('QPERIAPT_ANDROID_CONSUMER_PROFILE','agp_full_release')):
            result = subprocess.run(['sh','-c',block],env={**clean,**selected,key:value},
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
            with self.subTest(key=key,value=value):
                self.assertNotEqual(result.returncode,0)
                self.assertIn(b'error:',result.stderr)
                self.assertEqual(result.stdout,b'')


class PhysicalSDKExportTests(unittest.TestCase):
    def test_actual_validators_export_and_replay_both_physical_sdk_closures(self):
        # APK tools use the existing deterministic unit fixture. This verifies
        # collection/replay contracts only; no physical runtime is claimed here.
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(consumer, 'run_sdk_tool', side_effect=fixture.sdk_runner):
            root = Path(temporary)
            pair = fixture.create_agp_fixture_pair(root / 'source', sdk_profile=True,
                device_abi='arm64-v8a', expected_runtime_profile=profiles.PHYSICAL_RUNTIME_PROFILE)
            for name, profile in pair.profiles.items():
                expected = consumer.validate_completed_profile(profile.root, profile.proof, sdk=profile.sdk, **profile.expected)
                self.assertEqual(expected['runtime_target'], {'kind':'physical','abi':'arm64-v8a','sdk':36,'page_size':4096})
                destination = root / name
                exported = consumer.export_completed_profile(profile.root, profile.proof, destination,
                    sdk=profile.sdk, **profile.expected)
                self.assertEqual(exported, expected)
                self.assertEqual(consumer.verify_exported_profile(profile.root, destination, sdk=profile.sdk, **profile.expected), expected)
                with self.assertRaises(consumer.AndroidAgpConsumerError):
                    consumer.verify_exported_profile(profile.root, destination, sdk=profile.sdk,
                        **{**profile.expected, 'expected_runtime_profile':'api35-16k'})
                original = json.loads(profile.proof.read_bytes())
                self.assertIsNone(original['emulator_control'])
                for field, value in (('kind','emulator'),('sdk',35),('page_size',16384),('abi','x86_64')):
                    changed = copy.deepcopy(original)
                    changed['device'][field] = value
                    profile.proof.write_text(json.dumps(changed))
                    with self.subTest(field=field), self.assertRaises(consumer.AndroidAgpConsumerError):
                        consumer.validate_completed_profile(profile.root, profile.proof, sdk=profile.sdk, **profile.expected)
                profile.proof.write_text(json.dumps(original))
            # Replay must remain independent of the collector's original paths.
            (pair.root / 'target' / proof.ANDROID_RUNS_ROOT_LEAF).rename(pair.root / 'target/retired-runs')
            pair.aar.parent.rename(pair.root / 'target/retired-aar')
            for name, profile in pair.profiles.items():
                consumer.verify_exported_profile(profile.root, root / name, sdk=profile.sdk, **profile.expected)


if __name__ == '__main__':
    unittest.main()
