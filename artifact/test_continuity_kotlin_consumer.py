"""Closed Maven/runtime identity and complete execution evidence for the JVM adapter."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

import continuity_kotlin_consumer as kotlin


class KotlinConsumerTests(unittest.TestCase):
    def test_every_owner_test_must_execute_without_skips_or_diagnostics(self):
        suite = ET.Element("testsuite", name="dev.qperiapt.continuity.OwnerTests", tests="8",
                           failures="0", errors="0", skipped="0")
        for name in sorted(kotlin.TEST_NAMES):
            ET.SubElement(suite, "testcase", name=name + "()", classname=suite.get("name"))
        data = ET.tostring(suite)
        self.assertEqual(kotlin.verify_tests(data)["tests"], 8)
        suite.remove(suite[0])
        with self.assertRaisesRegex(ValueError, "did not all execute"):
            kotlin.verify_tests(ET.tostring(suite))
        suite = ET.fromstring(data)
        ET.SubElement(suite[0], "skipped")
        with self.assertRaisesRegex(ValueError, "did not all execute"):
            kotlin.verify_tests(ET.tostring(suite))
        suite = ET.fromstring(data)
        ET.SubElement(suite, "system-err").text = "native owner cleanup failed"
        with self.assertRaisesRegex(ValueError, "unexpected diagnostics"):
            kotlin.verify_tests(ET.tostring(suite))
        with self.assertRaisesRegex(ValueError, "external declarations"):
            kotlin.verify_tests(b'<!DOCTYPE testsuite [<!ENTITY x "test">]>' + data)

    def test_tool_identity_covers_implementation_not_only_launchers(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "jdk"
            (root / "bin").mkdir(parents=True); (root / "lib").mkdir()
            (root / "bin/java").write_bytes(b"not executed launcher fixture")
            (root / "lib/modules").write_bytes(b"original implementation fixture")
            original = kotlin.tool_identity(root)
            self.assertEqual(set(original["files"]), {"bin/java", "lib/modules"})
            (root / "lib/modules").write_bytes(b"different implementation fixture")
            self.assertNotEqual(kotlin.tool_identity(root), original)
            (root / "lib/link").symlink_to("modules")
            self.assertEqual(kotlin.tool_identity(root)["files"]["lib/link"]["target"], "lib/modules")
            (root / "lib/link").unlink()
            outside = root.parent / "outside"; outside.write_bytes(b"outside tool authority")
            (root / "lib/link").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "escapes"):
                kotlin.tool_identity(root)

    def test_runtime_requires_exact_coordinates_bytes_and_outside_distribution(self):
        with tempfile.TemporaryDirectory() as folder:
            outside = Path(folder).resolve(); distribution = outside / "installed"
            (distribution / "lib").mkdir(parents=True)
            repository = outside / "repository"; repository.mkdir()
            coordinate = kotlin.maven_contract().coordinate
            components = [(coordinate, "sdk.jar"), ("org.jetbrains.kotlin:kotlin-stdlib:2.4.20", "kotlin.jar"),
                          ("org.jetbrains:annotations:13.0", "annotations.jar")]
            rows = []
            for name, leaf in components:
                data = ("not executed JAR fixture: " + name).encode()
                path = repository / leaf; path.write_bytes(data)
                (distribution / "lib" / leaf).write_bytes(data)
                rows.append(f"{name}\t{path}\t{hashlib.sha256(data).hexdigest()}\n")
            (distribution / "lib/continuity-installed-consumer.jar").write_bytes(b"consumer fixture")
            encoded = "".join(rows).encode(); digest = hashlib.sha256((repository / "sdk.jar").read_bytes()).hexdigest()
            self.assertEqual(set(kotlin.runtime_closure(encoded, distribution, digest, outside)), {name for name, _ in components})
            for changed in (encoded + rows[0].encode(), "".join(rows[:-1]).encode(), encoded.replace(b":2.4.20\t", b":2.+\t")):
                with self.assertRaisesRegex(ValueError, "coordinate|closure"):
                    kotlin.runtime_closure(changed, distribution, digest, outside)
            noncanonical = encoded.replace(str(repository / "sdk.jar").encode(),
                                           str(repository / "../repository/sdk.jar").encode())
            with self.assertRaisesRegex(ValueError, "location differs"):
                kotlin.runtime_closure(noncanonical, distribution, digest, outside)
            (distribution / "lib/sdk.jar").write_bytes(b"substituted installed dependency")
            with self.assertRaisesRegex(ValueError, "differs from resolution"):
                kotlin.runtime_closure(encoded, distribution, digest, outside)
            (distribution / "lib/sdk.jar").write_bytes((repository / "sdk.jar").read_bytes())
            (distribution / "lib/unlisted.jar").write_bytes(b"extra runtime implementation")
            with self.assertRaisesRegex(ValueError, "unqualified dependency"):
                kotlin.runtime_closure(encoded, distribution, digest, outside)

if __name__ == "__main__":
    unittest.main()
