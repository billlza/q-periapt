"""Package-admission mutations; executable JVM/native proof uses real installed consumers."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

import jvm_sdk_package as jvm


class JvmSDKPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / "maven"
        self.directory = self.repository / jvm.MAVEN_PATH
        self.directory.mkdir(parents=True)
        self.binary = {f"dev/qperiapt/{name}.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x45fixture-header-only"
            for name in ("QPeriaptRuntime", "QPeriaptKey", "QPeriaptSecret", "QPeriaptExpert", "QPeriaptHybrid",
                         "QPeriaptPersistentRuntime", "QPeriaptPolicyRecoveryTrust", "QPeriaptPolicyRecoveryRequest",
                         "QPeriaptPolicyRecoveryAuthorization", "QPeriaptPolicyRecoveryResult", "QPeriaptPolicyRecoveryReopen")}
        self.binary["META-INF/dev.qperiapt_q-periapt-hybrid.kotlin_module"] = b"fixture"
        self.binary["META-INF/MANIFEST.MF"] = ("Manifest-Version: 1.0\r\nAutomatic-Module-Name: dev.qperiapt.hybrid\r\n"
            "Implementation-Title: Q-Periapt Kotlin/JVM SDK\r\nImplementation-Version: 0.2.0\r\n"
            "QPeriapt-ABI: 2\r\nQPeriapt-SDK-Extension: 1\r\n\r\n").encode()
        source_root = jvm.BINDING / "src/main/kotlin"
        self.source = {path.relative_to(source_root).as_posix(): path.read_bytes() for path in source_root.rglob("*.kt")}
        self.source["META-INF/MANIFEST.MF"] = b"Manifest-Version: 1.0\r\n\r\n"
        for name, path in jvm.NOTICE_PATHS.items():
            self.binary[name] = self.source[name] = path.read_bytes()
        self.pom = (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
            f'<groupId>{jvm.GROUP}</groupId><artifactId>{jvm.NAME}</artifactId><version>{jvm.VERSION}</version>'
            f'<dependencies><dependency><groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-stdlib</artifactId>'
            f'<version>{jvm.KOTLIN}</version><scope>compile</scope></dependency></dependencies></project>')
        self.write_repository()

    def write_repository(self):
        for suffix, files in ((".jar", self.binary), ("-sources.jar", self.source)):
            with zipfile.ZipFile(self.directory / f"{jvm.PREFIX}{suffix}", "w") as archive:
                for name, data in files.items():
                    archive.writestr(name, data)
        (self.directory / f"{jvm.PREFIX}.pom").write_text(self.pom)
        self.module = {"formatVersion": "1.1", "component": {"group": jvm.GROUP, "module": jvm.NAME,
            "version": jvm.VERSION, "attributes": {"org.gradle.status": "release"}},
            "createdBy": {"gradle": {"version": "9.8.0"}}, "variants": []}
        for variant in ("apiElements", "runtimeElements", "sourcesElements"):
            sources = variant == "sourcesElements"
            name = f"{jvm.PREFIX}{'-sources' if sources else ''}.jar"
            data = (self.directory / name).read_bytes()
            row = {"name": variant, "attributes": {} if sources else {"org.gradle.jvm.version": 25},
                "files": [{"name": name, "url": name, "size": len(data),
                    **{algorithm: hashlib.new(algorithm, data).hexdigest() for algorithm in ("md5", "sha1", "sha256", "sha512")}}]}
            if not sources:
                row["dependencies"] = [{"group": "org.jetbrains.kotlin", "module": "kotlin-stdlib", "version": {"requires": jvm.KOTLIN}}]
            self.module["variants"].append(row)
        self.write_module_checksums()

    def write_module_checksums(self):
        (self.directory / f"{jvm.PREFIX}.module").write_text(json.dumps(self.module))
        for suffix in (".jar", "-sources.jar", ".pom", ".module"):
            path = self.directory / f"{jvm.PREFIX}{suffix}"
            for algorithm in ("md5", "sha1", "sha256", "sha512"):
                path.with_name(f"{path.name}.{algorithm}").write_text(hashlib.new(algorithm, path.read_bytes()).hexdigest())

    def test_structural_fixture_and_checksum_rejection(self):
        self.assertEqual(jvm.verify_maven(self.repository)["coordinate"], jvm.COORDINATE)
        (self.directory / f"{jvm.PREFIX}.jar.sha256").write_text("0" * 64)
        with self.assertRaisesRegex(ValueError, "checksum differs"):
            jvm.verify_maven(self.repository)

    def test_rehashed_missing_persistent_api_is_rejected(self):
        del self.binary["dev/qperiapt/QPeriaptPersistentRuntime.class"]
        self.write_repository()
        with self.assertRaisesRegex(ValueError, "required.*class|owner.*class|class.*missing"):
            jvm.verify_maven(self.repository)

    def test_rehashed_duplicate_gradle_component_is_rejected(self):
        path = self.directory / f"{jvm.PREFIX}.module"
        data = path.read_bytes().replace(b"{", b'{"component":null,', 1)
        path.write_bytes(data)
        for algorithm in ("md5", "sha1", "sha256", "sha512"):
            path.with_name(f"{path.name}.{algorithm}").write_text(hashlib.new(algorithm, data).hexdigest())
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: component"):
            jvm.verify_maven(self.repository)

    def test_rehashed_bytecode_and_embedded_native_rejection(self):
        self.binary["dev/qperiapt/QPeriaptKey.class"] = b"\xca\xfe\xba\xbe\x00\x00\x00\x41"
        self.write_repository()
        with self.assertRaisesRegex(ValueError, "non-preview JDK 25"):
            jvm.verify_maven(self.repository)
        self.binary["dev/qperiapt/QPeriaptKey.class"] = b"\xca\xfe\xba\xbe\x00\x00\x00\x45"
        self.binary["native/lib.so"] = b"unexpected native payload"
        self.write_repository()
        with self.assertRaisesRegex(ValueError, "unexpected resource"):
            jvm.verify_maven(self.repository)

    def test_rehashed_source_and_license_changes_rejected(self):
        original = self.source["dev/qperiapt/QPeriaptSDK.kt"]
        self.source["dev/qperiapt/QPeriaptSDK.kt"] = original + b"\n// different source\n"
        self.write_repository()
        with self.assertRaisesRegex(ValueError, "sources JAR does not match"):
            jvm.verify_maven(self.repository)
        self.source["dev/qperiapt/QPeriaptSDK.kt"] = original
        self.binary["META-INF/licenses/MIT.txt"] = b"substituted notice"
        self.write_repository()
        with self.assertRaisesRegex(ValueError, "license differs"):
            jvm.verify_maven(self.repository)

    def test_rehashed_coordinate_dependency_and_redirect_rejected(self):
        self.pom = self.pom.replace("0.2.0", "0.1.5")
        self.write_repository()
        with self.assertRaisesRegex(ValueError, "coordinate differs"):
            jvm.verify_maven(self.repository)
        self.pom = self.pom.replace("0.1.5", "0.2.0")
        self.write_repository()
        self.module["variants"][0]["dependencies"][0]["version"]["requires"] = "2.+"
        self.write_module_checksums()
        with self.assertRaisesRegex(ValueError, "dependency differs"):
            jvm.verify_maven(self.repository)
        self.write_repository()
        self.module["variants"][0]["available-at"] = {"url": "https://invalid.test/redirect"}
        self.write_module_checksums()
        with self.assertRaisesRegex(ValueError, "redirect is forbidden"):
            jvm.verify_maven(self.repository)

    def test_jar_path_escape_rejected_without_extraction(self):
        self.binary["../outside.class"] = b"fixture"
        self.write_repository()
        with self.assertRaisesRegex(ValueError, "unsafe path"):
            jvm.jar_files(self.directory / f"{jvm.PREFIX}.jar")
        self.assertFalse((self.root.parent / "outside.class").exists())

    def test_maven_unlisted_file_and_symlink_rejected(self):
        path = self.repository / "unlisted"
        path.write_bytes(b"unlisted")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            jvm.verify_maven(self.repository)
        path.unlink()
        path.symlink_to(self.directory / f"{jvm.PREFIX}.jar")
        with self.assertRaisesRegex(ValueError, "symlink is forbidden"):
            jvm.verify_maven(self.repository)

    def test_consumer_pins_preserve_existing_upstream_requirements(self):
        consumer = self.root / "consumer"
        consumer.mkdir()
        jvm.pin_consumer_dependencies(consumer, self.repository)
        original = ET.parse(jvm.BINDING / "gradle/verification-metadata.xml").getroot()
        updated = ET.parse(consumer / "gradle/verification-metadata.xml").getroot()
        ns = {"v": "https://schema.gradle.org/dependency-verification"}
        def structure(node):
            return node.tag, node.attrib, (node.text or "").strip(), [structure(child) for child in node]
        self.assertEqual(structure(original.find("v:configuration", ns)), structure(updated.find("v:configuration", ns)))
        old = original.find("v:components", ns)
        new = updated.find("v:components", ns)
        self.assertEqual([structure(node) for node in old], [structure(node) for node in list(new)[:-1]])
        self.assertEqual(new[-1].attrib, {"group": jvm.GROUP, "name": jvm.NAME, "version": jvm.VERSION})
        self.assertEqual(len(new[-1]), 3)


if __name__ == "__main__":
    unittest.main()
