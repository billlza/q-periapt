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
        self.select_contract(jvm.product_maven_contract())

    def select_contract(self, contract):
        self.contract = contract
        self.repository = self.root / ("maven-" + contract.name)
        self.directory = self.repository / contract.path
        self.directory.mkdir(parents=True, exist_ok=True)
        self.binary = {f"{contract.class_prefix}{name}.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x45fixture-header-only"
            for name in contract.required_classes}
        self.binary[f"META-INF/{contract.group}_{contract.name}.kotlin_module"] = b"fixture"
        attributes = {"Manifest-Version": "1.0", "Automatic-Module-Name": contract.module,
            "Implementation-Title": contract.title, "Implementation-Version": contract.version,
            **dict(contract.manifest_extensions)}
        self.binary["META-INF/MANIFEST.MF"] = ("\r\n".join(f"{key}: {value}" for key, value in attributes.items()) + "\r\n\r\n").encode()
        source_root = contract.binding / "src/main/kotlin"
        self.source = {path.relative_to(source_root).as_posix(): path.read_bytes() for path in source_root.rglob("*.kt")}
        self.source["META-INF/MANIFEST.MF"] = b"Manifest-Version: 1.0\r\n\r\n"
        for name, path in jvm.NOTICE_PATHS.items():
            self.binary[name] = self.source[name] = path.read_bytes()
        self.pom = (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
            f'<groupId>{contract.group}</groupId><artifactId>{contract.name}</artifactId><version>{contract.version}</version>'
            f'<dependencies><dependency><groupId>org.jetbrains.kotlin</groupId><artifactId>kotlin-stdlib</artifactId>'
            f'<version>{contract.kotlin_version}</version><scope>compile</scope></dependency></dependencies></project>')
        self.write_repository()

    def write_repository(self):
        contract = self.contract
        for suffix, files in ((".jar", self.binary), ("-sources.jar", self.source)):
            with zipfile.ZipFile(self.directory / f"{contract.prefix}{suffix}", "w") as archive:
                for name, data in files.items():
                    archive.writestr(name, data)
        (self.directory / f"{contract.prefix}.pom").write_text(self.pom)
        self.module = {"formatVersion": "1.1", "component": {"group": contract.group, "module": contract.name,
            "version": contract.version, "attributes": {"org.gradle.status": "release"}},
            "createdBy": {"gradle": {"version": "9.8.0"}}, "variants": []}
        for variant in ("apiElements", "runtimeElements", "sourcesElements"):
            sources = variant == "sourcesElements"
            name = f"{contract.prefix}{'-sources' if sources else ''}.jar"
            data = (self.directory / name).read_bytes()
            row = {"name": variant, "attributes": {} if sources else {"org.gradle.jvm.version": 25},
                "files": [{"name": name, "url": name, "size": len(data),
                    **{algorithm: hashlib.new(algorithm, data).hexdigest() for algorithm in ("md5", "sha1", "sha256", "sha512")}}]}
            if not sources:
                row["dependencies"] = [{"group": "org.jetbrains.kotlin", "module": "kotlin-stdlib", "version": {"requires": contract.kotlin_version}}]
            self.module["variants"].append(row)
        self.write_module_checksums()

    def write_module_checksums(self):
        (self.directory / f"{self.contract.prefix}.module").write_text(json.dumps(self.module))
        for suffix in (".jar", "-sources.jar", ".pom", ".module"):
            path = self.directory / f"{self.contract.prefix}{suffix}"
            for algorithm in ("md5", "sha1", "sha256", "sha512"):
                path.with_name(f"{path.name}.{algorithm}").write_text(hashlib.new(algorithm, path.read_bytes()).hexdigest())

    def test_structural_fixture_and_checksum_rejection(self):
        self.assertEqual(jvm.verify_maven(self.repository)["coordinate"], jvm.COORDINATE)
        (self.directory / f"{jvm.PREFIX}.jar.sha256").write_text("0" * 64)
        with self.assertRaisesRegex(ValueError, "checksum differs"):
            jvm.verify_maven(self.repository)

    def test_code_selected_profiles_reject_rehashed_kotlin_pom_rebinding(self):
        import continuity_kotlin_consumer as continuity
        for contract, selected, other in ((jvm.product_maven_contract(), "2.4.21", "2.4.20"),
                                          (continuity.maven_contract(), "2.4.20", "2.4.21")):
            with self.subTest(coordinate=contract.coordinate):
                self.assertEqual(contract.kotlin_version, selected)
                self.select_contract(contract)
                self.assertEqual(jvm.verify_maven(self.repository, contract=contract)["coordinate"], contract.coordinate)
                self.pom = self.pom.replace(f"<version>{selected}</version>", f"<version>{other}</version>")
                self.write_repository()
                # Even a coherently changed, rehashed POM and module cannot pick
                # the other product's Kotlin version from candidate bytes.
                for variant in self.module["variants"][:2]:
                    variant["dependencies"][0]["version"]["requires"] = other
                self.write_module_checksums()
                with self.assertRaisesRegex(ValueError, "Maven dependencies differ"):
                    jvm.verify_maven(self.repository, contract=contract)

    def test_code_selected_profiles_reject_rehashed_kotlin_module_rebinding(self):
        import continuity_kotlin_consumer as continuity
        for contract, other in ((jvm.product_maven_contract(), "2.4.20"),
                                (continuity.maven_contract(), "2.4.21")):
            for variant_index in (0, 1):
                with self.subTest(coordinate=contract.coordinate, variant=variant_index):
                    self.select_contract(contract)
                    self.module["variants"][variant_index]["dependencies"][0]["version"]["requires"] = other
                    self.write_module_checksums()
                    with self.assertRaisesRegex(ValueError, "Gradle JVM version or dependency differs"):
                        jvm.verify_maven(self.repository, contract=contract)

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
