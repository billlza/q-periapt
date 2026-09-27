"""Maven metadata and bundle mutations; synthetic AAR bytes are never runtime evidence."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import android_elf
import android_sdk_package as sdk


class AndroidSDKPackageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / "maven"
        self.directory = self.repo / sdk.MAVEN_PATH
        self.directory.mkdir(parents=True)
        self.aar = b"structural fixture only; not an executable AAR"
        self.sha = hashlib.sha256(self.aar).hexdigest()
        (self.directory / f"{sdk.PREFIX}.aar").write_bytes(self.aar)
        self.pom = (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>dev.qperiapt</groupId>'
                    f'<artifactId>{sdk.NAME}</artifactId><version>{sdk.VERSION}</version><packaging>aar</packaging></project>')
        source = sdk.ROOT / "bindings/android/src/main/java"
        self.sources = {p.relative_to(source).as_posix(): p.read_bytes() for p in source.rglob("*.java")}
        self.sources.update({f"META-INF/licenses/{name}": (sdk.ROOT / "LICENSES" / name).read_bytes()
                            for name in ("Apache-2.0.txt", "MIT.txt")})
        self.sources["META-INF/MANIFEST.MF"] = b"Manifest-Version: 1.0\r\n\r\n"
        self.update()

    def update(self):
        (self.directory / f"{sdk.PREFIX}.pom").write_text(self.pom)
        with zipfile.ZipFile(self.directory / f"{sdk.PREFIX}-sources.jar", "w") as archive:
            archive.writestr("META-INF/", b"")
            for name, data in self.sources.items():
                archive.writestr(name, data)
        for suffix in (".aar", ".pom", "-sources.jar"):
            path = self.directory / f"{sdk.PREFIX}{suffix}"
            for algorithm in ("md5", "sha1", "sha256", "sha512"):
                path.with_name(path.name + "." + algorithm).write_text(hashlib.new(algorithm, path.read_bytes()).hexdigest())

    def test_gradle_directory_records_and_checksum_pins(self):
        sdk.verify_maven(self.repo, self.sha)
        with self.assertRaisesRegex(ValueError, "AAR differs"):
            sdk.verify_maven(self.repo, "0" * 64)
        (self.directory / f"{sdk.PREFIX}.pom.sha256").write_text("0" * 64)
        with self.assertRaisesRegex(ValueError, "checksum differs"):
            sdk.verify_maven(self.repo, self.sha)

    def test_rehashed_pom_changes_are_rejected(self):
        original = self.pom
        for text, reason in ((original.replace(sdk.VERSION, "0.1.5"), "coordinate or packaging"),
                             (original.replace("<packaging>aar</packaging>", "<packaging>jar</packaging>"), "coordinate or packaging"),
                             (original.replace("</project>", "<dependencies/></project>"), "dependency or resolution override")):
            with self.subTest(pom=text):
                self.pom = text
                self.update()
                with self.assertRaisesRegex(ValueError, reason):
                    sdk.verify_maven(self.repo, self.sha)

    def test_rehashed_source_and_unsafe_jar_entry_rejected(self):
        name = "dev/qperiapt/android/QPeriaptSDK.java"
        original = self.sources[name]
        self.sources[name] += b"\n// changed source\n"
        self.update()
        with self.assertRaisesRegex(ValueError, "sources JAR or project notices"):
            sdk.verify_maven(self.repo, self.sha)
        self.sources[name] = original
        self.sources["../outside.java"] = b"unsafe path"
        self.update()
        with self.assertRaisesRegex(android_elf.AndroidVerificationError, "traverses a parent"):
            sdk.verify_maven(self.repo, self.sha)
        self.assertFalse((self.root.parent / "outside.java").exists())

    def test_bundle_pin_inventory_and_publication_flag(self):
        (self.root / "README.md").write_bytes((sdk.ROOT / "bindings/android/PackageREADME.md").read_bytes())
        (self.root / "MANIFEST.json").write_text("{}\n")
        contents = {"schema": 1, "coordinate": sdk.COORDINATE, "source_tree_sha256": "a" * 64,
                    "aar_sha256": self.sha, "aar_manifest_sha256": sdk.snapshot(self.root / "MANIFEST.json").sha256,
                    "files": sdk.entries(self.root), "release_claim_eligible": False}
        sdk.write_json(self.root / sdk.CONTENTS, contents)
        pin = sdk.snapshot(self.root / sdk.CONTENTS).sha256
        sdk.verify_bundle(self.root, pin)
        with self.assertRaisesRegex(ValueError, "pinned manifest"):
            sdk.verify_bundle(self.root, "0" * 64)
        (self.root / "extra").write_bytes(b"unlisted")
        with self.assertRaisesRegex(ValueError, "inventory or digest"):
            sdk.verify_bundle(self.root, pin)
        (self.root / "extra").unlink()
        contents["release_claim_eligible"] = True
        (self.root / sdk.CONTENTS).write_text(json.dumps(contents))
        with self.assertRaisesRegex(ValueError, "candidate identity"):
            sdk.verify_bundle(self.root, sdk.snapshot(self.root / sdk.CONTENTS).sha256)


if __name__ == "__main__":
    unittest.main()
