import base64
import csv
import hashlib
import io
import unittest
import zipfile

from continuity_independent_python import DIST, PACKAGE, inspect_wheel


class WheelBoundaryTests(unittest.TestCase):
    sources = {"__init__.py": b'"""Reference package."""\n', "wire.py": b"VALUE = 1\n"}
    licenses = {"LICENSE-APACHE": b"Apache text\n", "LICENSE-MIT": b"MIT text\n"}
    readme = b"Reference scope.\n"

    def wheel(self, mutate=lambda files: None):
        files = {PACKAGE + "/" + n: b for n, b in self.sources.items()}
        files.update({DIST + "/licenses/" + n: b for n, b in self.licenses.items()})
        files[DIST + "/METADATA"] = (
            "Metadata-Version: 2.5\nName: qperiapt-continuity-reference\nVersion: 0.0.0\n"
            "Requires-Python: >=3.14,<3.15\nLicense-Expression: Apache-2.0 OR MIT\n"
            "Classifier: Private :: Do Not Upload\nRequires-Dist: cryptography==48.0.1\n"
            "Import-Name: qperiapt_continuity_reference\nLicense-File: LICENSE-APACHE\n"
            "License-File: LICENSE-MIT\n\n").encode() + self.readme + b"\n"
        files[DIST + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: flit 4.1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        mutate(files)
        record = io.StringIO(newline="")
        writer = csv.writer(record)
        for name, body in files.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
            writer.writerow([name, "sha256=" + digest, str(len(body))])
        writer.writerow([DIST + "/RECORD", "", ""])
        files[DIST + "/RECORD"] = record.getvalue().encode()
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in files.items():
                archive.writestr(name, body)
        return output.getvalue()

    def test_closed_source_package(self):
        files = inspect_wheel(self.wheel(), self.sources, self.licenses, self.readme)
        self.assertEqual(files[PACKAGE + "/wire.py"], self.sources["wire.py"])

    def test_valid_record_does_not_authorize_changed_source(self):
        with self.assertRaisesRegex(ValueError, "source or license differs"):
            inspect_wheel(self.wheel(lambda f: f.update({PACKAGE + "/wire.py": b"VALUE = 2\n"})),
                          self.sources, self.licenses, self.readme)

    def test_added_import_hook_is_not_installed(self):
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            inspect_wheel(self.wheel(lambda f: f.update({"reference.pth": b"import hidden_hook\n"})),
                          self.sources, self.licenses, self.readme)

    def test_dependency_pin_cannot_be_widened(self):
        def change(files):
            name = DIST + "/METADATA"
            files[name] = files[name].replace(b"cryptography==48.0.1", b"cryptography>=48")
        with self.assertRaisesRegex(ValueError, "Requires-Dist"):
            inspect_wheel(self.wheel(change), self.sources, self.licenses, self.readme)

    def test_description_bytes_cannot_be_rewritten(self):
        def change(files):
            name = DIST + "/METADATA"
            files[name] = files[name].replace(self.readme, b"Different support promise.\n")
        with self.assertRaisesRegex(ValueError, "README differ"):
            inspect_wheel(self.wheel(change), self.sources, self.licenses, self.readme)

    def test_stale_record_is_rejected(self):
        with zipfile.ZipFile(io.BytesIO(self.wheel())) as original:
            files = {name: original.read(name) for name in original.namelist()}
        name = DIST + "/WHEEL"
        files[name] += b"\n"
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, body in files.items():
                archive.writestr(name, body)
        with self.assertRaisesRegex(ValueError, "RECORD content"):
            inspect_wheel(output.getvalue(), self.sources, self.licenses, self.readme)
