import base64
import csv
import hashlib
import io
import json
import unittest
import zipfile

from continuity_independent_python import DIST, PACKAGE, inspect_wheel, verify_installation, verify_extension_session


class ExtensionSessionReceiptTests(unittest.TestCase):
    def report(self):
        return {"schema_version":1,"kind":"qperiapt.enrollment_extension_session","completed":True,
                "provider":"48.0.1","implementation":"/installed/client.py","native_sha256":"a"*64,
                "profiles":[{"completed":True,"profile":name,"native_commands":commands,
                    "witness_requests":witness,"bootstrap_time":210,"traffic_time":220,
                    "original_expiry":160,"extended_expiry":300,"confirmed_epoch":1,
                    "refusal_cases":["expired-original-policy","selected-installation-refuses-extension","extended-credential-expiry"]}
                    for name,commands,witness in [("local",13,0),("witness",125,110)]]}

    def verify(self, report):
        verify_extension_session(report,implementation="/installed/client.py",native_sha256="a"*64)

    def test_both_complete_profiles(self):
        self.verify(self.report())

    def test_old_clock_partial_work_or_false_types_cannot_claim_extension_session(self):
        for field,value in [("bootstrap_time",150),("traffic_time",170),("original_expiry",300),
                            ("confirmed_epoch",0),("confirmed_epoch",True),("completed",1),
                            ("witness_requests",0),("native_commands",124),("refusal_cases",[])]:
            with self.subTest(field=field,value=value):
                report=self.report(); report["profiles"][1][field]=value
                with self.assertRaisesRegex(ValueError,"workload, time or refusal"):
                    self.verify(report)

    def test_wrong_native_installed_owner_or_missing_profile_is_rejected(self):
        for field,value in [("native_sha256","b"*64),("implementation","/checkout/client.py"),
                            ("completed",False),("profiles",[]),("schema_version",True)]:
            with self.subTest(field=field):
                report=self.report(); report[field]=value
                with self.assertRaises(ValueError): self.verify(report)


class WheelBoundaryTests(unittest.TestCase):
    sources = {"__init__.py": b'"""Reference package."""\n', "wire.py": b"VALUE = 1\n"}
    licenses = {"LICENSE-APACHE": b"Apache text\n", "LICENSE-MIT": b"MIT text\n"}
    readme = b"Reference scope.\n"

    @staticmethod
    def record(files):
        record = io.StringIO(newline="")
        writer = csv.writer(record)
        for name, body in files.items():
            if name == DIST + "/RECORD":
                continue
            digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
            writer.writerow([name, "sha256=" + digest, str(len(body))])
        writer.writerow([DIST + "/RECORD", "", ""])
        return record.getvalue().encode()

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
        files[DIST + "/RECORD"] = self.record(files)
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

    def installed(self, mutate=lambda files: None):
        wheel = self.wheel()
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            original = {name: archive.read(name) for name in archive.namelist()}
        files = dict(original)
        digest = hashlib.sha256(wheel).hexdigest()
        url = "file:///private/reference.whl"
        files[DIST + "/INSTALLER"] = b"pip\n"
        files[DIST + "/REQUESTED"] = b""
        files[DIST + "/direct_url.json"] = json.dumps({"url": url, "archive_info": {
            "hash": "sha256=" + digest, "hashes": {"sha256": digest}}}).encode()
        mutate(files)
        files[DIST + "/RECORD"] = self.record(files)
        return files, original, url, digest

    def test_pip_metadata_is_bound_to_selected_wheel(self):
        files, original, url, digest = self.installed()
        verify_installation(files, original, wheel_url=url, digest=digest)

    def test_editable_install_is_not_a_wheel_consumer(self):
        def change(files):
            files[DIST + "/direct_url.json"] = b'{"url":"file:///checkout","dir_info":{"editable":true}}'
        files, original, url, digest = self.installed(change)
        with self.assertRaisesRegex(ValueError, "origin differs"):
            verify_installation(files, original, wheel_url=url, digest=digest)

    def test_valid_installed_record_does_not_authorize_source_change(self):
        files, original, url, digest = self.installed(lambda f: f.update({PACKAGE + "/wire.py": b"VALUE = 2\n"}))
        with self.assertRaisesRegex(ValueError, "installed source or metadata differs"):
            verify_installation(files, original, wheel_url=url, digest=digest)
