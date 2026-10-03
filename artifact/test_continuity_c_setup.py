"""Parser controls use synthetic public bytes, not native or cryptographic proof."""
import json
from pathlib import Path
import tempfile
import unittest
import continuity_c_setup as setup


class ContinuityCSetupTests(unittest.TestCase):
    def fixture(self, directory):
        journal, batch = b"j" * 32, b"b" * 32
        data = {"setup-original-journal": journal,
            "setup-local-result.json": json.dumps(dict(schema_version=1, language="C", completed=True,
                pre_cancel_absent=True, same_genesis=True, active_prepare_refused=True, release_claim_eligible=False)).encode()}
        prepared = b"setup-prepared:1\n"+journal.hex().encode()+b"\n"+b"0"*192+b"\n"+b"0"*64+b"\n"
        commands = dict(create=b"setup-status:1\n"+journal.hex().encode()+b"\n",
            creating=b"setup-status:1\n"+journal.hex().encode()+b"\n",
            active=b"setup-status:2\n"+journal.hex().encode()+b"\n",
            prepare=prepared, **{"prepare-repeat":prepared,"precancel":b"setup-refused:302\n",
            "active-refuses-prepare":b"setup-refused:211\n"},
            activate=b"setup-activated\n"+batch.hex().encode()+b"\n",
            reactivate=b"setup-activated\n"+batch.hex().encode()+b"\n")
        for label, output in commands.items():
            data["setup-"+label+".stdout"] = output
            data["setup-"+label+".stderr"] = b""
        for name, value in data.items(): (directory/name).write_bytes(value)
        return ("test "+setup.TESTS["local"]+" ... ok\n"
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;\n").encode()

    def test_original_creation_and_active_phase_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout = self.fixture(root)
            checked = setup.verify_execution(stdout,root,scenario="local")
            self.assertEqual(len(checked["public_readbacks"]|checked["command_logs"]),20)
            for name, bad in [("setup-original-journal", b"x"*32),
                ("setup-create.stdout", (root/"setup-active.stdout").read_bytes()),
                ("setup-prepare-repeat.stdout", b"setup-refused:211\n"),
                ("setup-active-refuses-prepare.stdout", (root/"setup-prepare.stdout").read_bytes()),
                ("setup-activate.stderr", b"activation failed\n"),
                ("setup-reactivate.stdout", b"setup-activated\n"+b"e"*64+b"\n")]:
                original = (root/name).read_bytes()
                (root/name).write_bytes(bad)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    setup.verify_execution(stdout,root,scenario="local")
                (root/name).write_bytes(original)

    def test_report_cannot_relabel_scope_or_replace_required_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stdout = self.fixture(root)
            report = json.loads((root/"setup-local-result.json").read_bytes())
            for key, value in [("schema_version",True),("language","Swift"),("same_genesis",False),
                               ("release_claim_eligible",True),("extra",True)]:
                (root/"setup-local-result.json").write_text(json.dumps(dict(report,**{key:value})))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    setup.verify_execution(stdout,root,scenario="local")
            (root/"setup-local-result.json").write_text(json.dumps(report))
            with self.assertRaises(ValueError): setup.verify_execution(stdout,root,scenario="witness")
            with self.assertRaises(ValueError): setup.verify_execution(stdout.replace(b"4 filtered",b"3 filtered"),root,scenario="local")

    def test_helper_requires_native_and_both_setup_tests(self):
        from continuity_package import TESTS
        names = sorted(set(setup.TESTS.values()) | {"fixture::"+name for name in TESTS})
        inventory = ("\n".join(name+": test" for name in names)+"\n5 tests, 0 benchmarks\n").encode()
        setup.helper_inventory(inventory)
        with self.assertRaises(ValueError): setup.helper_inventory(inventory.replace((names[0]+": test\n").encode(),b""))
        with self.assertRaises(ValueError): setup.helper_inventory(inventory.replace(b"5 tests",b"4 tests"))
