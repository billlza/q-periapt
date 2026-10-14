"""Reader rejection controls only; these synthetic frames are not crypto evidence."""
from pathlib import Path
import tempfile
import unittest
import zipfile
import rust_sdk_profile as sdk

import continuity_android_contract as contract
import continuity_android_pending as pending


def fixture(directory: Path, label: str = pending.LABEL) -> bytes:
    root = directory / label; (root / "inputs").mkdir(parents=True)
    carrier, trust, outcome = label.split("-"); applied = outcome == "applied"
    proposal = b"QPWRPL01" + bytes([1]) * 385
    metadata = b"QPWRMD01" + proposal[8:361] + (96).to_bytes(8,"big") + bytes([2])*96 + (96).to_bytes(8,"big") + bytes([3])*96
    frame = len(metadata).to_bytes(4,"big") + (1).to_bytes(4,"big") + proposal + bytes(3) + bytes([4])*32 + metadata + b"s"
    for name,mode in pending.cases(applied):
        (root/(name+".stdout")).write_bytes(f"{trust}:{mode}:passed\n".encode())
        (root/(name+".stderr")).write_bytes(b"")
    for name in ["original.request","activated.request","original-identity-after"]:
        (root/name).write_bytes(b"r"*5506)
    for name in ["pending-before-expiry","pending-after-expiry","pending-after-cancel"]:(root/name).write_bytes(frame)
    for name,code in [("roster-peer-unassociated",201),("original-roster-unknown",218),("damaged-metadata",102),
                      ("unapproved",103),("pending-absent",201),("still-expired",104),("cancelled",302)]:
        (root/name).write_bytes(code.to_bytes(4,"big"))
    for name in ["confirmed","retried"]:(root/name).write_bytes(b"\1")
    for name,data in [("inputs/pending-proposal",proposal),("inputs/pending-metadata",metadata),
                      ("inputs/connection-session",b"a"*32),("inputs/connection-message",b"b"*32),
                      ("roster-connected",b"a"*32),("roster-unknown",b"a"*32+b"b"*32),
                      ("roster-effect-before",b"a"*32+b"b"*32+b"persisted before process exit"),
                      ("expiry-observation",(100).to_bytes(8,"big")+(101).to_bytes(8,"big")),
                      ("unprocessed-original-advance",bytes(204)+b"\2"+bytes(3469)),
                      ("processed-original-advance",bytes(204)+b"\2"+bytes(3469)),
                      ("original-advance-reply",bytes(204)+b"\2"+bytes(3454)),
                      ("controller-read-only",bytes([applied])),("completed",pending.COMPLETED)]:
        (root/name).write_bytes(data)
    return (pending.marker(label)+"\n"+"test "+pending.TESTS[label]+" ... ok\n"+
        f"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {len(contract.TESTS)-1} filtered out;\n").encode()


class PendingWriteReaderTests(unittest.TestCase):
    def test_complete_scenario_requires_new_catalog_test_and_all_processes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);stdout=fixture(root)
            self.assertEqual(pending.verify_execution(stdout,root)[pending.LABEL]["foreign_processes"],20)
            for bad in [stdout.replace(b"1 passed",b"0 passed"),stdout.replace(b"0 ignored",b"1 ignored"),
                        stdout.replace(pending.marker(pending.LABEL).encode(),b"omitted"),stdout+pending.marker(pending.LABEL).encode()+b"\n"]:
                with self.assertRaises(ValueError):pending.verify_execution(bad,root)
            old="\n".join(name+": test" for name in sorted(contract.JOINT_CYCLE_TESTS))
            with self.assertRaises(ValueError):contract.verify_catalog((old+f"\n{len(contract.JOINT_CYCLE_TESTS)} tests, 0 benchmarks\n").encode())

    def test_missing_data_diagnostics_or_success_coercion_are_rejected(self):
        changes=[("completed",b""),("retried",b""),("still-expired",b"\1"),("unapproved",b"\1"),
                 ("confirmed.stderr",b"native failure"),("pending-after-expiry.stdout",b""),
                 ("original-identity-after",b"x"*5506),("expiry-observation",bytes(16)),
                 ("unprocessed-original-advance",bytes(3674)),("roster-effect-before",b"another effect"),
                 ("cancelled",b"\1"),("pending-after-cancel",b""),("controller-read-only",b"\1")]
        for name,data in changes:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);stdout=fixture(root);(root/pending.LABEL/name).write_bytes(data)
                with self.assertRaises(ValueError):pending.verify_execution(stdout,root)

    def test_applied_route_requires_real_advance_reply_and_read_only_completion(self):
        for label in pending.TESTS:
            with self.subTest(label=label),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);stdout=fixture(root,label)
                self.assertEqual(pending.verify_execution(stdout,root,label)[label]["foreign_processes"],19 if label.endswith("-applied") else 20)
                if label.endswith("-applied"):
                    path=root/label/"original-advance-reply";path.write_bytes(bytes(3659))
                    with self.assertRaises(ValueError):pending.verify_execution(stdout,root,label)

    def test_complete_batch_cannot_omit_or_repeat_a_route(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for label in pending.TESTS:fixture(root,label)
            stdout=("\n".join(pending.marker(label) for label in pending.TESTS)+"\n"+
                "\n".join("test "+test+" ... ok" for test in pending.TESTS.values())+"\n"+
                f"test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; {len(contract.TESTS)-8} filtered out;\n").encode()
            for label in pending.TESTS:pending.verify_execution(stdout,root,label,batch=True)
            for bad in [stdout.replace(b"8 passed",b"7 passed"),stdout+b"test "+pending.TEST.encode()+b" ... ok\n"]:
                with self.assertRaises(ValueError):pending.verify_execution(bad,root,batch=True)

    def test_prior_physical_capture_uses_its_explicit_historical_contract(self):
        archive=sdk.ROOT/'research/sdk-alpha1/evidence/20261014-configured-pending-write-inspection/CAPTURE.zip'
        with tempfile.TemporaryDirectory() as temp,zipfile.ZipFile(archive) as bundle:
            root=Path(temp)
            for name in bundle.namelist():
                if name.startswith('device/public/'):
                    path=root/name.removeprefix('device/public/');path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(bundle.read(name))
            stdout=bundle.read('device/execution.stdout')
            result=pending.verify_execution(stdout,root,legacy=True,catalog=contract.SINGLE_PENDING_TESTS)
            self.assertEqual(result[pending.LABEL]['foreign_processes'],18)
            with self.assertRaises(ValueError):pending.verify_execution(stdout,root)

    def test_partial_or_substituted_complete_metadata_cannot_pass(self):
        for kind in ["truncated","tail","reserved","length","changed"]:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);stdout=fixture(root);path=root/pending.LABEL/"pending-after-expiry"
                data=bytearray(path.read_bytes())
                if kind=="truncated":data=data[:-1]
                elif kind=="tail":data+=b"x"
                elif kind=="reserved":data[401]=1
                elif kind=="length":data[:4]=bytes([255])*4
                else:data[-2]^=1
                path.write_bytes(data)
                with self.assertRaises(ValueError):pending.verify_execution(stdout,root)


if __name__=="__main__":unittest.main()
