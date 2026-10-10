"""Negative controls for public managed-C readback, not runtime crypto evidence."""
from pathlib import Path
import tempfile
import unittest

import continuity_c_managed as managed
from continuity_c_witness import commit

STDOUT = (f"test {managed.TEST} ... ok\n"
          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;\n").encode()


def evidence(root: Path):
    s, m, n = (bytes([value]) * 32 for value in (10, 11, 12))
    sh, mh, nh = s.hex(), m.hex(), n.hex()
    def write(name, data):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for name, data in [("managed-session", s), ("managed-message", m), ("managed-next-message", n),
                       ("managed-traffic-result", managed.MARKER)]:
        write(name, data)
    outputs = {"connect": sh+"\n", "next": mh+"\n", "wrong-registry": "managed-rejected:211\n",
               "bad-witness": "managed-rejected:218\n", "uncertain": "managed-delivery-unknown:2\n",
               "closed": "managed-closed query=202 send=1202 reopened_registry_old_owner=1202 original_status=2\n",
               "resend": "managed-consumed:3\n", "rekey": "managed-rekey:1\n",
               "next-rekey": nh+"\n", "post-rekey": "managed-consumed:3\n"}
    for label, output in outputs.items():
        write(f"managed-{label}.stdout", output.encode())
        write(f"managed-{label}.stderr", b"")
    servers = {"bootstrap": f"served:1:0:0:0\n{sh}\n{'0'*64}\n", "unknown": "",
               "resend": f"served:2:0:1:0\n{sh}\n{mh}\n", "rekey": "server-rekey-1\n",
               "post-rekey": f"served:2:0:1:1\n{sh}\n{nh}\n"}
    for label, output in servers.items():
        write(f"traffic-{label}.stdout", ("listening:40001\n"+output).encode())
        write(f"traffic-{label}.stderr", b"")
    for message in (m, n):
        write("responder/application-"+message.hex(), s+message+b"persisted before process exit")
    identity, key = b"w"*32, b"k"*1985
    write("initiator/witness-id", identity)
    write("initiator/witness-public", key)
    authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", identity+key)
    records = []
    for ordinal in (1, 2):
        subject = bytes([ordinal])*96
        first = (1).to_bytes(8, "big")*2+bytes([ordinal+2])*32
        following = (1).to_bytes(8, "big")+(2).to_bytes(8, "big")+bytes([ordinal+4])*32
        for step, operation, outcome, head in [(0, b"\x01"+bytes(96), 1, first),
                                               (1, b"\x02"+first+following, 2, following)]:
            command = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority+subject+operation)
            request = b"QPANRQ01"+authority+subject+command+bytes([ordinal*10+step])*32+operation
            reply = (b"QPANRS01"+authority+subject+commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", request)
                     +command+bytes([outcome])+head+bytes([step])+(command if step else bytes(32)))
            records.append(b"\x01"+len(request).to_bytes(4,"big")+request+bytes(3373)
                           +len(reply).to_bytes(4,"big")+reply+bytes(3373))
    write("managed-witness-transcript", b"".join(records))
    write("managed-witness-exchanges", (4).to_bytes(8,"big"))


class ManagedCReadbackTests(unittest.TestCase):
    def test_complete_readback_keeps_its_narrow_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence(root)
            result = managed.verify_execution(STDOUT, root)
            self.assertTrue(result["host_effect_deduplicated"])
            self.assertFalse(result["release_claim_eligible"])
            self.assertEqual((result["query_closed"], result["send_closed"]), (202, 1202))

    def test_missing_execution_or_changed_original_operation_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence(root)
            for stdout in (b"", STDOUT.replace(b"1 passed", b"0 passed"), STDOUT.replace(b" ... ok", b" ... ignored")):
                with self.subTest(stdout=stdout), self.assertRaises(ValueError):
                    managed.verify_execution(stdout, root)
            changes = [("managed-traffic-result", b"release_qualified=true\n"),
                       ("managed-uncertain.stdout", b"managed-consumed:3\n"),
                       ("managed-closed.stdout", b"managed-closed:202\n"),
                       ("traffic-resend.stdout", b"listening:40001\nserved:2:0:1:1\n"),
                       ("managed-next-message", bytes([11])*32),
                       ("managed-witness-exchanges", (3).to_bytes(8,"big")),
                       ("managed-rekey.stderr", b"failed after commit\n")]
            for name, value in changes:
                path = root/name
                before = path.read_bytes()
                path.write_bytes(value)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    managed.verify_execution(STDOUT, root)
                path.write_bytes(before)

    def test_extra_or_changed_host_effect_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence(root)
            path = root/"responder/application-extra"
            path.write_bytes(b"extra external effect")
            with self.assertRaisesRegex(ValueError, "census"):
                managed.verify_execution(STDOUT, root)
            path.unlink()
            path = root/("responder/application-"+(bytes([11])*32).hex())
            path.write_bytes(b"wrong host input")
            with self.assertRaisesRegex(ValueError, "host effect"):
                managed.verify_execution(STDOUT, root)


if __name__ == "__main__":
    unittest.main()
