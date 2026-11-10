"""Synthetic reader counterexamples; not cryptographic or device evidence."""
from pathlib import Path
import tempfile
import unittest
import continuity_android_remote_credential as remote
from test_continuity_android_credential import fixture as local_fixture

def fixture(root: Path) -> bytes:
    stdout=local_fixture(root)
    for carrier in ("signed","tls"):
        for profile in ("fixed","recoverable"):
            base=root/(carrier+"-"+profile);pending=b"x"*32+b"n"*32;target=(2).to_bytes(8,"big")+b"e"*32
            values={"remote-uncertain":pending,"remote-acknowledged":pending,"remote-self-refused":(211).to_bytes(4,"big"),
                "remote-admitted":target+b"z"*32,"remote-reopened":target+b"z"*32,"remote-effect-count":(2).to_bytes(4,"big"),
                "remote-effect-before":pending+b"persisted before process exit","remote-effect-after":pending+b"persisted before process exit",
                "inputs/remote-operation":b"u"*32,"inputs/remote-statement":b"v"*32,"inputs/remote-version":target[:8],
                "inputs/remote-digest":target[8:],"inputs/remote-grant":b"synthetic-reader-input"}
            proposal=bytearray(296);proposal[:8]=b"QPCRNP01";proposal[136:168]=b"u"*32;proposal[168:200]=b"v"*32
            values["remote-native-proposal"]=proposal
            for name,mode in remote.CASES:
                values[name+".stdout"]=f"{profile}:{mode}:passed\n".encode();values[name+".stderr"]=b""
            for name in remote.NATIVE:
                if name=="credential-witness-prepare":text="credential-witness-prepared\n"
                else:
                    phase=1 if name=="credential-stage" else 2;version=0 if phase==1 else 2;digest=bytes(32) if phase==1 else b"e"*32
                    text=f"credential-phase:{phase}\n{(b'u'*32).hex()}\n{(b'v'*32).hex()}\ncredential-head:{version}\n{digest.hex()}\ncredential-observed:0\n"
                values["remote-native-"+name+".stdout"]=text.encode();values["remote-native-"+name+".stderr"]=b""
            for mode,text in (("crash",""),("message",f"served:2:0:1:0\n{pending[:32].hex()}\n{pending[32:].hex()}\n")):
                values["traffic-remote-credential-"+mode+".stdout"]=("listening:12345\n"+text).encode()
                values["traffic-remote-credential-"+mode+".stderr"]=b""
            for name,data in values.items():(base/name).write_bytes(data)
            stdout+=f"qualified remote credential {carrier}/{profile}: explicit remote grant, stale peer refusal, original pending message, restart, exact retry, two distinct business effects\n".encode()
    return stdout

class RemoteCredentialReaderTests(unittest.TestCase):
    def test_complete_routes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);stdout=fixture(root);result=remote.verify_execution(stdout,root)
            self.assertEqual(sum(v["foreign_processes"] for v in result.values()),150)
            self.assertTrue(all(v["remote_renewal_qualified"] for v in result.values()))
            with self.assertRaises(ValueError):remote.verify_execution(stdout.replace(b"qualified remote credential tls/fixed",b"missing"),root)
    def test_original_target_message_and_effect_cannot_be_replaced(self):
        for name in ("remote-reopened","remote-acknowledged","remote-effect-after","remote-effect-count","remote-native-proposal",
                     "remote-self-refused","inputs/remote-digest","remote-native-credential-witness-commit.stdout"):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);stdout=fixture(root);p=root/"signed-fixed"/name;data=p.read_bytes();p.write_bytes(bytes([data[0]^1])+data[1:])
                with self.assertRaises(ValueError):remote.verify_execution(stdout,root)
    def test_native_diagnostics_and_substituted_receiver_are_refused(self):
        for name in ("remote-native-credential-stage.stderr","traffic-remote-credential-message.stderr"):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);stdout=fixture(root);(root/"tls-recoverable"/name).write_bytes(b"unexpected diagnostic")
                with self.assertRaises(ValueError):remote.verify_execution(stdout,root)

if __name__=="__main__":unittest.main()
