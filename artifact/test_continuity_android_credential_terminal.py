"""Synthetic reader counterexamples, not expiry or cryptographic evidence."""
from pathlib import Path
import tempfile
import unittest
import continuity_android_credential_terminal as terminal
import continuity_android_credential as credential
import continuity_android_remote_credential as remote
import continuity_android_witness as witness
from test_continuity_android_remote_credential import fixture as remote_fixture

def fixture(root:Path)->bytes:
    stdout=remote_fixture(root)
    for carrier in ("signed","tls"):
        for profile in ("fixed","recoverable"):
            base=root/(carrier+"-"+profile);operation=b"q"*32;statement=b"r"*32;target=(3).to_bytes(8,"big")+b"c"*32
            pending=(1).to_bytes(4,"big")+operation+statement+bytes(48);closed=(4).to_bytes(4,"big")+operation+statement+target+bytes(8)
            values={"terminal-close-committed":(base/"credential-recovered").read_bytes(),"terminal-expiry-committed":(base/"credential-recovered").read_bytes(),
                "inputs/terminal-operation":operation,"inputs/terminal-statement":statement,"inputs/terminal-version":target[:8],"inputs/terminal-digest":target[8:],
                "inputs/terminal-grant":b"synthetic-reader-input","terminal-expiry-observation":b"".join(n.to_bytes(8,"big") for n in (100,101,200,300)),
                "terminal-active":(base/"credential-original-identity").read_bytes()+b"z"*32,"terminal-effect-count":(3).to_bytes(4,"big")}
            for name in ("terminal-staged","terminal-pending","terminal-pending-expired"):values[name]=pending
            for name in ("terminal-status-closed","terminal-reconciled","terminal-close-replayed","terminal-commit-replayed"):values[name]=closed
            for name,code in (("terminal-reserved-refused",215),("terminal-activate-refused",215),("terminal-expired-refused",215),("terminal-expired-stage-refused",104),("terminal-cleanup-unknown",218)):values[name]=code.to_bytes(4,"big")
            cancel=bytearray(248);cancel[:8]=b"QPCRNC01";cancel[136:168]=operation;cancel[168:200]=statement
            values["terminal-cancellation"]=cancel;values["terminal-cancellation-replayed"]=cancel
            request,reply=bytearray(3674),bytearray(3659);request[204]=8;reply[204]=11
            values["terminal-lost-ack-request"]=request;values["terminal-lost-ack-reply"]=reply
            values["terminal-no-commit-transcript"]=b"\0"+request+reply
            sent=b"x"*32+b"z"*32;values["terminal-sent"]=sent;values["terminal-effect"]=sent+b"persisted before process exit"
            values["traffic-terminal-credential-message.stderr"]=b""
            values["traffic-terminal-credential-message.stdout"]=f"listening:12345\nserved:2:0:1:1\n{sent[:32].hex()}\n{sent[32:].hex()}\n".encode()
            for name,mode in terminal.CASES:values[name+".stdout"]=f"{profile}:{mode}:passed\n".encode();values[name+".stderr"]=b""
            for name,data in values.items():(base/name).write_bytes(data)
            stdout+=f"qualified credential terminal {carrier}/{profile}: committed outcome retained, real roster expiry, independent cancellation, lost cleanup acknowledgment, original authority and traffic restored\n".encode()
    return stdout

class TerminalReaderTests(unittest.TestCase):
    def test_export_preserves_base_witness_and_all_credential_layers(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp)/"source";source.mkdir()
            output=Path(temp)/"output";output.mkdir()
            stdout=fixture(source);expected=terminal.verify_execution(stdout,source)
            witness.export_public(stdout,source,output,"android-jni-release-credential-",expected,
                managed=True,extra_public=credential.PUBLIC+remote.PUBLIC+terminal.PUBLIC,
                verifier=terminal.verify_execution)
            for label in expected:
                for name in ("original.request","credential-proposal","remote-admitted","terminal-no-commit-transcript"):
                    self.assertEqual((output/("android-jni-release-credential-"+label+"-"+name+".public")).read_bytes(),
                                     (source/label/name).read_bytes())

    def test_complete_and_missing_route(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);stdout=fixture(root);result=terminal.verify_execution(stdout,root)
            self.assertEqual(sum(r["foreign_processes"] for r in result.values()),222)
            self.assertTrue(all(r["witnessed_expiry_cancellation_qualified"] and not r["local_only_expired_uncommitted_qualified"] for r in result.values()))
            with self.assertRaises(ValueError):terminal.verify_execution(stdout.replace(b"qualified credential terminal tls/fixed",b"missing"),root)
    def test_original_commit_pending_closed_identity_and_effect_are_retained(self):
        for name in ("terminal-close-committed","terminal-pending-expired","terminal-status-closed","terminal-cancellation-replayed","terminal-active","terminal-effect-count"):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);stdout=fixture(root);path=root/"signed-fixed"/name;data=path.read_bytes();path.write_bytes(bytes([data[0]^1])+data[1:])
                with self.assertRaises(ValueError):terminal.verify_execution(stdout,root)
    def test_real_expiry_and_lost_ack_cannot_be_substituted(self):
        for name,offset,value in (("terminal-expiry-observation",15,99),("terminal-no-commit-transcript",0,1),
                                 ("terminal-no-commit-transcript",205,5),("terminal-no-commit-transcript",205,7),("terminal-lost-ack-reply",204,9)):
            with self.subTest(name=name,offset=offset,value=value),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);stdout=fixture(root);path=root/"tls-fixed"/name;data=bytearray(path.read_bytes());data[offset]=value;path.write_bytes(data)
                with self.assertRaises(ValueError):terminal.verify_execution(stdout,root)

if __name__=="__main__":unittest.main()
