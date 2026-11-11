"""Synthetic rejection controls are not device or cryptographic evidence."""
from pathlib import Path
import tempfile
import unittest
import continuity_android_local_credential as local
import continuity_android_jni as android
import rust_sdk_profile as sdk
from test_continuity_android_jni import fixture as baseline

def fixture(root):
    stdout=baseline(root)
    for profile in ("fixed","recoverable"):
        base=root/profile;(base/"inputs").mkdir()
        first=b"a"*32+b"b"*32;second=b"c"*32+b"d"*32
        previous=(1).to_bytes(8,"big")+b"e"*32;target=(3).to_bytes(8,"big")+b"f"*32
        identity=b"g"*64+b"h"*32;sent=b"s"*32+b"h"*32
        expired=(3).to_bytes(4,"big")+first+previous+(100).to_bytes(8,"big")
        committed=(2).to_bytes(4,"big")+second+target+bytes(8)
        values={"inputs/local-first-operation":first[:32],"inputs/local-first-statement":first[32:],
         "inputs/local-first-version":(2).to_bytes(8,"big"),"inputs/local-first-digest":b"k"*32,
         "inputs/local-first-grant":b"synthetic first grant","inputs/local-second-grant":b"synthetic second grant",
         "inputs/local-second-operation":second[:32],"inputs/local-second-statement":second[32:],
         "inputs/trusted-roster-version":previous[:8],"inputs/trusted-roster-digest":previous[8:],
         "inputs/local-second-version":target[:8],"inputs/local-second-digest":target[8:],
         "inputs/local-next-message":identity[64:],"local-original":identity,"local-active":identity,
         "local-expired":expired,"local-expired-replayed":expired,"local-retained-terminal":expired,
         "local-next-active":identity[:64],"local-next-reopened":identity[:64],"local-next-status":committed,"local-next-expiry":committed,
         "local-next-staged":(1).to_bytes(4,"big")+second+bytes(48),"local-sent":sent,"local-effect":sent+b"persisted before process exit",
         "local-receiver.log":b"test fixture::service_peer_process ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n","local-peer-admitted":target,"local-effect-count":(2).to_bytes(4,"big"),"local-expiry-observation":b"".join(n.to_bytes(8,"big") for n in (90,100,1000,2000))}
        for name in ("local-staged","local-stage-replayed","local-pending"):values[name]=(1).to_bytes(4,"big")+first+bytes(48)
        for name,n in (("local-rejected",102),("local-replacement-blocked",211),("local-expired-activate",104),("local-needs-approval",104)):values[name]=n.to_bytes(4,"big")
        for name,mode in local.CASES:values[name+".stdout"]=f"{profile}:{mode}:passed\n".encode();values[name+".stderr"]=b""
        for name,data in values.items():(base/name).write_bytes(data)
        stdout+=f"qualified local credential {profile}: 18 foreign processes; real target-roster expiry, explicit non-commit, retained terminal, original traffic and independent successor\n".encode()
    return stdout

class LocalCredentialTests(unittest.TestCase):
    def test_exported_public_inventory_replays_without_private_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root / "source"; source.mkdir()
            stdout = fixture(source); replay = root / "public"
            files = local.PUBLIC + tuple(name + "." + suffix for name, _ in android.CASES
                                        for suffix in ("stdout", "stderr"))
            for trust in ("fixed", "recoverable"):
                for name in files:
                    sdk.copy(source / trust / name, replay / trust / name)
            self.assertEqual(local.verify_execution(stdout, replay), local.verify_execution(stdout, source))

    def test_workflow_uploads_nested_public_inputs(self):
        workflow = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
        partition = workflow.read_text().split(
            "name: continuity-installed-${{ matrix.consumer }}-${{ matrix.profile }}", 1)[1]
        upload = partition.split("          path: |", 1)[1].split("\n\n", 1)[0]
        prefix = "target/continuity-installed-swift/"
        patterns = [line.strip()[len(prefix):] for line in upload.splitlines()
                    if line.strip().startswith(prefix + "android-jni-")]
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            names = [f"android-jni-debug-fixed-{name}.public" for name in local.PUBLIC]
            names.append("android-jni-debug-policy-renewal-local-fixed-inputs/policy-target/protocol-policy.public")
            for name in names:
                path = output / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic public record")
            private = output / "android-jni-debug-fixed-inputs/configuration"
            private.write_bytes(b"synthetic excluded configuration")
            published = {path.relative_to(output).as_posix() for pattern in patterns
                         for path in output.glob(pattern) if path.is_file()}
            self.assertEqual(published, set(names))

    def test_complete_and_missing_process(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);stdout=fixture(root);result=local.verify_execution(stdout,root)
            self.assertEqual(sum(r["foreign_processes"] for r in result.values()),60)
            for name in ("local-sent.stdout","local-expired.stderr"):
                p=root/"fixed"/name;before=p.read_bytes();p.write_bytes(b"unexpected")
                with self.assertRaises(ValueError):local.verify_execution(stdout,root)
                p.write_bytes(before)
            with self.assertRaises(ValueError):local.verify_execution(stdout.replace(b"qualified local credential recoverable",b"missing"),root)
    def test_terminal_scope_time_identity_and_effect_substitution(self):
        for name in ("local-expired","local-expired-replayed","local-retained-terminal","local-replacement-blocked","local-pending",
                     "local-active","local-next-reopened","local-effect-count","local-next-staged","local-next-expiry"):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as t:
                root=Path(t);stdout=fixture(root);p=root/"fixed"/name;data=p.read_bytes();p.write_bytes(bytes([data[0]^1])+data[1:])
                with self.assertRaises(ValueError):local.verify_execution(stdout,root)
    def test_actual_expiry_and_independent_successor_required(self):
        for name,data in (("local-expiry-observation",b"".join(n.to_bytes(8,"big") for n in (101,100,1000,2000))),
                          ("inputs/local-second-operation",b"a"*32),("inputs/local-next-message",b"q"*32)):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as t:
                root=Path(t);stdout=fixture(root);(root/"recoverable"/name).write_bytes(data)
                with self.assertRaises(ValueError):local.verify_execution(stdout,root)

if __name__=="__main__":unittest.main()
