"""Read remote-grant continuation; native consumers authenticate grant signatures."""
from pathlib import Path
import continuity_android_credential as credential
import rust_sdk_profile as sdk

TEST = credential.TEST
CASES = (("remote-uncertain","credential-remote-uncertain"),("remote-self-refused","credential-remote-self-refused"),
         ("remote-admitted","credential-remote-admit"),("remote-reopened","credential-remote-reopen"),
         ("remote-acknowledged","credential-remote-retry"))
NATIVE = ("credential-stage","credential-witness-prepare","credential-witness-commit","credential-witness-reconcile")
PUBLIC = tuple(name for name,_ in CASES) + tuple(name+"."+suffix for name,_ in CASES for suffix in ("stdout","stderr")) + (
    "remote-native-proposal","remote-effect-before","remote-effect-after","remote-effect-count",
    "inputs/remote-grant","inputs/remote-operation","inputs/remote-statement","inputs/remote-version","inputs/remote-digest",
) + tuple("remote-native-"+name+"."+suffix for name in NATIVE for suffix in ("stdout","stderr")) + tuple(
    "traffic-remote-credential-"+name+"."+suffix for name in ("crash","message") for suffix in ("stdout","stderr"))


def verify_execution(stdout: bytes, directory: Path) -> dict:
    results=credential.verify_execution(stdout,directory);lines=stdout.decode().splitlines()
    for label,result in results.items():
        carrier,profile=label.split("-",1);base=directory/label
        def read(name): return sdk.snapshot(base/name).data
        marker=f"qualified remote credential {carrier}/{profile}: explicit remote grant, stale peer refusal, original pending message, restart, exact retry, two distinct business effects"
        sdk.require(lines.count(marker)==1,"Android remote credential route missing or duplicated")
        for name,mode in CASES:
            sdk.require(read(name+".stdout")==f"{profile}:{mode}:passed\n".encode() and read(name+".stderr")==b"",
                        "Android remote credential process omitted an outcome or reported diagnostics")
        original=read("credential-uncertain");pending=read("remote-uncertain")
        sdk.require(len(pending)==64 and pending[:32]==original[:32] and any(pending[32:]) and pending[32:]!=original[32:]
                    and read("remote-acknowledged")==pending,"remote renewal replaced the original session or pending message")
        target=read("inputs/remote-version")+read("inputs/remote-digest");admitted=read("remote-admitted")
        sdk.require(len(target)==40 and target[:8]==(2).to_bytes(8,"big") and any(target[8:]) and len(admitted)==72
                    and admitted[:40]==target and any(admitted[40:]) and read("remote-reopened")==admitted,
                    "remote grant target or next original message slot changed after reopen")
        sdk.require(read("remote-self-refused")== (211).to_bytes(4,"big"),"remote API admitted a local renewal")
        effect=pending+b"persisted before process exit"
        sdk.require(read("remote-effect-before")==effect and read("remote-effect-after")==effect
                    and read("remote-effect-count")== (2).to_bytes(4,"big"),"remote renewal duplicated or replaced business effects")
        operation,statement=read("inputs/remote-operation"),read("inputs/remote-statement")
        proposal=read("remote-native-proposal")
        sdk.require(len(operation)==len(statement)==32 and any(operation) and any(statement) and len(proposal)==296
                    and proposal[:8]==b"QPCRNP01" and proposal[136:168]==operation and proposal[168:200]==statement,
                    "native counterparty changed its original renewal operation")
        for name in NATIVE:
            sdk.require(read("remote-native-"+name+".stderr")==b"","native counterparty renewal emitted diagnostics")
            if name=="credential-witness-prepare": expected="credential-witness-prepared\n"
            else:
                phase=1 if name=="credential-stage" else 2
                version=0 if phase==1 else 2;digest=bytes(32) if phase==1 else target[8:]
                expected=f"credential-phase:{phase}\n{operation.hex()}\n{statement.hex()}\ncredential-head:{version}\n{digest.hex()}\ncredential-observed:0\n"
            sdk.require(read("remote-native-"+name+".stdout")==expected.encode(),"native counterparty renewal outcome differs")
        for mode,expected in (("crash",""),("message",f"served:2:0:1:0\n{pending[:32].hex()}\n{pending[32:].hex()}\n")):
            prefix="traffic-remote-credential-"+mode;parts=read(prefix+".stdout").decode().split("\n",1)
            sdk.require(read(prefix+".stderr")==b"" and len(parts)==2 and parts[0].startswith("listening:")
                        and parts[0][10:].isdigit() and 0<int(parts[0][10:])<=65535 and parts[1]==expected,
                        "remote-renewal receiver traffic outcome differs")
        result.update(foreign_processes=result["foreign_processes"]+len(CASES),remote_renewal_qualified=True,
                      remote_pending_message=pending[32:].hex(),remote_target_digest=target[8:].hex())
    return results
