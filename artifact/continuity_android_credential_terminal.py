"""Read witnessed cancellation/expiry outcomes, without inferring NoCommit."""
from pathlib import Path
import continuity_android_remote_credential as remote
import rust_sdk_profile as sdk

TEST=remote.TEST
CASES=(("terminal-close-committed","credential-terminal-close-committed"),("terminal-expiry-committed","credential-terminal-expiry-committed"),
       ("terminal-staged","credential-terminal-stage"),("terminal-cancellation","credential-terminal-cancel-prepare"),
       ("terminal-cancellation-replayed","credential-terminal-cancel-prepare"),("terminal-pending","credential-terminal-pending"),
       ("terminal-reserved-refused","credential-terminal-commit-reserved-refused"),("terminal-activate-refused","credential-terminal-activate-refused"),
       ("terminal-expired-refused","credential-terminal-commit-expired-refused"),("terminal-pending-expired","credential-terminal-pending"),
       ("terminal-expired-stage-refused","credential-terminal-expired-stage-refused"),
       ("terminal-cleanup-unknown","credential-terminal-reconcile-unknown"),("terminal-status-closed","credential-terminal-status-closed"),
       ("terminal-reconciled","credential-terminal-reconcile"),("terminal-close-replayed","credential-terminal-close-replay"),
       ("terminal-commit-replayed","credential-terminal-commit-replay"),("terminal-active","credential-terminal-active"),
       ("terminal-sent","credential-terminal-send"))
PUBLIC=tuple(name for name,_ in CASES)+tuple(name+"."+suffix for name,_ in CASES for suffix in ("stdout","stderr"))+(
    "terminal-expiry-observation","terminal-lost-ack-request","terminal-lost-ack-reply","terminal-no-commit-transcript",
    "terminal-effect","terminal-effect-count","traffic-terminal-credential-message.stdout","traffic-terminal-credential-message.stderr",
    "inputs/terminal-operation","inputs/terminal-statement","inputs/terminal-version","inputs/terminal-digest","inputs/terminal-grant")

def verify_execution(stdout: bytes,directory: Path)->dict:
    result=remote.verify_execution(stdout,directory);lines=stdout.decode().splitlines()
    for label,record in result.items():
        carrier,profile=label.split("-",1);base=directory/label
        def read(name):return sdk.snapshot(base/name).data
        marker=f"qualified credential terminal {carrier}/{profile}: committed outcome retained, real roster expiry, independent cancellation, lost cleanup acknowledgment, original authority and traffic restored"
        sdk.require(lines.count(marker)==1,"Android credential terminal route missing or duplicated")
        for name,mode in CASES:
            sdk.require(read(name+".stderr")==b"" and read(name+".stdout")==f"{profile}:{mode}:passed\n".encode(),"credential terminal process omitted its outcome")
        committed=read("credential-recovered")
        sdk.require(read("terminal-close-committed")==committed and read("terminal-expiry-committed")==committed,"terminal cleanup replaced an existing commit")
        operation,statement=read("inputs/terminal-operation"),read("inputs/terminal-statement")
        target=read("inputs/terminal-version")+read("inputs/terminal-digest")
        sdk.require(len(operation)==len(statement)==32 and any(operation) and any(statement) and len(target)==40
                    and target[:8]==(3).to_bytes(8,"big") and any(target[8:]),"terminal original operation/target malformed")
        pending=(1).to_bytes(4,"big")+operation+statement+bytes(48)
        sdk.require(all(read(name)==pending for name in ("terminal-staged","terminal-pending","terminal-pending-expired")),"expiry or Unavailable was misclassified as NoCommit")
        cancellation=read("terminal-cancellation")
        sdk.require(len(cancellation)==248 and cancellation[:8]==b"QPCRNC01" and cancellation[136:168]==operation
                    and cancellation[168:200]==statement and read("terminal-cancellation-replayed")==cancellation,"original cancellation expectation changed")
        for name,code in (("terminal-reserved-refused",215),("terminal-activate-refused",215),("terminal-expired-refused",215),("terminal-expired-stage-refused",104),("terminal-cleanup-unknown",218)):
            sdk.require(read(name)==code.to_bytes(4,"big"),"terminal refusal or lost cleanup outcome differs")
        observed=read("terminal-expiry-observation")
        sdk.require(len(observed)==32,"terminal expiry observation missing")
        until,at,credential_until,policy_until=(int.from_bytes(observed[i:i+8],"big") for i in range(0,32,8))
        sdk.require(0<until<=at<credential_until and at<policy_until,"target roster did not expire under a live original policy")
        closed=(4).to_bytes(4,"big")+operation+statement+target+bytes(8)
        sdk.require(all(read(name)==closed for name in ("terminal-status-closed","terminal-reconciled","terminal-close-replayed","terminal-commit-replayed")),"lost ACK or exact replay changed Closed history")
        request,reply=read("terminal-lost-ack-request"),read("terminal-lost-ack-reply")
        sdk.require(len(request)==3674 and request[204]==8 and len(reply)==3659 and reply[204]==11,"cleanup failure lacks its real acknowledgment exchange")
        transcript=read("terminal-no-commit-transcript")
        sdk.require(0<len(transcript)<=128*7334 and len(transcript)%7334==0,"terminal transcript frame bound")
        lost=[]
        for start in range(0,len(transcript),7334):
            frame=transcript[start:start+7334]
            sdk.require(frame[0] in (0,1) and frame[205] not in (5,7),"cancellation recovery dispatched Commit or Close")
            if frame[0]==0:lost.append(frame)
        sdk.require(lost==[b"\0"+request+reply],"cleanup failure omitted or substituted the lost acknowledgment")
        identity=read("credential-original-identity");next_slot=read("remote-admitted")[40:]
        sdk.require(read("terminal-active")==identity+next_slot,"cancellation changed original identity/journal/next slot")
        sent=read("credential-connected")+next_slot
        sdk.require(read("terminal-sent")==sent and read("terminal-effect")==sent+b"persisted before process exit"
                    and read("terminal-effect-count")== (3).to_bytes(4,"big"),"preceding authority traffic changed or duplicated effects")
        parts=read("traffic-terminal-credential-message.stdout").decode().split("\n",1)
        sdk.require(read("traffic-terminal-credential-message.stderr")==b"" and len(parts)==2 and parts[0].startswith("listening:")
                    and parts[0][10:].isdigit() and 0<int(parts[0][10:])<=65535
                    and parts[1]==f"served:2:0:1:1\n{sent[:32].hex()}\n{sent[32:].hex()}\n","terminal receiver traffic omitted its original result")
        record.update(foreign_processes=record["foreign_processes"]+len(CASES),witnessed_expiry_cancellation_qualified=True,
                      local_only_expired_uncommitted_qualified=False,cancelled_target_digest=target[8:].hex())
    return result
