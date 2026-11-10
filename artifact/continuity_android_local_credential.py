"""Actual local-expiry process outcomes; historical facts grant no fresh authority."""
from pathlib import Path
import continuity_android_jni as android
import rust_sdk_profile as sdk

CASES=(("local-original","credential-local-identity"),("local-rejected","credential-local-rejected"),
 ("local-staged","credential-local-stage"),("local-stage-replayed","credential-local-stage"),
 ("local-replacement-blocked","credential-local-next-stage-blocked"),("local-expired-activate","credential-local-expired-activate"),
 ("local-pending","credential-local-pending"),("local-expired","credential-local-reconcile"),
 ("local-expired-replayed","credential-local-reconcile"),("local-needs-approval","credential-local-needs-approval"),("local-active","credential-local-active"),
 ("local-sent","credential-local-send"),("local-next-staged","credential-local-next-stage"),
 ("local-retained-terminal","credential-local-reconcile"),("local-next-active","credential-local-next-activate"),
 ("local-next-status","credential-local-next-status"),("local-next-expiry","credential-local-next-expiry"),
 ("local-next-reopened","credential-local-next-reopen"))
PUBLIC=android.PUBLIC+tuple(name for name,_ in CASES)+tuple(name+"."+suffix for name,_ in CASES for suffix in ("stdout","stderr"))+(
 "local-receiver.log","local-expiry-observation","local-peer-admitted","local-effect","local-effect-count","inputs/local-next-message",
 "inputs/trusted-roster-version","inputs/trusted-roster-digest")+tuple(
 "inputs/local-"+prefix+"-"+name for prefix in ("first","second") for name in ("operation","statement","version","digest","grant"))

def verify_execution(stdout: bytes,directory: Path)->dict:
    results=android.verify_execution(stdout,directory);lines=stdout.decode().splitlines()
    for profile,record in results.items():
        base=directory/profile
        def read(name):return sdk.snapshot(base/name).data
        marker=f"qualified local credential {profile}: 18 foreign processes; real target-roster expiry, explicit non-commit, retained terminal, original traffic and independent successor"
        sdk.require(lines.count(marker)==1,"local credential route missing or duplicated")
        for name,mode in CASES:
            sdk.require(read(name+".stderr")==b"" and read(name+".stdout")==f"{profile}:{mode}:passed\n".encode(),"local credential process outcome missing")
        def scope(prefix):
            op,statement=read("inputs/local-"+prefix+"-operation"),read("inputs/local-"+prefix+"-statement")
            sdk.require(len(op)==len(statement)==32 and any(op) and any(statement),"original local grant scope")
            return op+statement
        first,second=scope("first"),scope("second")
        sdk.require(first[:32]!=second[:32] and first[32:]!=second[32:],"new grant reused old scope")
        pending=(1).to_bytes(4,"big")+first+bytes(48)
        sdk.require(all(read(n)==pending for n in ("local-staged","local-stage-replayed","local-pending")),"expired pending intent was implicitly replaced")
        for name,code in (("local-rejected",102),("local-replacement-blocked",211),("local-expired-activate",104),("local-needs-approval",104)):
            sdk.require(read(name)==code.to_bytes(4,"big"),"local refusal missing")
        observation=read("local-expiry-observation");sdk.require(len(observation)==32,"real expiry observation missing")
        until,at,credential_until,policy_until=(int.from_bytes(observation[i:i+8],"big") for i in range(0,32,8))
        sdk.require(0<until<=at<credential_until and at<policy_until,"local target did not expire under live preceding authority")
        expired=read("local-expired");sdk.require(len(expired)==116,"expired status width")
        observed=int.from_bytes(expired[108:],"big")
        head=read("inputs/trusted-roster-version")+read("inputs/trusted-roster-digest")
        sdk.require(len(head)==40 and head[:8]==(1).to_bytes(8,"big") and any(head[8:]),"preceding roster checkpoint")
        sdk.require(at<=observed<credential_until and expired==(3).to_bytes(4,"big")+first+head+observed.to_bytes(8,"big"),"local expiry omitted exact predecessor/non-commit/time")
        sdk.require(read("local-expired-replayed")==expired and read("local-retained-terminal")==expired,"terminal fact changed on replay or new staging")
        identity=read("local-original");next_slot=read("inputs/local-next-message")
        sdk.require(len(identity)==96 and all(any(identity[i:i+32]) for i in (0,32,64)) and len(next_slot)==32
                    and identity[64:]==next_slot and read("local-active")==identity,"local expiry changed identity/journal/next slot")
        sent=read("connected.session")+next_slot
        sdk.require(read("local-sent")==sent and read("local-effect")==sent+b"persisted before process exit"
                    and read("local-effect-count")==(2).to_bytes(4,"big"),"local expiry lost or duplicated application effects")
        sdk.require(read("local-receiver.log").decode().count("test fixture::service_peer_process ... ok") == 1
                    and "test result: ok. 1 passed; 0 failed; 0 ignored;" in read("local-receiver.log").decode(),"original-session receiver was not restored successfully")
        target=read("inputs/local-second-version")+read("inputs/local-second-digest")
        sdk.require(len(target)==40 and target[:8]==(3).to_bytes(8,"big") and any(target[8:]),"independent successor checkpoint")
        sdk.require(read("local-peer-admitted")==target,"counterparty omitted exact peer renewal admission")
        sdk.require(read("local-next-staged")== (1).to_bytes(4,"big")+second+bytes(48),"new original grant not staged")
        committed=(2).to_bytes(4,"big")+second+target+bytes(8)
        sdk.require(read("local-next-status")==committed and read("local-next-expiry")==committed
                    and read("local-next-active")==identity[:64] and read("local-next-reopened")==identity[:64],"new activation changed identity/journal or terminal outcome")
        record.update(foreign_processes=record["foreign_processes"]+len(CASES),local_only_expired_uncommitted_qualified=True,
                      target_roster_expired=True,original_policy_live=True)
    return results
