"""Installed Java recovery with C setup/traffic and independent native readback."""
from pathlib import Path
import os
import shlex
import sys
import tempfile
import continuity_c_consumer as c
import continuity_android_recovery_records as records
import continuity_c_account_witness as witness
import continuity_c_account_tls as tls
import continuity_c_account_tls_loss as loss
import continuity_c_witness as exports
from continuity_c_enrollment import _require_enrollment_execution
import rust_sdk_profile as sdk

SCOPE = "packaged Java/JNI recovery; C registration, policy/roster and operational traffic; native complete-report oracle; same host and engine; no ART or independent-implementation claim"
RESULT_TEST = "credential_renewal::independent_policy::witnessed::roster::traffic::fanout::c_required_peer_revocation_reconciles_every_original_account_member_before_retirement"
WITNESS_CASES = ((witness.TEST,witness.verify_execution),(witness.TLS_TEST,tls.verify_execution),
                 (witness.TLS_LOSS_TEST,loss.verify_execution),(witness.OWN_TLS_LOSS_TEST,loss.verify_own_execution))

def driver(directory: Path, java: Path, jar: Path, tests: Path, library: Path, client: Path,
           captures: Path, *, recovery_only: bool) -> Path:
    name='recovery-results' if recovery_only else 'recovery-witness'
    program=directory/(name+'.py')
    command=[str(java),'--enable-native-access=ALL-UNNAMED','-Xcheck:jni','-Djava.library.path='+str(library),
             '-cp',str(jar)+os.pathsep+str(tests),'dev.qperiapt.continuity.android.tests.RecoveryProbe']
    program.write_text('import os,sys,json,uuid,hashlib,re\nfrom pathlib import Path\n'
        'args=sys.argv[1:]\noffset=2 if args and args[0] in ("--witness","--witness-tls") else 0\n'
        'mode=args[offset]\nis_recovery=mode.startswith("recover-")\n'
        + ('assert is_recovery\n' if recovery_only else '')
        + 'assert len(args)>offset+1\noriginal=args[offset+2] if is_recovery else None\n'
        'assert not is_recovery or (len(args)==offset+3 and re.fullmatch("[0-9a-f]{64}",original))\n'
        'run=Path('+repr(str(captures))+')/uuid.uuid4().hex\nrun.mkdir()\n'
        '(run/"dispatch.json").write_text(json.dumps({"mode":mode,"carrier":args[0] if offset else "local",'
        '"role":"Java recovery" if is_recovery else "C operational/reference",'
        '"installation_sha256":hashlib.sha256(args[offset+1].encode()).hexdigest(),"original_id":original})+"\\n")\n'
        'command=('+repr(command)+' if is_recovery else ['+repr(str(client))+'])+args\n'
        'os.execve(command[0],command,dict(os.environ,QPC_RECOVERY_CAPTURE=str(run)))\n')
    launcher=directory/name
    launcher.write_text('#!/bin/sh\nexec '+shlex.join([sys.executable,str(program)])+' "$@"\n');launcher.chmod(0o700)
    return launcher

def qualify(consumer: Path, installed: Path, output: Path, profile: str, environment: dict,
            run, *, java: Path, jar: Path, tests: Path, android: Path, android_driver: Path, client: Path) -> dict:
    sdk.require(profile in ('debug','release'),"recovery build profile")
    result={'completed':False,'scope':SCOPE,'release_claim_eligible':False}
    prefix=profile+'-recovery'
    # Explicitly replace inherited fixture selectors. No recovery command falls
    # back to C after a Java failure; C serves only its declared operational role.
    env={k:v for k,v in environment.items() if not k.startswith(('QPC_','QPERIAPT_'))}
    cargo=Path(environment['RUSTC']).parent/'cargo';target=Path(environment['CARGO_TARGET_DIR'])/profile
    try:
        runtime_root=Path(tempfile.mkdtemp(prefix='jni-recovery-',dir=installed)).resolve()
        result['runtime_directory']=str(runtime_root)
        first=runtime_root/'first-use'
        stdout=run([str(android),'--exact',records.FIRST_USE_TEST,'--nocapture'],prefix+'-first-use',consumer,
                   dict(env,QPC_ANDROID_CASES=str(first),QPC_ANDROID_DRIVER=str(android_driver)))
        result['first_use']=records.first_use(stdout,first)
        first_public=output/('android-jni-'+prefix+'-first-use-public')
        for trust in result['first_use']:
            for name in records.FIRST_USE_PUBLIC:sdk.copy(first/trust/name,first_public/trust/name)
        sdk.require(records.first_use(stdout,first_public)==result['first_use'],"first-use public replay differs")
        extra=['--release'] if profile=='release' else []
        binaries={}
        for name in ('account_witness','enrollment'):
            built=run([str(cargo),'test','--offline','--locked','--test',name,'--no-run','--message-format=json','-j','2',*extra],prefix+'-'+name+'-build',consumer,environment)
            binaries[name]=c.built_artifact(built,consumer,target,library=False,test_name=name)
        captures=output/('android-jni-'+prefix+'-witness-calls');captures.mkdir()
        launcher=driver(runtime_root,java,jar,tests,installed,client,captures,recovery_only=False)
        witness.helper_inventory(run([str(binaries['account_witness']),'--list'],prefix+'-witness-inventory',consumer,env))
        oracles=[]
        for index,(test,verify) in enumerate(WITNESS_CASES):
            evidence=runtime_root/(prefix+'-oracle-'+str(index))
            stdout=run([str(binaries['account_witness']),'--exact',test,'--nocapture'],prefix+'-witness-'+str(index),consumer,
                       dict(env,QPERIAPT_C_OWNER_CLIENT=str(launcher),QPERIAPT_INSTALLED_CLIENT_LANGUAGE='C',QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence)))
            directory=evidence.with_name(evidence.name+'-account')/'initiator'
            checked=verify(stdout,directory,language='C')
            public=output/('android-jni-'+prefix+'-oracle-'+str(index))
            exports.export_selected(checked,directory,public,SCOPE,
                replay=lambda path,verify=verify,stdout=stdout:verify(stdout,path,language='C'))
            # The old native fixture labels its result C. Preserve its actual
            # semantic oracle without claiming Java performed C registration.
            oracles.append({k:v for k,v in checked.items() if k not in ('scope','language')})
        result['native_oracles']=oracles
        result['witness']=records.dispatches(captures,expected_java=44,expected_c=18,
            account_reports={row['batch']:row['public_readbacks']['c-account-loss-report'] for row in oracles})
        captures=output/('android-jni-'+prefix+'-result-calls');captures.mkdir()
        launcher=driver(runtime_root,java,jar,tests,installed,client,captures,recovery_only=True)
        stdout=run([str(binaries['enrollment']),'--exact',RESULT_TEST,'--nocapture'],prefix+'-results',consumer,
                   dict(env,QPERIAPT_C_OWNER_CLIENT=str(client),QPERIAPT_INSTALLED_CLIENT_LANGUAGE='C',
                        QPERIAPT_ACCOUNT_RESULT_CLIENT=str(launcher),QPERIAPT_ACCOUNT_RESULT_LANGUAGE='Android'))
        _require_enrollment_execution(stdout.decode(),{RESULT_TEST},'Android committed-member recovery did not execute')
        stderr=sdk.snapshot(output/('android-jni-'+prefix+'-results.stderr')).data.decode()
        for carrier in ('signed-TCP','mutual-TLS'):
            marker=f'FOREIGN_ACCOUNT_RECONCILIATION language=Android carrier={carrier} cut=None members=2 original_ids=true complete_results=true consumed_vs_unknown=true durable_host_report=true retired=true foreign_member_closure=true foreign_registration=false native_authority_setup=true'
            sdk.require(stderr.splitlines().count(marker)==1,"recovery/registration scope marker differs")
        result['committed_members']=records.dispatches(captures,expected_java=18,expected_c=0)
        result['binaries']={name:sdk.snapshot(path,maximum=c.MAX_BINARY).sha256 for name,path in binaries.items()}
        result['completed']=True
        return result
    finally:sdk.write_json(output/('ANDROID_RECOVERY_'+profile.upper()+'.json'),result)
