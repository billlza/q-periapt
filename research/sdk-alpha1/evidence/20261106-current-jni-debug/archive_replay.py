"""Read original exported JNI records; never invoke a native workload."""
import hashlib
import json
import pathlib
import re
import sys

TOOL_ROOT = pathlib.Path(__file__).resolve().parent
ROOT = pathlib.Path(sys.argv[3]).resolve()
SOURCE = pathlib.Path(__file__).resolve().parents[2] / 'artifact'
PROFILE = sys.argv[2]
RAW = ROOT / 'raw'
if PROFILE not in ('debug', 'release'):
    raise ValueError('unsupported recorded profile')
PREFIX = 'android-jni-' + PROFILE + '-'
attempt = sys.argv[1]
if re.fullmatch(r'replay-\d\d', attempt) is None:
    raise ValueError('expected fresh replay attempt name')
OUT = ROOT / attempt
OUT.mkdir()
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and sys.pycache_prefix

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes
import continuity_android_jni as jni
import continuity_android_contract as contract
import continuity_android_account as account
import continuity_android_local_credential as local_credential
import continuity_android_witness as witness
import continuity_android_credential as credential
import continuity_android_remote_credential as remote_credential
import continuity_android_credential_terminal as terminal
import continuity_android_policy_expiry as expiry
import continuity_android_pending as pending
import continuity_android_continuation as continuation
import continuity_android_policy_renewal as renewal
import continuity_android_retirement as retirement
import continuity_android_root as roots
import continuity_android_roster as roster
import continuity_android_roster_witness as roster_witness
import continuity_android_policy_roster as policy_roster
import continuity_android_policy_credential as policy_credential
import continuity_android_joint_policy as joint
import continuity_android_witness_joint as joint_witness
import continuity_android_joint_cycle as cycle
import continuity_android_recovery as recovery
import continuity_android_recovery_records as recovery_records

def sha(data):
    return hashlib.sha256(data).hexdigest()

def load(path):
    return parse_strict_json_bytes(path.read_bytes(),label=str(path))

report = load(RAW/'ANDROID_JNI_CONSUMER.json')
expected = report['profiles'][PROFILE]
sdk.require(report['build_profiles']==[PROFILE] and report['partition_completed'] is True and
            report['completed'] is False and report['release_claim_eligible'] is False, 'original partition scope differs')
observed = {}
copied = {}
checks = []

def stdout(label):
    command=load(RAW/(PREFIX+label+'.json'))
    sdk.require(command['returncode']==0,'original native command failed')
    return (RAW/(PREFIX+label+'.stdout')).read_bytes()

def finish(field, value):
    sdk.require(value==expected[field], 'original reader outcome differs: '+field)
    observed[field]=value
    (OUT/'REPLAYED.json').write_text(json.dumps(observed,indent=2)+'\n')
    print(json.dumps({'field':field,'equal_to_original':True}),flush=True)

def flat(folder, label, names, prefix, *, destination_label=None, suffix='.public'):
    base=OUT/'reconstructed'/folder
    for name in dict.fromkeys(names):
        source=RAW/(PREFIX+prefix+label+'-'+name+suffix)
        target=base/(destination_label or label)/name
        data=source.read_bytes()
        target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists():
            sdk.require(target.read_bytes()==data,'conflicting original-record alias')
        else:
            with target.open('xb') as out:out.write(data)
        copied[target.relative_to(OUT).as_posix()]={'source':source.relative_to(RAW).as_posix(),'sha256':sha(data),'bytes':len(data)}
    return base

catalog=stdout('test-catalog')
contract.verify_catalog(catalog)
sdk.require(stdout('boundary')==b'configuration:bridge:passed\n' and
            (RAW/(PREFIX+'boundary.stderr')).read_bytes()==b'', 'JNI boundary result differs')
finish('boundary_checks',True)

for trust in ('fixed','recoverable'):
    folder=flat('account',trust,account.PUBLIC,'account-')
finish('account_outcomes',account.verify_execution(stdout('account'),folder))

for trust in ('fixed','recoverable'):
    folder=flat('lifecycle',trust,local_credential.PUBLIC,'')
    streams=tuple(label+'.'+stream for label,_ in jni.CASES for stream in ('stdout','stderr'))
    folder=flat('lifecycle',trust,streams,'',suffix='')
finish('outcomes',local_credential.verify_execution(stdout('execution'),folder))

for lane,managed in (('witness',False),('authority',True),('credential',True)):
    for carrier in ('signed','tls'):
        for trust in ('fixed','recoverable'):
            extra=credential.PUBLIC+remote_credential.PUBLIC+terminal.PUBLIC if lane=='credential' else ()
            folder=flat(lane,carrier+'-'+trust,witness.public(carrier,managed=managed)+extra,lane+'-')
    value=(terminal.verify_execution(stdout(lane),folder) if lane=='credential'
           else witness.verify_execution(stdout(lane),folder,managed=managed))
    finish(lane+'_outcomes',value)

value={}
for trust in expiry.TESTS:
    for carrier in ('signed','tls'):
        for outcome in ('closed','applied'):
            label=carrier+'-'+trust+'-'+outcome
            folder=flat('policy-expiry-'+trust,label,expiry.public(outcome=='applied'),'policy-expiry-')
    value.update(expiry.verify_execution(stdout('policy-expiry-'+trust),folder,trust))
finish('policy_expiry_outcomes',value)

for lane,tests,field,options,suffix in (
    ('pending-write',pending.TESTS,'pending_write_outcomes',{},''),
    ('pending-query',pending.QUERY_TESTS,'pending_query_cancellation_outcomes',{'query_cancel':True},'-query-cancel'),
    ('pending-process',pending.PROCESS_TESTS,'pending_process_loss_outcomes',{'process_loss':True},'-process-loss')):
    value={}
    for label in tests:
        folder=flat(lane,label,pending.public(label.endswith('-applied'),**options),lane+'-',destination_label=label+suffix)
        value.update(pending.verify_execution(stdout(lane),folder,label,batch=True,**options))
    finish(field,value)

value={}
for label in continuation.TESTS:
    folder=flat('pending-continuation',label,continuation.public(label),'pending-continuation-',destination_label=label+'-continuation')
    value.update(continuation.verify_execution(stdout('pending-continuation'),folder,label,batch=True))
finish('pending_continuation_outcomes',value)

value={}
for trust in renewal.TESTS:
    for carrier in ('local','signed','tls'):
        label=carrier+'-'+trust
        folder=flat('policy-renewal-'+trust,label,renewal.public(carrier),'policy-renewal-')
    value.update(renewal.verify_execution(stdout('policy-renewal-'+trust),folder,trust))
finish('policy_renewal_outcomes',value)

finish('retirement_outcomes',retirement.verify_execution(stdout('retirement'),RAW/(PREFIX+'retirement')))
finish('root_outcomes',{route:roots.verify_execution(stdout('root-'+route),RAW/(PREFIX+'root-'+route),route) for route in roots.TESTS})
value={}
for lane,remote in (('roster-local',False),('roster-peer',True)):
    value[lane]=roster.verify_local(stdout(lane),RAW/(PREFIX+lane),remote=remote)
value['roster-witness']=roster_witness.verify_execution(stdout('roster-witness'),RAW/(PREFIX+'roster-witness'))
value['policy-roster']=policy_roster.verify_execution(stdout('policy-roster'),RAW/(PREFIX+'policy-roster'))
finish('roster_outcomes',value)

value={}
for label in policy_credential.TESTS:
    carrier,trust=label.split('-',1)
    value[label]=policy_credential.verify_execution(stdout('policy-credential-'+label),RAW/(PREFIX+'policy-credential-'+label),trust,carrier)
finish('policy_credential_outcomes',value)
value={}
for label in joint.TESTS:
    trust,outcome=label.split('-',1)
    value[label]=joint.verify_execution(stdout('joint-policy-'+label),RAW/(PREFIX+'joint-policy-'+label),trust,outcome=='applied')
finish('joint_policy_outcomes',value)
value={};folders={}
for label in joint_witness.TESTS:
    carrier,trust,outcome=label.split('-');folder=RAW/(PREFIX+'witness-joint-'+label)
    value[label]=joint_witness.verify_execution(stdout('witness-joint'),folder,carrier,trust,outcome=='applied',batch=True)
    folders[label]=folder
joint_witness.verify_batch_identities(folders)
finish('witness_joint_outcomes',value)
value={};identities=set()
for label in cycle.TESTS:
    carrier,trust=label.split('-');folder=RAW/(PREFIX+'joint-cycle-'+label)
    value[label]=cycle.verify_execution(stdout('joint-cycle'),folder,carrier,trust,batch=True)
    identities.add((folder/label/'original.identity').read_bytes())
sdk.require(len(identities)==len(cycle.TESTS),'cycle routes reused an original owner')
finish('joint_policy_cycles',value)

old=expected['recovery_outcomes']
sdk.require(stdout('recovery-host-records')==b'host-record-retention:passed\n' and
            (RAW/(PREFIX+'recovery-host-records.stderr')).read_bytes()==b'', 'host report retention result differs')
value={'host_record_retention':True,'first_use':recovery_records.first_use(stdout('recovery-first-use'),RAW/(PREFIX+'recovery-first-use-public'))}
recovery.witness.helper_inventory(stdout('recovery-witness-inventory'))
oracles=[]
for index,(_,verify) in enumerate(recovery.WITNESS_CASES):
    row=verify(stdout('recovery-witness-'+str(index)),RAW/(PREFIX+'recovery-oracle-'+str(index)),language='C')
    oracles.append({k:v for k,v in row.items() if k not in ('scope','language')})
value['native_oracles']=oracles
value['witness']=recovery_records.dispatches(RAW/(PREFIX+'recovery-witness-calls'),expected_java=44,expected_c=18,
    account_reports={row['batch']:row['public_readbacks']['c-account-loss-report'] for row in oracles})
recovery._require_enrollment_execution(stdout('recovery-results').decode(),{recovery.RESULT_TEST},'Android committed-member recovery did not execute')
diagnostics=(RAW/(PREFIX+'recovery-results.stderr')).read_text().splitlines()
for carrier in ('signed-TCP','mutual-TLS'):
    marker=f'FOREIGN_ACCOUNT_RECONCILIATION language=Android carrier={carrier} cut=None members=2 original_ids=true complete_results=true consumed_vs_unknown=true durable_host_report=true retired=true foreign_member_closure=true foreign_registration=false native_authority_setup=true'
    sdk.require(diagnostics.count(marker)==1,'recovery/registration scope marker differs')
value['committed_members']=recovery_records.dispatches(RAW/(PREFIX+'recovery-result-calls'),expected_java=18,expected_c=0)
sdk.require(all(old[k]==v for k,v in value.items()),'recovery public outcome differs')
observed['recovery_outcomes']=value
print(json.dumps({'field':'recovery_outcomes','public_fields_equal_to_original':sorted(value),'receipt_only_fields':['binaries','runtime_directory','completed','scope','release_claim_eligible']}),flush=True)

receipt_fields={'native_sha256','bridge_sha256','receiver_sha256','test_sha256','policy_target_client_sha256'}
sdk.require(set(observed)|receipt_fields==set(expected),'unaccounted JNI report field')
manifest=load(ROOT.parent/'READER_SOURCE.json');loaded={}
for module in list(sys.modules.values()):
    name=getattr(module,'__file__',None)
    if name:
        path=pathlib.Path(name).resolve()
        if path.is_relative_to(SOURCE):
            relative=path.relative_to(SOURCE.parent).as_posix();digest=sha(path.read_bytes())
            sdk.require(manifest['files'].get(relative)==digest,'loaded reader differs from pinned source')
            loaded[relative]=digest
(OUT/'REPLAYED.json').write_text(json.dumps(observed,indent=2)+'\n')
(OUT/'COPIED.json').write_text(json.dumps(copied,indent=2,sort_keys=True)+'\n')
result={'source_commit':manifest['commit'],'profile':PROFILE,'public_outcome_fields_replayed':sorted(observed),
    'receipt_only_binary_fields':sorted(receipt_fields),'recovery_receipt_only_fields':['binaries','runtime_directory','completed','scope','release_claim_eligible'],
    'loaded_reader_sources':dict(sorted(loaded.items())),'reconstructed_original_files':len(copied),
    'original_jni_report_sha256':sha((RAW/'ANDROID_JNI_CONSUMER.json').read_bytes()),
    'public_trace_readback_completed':True,'native_workload_executed':False,'aggregate_completed':False,
    'physical_art_aar_qualified':False,'release_claim_eligible':False}
(OUT/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'public_trace_readback_completed':True,'outcome_fields':len(observed),'loaded_reader_modules':len(loaded),'reconstructed_original_files':len(copied)}),flush=True)
