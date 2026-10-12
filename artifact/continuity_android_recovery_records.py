"""Exact JNI process receipts and original public recovery records."""
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import re
import continuity_android_account as account
import continuity_android_contract as contract
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

FIRST_USE_TEST = "android_account::recovery::first_use"
FIRST_USE_CASES = (("recovery-next-before","account-next"),("recovery-original-results","recovery-account-query")) + tuple(
    (f"recovery-{label}-{index}",mode) for index in (0,1) for label,mode in (
        ("frozen","recovery-session-freeze"),("ack","recovery-session-ack"),("retired","recovery-session-retire"),
        ("tamper","recovery-archive-tamper"),("restored","recovery-archive-restore"))) + (
        ("recovery-final-results","recovery-account-retire"),("recovery-account-retired","recovery-account-retired"),("recovery-next-after","account-next"))
FIRST_USE_PUBLIC = account.PUBLIC + tuple(name for name,_ in FIRST_USE_CASES) + tuple(
    name+"."+suffix for name,_ in FIRST_USE_CASES for suffix in ("stdout","stderr"))

def first_use(stdout: bytes, cases: Path) -> dict:
    result=account.verify_execution(stdout,cases,test=FIRST_USE_TEST)
    for trust,value in result.items():
        def read(name): return sdk.snapshot(cases/trust/name).data
        marker=f"qualified first-use recovery {trust}: original Java installation; complete results, full session reports, exact acknowledgement, authenticated archive/index restore and unchanged account position"
        sdk.require(stdout.decode().splitlines().count(marker)==1,"missing first-use recovery workload")
        for name,mode in FIRST_USE_CASES:
            sdk.require(read(name+".stdout")==f"{trust}:{mode}:passed\n".encode() and read(name+".stderr")==b"","first-use child outcome differs")
        current=read("recovery-original-results")
        originals=sorted(read(f"cancel-resumed-{i}")[:80] for i in (0,1))
        expected=read("cancel-operation")+(2).to_bytes(4,"big")+b"".join(row+(2).to_bytes(4,"big") for row in originals)
        sdk.require(current==expected==read("recovery-final-results"),"complete original member result changed")
        sdk.require(read("recovery-next-before")==read("recovery-next-after") and len(read("recovery-next-before"))==32,"recovery changed account position")
        for index in (0,1):
            report=read(f"recovery-frozen-{index}");archive=read(f"recovery-retired-{index}")
            sdk.require(len(report)==32 and any(report) and read(f"recovery-ack-{index}")==report,"original session report changed")
            sdk.require(len(archive)==362 and read(f"recovery-restored-{index}")==archive and read(f"recovery-tamper-{index}")==(208).to_bytes(4,"big"),"authenticated archive recovery differs")
        sdk.require(read("recovery-account-retired")== (112).to_bytes(4,"big"),"retired aggregate reopened")
        value.update(foreign_processes=len(account.CASES)+len(FIRST_USE_CASES),archive_restores=2)
    return result

def dispatches(directory: Path, *, expected_java: int, expected_c: int,
               account_reports: dict[str, str] | None = None) -> dict:
    modes=Counter();reports=defaultdict(set);roles=Counter();reconciliations=defaultdict(list)
    observed_accounts=set()
    for path in sorted(directory.iterdir()):
        sdk.require(path.is_dir() and not path.is_symlink() and re.fullmatch(r"[0-9a-f]{32}",path.name),"invalid recovery capture directory")
        row=parse_strict_json_bytes(sdk.snapshot(path/'dispatch.json').data,label='recovery dispatch')
        sdk.require(set(row)=={'mode','carrier','role','installation_sha256','original_id'} and row['carrier'] in ('local','--witness','--witness-tls'),"recovery dispatch schema")
        sdk.require(re.fullmatch(r'[0-9a-f]{64}',row['installation_sha256']) is not None,"original installation identity")
        roles[row['role']]+=1
        if row['role']=='C operational/reference':
            sdk.require(not row['mode'].startswith('recover-') and row['original_id'] is None
                        and {p.name for p in path.iterdir()}=={'dispatch.json'},"C setup misclassified as Java recovery");continue
        sdk.require(row['role']=='Java recovery' and re.fullmatch(r'[0-9a-f]{64}',row['original_id']) is not None,"unknown recovery role/identity")
        mode=row['mode'];modes[mode]+=1;original=row['original_id'];allowed={'dispatch.json','completed.txt','result.txt'}
        sdk.require(sdk.snapshot(path/'completed.txt').data==b'\x01',"Java recovery process incomplete")
        text=sdk.snapshot(path/'result.txt').data.decode('ascii')
        if mode.startswith('recover-member-'):
            sdk.require(mode in ('recover-member-freeze','recover-member-ack'),"unknown member recovery mode")
            allowed.add('member-report.txt');report=sdk.snapshot(path/'member-report.txt').data
            sdk.require(report.startswith(b'QPC-C-LOSS/1\nreport ') and b'\nheader '+original.encode()+b' ' in report,"member report scope")
            sdk.require(text==('member-frozen\n' if mode=='recover-member-freeze' else 'member-accounted\n'),"member outcome differs")
            reports[('member',row['installation_sha256'],original)].add(hashlib.sha256(report).hexdigest())
        elif mode in ('recover-account-results','recover-account-settled-retire'):
            lines=text.splitlines();sdk.require(lines[:3]==['QPC-C-RECONCILIATION/1','batch '+original,'members 2'] and len(lines)==5,"complete result framing")
            members=[]
            for index,line in enumerate(lines[3:]):
                match=re.fullmatch(rf'member {index} ([0-9a-f]{{32}}) ([0-9a-f]{{64}}) ([0-9a-f]{{64}}) ([1-6])',line)
                sdk.require(match is not None,"reconciled member omitted");members.append(match.groups())
            sdk.require(members[0][0]<members[1][0],"canonical members changed")
            reconciliations[(row['installation_sha256'],original)].append(members)
            if mode.endswith('settled-retire'):
                allowed.add('reconciliation.txt');sdk.require(sdk.snapshot(path/'reconciliation.txt').data==text.encode() and sorted(m[3] for m in members)==['2','4'],"unknown member relabeled consumed")
        else:
            expected={'recover-account-committed':'account-committed-not-abandoned\n','recover-account-witness-freeze':'account-freeze-outcome-unavailable\n',
                      'recover-account-witness-ack':'account-acknowledgement-outcome-unavailable\n','recover-account-witness-retire':'account-retirement-outcome-unavailable\n',
                      'recover-account-retire':'account-retired\n','recover-account-retire-reconcile':'account-retired\n'}
            if mode in ('recover-account-freeze','recover-account-freeze-reconcile','recover-account-ack','recover-account-ack-reconcile'):
                kind='frozen' if 'freeze' in mode else 'acknowledged'
                sdk.require(re.fullmatch(r'account-'+kind+r':[0-9a-f]{64}\n',text) is not None,"report outcome framing")
            elif mode in ('recover-account-reject','recover-account-retired','recover-account-absent'):
                codes='(?:216|211|218)' if mode.endswith('reject') else '112' if mode.endswith('retired') else '201'
                sdk.require(re.fullmatch('account-selection-refused:'+codes+'\n',text) is not None,"selection failure changed")
            else:sdk.require(mode in expected and text==expected[mode],"recovery outcome differs")
            needs_report=mode in ('recover-account-freeze','recover-account-freeze-reconcile','recover-account-witness-ack','recover-account-ack','recover-account-ack-reconcile','recover-account-witness-retire','recover-account-retire','recover-account-retire-reconcile')
            if needs_report:
                allowed.add('account-report.txt');report=sdk.snapshot(path/'account-report.txt').data
                sdk.require(account_reports is not None and original in account_reports
                            and hashlib.sha256(report).hexdigest()==account_reports[original],
                            "Java report differs from complete native accounting")
                observed_accounts.add(original)
                sdk.require(report.startswith(('QPC-C-ACCOUNT-LOSS/1\nbatch '+original+'\nreport ').encode()),"account report scope changed")
                report_id=report.decode('ascii').splitlines()[2].removeprefix('report ')
                sdk.require(re.fullmatch('[0-9a-f]{64}',report_id) is not None,"account report ID")
                if text.startswith(('account-frozen:','account-acknowledged:')):sdk.require(text.split(':')[1].strip()==report_id,"reported acknowledgement changed")
                reports[('account',row['installation_sha256'],original)].add(hashlib.sha256(report).hexdigest())
        sdk.require({p.name for p in path.iterdir()}==allowed,"unexpected recovery capture file")
    sdk.require(roles==Counter({'Java recovery':expected_java,**({'C operational/reference':expected_c} if expected_c else {})}),"recovery process roles/counts changed")
    sdk.require(all(len(values)==1 for values in reports.values()),"immutable report changed across retry")
    sdk.require(observed_accounts==set(account_reports or {}),"complete account report omitted")
    for values in reconciliations.values():
        sdk.require(len(values)==4 and len({tuple(row[:3] for row in members) for members in values})==1,"original member IDs changed across observation")
        confirmed=[i for i in (0,1) if all(members[i][3]=='2' for members in values)]
        sdk.require(len(confirmed)==1 and Counter(members[1-confirmed[0]][3] for members in values)==Counter({'1':2,'3':1,'4':1}),"confirmed/pending/unknown distinction lost")
    return {'java_processes':expected_java,'C_processes':expected_c,'modes':dict(sorted(modes.items())),'immutable_reports':len(reports),'reconciled_accounts':len(reconciliations)}
