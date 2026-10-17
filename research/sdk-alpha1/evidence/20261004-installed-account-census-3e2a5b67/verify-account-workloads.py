from pathlib import Path
import json,hashlib
import continuity_c_account_tls_loss as loss
import continuity_c_account_delivery as delivery
import continuity_c_witness as witness
w=Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite/target/credential-renewal-20261004')
scenarios=[('01','C','mutual-tls-loss'),('01','C','own-tls-loss'),('01','C','mutual-tls-delivery'),('02','C','own-tls-delivery')]+[('03',language,scenario) for language in ['Swift','Kotlin'] for scenario in ['mutual-tls-loss','own-tls-loss','mutual-tls-delivery','own-tls-delivery']]
out=w/'account-workload-qualified-01';out.mkdir(mode=0o700)
records=[]
for cohort,language,scenario in scenarios:
 outside=w/('account-workload-census-'+cohort)/(language.lower()+'-'+scenario)
 trace=list((outside/'result').glob('*trace-debug.stdout'));assert len(trace)==1;stdout=trace[0].read_bytes()
 module=loss if 'loss' in scenario else delivery
 own=scenario.startswith('own-')
 verifier=module.verify_own_execution if own else module.verify_execution
 raw=list(outside.glob('*-runtime-account'));assert len(raw)==1
 selected=raw[0]/'initiator' if 'loss' in scenario else raw[0]
 checked=verifier(stdout,selected,language=language)
 destination=out/(language.lower()+'-'+scenario)
 public=witness.export_selected(checked,selected,destination,module.scope(language,same_account=own),replay=lambda path:verifier(stdout,path,language=language))
 records.append(dict(language=language,scenario=scenario,trace=str(trace[0]),trace_sha256=hashlib.sha256(stdout).hexdigest(),execution=checked,public_files=public))
 print(language,scenario,'verified original and exported public evidence',flush=True)
report=dict(completed=True,scope='12 actual archive Debug C/Swift/Kotlin account traces; exact original outputs revalidated with current census; same native engine and host',records=records,release_claim_eligible=False)
(out/'QUALIFICATION.json').write_text(json.dumps(report,indent=2)+'\n')
