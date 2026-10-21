"""Native adoption of the same HTTP-issued complete-account target."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from native_exchange_fixture import b64,save
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.local_renewal_protocol import Proposal
from qperiapt_continuity_reference.wire import require


def adopt(root,native,request,approval,issued,companion,target,witness,run,session):
    label='native-cg';key_paths=(native.directory/'device.key',root/'native-wrap.key')
    keys={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in key_paths}
    common=[*native.common,root/(label+'-approval.json'),root/(label+'-issued.json'),root/'cohort-current.json',
            root/'policy-pins.json',root/'policy-materials.json',root/'policy-pins.json',root/'policy-materials.json',witness.endpoint()]
    companions={'schema':'qperiapt-account-credential-grants/1','grants':[companion]}
    selected=root/(label+'-companions.json');save(selected,companions)
    extra=['--companion-grants',selected]
    pending=run([native.binary,'renewal-stage',*common,*extra],label+'-stage')
    require(pending=={'state':'Pending','operation':issued['operation'],'statement':issued['statement']},'native cohort pending identity')
    # Native stage retains a request; it does not publish a runtime or seal the
    # child image. Once the full request is retained, a single-grant retry must
    # not replace its original companion collection.
    run([native.binary,'renewal-stage',*common],label+'-single-refused',success=False)
    require(run([native.binary,'renewal-status',*native.common],label+'-after-refusal')==pending,
            'native account retry changed the retained target')
    occupied=root/(label+'-occupied.json');save(occupied,b'original native cohort export retained')
    run([native.binary,'renewal-witness-prepare',*common,occupied,*extra],label+'-lost-export',success=False)
    require(occupied.read_bytes()==b'original native cohort export retained','native cohort overwrote export')
    prep_file=root/(label+'-preparation.json')
    run([native.binary,'renewal-witness-prepare',*common,prep_file,*extra],label+'-prepare')
    second=root/(label+'-preparation-retry.json')
    run([native.binary,'renewal-witness-prepare',*common,second,*extra],label+'-prepare-retry')
    prep=json.loads(prep_file.read_bytes());require(json.loads(second.read_bytes())==prep,'native cohort resealed target')
    proposal=Proposal.decode(encoded(prep['proposal'],329))
    require(proposal.subject==bytes(native.prepared['subject']) and proposal.operation==bytes(issued['operation'])
            and proposal.statement==bytes(issued['statement']) and proposal.policy is None,'native cohort proposal scope')
    policy={'pins':json.loads((root/'policy-pins.json').read_bytes()),'materials':json.loads((root/'policy-materials.json').read_bytes())}
    trust=root/(label+'-witness-trust.json')
    save(trust,{'schema':'qperiapt-witness-credential-renewal-trust/1','account':target,
        'enrollment':issued['enrollment'],'operation':issued['operation'],'statement':issued['statement'],
        'subject':b64(bytes(native.prepared['subject'])),'proposal_binding':list(proposal.binding),
        'lineage':{'kind':'original'},'original':policy,'policy':policy})
    run([native.binary,'renewal-activate',*common,*extra],label+'-unapproved',success=False)
    run(witness.command('credential-prepare',trust,prep_file,root/(label+'-issued.json')),
        label+'-witness-lost-output',success=False,lost_stdout=True)
    require(run(witness.command('credential-prepare',trust,prep_file,root/(label+'-issued.json')),label+'-witness-retry')==
            {'binding':list(proposal.binding),'state':'Prepared'},'native cohort operator retry')
    run([native.binary,'renewal-activate',*common,*extra],label+'-commit-lost-output',success=False,lost_stdout=True)
    terminal=run([native.binary,'renewal-status',*native.common],label+'-status')
    require(terminal=={'state':'Committed','operation':issued['operation'],'statement':issued['statement'],'target':issued['checkpoint']},
            'native cohort terminal identity')
    active=run([native.binary,'renewal-activate',*common,*extra],label+'-activate-retry')
    require(active=={'state':'Active','operation':issued['operation'],'statement':issued['statement'],
                    'journal':list(native.journal),'checkpoint':issued['checkpoint']},'native cohort changed original journal')
    require(all(hashlib.sha256(p.read_bytes()).hexdigest()==keys[str(p)] for p in key_paths),'native cohort replaced protected keys')
    native.current=target;native.current_path=root/'cohort-current.json'
    native.local_inputs=[native.current_path,*native.local_inputs[1:]]
    native.active_args=[*native.common,*native.local_inputs,witness.endpoint()]
    return {'label':'native','kind':'native','request':request,'approval':approval,'issued':issued,'companions':[companion],
            'preparation':prep,'binding':list(proposal.binding),'state':'Applied','terminal':terminal,'activation':active,
            'original_key_unchanged':True,'session':session,'journal':b64(native.journal)}
