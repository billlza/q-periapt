"""Authenticated same-key G after R/P/R on the surviving original installation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
from native_exchange_fixture import b64, save
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.local_renewal_protocol import Proposal
from qperiapt_continuity_reference.wire import require
from host_roster_policy import activation


def renew(root, native, probe, witness, run, policy):
    operation = b64(os.urandom(32)); request_file = root/'g-request.json'
    run([native.binary,'renewal-request',*native.common,operation,
         root/'policy-pins.json',root/'policy-materials.json',witness.endpoint(),request_file],'g-request')
    request = json.loads(request_file.read_bytes())
    require(request['previous_checkpoint']==native.current['roster']['checkpoint']
            and request['current_policy']==policy['progress']['target']
            and request['current_policy_authorization']==list(encoded(policy['statement'],32,32)),
            'G discarded preceding R or independent P')
    extension = {'request_id':list(os.urandom(32)), 'enrollment':native.invitation['operation'],
                 'previous_extension':None, 'predecessor':native.current['roster']['checkpoint'],
                 'valid_until':native.invitation['valid_until']+3600}
    extended = probe.request('alice','g-extension','/api/enrollment/extend-credential',extension)
    target = probe.request('alice','g-current','/api/enrollment/root')
    require(extended['checkpoint']==target['roster']['checkpoint'], 'G extension target differs')
    body = {'retained':request, 'original_extension':None, 'previous_extension':None,
            'successor_extension':extension['request_id'], 'target_checkpoint':extended['checkpoint']}
    require(probe.request('alice','g-absent','/api/enrollment/credential-grant/status',body)=={'state':'Absent'},
            'G was already issued')
    probe.request('alice','g-lost','/api/enrollment/credential-grant',body,lost=True)
    observed = probe.request('alice','g-status','/api/enrollment/credential-grant/status',body)
    issued_bytes = probe.request('alice','g-retry','/api/enrollment/credential-grant',body,raw=True)
    require(observed['state']=='Issued' and encoded(observed['response'],131072)==issued_bytes,
            'G lost HTTP result was replaced')
    issued = json.loads(issued_bytes)
    approval_file=root/'g-approval.json'; issued_file=root/'g-issued.json'; current_file=root/'g-current.json'
    save(approval_file,body); save(issued_file,issued_bytes); save(current_file,target)
    common = [*native.common,approval_file,issued_file,current_file,
              root/'policy-pins.json',root/'policy-materials.json',*native.local_inputs[1:],witness.endpoint()]
    require(run([native.binary,'renewal-stage',*common],'g-stage')['state']=='Pending', 'G did not stage')
    preparation_file=root/'g-preparation.json'
    run([native.binary,'renewal-witness-prepare',*common,preparation_file],'g-prepare')
    preparation = json.loads(preparation_file.read_bytes())
    # This test controller selects its own exported intent. The operator input
    # remains independent from an incoming remote proposal in the product path.
    proposal = Proposal.decode(encoded(preparation['proposal'],4096))
    require(proposal.subject==bytes(native.prepared['subject']) and proposal.operation==bytes(issued['operation'])
            and proposal.statement==bytes(issued['statement']) and proposal.policy==encoded(policy['statement'],32,32),
            'G proposal is not the original selected P/owner')
    trust_file=root/'g-witness-trust.json'
    save(trust_file,{'schema':'qperiapt-witness-credential-renewal-trust/1', 'account':target,
        'enrollment':native.invitation['operation'], 'operation':issued['operation'], 'statement':issued['statement'],
        'subject':b64(bytes(native.prepared['subject'])), 'proposal_binding':list(proposal.binding),
        'lineage':{'kind':'independent','statement':list(proposal.policy)},
        'original':json.loads(native.original_policy.read_bytes()), 'policy':json.loads(native.policy_input.read_bytes())})
    run([native.binary,'renewal-activate',*common],'g-unapproved',success=False)
    run(witness.command('credential-prepare',trust_file,preparation_file,issued_file),
        'g-witness-lost-output',success=False,lost_stdout=True)
    require(run(witness.command('credential-prepare',trust_file,preparation_file,issued_file),'g-witness-retry')==
            {'binding':list(proposal.binding),'state':'Prepared'}, 'G witness exact retry differs')
    run([native.binary,'renewal-activate',*common],'g-activation-lost-output',success=False,lost_stdout=True)
    terminal = run([native.binary,'renewal-status',*native.common],'g-terminal')
    require(terminal=={'state':'Committed','operation':issued['operation'],'statement':issued['statement'],
                      'target':issued['checkpoint']}, 'G original terminal result differs')
    active = run([native.binary,'renewal-activate',*common],'g-recovered-activation')
    require(bytes(active['journal'])==native.journal and active['checkpoint']==issued['checkpoint'],
            'G changed original journal or checkpoint')
    native.current=target; native.current_path=current_file
    native.local_inputs=[current_file,*native.local_inputs[1:]]
    native.active_args=[*native.common,*native.local_inputs,witness.endpoint()]
    require(bytes(run(activation(native),'g-reopen')['journal'])==native.journal,'G cannot reopen original P owner')
    return {'request':request,'extension':extended,'issued':issued,'preparation':preparation,
            'terminal':terminal,'activation':active,'proposal_binding':list(proposal.binding)}
