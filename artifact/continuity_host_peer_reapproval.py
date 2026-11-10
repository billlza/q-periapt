"""Bind the host's actual reapproval successor to original client P/G requests."""
import hashlib
from continuity_independent_python import require
from continuity_host_roster_credential import raw
from continuity_host_roster_policy import wire

HTTP = ('peer-reapproval-lost','peer-reapproval-retry','peer-original-issue-refused')


def verify(value):
    result=value['independent_reapproval'];p=value['independent_policy_transition']['request']
    require(raw(result['original_operation']) != raw(result['issued_operation'])
            and result['issued_operation']==p['enrollment']==value['independent_credential_transition']['request']['enrollment']
            and result['journal']==p['scope']['journal'] and result['same_identity'] is True,
            'independent original reapproval lineage')
    for field in ('request_sha256','signing_key_sha256'):
        h=result[field];require(type(h) is str and len(h)==64 and all(c in '0123456789abcdef' for c in h),
                                'independent reapproval public digest')


def retain(value,copy,doc,commands,responses):
    from evidence_io import parse_strict_json_bytes
    result=doc('peer-reapproval.json');request=doc('peer-reapproval-request.json')
    original=doc('peer-invitation.json');approved=doc('peer-approved-invitation.json')
    require(result==value['independent_reapproval'] and original['operation']==result['original_operation']
            and approved['operation']==result['issued_operation'] and request['previous']==original['operation']
            and request['request_id']==approved['request_id'] and request['predecessor']==approved['predecessor'],
            'independent reapproval retained decision')
    require(hashlib.sha256(copy('peer-signing-public.bin')).hexdigest()==result['signing_key_sha256'],
            'independent retained signing identity digest')
    proof=copy('peer-request.bin')
    require(hashlib.sha256(proof).hexdigest()==result['request_sha256'] and wire(request['request'])==proof,
            'independent original reapproval proof')
    for label in HTTP[:2]:
        require(commands[label]['account']=='bob' and commands[label]['route']=='/api/enrollment/reapprove'
                and commands[label]['body']==request,'independent reapproval account request')
    require(approved==parse_strict_json_bytes(responses['peer-reapproval-retry'].encode(),label='reapproval successor')
            and commands['peer-original-issue-refused']['body']=={'operation':original['operation']}
            and commands['peer-issue']['body']=={'operation':approved['operation']},
            'independent reapproval actual issuance')
    require(all(original[k]==approved[k] for k in ('application','root_revision','root','family','device',
        'generation','valid_from','valid_until','predecessor')), 'independent reapproval device intent')
