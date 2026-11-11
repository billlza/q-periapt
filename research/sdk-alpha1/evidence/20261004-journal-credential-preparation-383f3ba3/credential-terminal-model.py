"""Finite exploration of a candidate witness terminal-floor contract.

Not a cryptographic proof or a product implementation. Abstract authenticated
root grants, durable atomic storage, fresh observations, and one writer lease.
Two distinct root-approved targets share one original predecessor; versions 2/3
are already signed into the existing credential-renewal grant. Ghost sets only
check invariants and are not proposed persistent storage.
"""
from dataclasses import dataclass,replace,asdict
from collections import deque
from pathlib import Path
import json,hashlib

@dataclass(frozen=True)
class State:
    floor:int=1
    slot:tuple=()
    witness:int=0
    witness_head:int=0
    local:int=0
    local_head:int=0
    intent:int=0
    proposals:frozenset=frozenset()
    observed:frozenset=frozenset()
    closed:frozenset=frozenset()
    committed:frozenset=frozenset()
    expired:bool=False

versions={1:2,2:3}
def actions(s,enforce_floor=True,ordinary_replay=False):
    if not s.expired:yield 'expire_targets',replace(s,expired=True)
    for op,v in versions.items():
        if not s.intent and s.local==0 and not s.expired and op not in s.observed:
            yield f'journal_reserve_{op}',replace(s,intent=op,proposals=s.proposals|{op})
        admissible=op in s.proposals and not s.slot and s.witness==0 and s.witness_head==0
        admissible=admissible and (not enforce_floor or v>s.floor)
        if admissible and not s.expired:
            yield f'witness_prepare_{op}',replace(s,slot=(op,'Prepared'))
        if admissible or s.slot==(op,'Prepared'):
            # Explicit authorized cancellation can close a still-live target too.
            # This also covers expiry close before a prepare reply is available.
            yield f'witness_close_{op}',replace(s,floor=max(s.floor,v),slot=(op,'Closed'),closed=s.closed|{op})
        if s.slot==(op,'Prepared') and not s.expired:
            yield f'witness_apply_{op}',replace(s,floor=max(s.floor,v),slot=(op,'Applied'),witness=op,witness_head=op,committed=s.committed|{op})
        if s.intent==op and s.slot in [(op,'Applied'),(op,'Closed')]:
            applied=s.slot[1]=='Applied'
            yield f'journal_resolve_{op}',replace(s,intent=0,local=op if applied else s.local,local_head=op if applied else s.local_head,observed=s.observed|{op})
        if s.slot in [(op,'Applied'),(op,'Closed')] and op in s.observed:
            yield f'ack_exact_terminal_{op}',replace(s,slot=())
        if ordinary_replay and s.intent==op and s.witness==0:
            yield f'BUG_ordinary_Advance_{op}',replace(s,witness_head=op,local_head=op)

def violation(s):
    if s.closed&s.committed:return 'a closed original operation later committed'
    if s.witness_head!=s.witness:return 'witness head and credential adoption split'
    if s.local_head!=s.local:return 'local head and credential adoption split'
    return None

def explore(**knobs):
    start=State();queue=deque([(start,[])]);seen={start};edges=0;recovery_after_expiry=False;close_then_next=False;max_depth=0
    while queue:
        s,path=queue.popleft();max_depth=max(max_depth,len(path))
        recovery_after_expiry |= s.expired and s.local==s.witness and s.local>0
        close_then_next |= 1 in s.closed and s.witness==2
        for label,nxt in actions(s,**knobs):
            edges+=1;bad=violation(nxt)
            if bad:return dict(safe=False,states=len(seen),edges=edges,counterexample=path+[label],violation=bad)
            if nxt not in seen:seen.add(nxt);queue.append((nxt,path+[label]))
    return dict(safe=True,states=len(seen),edges=edges,max_shortest_path=max_depth,exact_recovery_after_expiry_reachable=recovery_after_expiry,closed_lower_version_then_new_target_reachable=close_then_next)

correct=explore();without_floor=explore(enforce_floor=False);ordinary=explore(ordinary_replay=True)
assert correct['safe'] and correct['exact_recovery_after_expiry_reachable'] and correct['closed_lower_version_then_new_target_reachable']
assert not without_floor['safe'] and not ordinary['safe']
record=dict(completed=True,scope='Finite two-target state exploration, not protocol security proof; signed successor roster version proposed as monotonic closure floor',assumptions=['Authenticated root grants already bind a strictly newer successor roster version','Fresh authenticated status, atomic durable witness and journal transactions','Exact terminal is retained durably locally before acknowledgement; absent/pruned status never means Closed','Ordinary Advance/Fence/control-plane updates cannot consume or bypass a prepared transaction','Same immutable witness subject and policy; no root rotation in this model'],remaining=['Prove floor interaction with subsequent roster refresh and credential lineage','Integrate bounded exact status, historical expiry handling, storage migration and live-command admission','Test all implementation crash and network boundaries; finite model is not equivalent to cryptographic or unbounded proof'],correct=correct,without_floor=without_floor,ordinary_replay=ordinary,release_claim_eligible=False,source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
Path(__file__).with_suffix('.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
