#!/usr/bin/env python3
"""Read-only source binding and independent SDK framing/controller checks.

This uses Python's standard library. It does not execute native Rust or prove
cryptographic indistinguishability. Run with --source-root pointing to the
retained q-periapt checkout; output files are written only to --output-dir.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
import subprocess

PIN = '228c944fc476e3e57d6c08063cacb19bca5b360e'
DEV = '1c68aa666db22d36ee136be1ec712545a9e74f03'
SALT = b'QPeriapt-SDK-HKDF-SHA256-v1'
DOMAIN = b'QPeriapt-SDK-Key-v1'
SDK = 'crates/q-periapt-sdk/src/'
DUR = 'research/continuity-identity-candidate/src/durable/'
FILES = [
    (SDK+'purpose.rs', [(12,45,'constants and purpose codes'), (56,86,'owned key and HKDF'), (89,155,'complete info and source derivation'), (161,245,'public native vectors')]),
    (SDK+'lib.rs', [(141,199,'runtime and admission'), (245,307,'verified metadata'), (320,325,'runtime close'), (439,459,'decapsulation owner'), (539,558,'source owner lifecycle')]),
    (SDK+'tests.rs', [(763,812,'five-purpose peer and lifecycle workload'), (814,855,'shape and resource workload'), (857,897,'different-root fixture')]),
    ('crates/q-periapt-policy/src/lib.rs', [(159,199,'trusted policy state and encoding')]),
    ('crates/q-periapt-core/src/lib.rs', [(478,489,'application-context bound')]),
    ('crates/q-periapt-ffi/src/sdk.rs', [(771,804,'derive reservation and publication'), (811,840,'derived export and close')]),
    ('crates/q-periapt-ffi/src/sdk/registry.rs', [(14,103,'object and individual close'), (120,183,'parent checks and allocation'), (234,284,'runtime children'), (350,449,'publication and rollback')]),
    (SDK+'expert/replay.rs', [(55,154,'retained key and encapsulation scopes')]),
    (SDK+'expert.rs', [(43,109,'typed component access and runtime binding'), (141,199,'explicit expanded key transfer')]),
    (DUR+'messages/rekey.rs', [(321,452,'retained offer token stages')]),
    (DUR+'messages/rekey/response.rs', [(114,145,'response context and root encoding'), (183,367,'response-token transitions')]),
    (DUR+'messages/rekey/completion.rs', [(761,931,'proposer reconstruction and install'), (942,1092,'retained responder root and receipt')]),
    ('research/continuity-identity-candidate/src/durable.rs', [(665,669,'lifetime database lock'), (784,840,'authenticated reopen and close')]),
    (DUR+'write_intent.rs', [(1108,1134,'exact pending recovery')]),
    (DUR+'messages/tests/reservation_disclosure/aggregate_copy.rs', [(68,158,'aggregate copy and original reservation')]),
    ('bindings/android/smoke/sdk/dev/qperiapt/androidsmoke/QPeriaptSDKWorkload.java', [(75,98,'two-peer five-purpose source consumer')]),
    ('docs/SDK_KEY_DERIVATION.md', [(1,135,'published native encoding and vector')]),
    ('Cargo.lock', [(925,941,'HKDF and HMAC dependency identities')]),
]

checks = []
def check(name, condition, category):
    checks.append({'name': name, 'category': category, 'passed': bool(condition)})

def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)

def source_binding(root):
    sources = {}
    records = []
    for relative, ranges in FILES:
        pinned = git(root, 'show', PIN+':'+relative)
        current = (root/relative).read_bytes()
        development = git(root, 'show', DEV+':'+relative)
        sources[relative] = pinned.decode()
        length = len(pinned.splitlines())
        # Whole-file docs range ends at the actual pinned file end.
        if relative.endswith('SDK_KEY_DERIVATION.md'):
            ranges = [(1, length, 'published native encoding and vector')]
        for start,end,claim in ranges:
            check(relative+':'+str(start)+'-'+str(end)+' range', 1 <= start <= end <= length, 'source_range')
        check(relative+' pinned worktree bytes', current == pinned, 'source_binding')
        records.append({'path':relative, 'line_count':length,
                        'ranges':[{'first':a,'last':b,'claim':c} for a,b,c in ranges],
                        'sha256':hashlib.sha256(pinned).hexdigest(),
                        'git_blob':git(root,'rev-parse',PIN+':'+relative).decode().strip(),
                        'worktree_matches_pin':current == pinned,
                        'development_matches_pin':development == pinned})
    purpose = sources[SDK+'purpose.rs']
    library = sources[SDK+'lib.rs']
    ffi = sources['crates/q-periapt-ffi/src/sdk.rs']
    registry = sources['crates/q-periapt-ffi/src/sdk/registry.rs']
    check('exact salt and domain literals', f'b"{SALT.decode()}"' in purpose and f'b"{DOMAIN.decode()}"' in purpose, 'source_anchor')
    fields = ['INFO_DOMAIN,','&1_u32.to_be_bytes()', '&2_u32.to_be_bytes()', 'state,', 'root,', '&(purpose as u32).to_be_bytes()', '&label_len.to_be_bytes()', 'label,', '&context_len.to_be_bytes()', 'context,', '&32_u16.to_be_bytes()']
    encoding = purpose.split('hkdf32(\n        secret,')[1].split('        ],')[0]
    locations = [encoding.index(field) for field in fields]
    check('native complete info field order', locations == sorted(locations), 'source_anchor')
    owner = purpose.split('pub struct DerivedKey {')[1].split('impl DerivedKey')[0]
    check('derived owner has separate bytes and runtime without KEM lease', 'Option<ZeroizingBytes<32>>' in owner and 'Arc<State>' in owner and 'KeyLease' not in owner, 'source_anchor')
    derive = purpose.split('pub fn derive_key(')[1].split('\n}\n')[0]
    check('derivation admission before source and KDF', derive.index('self.state.begin()?') < derive.index('self.inner.as_ref()') < derive.index('let bytes = derive('), 'source_anchor')
    check('native owner close and runtime guards', 'self.bytes = None;' in purpose and 'self.inner = None;' in library and 'self.state.ensure_open()?;' in purpose, 'source_anchor')
    check('actual HKDF extract and multipart expand', 'Hkdf::<Sha256>::extract(Some(salt), ikm)' in purpose and 'hkdf.expand_multi_info(info, output.as_mut_bytes())' in purpose, 'source_anchor')
    call = ffi.split('fn q_periapt_sdk_secret_derive(')[1].split('/// Explicitly copy')[0]
    check('FFI derives under runtime parent before publication', call.index('reserve(parent)?') < call.index('.derive_key(') < call.index('slot.install(') < call.index('slot.publish()'), 'source_anchor')
    publication = registry.split('pub(super) fn publish(mut self)')[1].split('impl<const N: usize> Drop')[0]
    check('FFI publication checks parent liveness', 'if !table.parent_live(parent)' in publication, 'source_anchor')
    response = sources[DUR+'messages/rekey/response.rs']
    completion = sources[DUR+'messages/rekey/completion.rs']
    production = git(root, 'grep', '-n', 'derive_root(', PIN, '--', DUR+'messages').decode().splitlines()
    production = [line for line in production if '/tests/' not in line]
    check('exact two durable production root callsites plus definition', len(production) == 3 and sum('fn derive_root(' in line for line in production) == 1, 'source_anchor')
    check('exact two installed rekey root assignments', len(re.findall(r'state\.rekey\s*=\s*root;', completion)) == 2, 'source_anchor')
    check('durable root info retains its source domain', 'pending-root/HKDF-SHA256/' in response and 'response-core' in response, 'source_anchor')
    return {'schema':'qperiapt-sdk-purpose-source-map/1', 'source_pin':PIN, 'comparison_commit':DEV,
            'files':records, 'scope':'Read-only pinned source binding; ranges support the manual induction in source_correspondence.md.'}

def mac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()

def info(state, root_digest, purpose, label, context):
    if len(label) == 0 or len(label) > 255 or len(context) > 65536:
        raise ValueError('InvalidLength')
    if not all(0x21 <= b <= 0x7e for b in label) or purpose not in range(1,6):
        raise ValueError('InvalidPurpose')
    assert len(state) == 36 and len(root_digest) == 32
    return b''.join([DOMAIN,(1).to_bytes(4,'big'),(2).to_bytes(4,'big'),state,root_digest,
                     purpose.to_bytes(4,'big'),len(label).to_bytes(2,'big'),label,
                     len(context).to_bytes(4,'big'),context,(32).to_bytes(2,'big')])

def parse(encoded):
    offset = 0
    def take(n):
        nonlocal offset
        result = encoded[offset:offset+n]
        if len(result) != n:
            raise ValueError('truncated')
        offset += n
        return result
    assert take(19) == DOMAIN and take(4) == (1).to_bytes(4,'big') and take(4) == (2).to_bytes(4,'big')
    state, root = take(36), take(32)
    p = int.from_bytes(take(4),'big')
    label = take(int.from_bytes(take(2),'big'))
    context = take(int.from_bytes(take(4),'big'))
    assert take(2) == b'\x00\x20' and offset == len(encoded)
    return state,root,p,label,context

def key(secret, encoded):
    return mac(mac(SALT,secret),encoded+b'\x01')

def ell(length):
    return 1+(length+9+63)//64

@dataclass
class Runtime:
    closed: bool = False
    operations: int = 0
    limit: int = 1
    def admit(self):
        if self.closed:
            raise ValueError('Closed')
        if self.operations >= self.limit:
            raise ValueError('ResourceLimit')
        self.operations += 1
    def close(self):
        self.closed = True

@dataclass
class Source:
    runtime: Runtime
    live: bool = True
    def close(self):
        self.live = False

@dataclass
class Owner:
    runtime: Runtime
    encoded: bytes
    value: bytes
    live: bool = True
    def checked_copy(self):
        if self.runtime.closed or not self.live:
            raise ValueError('Closed')
        return self.value
    def close(self):
        self.live = False

class Controller:
    def __init__(self):
        self.entries = {}
        self.marked = None
        self.secret = bytes([7])*32
    def begin(self, source):
        source.runtime.admit()
        if not source.live:
            source.runtime.operations -= 1
            raise ValueError('Closed')
        return source.runtime
    def finish(self, ticket, encoded, mark=False):
        if mark:
            if encoded in self.entries or self.marked is not None:
                ticket.operations -= 1
                raise ValueError('Freshness')
            self.marked = encoded
        value = self.entries.setdefault(encoded,key(self.secret,encoded))
        ticket.operations -= 1
        return Owner(ticket, encoded, value)
    def derive(self, source, encoded, mark=False):
        return self.finish(self.begin(source),encoded,mark)
    def publish(self, owner):
        if owner.runtime.closed:
            owner.close()
            return False
        return True

def fails(action, expected):
    try:
        action()
    except ValueError as exc:
        return str(exc) == expected
    return False

def algebra_and_controller():
    state,root = bytes([2])*36, bytes([3])*32
    check('salt/domain lengths', (len(SALT),len(DOMAIN)) == (27,19), 'algebra')
    r0 = SALT+b'\0'*5
    check('short salt has identical 64-byte HMAC key block', SALT.ljust(64,b'\0') == r0.ljust(64,b'\0') and len(r0) == 32, 'algebra')
    check('fixed salt normalization at public samples', all(mac(SALT,bytes([i])*32)==mac(r0,bytes([i])*32) for i in [0,1,7,255]), 'algebra')
    baseline = info(state,root,1,b'app/v1/aes256',b'transcript')
    check('native public purpose vector', key(bytes([7])*32,baseline).hex() == '899c3fe0b3419a6f3947c4e237daf8970b2c29442d9fce4385d30d2558242f65', 'algebra')
    rfc = mac(mac(bytes(range(13)),bytes([11])*22),bytes(range(0xf0,0xfa))+b'\x01')
    check('RFC5869 first-block vector', rfc.hex() == '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf', 'algebra')
    minimum = info(state,root,1,b'a',b'')
    maximum = info(state,root,5,b'a'*255,b'x'*65536)
    check('exact min/max info and row lengths', (len(minimum),len(maximum),len(minimum)+1,len(maximum)+1) == (108,65898,109,65899), 'algebra')
    check('row padding full limit and retained native root', (ell(65899),ell(98)) == (1031,3), 'algebra')
    examples = [info(state,root,p,a,c) for p in range(1,6) for a,c in [(b'a',b''),(b'ab',b'c'),(b'a',b'bc'),(b'a'*255,b'x'*65536)]]
    check('full effective info parse round trips', all(info(*parse(x)) == x for x in examples), 'framing')
    a = info(state,root,1,b'ab',b'c'); b = info(state,root,1,b'a',b'bc')
    check('ambiguous raw label/context concatenation is separated', b'ab'+b'c' == b'a'+b'bc' and a != b, 'counterexample_repair')
    five = [info(state,root,p,b'app/v1/aes256',b'authenticated-transcript') for p in range(1,6)]
    check('five native purpose descriptors and row budget', len(set(five)) == 5 and all(len(x)==144 for x in five) and ell(145)==4 and 2+(2+ell(145))*5 == 32, 'algebra')
    check('policy/root fields contribute exact bytes', info(bytes(36),root,1,b'app',b'ctx') != info(state,root,1,b'app',b'ctx') != info(state,bytes(32),1,b'app',b'ctx'), 'framing')
    for label,context,error in [(b'',b'','InvalidLength'),(b'x'*256,b'','InvalidLength'),(b'a',b'x'*65537,'InvalidLength'),(b' ',b'','InvalidPurpose'),(b'\0',b'','InvalidPurpose'),(b'\xff',b'','InvalidPurpose')]:
        check('shape validation '+str(len(label))+'/'+str(len(context))+'/'+label[:1].hex(), fails(lambda:info(state,root,1,label,context),error), 'framing')
    ctl=Controller(); rt=Runtime(); src=Source(rt)
    owner1=ctl.derive(src,baseline); owner2=ctl.derive(src,baseline)
    check('equal-info new owners retain one table value', owner1 is not owner2 and owner1.value == owner2.value and len(ctl.entries)==1, 'owner_model')
    owner1.close()
    check('local derived close preserves sibling alias', fails(owner1.checked_copy,'Closed') and owner2.checked_copy()==owner2.value, 'counterexample_repair')
    copied=owner2.checked_copy(); src.close()
    check('source close preserves existing derived owner', fails(lambda:ctl.derive(src,baseline),'Closed') and owner2.checked_copy()==copied, 'owner_model')
    rt.close()
    check('runtime close blocks later export and preserves earlier copy', fails(owner2.checked_copy,'Closed') and len(copied)==32, 'owner_model')
    ctl=Controller(); rt=Runtime(); src=Source(rt)
    ticket=ctl.begin(src); rt.close(); late=ctl.finish(ticket,baseline)
    check('admitted derive completes after runtime close with guarded owner', baseline in ctl.entries and fails(late.checked_copy,'Closed') and rt.operations==0, 'owner_model')
    ctl=Controller(); rt=Runtime(); src=Source(rt)
    ticket=ctl.begin(src)
    check('in-flight admission budget', fails(lambda:ctl.begin(src),'ResourceLimit'), 'owner_model')
    ctl.finish(ticket,baseline)
    check('in-flight admission returns after completion', ctl.derive(src,baseline).value == key(ctl.secret,baseline), 'owner_model')
    ctl=Controller(); rt1=Runtime(); rt2=Runtime(); s1=Source(rt1); s2=Source(rt2)
    unpublished=ctl.derive(s1,baseline); rt1.close()
    check('failed publication retains first computation ledger', not ctl.publish(unpublished) and baseline in ctl.entries, 'owner_model')
    alias=ctl.derive(s2,baseline)
    check('later runtime alias retrieves prepublication value', alias.value == unpublished.value and len(ctl.entries)==1, 'owner_model')
    check('publication retry supplies an existing entry', fails(lambda:ctl.derive(s2,baseline,mark=True),'Freshness'), 'counterexample_repair')
    fresh=ctl.derive(s2,maximum,mark=True); same=ctl.derive(s2,maximum)
    check('marked key ownership is keyed by full descriptor', ctl.marked==fresh.encoded==same.encoded and fresh.value==same.value, 'owner_model')
    check('other descriptors remain ordinary available keys', alias.encoded!=ctl.marked and alias.checked_copy()==alias.value, 'owner_model')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,default=Path(__file__).resolve().parent)
    args=parser.parse_args()
    source_map=source_binding(args.source_root.resolve())
    algebra_and_controller()
    args.output_dir.mkdir(parents=True,exist_ok=True)
    (args.output_dir/'source_map.json').write_text(json.dumps(source_map,indent=2)+'\n')
    report={'schema':'qperiapt-sdk-purpose-independent-checks/1', 'source_pin':PIN,
            'scope':'Pinned source anchors, stdlib HMAC/framing, and finite owner/controller model; native Rust execution is separately retained in native_test_receipt.json.',
            'passed':sum(x['passed'] for x in checks), 'total':len(checks),
            'failures':[x for x in checks if not x['passed']], 'checks':checks}
    (args.output_dir/'validation_report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':report['passed'],'total':report['total'],'failures':report['failures'],
                      'source_files':len(source_map['files']),
                      'development_equal_files':sum(x['development_matches_pin'] for x in source_map['files'])},indent=2))
    raise SystemExit(bool(report['failures']))

if __name__=='__main__':
    main()
