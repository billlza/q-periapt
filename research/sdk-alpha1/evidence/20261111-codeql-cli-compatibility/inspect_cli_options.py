"""Read CodeQL CLI option annotations without executing Java."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile

ROOT=Path('/workspace/scratch/qperiapt-recovery-20261111/wrapper-diagnostics')
class Reader:
    def __init__(self,data): self.data,self.pos=data,0
    def take(self,n):
        b=self.data[self.pos:self.pos+n]; assert len(b)==n
        self.pos+=n; return b
    def num(self,n): return int.from_bytes(self.take(n),'big')

def inspect(data):
    r=Reader(data); assert r.num(4)==0xcafebabe
    r.take(4); cp=[None]*r.num(2); i=1
    while i<len(cp):
        tag=r.num(1)
        if tag==1: value=r.take(r.num(2)).decode('utf-8',errors='replace')
        elif tag in (3,4): value=r.take(4).hex()
        elif tag in (5,6): value=r.take(8).hex()
        elif tag in (7,8,16,19,20): value=r.num(2)
        elif tag in (9,10,11,12,17,18): value=[r.num(2),r.num(2)]
        elif tag==15: value=[r.num(1),r.num(2)]
        else: raise ValueError(tag)
        cp[i]=(tag,value); i+=2 if tag in (5,6) else 1
    def const(i):
        if i==0: return None
        tag,value=cp[i]
        if tag in (7,8,16,19,20): return const(value)
        return value
    def annotation(q):
        kind=const(q.num(2)); pairs={}
        for _ in range(q.num(2)):
            name=const(q.num(2)); pairs[name]=element(q)
        return {'type':kind,'values':pairs}
    def element(q):
        tag=chr(q.num(1))
        if tag in 'BCDFIJSZsc': return const(q.num(2))
        if tag=='e': return {'enum':const(q.num(2)),'value':const(q.num(2))}
        if tag=='@': return annotation(q)
        if tag=='[': return [element(q) for _ in range(q.num(2))]
        raise ValueError(tag)
    def attrs(q):
        result=[]
        for _ in range(q.num(2)):
            name=const(q.num(2)); data=q.take(q.num(4))
            if name in ('RuntimeVisibleAnnotations','RuntimeInvisibleAnnotations'):
                a=Reader(data); result.extend(annotation(a) for _ in range(a.num(2)))
                assert a.pos==len(data)
        return result
    r.num(2); name,parent=const(r.num(2)),const(r.num(2))
    r.take(2*r.num(2)); members=[]
    for kind in ('field','method'):
        for _ in range(r.num(2)):
            flags=r.num(2); name_=const(r.num(2)); desc=const(r.num(2)); annotations=attrs(r)
            members.append({'kind':kind,'name':name_,'descriptor':desc,'annotations':annotations})
    annotations=attrs(r)
    assert r.pos==len(data)
    return {'name':name,'parent':parent,'bytes':len(data),
            'sha256':hashlib.sha256(data).hexdigest(),'members':members,
            'annotations':annotations,
            'option_strings':[x[1] for x in cp[1:] if x and x[0]==1 and x[1].startswith('--')]}

with zipfile.ZipFile(ROOT/'codeql/tools/codeql.jar') as z:
    names=z.namelist()
    matches=[n for n in names if n.startswith('com/semmle/cli2/') and n.endswith('.class')
             and (b'--qlconfig-file' in z.read(n) or ('/test/' in n and 'Extract' in n))]
    initial=[
        'com/semmle/cli2/VersionCommand.class',
        'com/semmle/cli2/resolve/ResolveRamCommand.class',
        'com/semmle/cli2/bqrs/DecodeCommand.class',
        'com/semmle/cli2/database/AnalyzeCommand.class',
        'com/semmle/cli2/resolve/ResolveQueriesCommand.class',
        'com/semmle/cli2/CommonOptions.class',
        *matches]
    results={}; pending=list(initial)
    while pending:
        path=pending.pop()
        if path in results or path not in names: continue
        item=inspect(z.read(path)); results[path]=item
        if item['parent'] and item['parent'].startswith('com/semmle/cli2/'):
            pending.append(item['parent']+'.class')
        for member in item['members']:
            if any(a['type'].endswith(('CommandLine$Mixin;','CommandLine$ArgGroup;'))
                   for a in member['annotations']):
                desc=member['descriptor']
                assert desc.startswith('L') and desc.endswith(';')
                pending.append(desc[1:-1]+'.class')
    report={'kind':'qperiapt.codeql_2272_static_option_readback',
            'jar_sha256':hashlib.sha256((ROOT/'codeql/tools/codeql.jar').read_bytes()).hexdigest(),
            'method':'Constant-pool and Picocli option/mixin/arg-group annotations; no JVM',
            'classes':results}
    (ROOT/'CLI_OPTION_DECLARATIONS.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'qlconfig_or_extract_classes':matches,'classes_read':len(results)}))
    for path,item in sorted(results.items()):
        print(json.dumps({'class':item['name'],'parent':item['parent'],'sha256':item['sha256'],
            'options':item['option_strings'],
            'mixins':[{'name':m['name'],'type':m['descriptor'],'annotations':m['annotations']}
                for m in item['members'] if any(a['type'].endswith(('CommandLine$Mixin;','CommandLine$ArgGroup;')) for a in m['annotations'])]}))
