"""Read the retained old-writer authority image without changing its canonical bytes."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--implementation-root',type=Path,required=True)
    parser.add_argument('--provider-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();implementation=args.implementation_root.resolve(strict=True)
    sys.path.insert(0,str(implementation))
    from qperiapt_continuity_reference.provider import load_provider
    load_provider(args.provider_root)
    from qperiapt_continuity_reference.account_authority_state import Image
    from qperiapt_continuity_reference.wire import VerificationKey,require
    from qperiapt_continuity_reference.witness import Pin
    folder=Path(__file__).resolve().parent/'fixtures/account-authority-v1'
    inputs={name:(folder/name).read_bytes() for name in ('image.bin','pins.json','ORIGIN.json')}
    origin=json.loads(inputs['ORIGIN.json']);pins=json.loads(inputs['pins.json'])
    digest=lambda value:hashlib.sha256(value).hexdigest()
    require(digest(inputs['image.bin'])==origin['image_sha256'] and digest(inputs['pins.json'])==origin['pins_sha256'],
            'old writer capture identity differs')
    require(origin['writer_product_source_commit']=='b019628acdf4412a6b7e9cd234304f4a14e157b0'
            and origin['writer_modules_match_committed_source']==101 and origin['original_store_unchanged'],
            'old writer provenance differs')
    family=bytes.fromhex(pins['family']);pin=Pin(bytes.fromhex(pins['identity']),VerificationKey(bytes.fromhex(pins['key'])))
    raw=inputs['image.bin'];image=Image.read(raw,family,pin)
    require(raw.startswith(b'QPRFAA01') and image.encode(family,pin)==raw,'old image was silently rewritten')
    selected=image.current(family,pin)
    require(len(selected)==1 and next(iter(selected.values())).checkpoint.revision==2
            and not next(iter(selected.values())).pending,'old active mapping changed')
    refused=[]
    def reject(label,operation):
        try:operation()
        except ValueError:refused.append(label)
        else:raise ValueError('invalid old history accepted: '+label)
    reject('unjustified-schema-two',lambda:Image.read(b'QPRFAA02'+raw[8:],family,pin))
    reject('truncated',lambda:Image.read(raw[:-1],family,pin))
    reject('trailing',lambda:Image.read(raw+b'\0',family,pin))
    first=image.replacements[0]
    reject('unknown-phase',lambda:replace(image,replacements=(replace(first,phase=99),*image.replacements[1:])).encode(family,pin))
    reject('initial-root-reuse',lambda:replace(image,initial=tuple(sorted((*image.initial,
           replace(image.initial[0],application=b'\xff'*32)),key=lambda row:row.application))).encode(family,pin))
    require({name:(folder/name).read_bytes() for name in inputs}==inputs,'compatibility inputs changed')
    modules={name:str(Path(module.__file__).resolve()) for name,module in sys.modules.items()
             if name.startswith('qperiapt_continuity_reference.') and getattr(module,'__file__',None)}
    require(modules and all(Path(path).is_relative_to(implementation) for path in modules.values()),
            'compatibility check imported source instead of selected installation')
    report={'completed':True,'old_schema':'QPRFAA01','canonical_bytes_preserved':True,'active_revision':2,
            'refusals':refused,'fixture_sha256':{name:digest(body) for name,body in inputs.items()},
            'imported_product_sha256':{path:digest(Path(path).read_bytes()) for path in modules.values()},
            'test_source_sha256':digest(Path(__file__).read_bytes()),
            'scope':'Actual old installed-writer capture decoded unchanged by selected installation; malformed histories refused. New adoption schema and actual storage reopening are qualified in separate runtime scenarios.'}
    with args.output.open('x') as out:json.dump(report,out,indent=2);out.write('\n')
    print(json.dumps({'completed':True,'refusals':len(refused),'modules':len(modules)}))


if __name__=='__main__':main()
