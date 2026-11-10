#!/usr/bin/env python3
"""A reentrant witness transport cannot release output after committing revocation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments,Counterpart
    args=arguments()
    from qperiapt_continuity_reference.provider import load_provider
    load_provider(args.provider_root)
    from fixture_inputs import load,load_witness_pin
    from qperiapt_continuity_reference.durable import owner_binding
    from qperiapt_continuity_reference.journal import Scope
    from qperiapt_continuity_reference.witness import Client,TcpTransport
    from qperiapt_continuity_reference.witness_session import WitnessSession
    from qperiapt_continuity_reference.wire import SigningKey,require
    from witness_fixture import Bridge
    out=args.output.resolve();out.mkdir();(out/'native').mkdir()
    private=Path(tempfile.mkdtemp(prefix='qperiapt-peer-reply-release-')).resolve()
    require(not private.is_relative_to(out),'private release fixture inside artifact')
    (out/'private-fixture-path').write_text(str(private)+'\n')
    native=Counterpart(args.native.resolve(),out/'native',required_witness=True,peer_lifecycle=True)
    bridge=None;owner=None
    try:
        signer=SigningKey();require(native.transfer(signer.public().raw)==b'\1ready','native enrollment')
        public=out/'native/public';pin=load_witness_pin(public);_,_,ctx=load(public,150,witness_pin=pin)
        path=private/'session';path.mkdir(mode=0o700);key=os.urandom(32);scope=Scope(os.urandom(32),owner_binding(ctx),ctx.digest)
        genesis=WitnessSession.provision(path,scope,key,ctx,signer,150)
        bridge=Bridge(native,out);bridge.call('trusted-enrollment',30,genesis.wire(),b'enrolled')
        armed=False;revoked=False
        transport=TcpTransport(bridge.address)
        roster=(public/'peer-revoked-roster').read_bytes();target=(public/'pin-peer-revoked-target').read_bytes()
        def carrier(request,deadline):
            nonlocal armed,revoked
            response=transport(request,deadline)
            if armed and request[204]==4:
                armed=False;owner._observer=None
                require(owner.admit_peer_roster(roster,target,170)==target,'nested revocation checkpoint')
                revoked=True
            return response
        client=Client(pin,ctx.witness.subject(scope.identity),signer,carrier)
        owner=WitnessSession.open(path,scope,key,ctx,client=client)
        initial=owner.initial(150);reply=bridge.call('bootstrap-response',4,initial)
        final=owner.finish(reply,150);session=bridge.call('bootstrap-complete',5,final)
        require(owner.activate(170)==session,'original session');bridge.call('native-activate',6,expected=session)
        identity=owner.next_id(170)
        def observe(stage):
            nonlocal armed
            if stage=='protocol:send-committed':armed=True
        owner._observer=observe
        outcome={}
        try:
            wire=owner.send(identity,b'withhold after current-authority callback',b'peer',170)
        except ValueError as error:
            require('peer authority changed during output admission' in str(error),'wrong release refusal: '+str(error))
            outcome={'released':False,'error':str(error)}
        else:
            outcome={'released':True,'ciphertext_bytes':len(wire),'ciphertext_sha256':hashlib.sha256(wire).hexdigest()}
        require(revoked and owner.peer_authority_status()[3] is False,'nested revocation did not persist')
        outcome['revoked']=revoked
        (out/'OUTCOME.json').write_text(json.dumps(outcome,indent=2)+'\n')
        (out/'ATTEMPTS.json').write_text(json.dumps(bridge.records,indent=2)+'\n')
        (out/'NATIVE.json').write_text(json.dumps(native.commands,indent=2)+'\n')
        require(not outcome['released'],'witness callback released ciphertext after committed peer revocation')
        print(json.dumps(outcome))
    finally:
        if owner:owner.close()
        if bridge:bridge.close()
        native.close()


if __name__=='__main__':main()
