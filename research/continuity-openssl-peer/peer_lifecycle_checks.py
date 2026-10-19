#!/usr/bin/env python3
"""Retained peer renewal/revocation across independent local and witnessed owners."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile


def scenario(args, output, witnessed, *, reentrant=False):
    from cryptography.exceptions import InvalidSignature
    from qperiapt_continuity_reference.durable import Session, owner_binding
    from qperiapt_continuity_reference.journal import Journal, Scope
    from qperiapt_continuity_reference.witness import Client, TcpTransport
    from qperiapt_continuity_reference.witness_session import WitnessSession
    from qperiapt_continuity_reference.witness_journal import WitnessJournal
    from qperiapt_continuity_reference.renewal import verify
    from qperiapt_continuity_reference.state_codec import decode
    from qperiapt_continuity_reference.wire import SigningKey, require
    from fixture_inputs import load, load_witness_pin
    from run import Counterpart
    from session_driver import SessionDriver
    from signing_fixture import write
    from traffic_checks import application
    from witness_fixture import Bridge
    from archived_fixture import load_version
    output.mkdir();(output/'native').mkdir()
    private=Path(tempfile.mkdtemp(prefix='qperiapt-peer-lifecycle-')).resolve()
    require(not private.is_relative_to(output),'private lifecycle fixture inside artifact')
    (output/'private-fixture-path').write_text(str(private)+'\n')
    native=Counterpart(args.native.resolve(),output/'native',send_budget=4,required_witness=witnessed,peer_lifecycle=True)
    bridge=None;refusals=[]
    def refuses(name,action,reason=None):
        try:action()
        except (ValueError,InvalidSignature,OSError) as error:
            require(reason is None or reason in str(error),'wrong refusal: '+name+': '+str(error))
            refusals.append({'case':name,'type':type(error).__name__,'error':str(error)})
        else:raise ValueError('expected refusal: '+name)
    try:
        signer=SigningKey();require(native.transfer(signer.public().raw)==b'\1ready','native ready')
        public=output/'native/public';pin=load_witness_pin(public) if witnessed else None
        _,_,ctx=load(public,150,witness_pin=pin)
        path=private/'session';path.mkdir(mode=0o700)
        scope=Scope(os.urandom(32),owner_binding(ctx),ctx.digest);key=os.urandom(32)
        config=private/'configuration'
        with os.fdopen(os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:
            f.write(key+scope.wire());f.flush();os.fsync(f.fileno())
        signer_path=private/'signer';write(signer_path,signer)
        old,old_hash=load_version(private,4)
        original=old.State(old.Initiator._prepare_for_journal(ctx,signer,150))
        require(original.format_version==4,'archived original writer format')
        if witnessed:
            old_journal=importlib.import_module(old.__package__+'.witness_journal')
            genesis=old_journal.WitnessJournal.provision(path,scope,key,old.encode(original),lambda data:old.decode(data,ctx).close(),ctx.witness)
            bridge=Bridge(native,output)
            bridge.call('trusted-enrollment',30,genesis.wire(),b'enrolled')
        else:
            old_journal=importlib.import_module(old.__package__+'.journal')
            owner=old_journal.Journal.create(path,scope,key,old.encode(original),lambda data:old.decode(data,ctx).close());owner.close()
        original.close()
        call=bridge.call if bridge else lambda name,command,wire=b'',expected=None,status=1:native.command(name,command,wire,status,expected)
        driver=SessionDriver(output,args.provider_root.resolve(),public,config,path,signer_path,
                             witness_address=(bridge.address[0]+':'+str(bridge.address[1])) if bridge else None)
        worker=driver.run
        def value(name,action,arguments=(),**kw):return bytes.fromhex(worker(name,action,arguments,**kw))
        def opened(observer=None):
            if witnessed:
                return WitnessSession.open(path,scope,key,ctx,client=Client(pin,ctx.witness.subject(scope.identity),signer,TcpTransport(bridge.address)),observer=observer)
            return Session.open(path,scope,key,ctx,observer=observer)
        initial=value('initial','initial',now=150);reply=call('bootstrap-response',4,initial)
        final=value('final','finish',(reply,),now=150);session=call('bootstrap-complete',5,final)
        require(value('activate','activate')==session,'original independent session');call('native-activate',6,expected=session)
        grants=[(public/('peer-renewal-'+str(i))).read_bytes() for i in [1,2]]
        operations=[(public/('peer-renewal-'+str(i)+'-operation')).read_bytes() for i in [1,2]]
        targets=[(public/('pin-peer-renewal-'+str(i)+'-target')).read_bytes() for i in [1,2]]
        for i in range(2):
            grant=verify(grants[i],ctx.devices[1],ctx.family,ctx.policy_digest,targets[i],now=210 if i==0 else 310)
            require(grant.statement==(public/('peer-renewal-'+str(i+1)+'-statement')).read_bytes(),'native/independent grant statement')
        from peer_lifecycle_controls import grant_controls
        grant_controls(ctx, grants[0], operations[0], targets[0], refuses)
        worker('old-format-refusal','admit_peer_credential_renewal',(grants[0],operations[0],targets[0]),refusal='established format five')
        identity=value('old-send-id','next_id');wire=value('old-send','send',(identity,b'original retained send',b'peer'))
        reverse_id=call('old-reverse-id',8);reverse=call('old-reverse-send',9,reverse_id+application(b'peer',b'original native reply'))
        require(worker('old-reverse-receive','receive',(reverse,b'peer'))==[reverse_id.hex(),b'original native reply'.hex()],'retained reverse plaintext')
        worker('upgrade-kill','upgrade_format',now=210,cut='protocol:format-upgraded')
        require(worker('upgrade-recovered','storage_format')==5,'explicit format five')
        owner=opened()
        try:
            with owner._state(operational=False) as (snapshot,_):
                refuses('old-reader-refuses-five',lambda:old.decode(snapshot.payload,ctx),'snapshot schema/context')
        finally:owner.close()
        worker('expired-peer-cached-send','resume',(identity,),now=210,refusal='expired or premature authority')
        worker('expired-peer-cached-receive','receive',(reverse,b'peer'),now=210,refusal='expired or premature authority')
        worker('expired-peer-ACK','acknowledgement',now=210,refusal='expired or premature authority')
        before=(path/'head').read_bytes()
        worker('wrong-root-operation','admit_peer_credential_renewal',(grants[0],bytes(32),targets[0]),now=210,refusal='operation differs')
        require(before==(path/'head').read_bytes(),'wrong operation changed state')
        worker('renewal-intent-kill','admit_peer_credential_renewal',(grants[0],operations[0],targets[0]),now=210,cut='committed:intent')
        if witnessed:call('witness-original-reopen',32,expected=b'witness reopened')
        require(value('renewal-original-retry','admit_peer_credential_renewal',(grants[0],operations[0],targets[0]),now=210)==targets[0],'renewal target')
        owner=opened()
        try:
            from peer_lifecycle_controls import stored_controls
            stored_controls(owner, ctx, refuses)
        finally:owner.close()
        same_head=(path/'head').read_bytes()
        resigned=(public/'peer-renewal-1-resigned').read_bytes()
        require(value('renewal-resigned-retry','admit_peer_credential_renewal',(resigned,operations[0],targets[0]),now=210)==targets[0]
                and same_head==(path/'head').read_bytes(),'semantic retry rewrote original signature bytes')
        require(value('same-original-ciphertext','resume',(identity,),now=210)==wire,'renewal replaced ciphertext')
        require(worker('same-original-plaintext','receive',(reverse,b'peer'),now=210)==[reverse_id.hex(),b'original native reply'.hex()],'renewal replaced retained plaintext')
        call('native-original-receive',7,application(b'peer',wire),b'original retained send')
        ack=call('native-original-consume',10,identity)
        require(worker('original-ACK','accept_acknowledgement',(ack,),now=210)==1,'original outcome')
        ack=value('consume-original-reply','consume',(reverse_id,),now=210);call('native-reverse-ACK',11,ack,(1).to_bytes(8,'big'))
        # Independent current authorization is genuinely after original peer expiry;
        # the native test counterpart retains its explicit overlapping clock170.
        next_id=value('renewed-send-id','next_id',now=210)
        next_wire=value('renewed-send','send',(next_id,b'new independent message',b'peer'),now=210)
        call('native-renewed-receive',7,application(b'peer',next_wire),b'new independent message')
        offer=value('renewed-offer','prepare_rekey_offer',now=210);response=call('renewed-response',14,offer)
        final=value('renewed-final','accept_rekey_response',(response,),now=210);receipt=call('renewed-receipt',15,final)
        require(worker('renewed-confirm','accept_rekey_receipt',(receipt,),now=210)==1,'renewed epoch')
        worker('first-grant-now-expired','next_id',now=310,refusal='expired or premature authority')
        worker('second-renewal-kill','admit_peer_credential_renewal',(grants[1],operations[1],targets[1]),now=310,cut='protocol:peer-renewal-committed')
        require(value('second-renewal-retry','admit_peer_credential_renewal',(grants[1],operations[1],targets[1]),now=310)==targets[1],'chained original lineage')
        worker('rollback-first-grant','admit_peer_credential_renewal',(grants[0],operations[0],targets[0]),now=250,refusal='predecessor differs')
        fork=(public/'peer-fork-roster').read_bytes();fork_target=(public/'pin-peer-fork-target').read_bytes()
        worker('same-version-fork','admit_peer_roster',(fork,fork_target),now=310,refusal='rollback or fork')
        revoked=(public/'peer-revoked-roster').read_bytes();target=(public/'pin-peer-revoked-target').read_bytes()
        if reentrant:
            def revoke_during_send(stage):
                if stage == 'protocol:send-committed':
                    owner._observer = None
                    owner.admit_peer_roster(revoked, target, 310)
            owner = opened(revoke_during_send)
            try:
                fresh = owner.next_id(310)
                refuses('reentrant-revocation-withholds-result',
                        lambda:owner.send(fresh,b'must be withheld after revocation',b'peer',310),'revoked')
                require(owner.peer_authority_status()[3] is False, 'reentrant revocation did not commit')
            finally:
                owner.close()
        else:
            worker('revocation-kill','admit_peer_roster',(revoked,target),now=310,cut='protocol:peer-roster-committed')
        require(value('revocation-exact-retry','admit_peer_roster',(revoked,target),now=310)==target,'revocation checkpoint')
        status=worker('revoked-metadata','peer_authority_status')
        require(status[0]==target.hex() and status[2]==operations[1].hex() and status[3] is False,'revoked persistent authority')
        worker('revoked-cached-send','resume',(next_id,),now=310,refusal='revoked')
        worker('revoked-ACK','acknowledgement',now=310,refusal='revoked')
        worker('revoked-rekey','prepare_rekey_offer',now=310,refusal='revoked')
        worker('revoked-old-grant','admit_peer_credential_renewal',(grants[1],operations[1],targets[1]),now=310,refusal='revoked')
        reappear=(public/'peer-reappeared-roster').read_bytes();new_target=(public/'pin-peer-reappeared-target').read_bytes()
        worker('revoked-generation-reappearance','admit_peer_roster',(reappear,new_target),now=310,refusal='revoked')
        worker('expired-local-cannot-update','admit_peer_roster',(revoked,target),now=351,refusal='expired or premature authority')
        require(worker('expired-all-metadata','peer_authority_status',now=450)==status,'historical metadata lost')
        if bridge:bridge.close()
        result={'witnessed':witnessed,'session':session.hex(),'worker_operations':driver.operations,'native_commands':native.commands,
                'witness_attempts':bridge.records if bridge else [],'direct_refusals':refusals,'process_kills':sum('signal' in row for row in driver.operations),'reentrant':reentrant,
                'archived_codec_sha256':old_hash,'original_context':ctx.digest.hex(),'peer_target':target.hex(),
                'scope':'Remote same-key grants and observed revocation for one existing session. Independent times210/310 exceed old peer credential intervals; actual native protocol counterpart remains at fixture time170. This does not qualify its local enrollment renewal or a whole deployed two-device lifecycle.'}
        bridge=None
        (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    finally:
        if bridge:
            (output/'ATTEMPTS.json').write_text(json.dumps(bridge.records,indent=2)+'\n');bridge.close()
        native.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    args=arguments()
    from qperiapt_continuity_reference.provider import load_provider
    crypto,backend=load_provider(args.provider_root)
    root=Path(__file__).resolve().parent;output=args.output.resolve();output.mkdir()
    def inventory():
        paths=[*sorted((root/'qperiapt_continuity_reference').glob('*.py')),*sorted(root.glob('*.py')),*sorted((root/'native/src').glob('*.rs')),root/'native/Cargo.toml',root/'native/Cargo.lock',root/'requirements.txt']
        return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before=inventory();rows={}
    for name,witnessed,reentrant in [('local',False,False),('witness',True,False),('local-release',False,True),('witness-release',True,True)]:
        rows[name]=scenario(args,output/name,witnessed,reentrant=reentrant)
    from qperiapt_continuity_reference.wire import require
    require(before==inventory(),'source closure changed')
    report={'source_files':before,'native_sha256':hashlib.sha256(args.native.read_bytes()).hexdigest(),
            'provider':{'cryptography':crypto.__version__,'openssl':backend.openssl_version_text()},
            'profiles':{name:{'worker_operations':len(row['worker_operations']),'native_commands':len(row['native_commands']),
                             'process_kills':row['process_kills'],'witness_attempts':len(row['witness_attempts'])} for name,row in rows.items()}}
    (output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report['profiles']))


if __name__=='__main__':main()
