"""Qualify an installed browser owner against the existing native reference service.

The test issuer approves fresh isolated devices. It does not replace application
authentication, and the shared native/WASM engine is not an independent peer.
"""
from pathlib import Path
import argparse
import contextlib
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'research/continuity-reference-app/tests/browser_session'
from bounded_process import capture_output
from continuity_browser_creation import installed_binding
from continuity_browser_session_records import verify
from c_package_manifest import rust_workspace_source_digest
from evidence_io import load_json_object_snapshot, parse_strict_json_bytes
import rust_sdk_profile as sdk


def digest(value):
    return hashlib.sha256(value).hexdigest()


def source_identity():
    paths=[]
    for directory in ('research/continuity-reference-app/src', 'research/continuity-openssl-peer/qperiapt_continuity_reference'):
        paths.extend(path for path in (ROOT/directory).rglob('*') if path.is_file() and path.suffix in ('.rs','.py'))
    paths.extend(FIXTURES/name for name in ('worker.js','run.js'))
    paths.extend(ROOT/'research/continuity-reference-app'/name for name in ('Cargo.toml','Cargo.lock',
        'tests/native_exchange_fixture.py','tests/native_network_driver.py'))
    paths.extend(ROOT/'artifact'/name for name in ('continuity_browser_session.py','continuity_browser_session_records.py',
        'continuity_browser_creation.py','wasm_sdk_package.py','rust_sdk_profile.py','bounded_process.py','evidence_io.py'))
    return {'rust_workspace_sha256':rust_workspace_source_digest(ROOT),
        'files':{str(path.relative_to(ROOT)):sdk.snapshot(path).sha256 for path in sorted(paths)}}


def qualify(output, receipt, node, cli, provider_root, native_target):
    sys.path.insert(0, str(ROOT / 'research/continuity-openssl-peer'))
    sys.path.insert(0, str(ROOT / 'research/continuity-reference-app/tests'))
    from qperiapt_continuity_reference.provider import load_provider
    provider, backend = load_provider(provider_root)
    provider_identity=lambda:{str(path.relative_to(provider_root)):sdk.snapshot(path,maximum=128*1024**2).sha256
        for path in sorted(provider_root.rglob('*')) if path.is_file() and path.suffix in ('.py','.so','.dylib')}
    provider_files=provider_identity()
    from native_exchange_fixture import Issuer, save, b64
    from native_network_driver import NativeService
    from qperiapt_continuity_reference.network import TcpTransport
    from qperiapt_continuity_reference.connection_run import Cancellation
    from qperiapt_continuity_reference.publication import Publication
    source=source_identity()
    output.mkdir(exist_ok=False)
    public=output/'public'; public.mkdir()
    logs=public/'logs'; logs.mkdir()
    web=output/'web'; web.mkdir()
    private=Path(tempfile.mkdtemp(prefix='qpc-browser-session-')).resolve(strict=True)
    installed,binding=installed_binding(receipt)
    shutil.copytree(installed/'web',web/'pkg')
    for name in ('worker.js','run.js'):
        shutil.copyfile(FIXTURES/name,web/name)
    save(web/'index.html',b'<!doctype html><meta charset="utf-8"><link rel="icon" href="data:"><script type="module" src="/run.js"></script><title>Installed browser native session</title>')
    env=dict(os.environ,CARGO_TARGET_DIR=str(native_target),RUSTFLAGS='-D warnings')
    sdk.command(['cargo','+1.98.1','build','--locked','--manifest-path','research/continuity-reference-app/Cargo.toml',
                 '--bin','q-periapt-native-device','--bin','q-periapt-native-session'],logs/'native-build',ROOT,environment=env)
    binaries={name:native_target/'debug'/name for name in ('q-periapt-native-device','q-periapt-native-session')}
    binary_hashes={name:sdk.snapshot(path,maximum=256*1024**2).sha256 for name,path in binaries.items()}
    commands=[]; services=[]; frames=[]; failures=[]; frame_lock=threading.Lock()
    session='qpc-session-'+uuid.uuid4().hex
    node=node.resolve(strict=True);cli=cli.resolve(strict=True)
    metadata=load_json_object_snapshot(cli.parent/'package.json',label='browser CLI metadata').value
    sdk.require(metadata.get('name')=='@playwright/cli' and metadata.get('version')=='0.1.22','browser CLI version differs')
    tool_identity=lambda:{'node':sdk.snapshot(node,maximum=256*1024**2).sha256,'cli':sdk.snapshot(cli).sha256}
    tools=tool_identity()
    report={'schema_version':1,'completed':False,'release_claim_eligible':False,'source':source,'tools':tools,
      'installed_sdk':binding,'native_binary_sha256':binary_hashes,'provider':provider.__version__,
      'provider_files':provider_files,'provider_openssl':backend.openssl_version_text(),
      'scope':'Installed browser public owner against repository-built native reference service; actual HTTP/TCP and OS time; fresh isolated test authority, local policy, not Passkey authorization, independent session implementation, TLS, physical device or power loss.'}

    def run(argv,label,*,json_output=True):
        result=capture_output([str(v) for v in argv],timeout_seconds=60,maximum_stdout_bytes=4*1024**2,maximum_stderr_bytes=1024**2)
        save(logs/(label+'.stdout'),result.stdout);save(logs/(label+'.stderr'),result.stderr)
        commands.append({'label':label,'exit':result.returncode,'stdout_sha256':digest(result.stdout),'stderr_sha256':digest(result.stderr)})
        sdk.require(result.returncode==0 and not result.stderr,'native command failed '+label)
        return parse_strict_json_bytes(result.stdout,label='native command '+label) if json_output else result.stdout

    def browser(argv,label):
        with contextlib.chdir(output):
            result=capture_output([str(node),str(cli),'--session',session,*argv],timeout_seconds=200,maximum_stdout_bytes=4*1024**2,maximum_stderr_bytes=1024**2)
        save(logs/(label+'.stdout'),result.stdout);save(logs/(label+'.stderr'),result.stderr)
        commands.append({'label':label,'exit':result.returncode,'stdout_sha256':digest(result.stdout),'stderr_sha256':digest(result.stderr)})
        sdk.require(result.returncode==0 and not result.stderr,'browser command failed '+label)
        return result.stdout

    def phase(name):
        code='''async page => {
          const phase = __PHASE__;
          const diagnostics=[], requests=[];
          page.on('pageerror', error=>diagnostics.push({type:'pageerror',message:String(error)}));
          page.on('console', message=>{if(['error','warning'].includes(message.type()))diagnostics.push({type:message.type(),message:message.text(),location:message.location()});});
          page.on('requestfailed', request=>requests.push({url:request.url(),failure:request.failure()}));
          await page.waitForFunction(()=>globalThis.fixtureReady===true,undefined,{timeout:15000});
          const result=await page.evaluate(p=>globalThis.runPhase(p),phase);
          return {status:'INSTALLED_SESSION_PHASE',phase,result,diagnostics,requests,browser:await page.evaluate(()=>navigator.userAgent)};
        }'''.replace('__PHASE__',json.dumps(name))
        path=output/(name+'.js');save(path,code.encode())
        text=browser(['run-code','--filename',str(path)],'browser-'+name).decode()
        sdk.require(text.count('### Result\n')==1 and '### Error' not in text,'browser phase failed '+name)
        value=parse_strict_json_bytes(text.split('### Result\n',1)[1].split('\n### ',1)[0].encode(),label='browser session phase '+name)
        sdk.require(value['status']=='INSTALLED_SESSION_PHASE' and value['phase']==name,'phase result differs')
        save(public/(name+'.json'),value)
        if name!='activate':
            sdk.require(not value['diagnostics'] and not value['requests'],'unexpected browser diagnostics '+name)
        else:
            sdk.require(len(value['requests'])==1 and value['requests'][0]['url']==origin+'/exchange/drop-once','expected lost response not observed')
            sdk.require(all(row['type']=='error' and row['location']['url']==origin+'/exchange/drop-once'
                            and 'ERR_EMPTY_RESPONSE' in row['message'] for row in value['diagnostics']), 'unrelated browser errors')
        return value['result']

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(web),**kwargs)
        def setup(self):self.request.settimeout(12);super().setup()
        def log_message(self,_format,*_args):pass
        def end_headers(self):
            self.send_header('Cross-Origin-Opener-Policy','same-origin')
            self.send_header('Cross-Origin-Embedder-Policy','require-corp')
            self.send_header('Cache-Control','no-store');super().end_headers()
        def do_POST(self):
            length=self.headers.get('Content-Length','')
            if (self.path not in ('/exchange','/exchange/drop-once') or not length.isdecimal()
                or not 10<=int(length)<=65536 or self.headers.get('Origin')!=origin):
                self.send_error(400);return
            try:
                request=self.rfile.read(int(length));sdk.require(len(request)==int(length),'truncated HTTP frame')
                with frame_lock:
                    number=len(frames)+1
                    sdk.require(self.server.upstream is not None,'native service not ready')
                    upstream=self.server.upstream
                response=TcpTransport(upstream)(request,time.monotonic()+10,Cancellation())
                save(public/f'{number:03}.request',request);save(public/f'{number:03}.response',response)
                with frame_lock:
                    sdk.require(len(frames)+1==number,'unexpected concurrent fixture exchange')
                    dropped=self.path.endswith('drop-once')
                    if dropped:sdk.require(not any(row['withheld'] for row in frames) and request[8]==3,'unexpected drop route')
                    frames.append({'sequence':number,'kind':request[8],'request_sha256':digest(request),
                      'response_sha256':digest(response),'withheld':dropped})
                if dropped:
                    self.connection.shutdown(socket.SHUT_RDWR);self.close_connection=True;return
                self.send_response(200);self.send_header('Content-Type','application/octet-stream')
                self.send_header('Content-Length',str(len(response)));self.end_headers();self.wfile.write(response)
            except BaseException as error:
                failures.append({'type':type(error).__name__,'message':str(error)})
                self.send_error(500)

    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=False;server.upstream=None
    origin=f'http://127.0.0.1:{server.server_port}'
    thread=threading.Thread(target=server.serve_forever,name='installed-browser-native-fixture');thread.start()
    opened=False;primary_error=None
    try:
        issuer=Issuer(private)
        native_dir=private/'native';native_dir.mkdir(mode=0o700)
        native_invitation,native_offer=issuer.invitation('native')
        common=[native_dir,private/'native-wrap.key',private/'native-invitation.json']
        run([binaries['q-periapt-native-device'],'provision-key',private/'native-wrap.key'],'native-key',json_output=False)
        run([binaries['q-periapt-native-device'],'begin',*common],'native-begin')
        run([binaries['q-periapt-native-device'],'request',*common,private/'native-request.bin'],'native-request')
        native_certificate=issuer.certificate(native_offer,(private/'native-request.bin').read_bytes())
        invitation,offer=issuer.invitation('browser')
        save(web/'initial.json',{'invitation':invitation,
          'pins':load_json_object_snapshot(private/'policy-pins.json',label='browser test policy pins').value,
          'materials':load_json_object_snapshot(private/'policy-materials.json',label='browser test policy materials').value})
        browser(['open',origin+'/index.html','--browser','chrome'],'browser-open');opened=True
        created=phase('create');sdk.require(created['secure'] and created['realm'],'not a real secure Worker')
        request=bytes(created['request']);sdk.require(len(request)==5506,'browser enrollment request width')
        save(public/'browser-enrollment.request',request)
        certificate=issuer.certificate(offer,request);current=issuer.current()
        save(private/'native-issued.json',issuer.issued(native_invitation,native_certificate))
        accepted=run([binaries['q-periapt-native-device'],'accept',*common,private/'native-issued.json',private/'current.json',
                      private/'policy-pins.json',private/'policy-materials.json'],'native-accept')
        run([binaries['q-periapt-native-device'],'prepare',*common,private/'current.json',private/'policy-pins.json',private/'policy-materials.json'],'native-prepare')
        active_args=[*common,private/'current.json',private/'policy-pins.json',private/'policy-materials.json','none']
        identifier=run([binaries['q-periapt-native-device'],'publication-next',*active_args],'native-publication-id')['publication']
        directory=os.urandom(32)
        save(private/'plan.json',{'schema':'qperiapt-native-publication-plan/1','directory':list(directory),
                                 'valid_from':issuer.start,'valid_until':issuer.start+600})
        published=private/'published';published.mkdir(mode=0o700)
        run([binaries['q-periapt-native-device'],'publish',*active_args,b64(bytes(identifier)),private/'plan.json',published],'native-publish')
        publication=Publication.decode((published/'publication.json').read_bytes())
        bundle=publication.bundle(certificate,issuer.roster).wire;save(private/'bundle.bin',bundle)
        trust={'schema':'qperiapt-native-peer-trust/1','directory':list(directory),
               'initiator':{'current':current,'device':list(offer.intent.device),'generation':1},
               'responder':{'current':current,'device':list(native_offer.intent.device),'generation':1}}
        save(private/'peer-trust.json',trust)
        run([binaries['q-periapt-native-session'],'provision-inbox',private/'inbox.redb',b64(bytes(accepted['journal']))],'native-inbox')
        inputs={'device_directory':str(native_dir),'wrapping_key':str(private/'native-wrap.key'),'invitation':str(private/'native-invitation.json'),
          'current_root':str(private/'current.json'),'policy_pins':str(private/'policy-pins.json'),
          'policy_materials':str(private/'policy-materials.json'),'witness_endpoint':'none','peer_trust':str(private/'peer-trust.json'),'bundle':str(private/'bundle.bin')}
        save(web/'grant.json',{'current':current,'certificate':b64(certificate),'native_device':list(native_offer.intent.device),
                              'directory':list(directory),'bundle':list(bundle)})
        report['served_files']={str(path.relative_to(web)):sdk.snapshot(path).sha256 for path in sorted(web.rglob('*')) if path.is_file()}
        sdk.require(all(report['served_files']['pkg/'+name]==sha for name,sha in binding['web_files'].items()),
                    'served browser bytes differ from installed package')
        first=NativeService(private,'native-first',binaries['q-periapt-native-session'],inputs);services.append(first)
        server.upstream=first.address
        original=phase('activate');report['before_restart']=original
        report['native_first']=first.stop(kill=True)
        second=NativeService(private,'native-reopened',binaries['q-periapt-native-session'],inputs);services.append(second)
        server.upstream=second.address
        resumed=phase('resume');report['after_restart']=resumed
        report['native_second']=second.stop()
        for label,message,expected_text in [('first',original['first'],b'installed browser epoch zero'),
          ('lost',original['lost'],b'original browser delivery with lost ACK'),
          ('last',resumed['last'],b'installed browser after full peer restart')]:
            target=private/(label+'.plaintext')
            run([binaries['q-periapt-native-session'],'read-inbox',private/'inbox.redb',b64(bytes(accepted['journal'])),
                 b64(bytes(original['session'])),b64(bytes(message)),target],'native-read-'+label)
            sdk.require(target.read_bytes()==expected_text,'native host effect differs '+label)
            save(public/('effect-'+label+'.bin'),target.read_bytes())
        lost=[row for row in frames if row['withheld']]
        sdk.require(len(lost)==1,'one actual reply must be withheld')
        replay=frames[lost[0]['sequence']]
        sdk.require(replay['kind']==3 and not replay['withheld'] and
          replay['request_sha256']==lost[0]['request_sha256'] and replay['response_sha256']==lost[0]['response_sha256'],
          'original request or reply changed across complete native restart')
        sdk.require(not failures,'fixture relay error')
        sdk.require(installed_binding(receipt)==(installed,binding),'installed package inputs changed')
        sdk.require({name:digest(path.read_bytes()) for name,path in binaries.items()}==binary_hashes,'native binaries changed')
        sdk.require(source_identity()==source and tool_identity()==tools,'qualification inputs changed')
        sdk.require(provider_identity()==provider_files,'independent test issuer provider changed')
        sdk.require({str(path.relative_to(web)):sdk.snapshot(path).sha256 for path in sorted(web.rglob('*')) if path.is_file()}==report['served_files'],
                    'served inputs changed during communication')
        report['completed']=True
    except BaseException as error:
        primary_error=error
        report['failure']={'type':type(error).__name__,'message':str(error)}
        raise
    finally:
        cleanup=[]
        if opened:
            try:browser(['close'],'browser-close')
            except BaseException as error:cleanup.append(error)
        server.shutdown();server.server_close();thread.join(timeout=5)
        if thread.is_alive():cleanup.append(RuntimeError('HTTP fixture retained thread'))
        for service in services:
            if service.result is None:
                try:service.stop()
                except BaseException as error:cleanup.append(error)
            for stream,path in (('stdout',service.stdout),('stderr',service.stderr)):
                try:save(logs/(service.label+'.'+stream),sdk.snapshot(path).data)
                except BaseException as error:cleanup.append(error)
        report.update(commands=commands,frames=frames,relay_failures=failures,private_state_not_archived=True)
        if cleanup:report['cleanup_failures']=[str(error) for error in cleanup];report['completed']=False
        try:
            if report['completed']:verify(report,public)
        except BaseException as error:
            report['completed']=False
            report['verification_failure']={'type':type(error).__name__,'message':str(error)}
            raise
        finally:
            save(public/'RESULT.json',report)
        if cleanup:raise BaseExceptionGroup('browser/native cleanup failed',([primary_error] if primary_error is not None else [])+cleanup)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','receipt','node','cli','provider-root','native-target'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    result=qualify(args.output.resolve(),args.receipt.resolve(),args.node,args.cli,args.provider_root,args.native_target.resolve())
    print(json.dumps({'completed':result['completed'],'frames':len(result['frames']),'output':str(args.output)}))
