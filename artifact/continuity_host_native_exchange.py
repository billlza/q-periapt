"""Installed public-advertisement consumer and native owned exchange boundary."""
from evidence_io import parse_strict_json_bytes, read_regular_snapshot
from continuity_independent_python import PACKAGE, require
import hashlib

CUT_STAGES = ('before-effect','after-effect','after-consumption')
CUT_LABELS = tuple('cut-'+stage for stage in CUT_STAGES)
CONFIRMATION_CUTS = ('stage-synced:intent','committed:intent')

LABELS = ('native-key','native-begin','native-request','native-accept','native-prepare',
          'native-publication-id','native-publish','native-inbox','wrong-inbox-journal','missing-inbox',
          'initial','initial-retry','final','final-retry','message','message-retry',
          'read-delivery') + tuple(label+suffix for label in CUT_LABELS for suffix in ('','-inspect','-retry','-readback')) + (
          'control-1','control-2','epoch-one-message')
REFUSALS = ('wrong-directory','wrong-responder','manifest-signature','membership-proof',
            'publication-cannot-select-root','journal-correlation','duplicate-json','wrong-inbox-journal','missing-inbox',
            'unrecorded-connection','forged-ready','wrong-ready-session','confirmation-close-during-write',
            'conflicting-ready-retry','closed-confirmed-owner',
            'cut-before-effect-inspect')


def expected_exit(label):
    if label in CUT_LABELS: return -9
    return 1 if label in ('missing-inbox','wrong-inbox-journal','cut-before-effect-inspect') else 0


def verify(observed, binaries, application):
    require(type(observed.get('schema_version')) is int and observed['schema_version'] == 3
            and observed.get('kind') == 'qperiapt.native_reference_exchange'
            and observed.get('completed') is True, 'native exchange report schema/completion')
    require(observed.get('native_sha256') == binaries
            and observed.get('implementation') == str(application / PACKAGE / 'publication.py')
            and observed.get('provider') == '48.0.1', 'native exchange implementation differs')
    require(type(observed.get('confirmed_epoch')) is int and observed['confirmed_epoch'] == 1
            and type(observed.get('control_exchanges')) is int and observed['control_exchanges'] == 2
            and observed.get('clock') == 'actual OS time', 'native exchange completion differs')
    commands = observed.get('commands')
    require(type(commands) is list and len(commands) == len(LABELS), 'native exchange command inventory')
    for label, command in zip(LABELS,commands):
        require(type(command) is dict and set(command) == {'label','exit'}
                and command['label'] == label and type(command['exit']) is int
                and command['exit'] == expected_exit(label), 'native exchange command result: '+label)
    require(observed.get('refusals') == list(REFUSALS), 'native exchange refusal inventory')
    kills=observed.get('process_kills')
    require(type(kills) is list and len(kills)==3,'native inbox crash inventory')
    pids=set()
    for stage,kill in zip(CUT_STAGES,kills):
        require(type(kill) is dict and set(kill)=={'stage','pid','exit','marker_sha256','inbox_flags'}
                and kill['stage']==stage and type(kill['pid']) is int and kill['pid']>0
                and kill['pid'] not in pids and type(kill['exit']) is int and kill['exit']==-9,
                'native inbox crash observation differs')
        require(type(kill['inbox_flags']) is int and 0<=kill['inbox_flags']<=255 and kill['inbox_flags']&4!=0,
                'native inbox two-phase recovery flag absent')
        pids.add(kill['pid'])
        require(kill['marker_sha256']==hashlib.sha256(f'{kill["pid"]} {stage}\n'.encode()).hexdigest(),
                'native inbox crash marker differs')
    confirmation=observed.get('connection_confirmation')
    flags=('recovery_failure','raw_traffic_unrecorded','exact_retry_unchanged','closed_owner_refused','post_rekey_reopen')
    require(type(confirmation) is dict and set(confirmation)=={'schema_version','process_kills',*flags}
            and type(confirmation['schema_version']) is int and confirmation['schema_version']==1
            and all(confirmation[flag] is True for flag in flags),'connection confirmation evidence differs')
    kills=confirmation['process_kills']
    require(type(kills) is list and len(kills)==2,'connection confirmation crash inventory')
    for stage,kill in zip(CONFIRMATION_CUTS,kills):
        require(type(kill) is dict and set(kill)=={'stage','pid','exit','marker_sha256'}
                and kill['stage']==stage and type(kill['pid']) is int and kill['pid']>0
                and kill['pid'] not in pids and type(kill['exit']) is int and kill['exit']==-9,
                'connection confirmation crash observation differs')
        pids.add(kill['pid'])
        require(kill['marker_sha256']==hashlib.sha256(
            f'{kill["pid"]} client-device:registration-store:{stage}\n'.encode()).hexdigest(),
            'connection confirmation crash marker differs')


def qualify(args, reference, application, provider, outside, output, snapshot, run):
    device = args.native_device.resolve(strict=True)
    session = args.native_session.resolve(strict=True)
    probe = args.crash_probe.resolve(strict=True)
    binaries = {str(path):read_regular_snapshot(path,maximum=128*1024**2,label='native exchange executable').sha256
                for path in (device,session,probe)}
    for name in ('native_exchange.py','native_exchange_fixture.py','native_exchange_cuts.py','native_connection_checks.py'):
        (outside/name).write_bytes(snapshot(reference/'tests'/name).data)
    private = outside/'private-native-exchange'
    import sys
    execution = run([sys.executable,'-I','-S','-B',str(outside/'native_exchange.py'),
                     '--native-device',str(device),'--native-session',str(session),'--crash-probe',str(probe),
                     '--implementation-root',str(application),'--provider-root',str(provider),
                     '--output',str(private)],'native-exchange')
    observed = parse_strict_json_bytes(execution.stdout,label='native owned exchange results')
    verify(observed,binaries,application)
    require(parse_strict_json_bytes(snapshot(private/'RESULT.json').data,label='native exchange retained result') == observed,
            'native exchange retained result differs')
    public = output/'native-exchange-public'; public.mkdir()
    for name in ['RESULT.json',*[label+suffix for label in LABELS for suffix in ('.stdout','.stderr')]]:
        (public/name).write_bytes(snapshot(private/name).data)
    for kill in observed['process_kills']:
        name='cut-'+kill['stage']+'.ready'; marker=snapshot(private/name)
        require(marker.sha256==kill['marker_sha256'],'native inbox retained marker differs')
        (public/name).write_bytes(marker.data)
    for kill in observed['connection_confirmation']['process_kills']:
        name='confirmation-'+kill['stage'].replace(':','-')+'.ready'; marker=snapshot(private/name)
        require(marker.sha256==kill['marker_sha256'],'connection confirmation retained marker differs')
        (public/name).write_bytes(marker.data)
    require({str(path):read_regular_snapshot(path,maximum=128*1024**2,label='native exchange executable').sha256
             for path in (device,session,probe)} == binaries, 'native exchange executable changed')
    return observed
