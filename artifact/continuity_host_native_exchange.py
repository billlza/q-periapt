"""Installed public-advertisement consumer and native owned exchange boundary."""
from evidence_io import parse_strict_json_bytes, read_regular_snapshot
from continuity_independent_python import PACKAGE, require
import hashlib

CUT_STAGES = ('before-effect','after-effect','after-consumption')
CUT_LABELS = tuple('cut-'+stage for stage in CUT_STAGES)
CONFIRMATION_CUTS = ('stage-synced:intent','committed:intent')
CONNECTION_EVENTS = ('authenticated-prefix-pending','lost-ack-exact-recovery','forged-ack-refused',
                     'cancelled-after-peer-commit','late-result-withheld','reentrant-close-withheld',
                     'bounded-original-rekey-recovery','cleanup-error-releases-owner')
CONNECTION_BOUNDS = ('zero-timeout','negative-timeout','boolean-timeout','nan-timeout','infinite-timeout',
                     'excessive-timeout','frame-capacity','reply-capacity','truncated-pair','zero-v2-epoch','pre-cancelled-run')
CONNECTION_LABELS = ('facade-pending-resume','facade-lost-ack','facade-lost-resume','facade-forged-resume',
                     'facade-cancel','facade-cancel-resume','facade-timeout-resume','facade-close-resume',
                     'facade-control-limited','facade-control-1','facade-control-2','facade-epoch-two','facade-read-delivery')
INBOUND_LABELS = ('inbound-next-empty','inbound-empty','inbound-next-before','inbound-before','inbound-before-status',
    'inbound-before-retry','inbound-next-after','inbound-after','inbound-after-retry','inbound-next-lost',
    'inbound-lost','inbound-lost-status','inbound-lost-retry','inbound-next-gap','inbound-gap','inbound-next-later',
    'inbound-later','inbound-gap-retry','inbound-later-status','inbound-next-cancel','inbound-cancel',
    'inbound-cancel-retry','inbound-next-false','inbound-false','inbound-false-retry','inbound-rekey',
    'inbound-next-epoch-three','inbound-epoch-three','duplex-return','duplex-read-delivery')
INBOUND_INTERRUPTS = ('inbound-before','inbound-after','inbound-lost','inbound-cancel','inbound-false')
INBOUND_EVENTS = ('empty-and-consumed-prefix','pending-effect-recovery','effect-deduplication-after-error',
    'consumed-response-loss','out-of-order-consumed-commitment','cancel-after-effect','explicit-consumer-result',
    'native-driven-rekey-and-delivery')

LABELS = ('native-key','native-begin','native-request','native-accept','native-prepare',
          'native-publication-id','native-publish','native-inbox','wrong-inbox-journal','missing-inbox',
          'initial','initial-retry','final','final-retry','message','message-retry',
          'read-delivery') + tuple(label+suffix for label in CUT_LABELS for suffix in ('','-inspect','-retry','-readback')) + (
          'control-1','control-2','epoch-one-message') + CONNECTION_LABELS + INBOUND_LABELS
REFUSALS = ('wrong-directory','wrong-responder','manifest-signature','membership-proof',
            'publication-cannot-select-root','journal-correlation','duplicate-json','wrong-inbox-journal','missing-inbox',
            'unrecorded-connection','forged-ready','wrong-ready-session','forged-connect-ready','confirmation-close-during-write',
            'conflicting-ready-retry','closed-confirmed-owner',
            'cut-before-effect-inspect','facade-reentrant-operation','facade-lost-ack','facade-closed-owner',
            'facade-conflicting-submission','facade-forged-ack','facade-cancelled-result','facade-deadline',
            'facade-reentrant-close','facade-false-control','facade-exchange-limit','facade-close-error',
            'inbound-consumed-direction','inbound-consumed-session','inbound-malformed-frame','inbound-legacy-receive-retired',
            'inbound-before-receiver','inbound-after-receiver','inbound-retained-commitment','inbound-cancel-receiver','inbound-false-receiver')


def expected_exit(label):
    if label in CUT_LABELS or label in INBOUND_INTERRUPTS: return -9
    return 1 if label in ('missing-inbox','wrong-inbox-journal','cut-before-effect-inspect') else 0


def verify(observed, binaries, application):
    require(type(observed.get('schema_version')) is int and observed['schema_version'] == 5
            and observed.get('kind') == 'qperiapt.native_reference_exchange'
            and observed.get('completed') is True, 'native exchange report schema/completion')
    require(observed.get('native_sha256') == binaries
            and observed.get('implementation') == str(application / PACKAGE / 'publication.py')
            and observed.get('provider') == '48.0.1', 'native exchange implementation differs')
    require(type(observed.get('confirmed_epoch')) is int and observed['confirmed_epoch'] == 3
            and type(observed.get('control_exchanges')) is int and observed['control_exchanges'] == 8
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
    flow=observed.get('connection_operations')
    require(type(flow) is dict and set(flow)=={'schema_version','events','boundary_checks','confirmed_epoch',
            'control_exchanges','native_commands','complete'} and flow['complete'] is True
            and flow['events']==list(CONNECTION_EVENTS) and flow['boundary_checks']==list(CONNECTION_BOUNDS),
            'owned connection operation evidence differs')
    for name,value in (('schema_version',1),('confirmed_epoch',2),('control_exchanges',3),('native_commands',12)):
        require(type(flow[name]) is int and flow[name]==value,'owned connection operation count: '+name)
    inbound=observed.get('inbound_operations')
    require(type(inbound) is dict and set(inbound)=={'schema_version','complete','events','interruptions',
        'effect_rows','consumer_calls','confirmed_epoch','control_exchanges','host_storage'}
        and inbound['complete'] is True and inbound['events']==list(INBOUND_EVENTS)
        and inbound['host_storage']=='SQLite FULL test host; process failure only, no physical power-loss claim',
        'inbound operation evidence differs')
    for name,value in (('schema_version',1),('effect_rows',9),('consumer_calls',11),('confirmed_epoch',3),('control_exchanges',3)):
        require(type(inbound[name]) is int and inbound[name]==value,'inbound operation count: '+name)
    interrupted=inbound['interruptions']
    require(type(interrupted) is list and len(interrupted)==5,'inbound interruption inventory')
    for label,cut in zip(INBOUND_INTERRUPTS,interrupted):
        require(type(cut) is dict and set(cut)=={'label','pid','exit','marker_sha256','request_sha256'}
            and cut['label']==label and type(cut['pid']) is int and cut['pid']>0 and cut['pid'] not in pids
            and type(cut['exit']) is int and cut['exit']==-9,'inbound interruption differs')
        pids.add(cut['pid'])
        require(cut['marker_sha256']==hashlib.sha256(f'{cut["pid"]} {label}\n'.encode()).hexdigest(),
                'inbound interruption marker differs')
        require(type(cut['request_sha256']) is str and len(cut['request_sha256'])==64
                and all(c in '0123456789abcdef' for c in cut['request_sha256']),'inbound request digest shape')


def qualify(args, reference, application, provider, outside, output, snapshot, run):
    device = args.native_device.resolve(strict=True)
    session = args.native_session.resolve(strict=True)
    probe = args.crash_probe.resolve(strict=True)
    outgoing = args.native_outgoing.resolve(strict=True)
    binaries = {str(path):read_regular_snapshot(path,maximum=128*1024**2,label='native exchange executable').sha256
                for path in (device,session,probe,outgoing)}
    for name in ('native_exchange.py','native_exchange_fixture.py','native_exchange_cuts.py','native_connection_checks.py',
                 'native_connection_flow.py','native_inbound_flow.py','native_outgoing_driver.py'):
        (outside/name).write_bytes(snapshot(reference/'tests'/name).data)
    private = outside/'private-native-exchange'
    import sys
    execution = run([sys.executable,'-I','-S','-B',str(outside/'native_exchange.py'),
                     '--native-device',str(device),'--native-session',str(session),'--crash-probe',str(probe),'--native-outgoing',str(outgoing),
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
    for cut in observed['inbound_operations']['interruptions']:
        name=cut['label']+'.ready'; marker=snapshot(private/name)
        require(marker.sha256==cut['marker_sha256'],'inbound retained interruption differs')
        request=snapshot(private/(cut['label']+'-requests')/'001.request')
        require(request.sha256==cut['request_sha256'],'inbound retained request differs')
        (public/name).write_bytes(marker.data); (public/(cut['label']+'.request')).write_bytes(request.data)
    require({str(path):read_regular_snapshot(path,maximum=128*1024**2,label='native exchange executable').sha256
             for path in (device,session,probe,outgoing)} == binaries, 'native exchange executable changed')
    return observed
