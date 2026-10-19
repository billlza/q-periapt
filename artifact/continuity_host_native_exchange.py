"""Installed public-advertisement consumer and native owned exchange boundary."""
from evidence_io import parse_strict_json_bytes, read_regular_snapshot
from continuity_independent_python import PACKAGE, require

LABELS = ('native-key','native-begin','native-request','native-accept','native-prepare',
          'native-publication-id','native-publish','native-inbox','wrong-inbox-journal','missing-inbox',
          'initial','initial-retry','final','final-retry','message','message-retry',
          'read-delivery','control-1','control-2','epoch-one-message')
REFUSALS = ('wrong-directory','wrong-responder','manifest-signature','membership-proof',
            'publication-cannot-select-root','journal-correlation','duplicate-json','wrong-inbox-journal','missing-inbox')


def verify(observed, binaries, application):
    require(type(observed.get('schema_version')) is int and observed['schema_version'] == 1
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
                and command['exit'] == (1 if label in ('missing-inbox','wrong-inbox-journal') else 0), 'native exchange command result: '+label)
    require(observed.get('refusals') == list(REFUSALS), 'native exchange refusal inventory')


def qualify(args, reference, application, provider, outside, output, snapshot, run):
    device = args.native_device.resolve(strict=True)
    session = args.native_session.resolve(strict=True)
    binaries = {str(path):read_regular_snapshot(path,maximum=128*1024**2,label='native exchange executable').sha256
                for path in (device,session)}
    for name in ('native_exchange.py','native_exchange_fixture.py'):
        (outside/name).write_bytes(snapshot(reference/'tests'/name).data)
    private = outside/'private-native-exchange'
    import sys
    execution = run([sys.executable,'-I','-S','-B',str(outside/'native_exchange.py'),
                     '--native-device',str(device),'--native-session',str(session),
                     '--implementation-root',str(application),'--provider-root',str(provider),
                     '--output',str(private)],'native-exchange')
    observed = parse_strict_json_bytes(execution.stdout,label='native owned exchange results')
    verify(observed,binaries,application)
    require(parse_strict_json_bytes(snapshot(private/'RESULT.json').data,label='native exchange retained result') == observed,
            'native exchange retained result differs')
    public = output/'native-exchange-public'; public.mkdir()
    for name in ['RESULT.json',*[label+suffix for label in LABELS for suffix in ('.stdout','.stderr')]]:
        (public/name).write_bytes(snapshot(private/name).data)
    require({str(path):read_regular_snapshot(path,maximum=128*1024**2,label='native exchange executable').sha256
             for path in (device,session)} == binaries, 'native exchange executable changed')
    return observed
