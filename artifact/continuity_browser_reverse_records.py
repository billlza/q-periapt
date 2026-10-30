"""Admission of real reverse deliveries, host effects and the pre-response cut."""
from pathlib import Path
from evidence_io import parse_strict_json_bytes
from rust_sdk_profile import require, snapshot

LABELS = ('reverse-native-next-first','browser-receive-first','reverse-native-deliver-first',
          'reverse-native-next-cut','browser-receive-cut','reverse-native-deliver-cut','reverse-native-status-cut',
          'browser-receive-retry','reverse-native-deliver-retry','reverse-native-status-retry',
          'reverse-native-next-last','browser-receive-last','reverse-native-deliver-last')
MESSAGES = {'first':b'native to installed browser epoch one',
            'cut':b'durable browser effect before Worker termination',
            'last':b'native to recovered browser after original retry'}


def verify(report: dict, public: Path, session: list, *, witness_context=None) -> None:
    require(type(report.get('schema_version')) is int and report['schema_version']==1 and report.get('completed') is True
            and report.get('release_claim_eligible') is False and report.get('session')==session,
            'reverse scope or original session differs')
    ids=report['message_ids']
    require(set(ids)==set(MESSAGES) and all(type(v) is list and len(v)==32
            and all(type(b) is int and 0<=b<=255 for b in v) for v in ids.values())
            and len({bytes(v) for v in ids.values()})==3,'reverse operation identities differ')
    require(report['before_retry']=='Committed' and report['after_retry']=='Acknowledged',
            'sender inferred application consumption or lost original retry')
    frames=report['frames'];require(len(frames)==4,'reverse frame inventory differs')
    require(len({row['native_pid'] for row in frames})==4 and all(type(row['native_pid']) is int
            and row['native_pid']>0 for row in frames),'native sender processes not observed')
    for number,row in enumerate(frames,1):
        cut=number==2
        require(type(row['sequence']) is int and row['sequence']==number and row['cut_before_response'] is cut
                and row['response_created'] is (not cut) and type(row['native_exit']) is int
                and row['native_exit']==(1 if cut else 0),'reverse disposition differs')
        request=snapshot(public/'reverse'/f'{number:03}.request')
        require(request.sha256==row['request_sha256'] and 10<=len(request.data)<=32768
                and request.data[:9]==b'QPCXCH01\x03','reverse actual request differs')
        response=public/'reverse'/f'{number:03}.response'
        if cut:
            require(not response.exists() and 'response_sha256' not in row,'an ACK was fabricated at the cut')
        else:
            raw=snapshot(response)
            require(raw.sha256==row['response_sha256'] and 10<=len(raw.data)<=32768
                    and raw.data[:9]==b'QPCXCH01\x83','reverse actual response differs')
    require(frames[1]['request_sha256']==frames[2]['request_sha256'],'retry replaced original native request')
    steps=report['steps'];require(set(steps)=={'first','cut','retry','last'},'reverse stage inventory differs')
    expected={'first':{'first':1},'cut':{'first':1,'cut':1},'retry':{'first':1,'cut':2},'last':{'first':1,'cut':2,'last':1}}
    for name,step in steps.items():
        require(step['session']==session,'browser opened a different session')
        rows=step['effects'];require(len(rows)==len(expected[name]),'host effect count differs')
        seen=set()
        for row in rows:
            labels=[key for key,value in ids.items() if row['message']==value]
            require(len(labels)==1,'host effect message differs');label=labels[0]
            require(label in expected[name] and label not in seen and row['session']==session
                    and row['key']==bytes(session).hex()+':'+bytes(ids[label]).hex()
                    and bytes(row['plaintext'])==MESSAGES[label] and type(row['applications']) is int
                    and row['applications']==1 and type(row['calls']) is int and row['calls']==expected[name][label],
                    'host consumption or durable deduplication differs')
            seen.add(label)
        current='cut' if name=='retry' else name
        require(step['effect'] in rows and step['effect']['message']==ids[current],'callback effect differs')
    require(steps['cut']['stage']=='host-effect-committed-before-consumer-return','wrong interruption boundary')
    for name in ('cut','last'):
        leases=steps[name]['leases']
        require(type(leases) is list and leases and all(type(r.get('count')) is int and r['count']>=0
                and type(r.get('elapsed_ms')) in (int,float) and r['elapsed_ms']>=0 for r in leases)
                and leases[-1]['count']==0,'terminated browser retained its original owner lease')
    commands=report['commands'];require([row['label'] for row in commands]==list(LABELS),'reverse command inventory differs')
    for row in commands:
        label=row['label'];negative=label=='reverse-native-deliver-cut';expected_exit=1 if negative else 0
        require(type(row['exit']) is int and type(row['expected_exit']) is int
                and row['exit']==row['expected_exit']==expected_exit,'reverse command did not execute as expected')
        data={stream:snapshot(public/'logs'/(label+'.'+stream)) for stream in ('stdout','stderr')}
        require(all(value.sha256==row[stream+'_sha256'] for stream,value in data.items()),'reverse command stream changed')
        stdout=data['stdout'].data;stderr=data['stderr'].data
        if negative:
            require(not stdout and b'Transport(' in stderr and b'UnexpectedEof' in stderr,'wrong native failure at receiver cut')
            continue
        require(not stderr,'reverse diagnostics differ')
        if label.startswith('browser-'):
            text=stdout.decode();require(text.count('### Result\n')==1 and '### Error' not in text,'browser failed')
            value=parse_strict_json_bytes(text.split('### Result\n',1)[1].split('\n### ',1)[0].encode(),label=label)
            name=label.removeprefix('browser-receive-')
            remaining = value['requests']
            if witness_context is not None:
                from continuity_browser_session_records import transport_requests
                remaining = transport_requests(value, public, *witness_context)
                require(not value['http_errors'], 'unexpected browser HTTP failure')
            require(value['phase']=='receive-'+name and value['status']=='INSTALLED_SESSION_PHASE'
                    and value['result']==steps[name] and not value['diagnostics'] and not remaining,
                    'browser receipt does not match actual phase')
        else:
            value=parse_strict_json_bytes(stdout,label=label)
            if '-next-' in label:require(value=={'message':ids[label.split('-next-',1)[1]]},'native next identity differs')
            elif '-status-' in label:
                require(value=={'status':report['before_retry' if label.endswith('cut') else 'after_retry']},'native original status differs')
            else:require(value=={'consumption':'Confirmed'},'native did not confirm actual reply')
