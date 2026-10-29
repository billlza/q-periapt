"""Installed, HTTP-authorized device replacement; no human or mobile claim."""
import base64
import sys
from continuity_independent_python import PACKAGE, require
from continuity_host_network import count, stats_shape
from evidence_io import parse_strict_json_bytes, read_regular_snapshot
from continuity_host_replacement_evidence import retain

LABELS = tuple(('witness-init sdk-init sdk-issue policy-init policy-issue account-init '
    'account-enable-enrollment account-enable-reapproval account-enable-credential-extension '
    'account-enable-credential-grants account-enable-policy-approvals account-enable-device-replacements '
    'native-key native-begin native-request native-accept native-prepare native-witness-enroll '
    'native-publication-id native-before-invalid-publication native-refuse-precredential-publication '
    'native-after-invalid-publication native-publication-id-after-refusal native-publish native-inbox '
    'native-original-status old-prepare old-witness-enroll native-unknown-peer old-connect old-connect-retry '
    'old-first-next old-first-send old-first-effect old-lost-next old-lost-send old-lost-status old-lost-effect '
    'native-before-replacement new-prepare new-before-witness replacement-witness-prepare '
    'replacement-witness-lost-commit replacement-witness-status old-retired-next old-retired-resume '
    'new-before-peer-roster native-peer-roster-lost-output native-peer-roster-retry native-peer-roster-rollback '
    'new-connect new-connect-retry new-message-next new-message-send new-effect new-rekey new-inbox '
    'native-reverse-next native-reverse-send new-read-reverse new-after-service-restart new-after-restart-next '
    'new-after-restart-send after-restart-effect old-retired-after-restart native-final-status old-effect-retained').split())
FAILED = tuple(('native-refuse-precredential-publication native-unknown-peer old-lost-send new-before-witness '
    'replacement-witness-lost-commit old-retired-next old-retired-resume new-before-peer-roster '
    'native-peer-roster-lost-output native-peer-roster-rollback old-retired-after-restart').split())
HTTP = tuple(('register-alice alice-prepare-root register-bob bob-prepare-root native-invitation native-approve '
    'native-issue native-authority-identity native-authority-root original-authority-identity original-authority-root '
    'original-invitation old-approve old-issue old-current replacement-invitation-lost '
    'account-after-invitation-loss-old-login account-after-invitation-loss-login replacement-invitation '
    'replacement-invitation-retry replacement-authority-identity replacement-authority-root new-approve new-issue-lost '
    'account-after-issuance-loss-old-login account-after-issuance-loss-login new-issue new-issue-retry '
    'old-issue-after-replacement new-current new-issue-final old-issue-final probe-finish').split())
REFUSALS = tuple(('native-unknown-peer new-before-witness old-retired-next new-before-peer-roster '
    'native-peer-roster-rollback old-cached-frame old-cached-frame-after-restart old-retired-after-restart').split())
BINARIES = ('account_host','account_client','sdk_authority','publisher','witness',
            'native_device','native_session','native_outgoing')


def action(label):
    if label.startswith('register-'): return 'register'
    if label.endswith('-loss-login'): return 'login'
    return 'finish' if label == 'probe-finish' else 'request'


def identity(value):
    require(type(value) is str and len(value) == 43, 'replacement identity length')
    raw = base64.b64decode(value + '=', altchars=b'-_', validate=True)
    require(len(raw) == 32 and any(raw) and base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == value,
            'replacement canonical identity')
    return raw


def stats(value, accepted, completed, errors=0, *, native=False, queued=False):
    stats_shape(value,native=native,queued=queued)
    for key, n in [('accepted', accepted), ('completed_responses', completed), ('operation_errors', errors),
                   ('evicted_incomplete', 0), ('read_errors', 0), ('rejected_busy', 0)]:
        count(value[key], n, 'replacement ' + key)
    require(value['last_operation_error'] in ('other error', 'ValueError') if errors else
            value['last_operation_error'] is None, 'replacement error disposition')


def verify(value, binaries, application):
    require(type(value) is dict and value.get('kind') == 'qperiapt.authenticated_device_replacement'
            and value.get('completed') is True and value.get('release_claim_eligible') is False
            and value.get('cleanup_errors') == [], 'replacement completion boundary')
    for key, n in [('schema_version', 1), ('effects', 5), ('confirmed_epoch', 1),
                   ('old_generation', 1), ('new_generation', 2)]: count(value.get(key), n, key)
    require(value.get('native_sha256') == binaries and value.get('provider') == '48.0.1'
            and value.get('implementation') == str(application / PACKAGE / 'session_cli.py')
            and value.get('clock') == 'actual OS time', 'replacement implementation')
    for key in ('old_state_unchanged', 'native_identity_unchanged', 'witness_keys_unchanged', 'original_bootstrap_recovered'):
        require(value.get(key) is True, 'replacement ' + key)
    require(len({identity(value.get(k)) for k in ('old_journal', 'new_journal', 'native_journal')}) == 3
            and identity(value.get('old_session')) != identity(value.get('new_session')), 'replacement distinct owners')
    require(value.get('commands') == [{'label': k, 'exit': 1 if k in FAILED else 0} for k in LABELS]
            and all(type(r['exit']) is int for r in value['commands']), 'replacement command inventory')
    require(value.get('account_requests') == [{'label': k, 'id': i, 'action': action(k)} for i, k in enumerate(HTTP, 1)]
            and all(type(r['id']) is int for r in value['account_requests']), 'replacement HTTP inventory')
    require(value.get('refusals') == list(REFUSALS), 'replacement refusal inventory')
    groups = [('services', ('old-native-service', 'new-native-service', 'new-native-service-reopened'), (0,-9,0)),
              ('witness_services', ('witness-first', 'witness-reopened'), (-9,0)),
              ('account_services', ('account-first', 'account-after-invitation-loss', 'account-after-issuance-loss'), (-9,-9,0))]
    pids = set()
    for key, labels, codes in groups + [('receiver', ('new-independent-service',), (0,))]:
        rows = [value.get('independent_service')] if key == 'receiver' else value.get(key)
        require(type(rows) is list and len(rows) == len(labels), 'replacement process inventory')
        for row, label, code in zip(rows, labels, codes):
            fields = {'label','pid','exit'} | ({'stats'} if code == 0 and key != 'account_services' else set())
            require(type(row) is dict and set(row) == fields and row['label'] == label, 'replacement process record')
            count(row['exit'], code, 'replacement process exit')
            require(type(row['pid']) is int and row['pid'] > 0 and row['pid'] not in pids, 'replacement process identity')
            pids.add(row['pid'])
    stats(value['services'][0]['stats'], 7, 5, 2, native=True)
    stats(value['services'][2]['stats'], 1, 1, native=True)
    stats(value['independent_service']['stats'], 1, 1)
    n = value['witness_services'][1]['stats']['completed_responses']
    require(type(n) is int and 1 <= n <= 1024, 'replacement witness workload bound')
    stats(value['witness_services'][1]['stats'], n+1, n, 1, native=True, queued=True)
    stats(value.get('relay'), 3, 2, 1)
    frames = value.get('frames')
    require(type(frames) is list and len(frames) == 3, 'replacement bootstrap frame inventory')
    for i, (row, kind) in enumerate(zip(frames, (1,1,2)), 1):
        count(row['kind'], kind, 'replacement frame kind')
        require(row['label'] == 'replacement-wire-' + str(i)
                and row['outcome'] == ('refused' if i == 1 else 'response'), 'replacement frame disposition')
    require(frames[0]['request_sha256'] == frames[1]['request_sha256'], 'replacement original bootstrap retry')


def qualify(args, reference, application, provider, outside, output, snapshot, run):
    paths = [getattr(args, key).resolve(strict=True) for key in BINARIES]
    def hashes():
        return {str(p): read_regular_snapshot(p, maximum=128*1024**2, label='replacement executable').sha256 for p in paths}
    binaries = hashes()
    for name in ('host_replacement', 'host_replacement_device', 'host_replacement_process',
                 'native_exchange_fixture', 'native_network_driver', 'independent_inbound_cli', 'witness_cli_exchange'):
        (outside / (name + '.py')).write_bytes(snapshot(reference / 'tests' / (name + '.py')).data)
    private = outside / 'private-authenticated-replacement'
    command = [sys.executable, '-I', '-S', '-B', str(outside / 'host_replacement.py')]
    for key, path in zip(BINARIES, paths): command += ['--' + key.replace('_','-'), str(path)]
    command += ['--implementation-root', str(application), '--provider-root', str(provider), '--output', str(private)]
    execution = run(command, 'authenticated-replacement')
    value = parse_strict_json_bytes(execution.stdout, label='installed authenticated replacement')
    verify(value, binaries, application)
    require(parse_strict_json_bytes(snapshot(private / 'RESULT.json').data, label='retained replacement') == value,
            'retained replacement differs')
    retain(value, private, output / 'authenticated-replacement-public', snapshot, LABELS, FAILED)
    require(hashes() == binaries, 'replacement executable changed')
    return value
