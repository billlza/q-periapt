"""Read back the archive-shipped roster authority refresh and original recovery.

Native public APIs verify signatures. This reader checks canonical commitments,
original operations, process completion and public durable readbacks; it is not
an independent protocol implementation or a credential-renewal qualification.
"""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import commit, head
from evidence_io import parse_strict_json_bytes

SCOPE = ("same-host native Rust installation recovery in separate device processes; "
         "required signed-TCP witness in the parent process; injected protocol time; "
         "same credential and policy; no TLS, independent engine, credential replacement or cross-host claim")


def envelope(wire: bytes, tag: bytes, size: int) -> bytes:
    sdk.require(len(wire) == size + 3377 and wire[:4] == size.to_bytes(4, 'big')
                and wire[4:12] == tag, 'roster renewal envelope differs')
    return wire[4:4 + size]


def verify(directory: Path) -> dict:
    public = {}
    def read(name, maximum=65536):
        item = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = dict(sha256=item.sha256, bytes=item.size)
        return item.data
    report = parse_strict_json_bytes(read('public-roster-result.json'), label='roster renewal result')
    sdk.require(isinstance(report, dict) and set(report) == {
        'schema', 'parent_pid', 'initial_time', 'expired_time', 'trace_count', 'device_exit_codes', 'carrier', 'clock'},
        'roster renewal result fields differ')
    for name in ('schema', 'parent_pid', 'initial_time', 'expired_time', 'trace_count'):
        sdk.require(type(report[name]) is int and 0 < report[name] < 2**64, 'roster renewal integer differs')
    sdk.require(report['schema'] == 1 and report['expired_time'] == report['initial_time'] + 60
                and 1 <= report['trace_count'] <= 256 and report['carrier'] == 'signed-tcp'
                and report['clock'] == 'injected-protocol-time'
                and isinstance(report['device_exit_codes'], list) and len(report['device_exit_codes']) == 3
                and all(type(value) is int and value == 0 for value in report['device_exit_codes']),
                'roster renewal execution scope differs')
    pids = [report['parent_pid']]
    for mode in ('expired', 'recover', 'revoke'):
        pid = read(mode + '-pid', 8)
        sdk.require(len(pid) == 8 and int.from_bytes(pid, 'big') > 0, 'roster renewal process id differs')
        pids.append(int.from_bytes(pid, 'big'))
        stdout = read(mode + '-process.stdout').decode()
        sdk.require(re.findall(r'^test ([a-z_:]+) \.\.\. ok$', stdout, re.MULTILINE) == ['service_peer_process']
                    and re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;', stdout, re.MULTILINE),
                    'roster renewal child did not execute its full workload')
    sdk.require(len(set(pids)) == 4, 'roster renewal omitted a separate device process')
    subject = read('witness-subject', 96)
    original_id, recovered_id = read('original-journal', 32), read('recovered-journal', 32)
    sdk.require(len(subject) == 96 and all(any(subject[n:n + 32]) for n in (0, 32, 64))
                and len(original_id) == 32 and original_id == recovered_id == subject[:32],
                'roster renewal replaced the original journal or subject')
    original, restored = read('original-outbox'), read('restored-outbox')
    # Fixed candidate hybrid profile: tag/context/nonce + 1216-byte public key
    # + 1120-byte ciphertext + 32-byte confirmation MAC, followed by signature.
    initial = envelope(original, b'QPBSI001', 2440)
    context = read('original-context', 32)
    sdk.require(len(context) == 32 and any(context) and initial[8:40] == context
                and context == read('recovered-context', 32) and original == restored,
                'roster renewal changed the original bootstrap outbox or context')
    account, root = read('local-account', 32), read('local-root', 1985)
    sdk.require(len(root) == 1985 and root[1952] in (2, 3)
                and account == commit(b'Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1', root),
                'roster renewal account root differs')
    certificate = envelope(read('local-certificate'), b'QPCERT01', 2097)
    credential = commit(b'Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1', certificate)
    sdk.require(certificate[8:40] == account
                and subject[32:64] == commit(b'Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/storage-owner',
                                            account + certificate[40:64] + credential),
                'roster renewal replaced the original credential owner')
    digests = {}
    for version in (2, 3, 4):
        body = envelope(read(f'renewal-roster-{version}'), b'QPROST01', 66 if version == 4 else 122)
        digest = read(f'renewal-digest-{version}', 32)
        sdk.require(body[8:40] == account and int.from_bytes(body[40:48], 'big') == version
                    and int.from_bytes(body[48:56], 'big') <= report['initial_time']
                    and int.from_bytes(body[56:64], 'big') == report['initial_time'] + (60 if version == 2 else 600)
                    and digest == commit(b'Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1', body),
                    'roster renewal checkpoint or validity differs')
        sdk.require(body[64:66] == (0 if version == 4 else 1).to_bytes(2, 'big'), 'roster renewal membership count differs')
        if version != 4:
            sdk.require(body[66:90] == certificate[40:64] and body[90:122] == credential,
                        'roster renewal changed credential membership')
        digests[version] = digest
    sdk.require(read('admitted-checkpoint', 32) == read('recovered-checkpoint', 32) == digests[3]
                and read('revoked-checkpoint', 32) == digests[4], 'roster renewal admitted, recovered or revoked checkpoint differs')
    before, after = read('before-head', 80), read('recovered-head', 80)
    sdk.require(len(before) == len(after) == 80 and any(before[48:]) and any(after[48:]), 'roster renewal observation width differs')
    old, new = head(before[:48]), head(after[:48])
    sdk.require(new[0] == old[0] and new[1] == old[1] + 1 and new[2] != old[2]
                and read('expired-head', 80) == read('refreshed-head', 80) == before
                and read('retried-head', 80) == after, 'roster renewal reset, fenced or duplicated a journal advance')
    identity, key = read('witness-id', 32), read('witness-public', 1985)
    sdk.require(len(identity) == 32 and any(identity) and len(key) == 1985 and key[1952] in (2, 3), 'roster renewal witness pin differs')
    authority = commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1', identity + key)
    operation = b'\x02' + before[:48] + after[:48]
    command = commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1', authority + subject + operation)
    sdk.require(after[48:] == command, 'roster renewal recovered another command')
    phase_bytes = read('trace-phases', 24)
    sdk.require(len(phase_bytes) == 24, 'roster renewal phase framing differs')
    expired_end, refreshed_end, end = (int.from_bytes(phase_bytes[n:n + 8], 'big') for n in (0, 8, 16))
    sdk.require(2 < expired_end and refreshed_end == expired_end + 1
                and refreshed_end < end == report['trace_count'], 'roster renewal phase boundaries differ')
    state, rejected, applied, challenges = before, 0, 0, set()
    for index in range(report['trace_count']):
        prefix = f'trace-{index:03}'
        rq = envelope(read(prefix + '.request', 3674), b'QPANRQ01', 297)
        at = read(prefix + '.time', 8)
        sdk.require(len(at) == 8 and int.from_bytes(at, 'big') == report['expired_time']
                    and rq[8:40] == authority and rq[40:136] == subject,
                    'roster renewal request used another authority, subject or protocol time')
        challenge, op, cmd = rq[168:200], rq[200:], rq[136:168]
        sdk.require(any(challenge) and challenge not in challenges
                    and cmd == commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1', authority + subject + op),
                    'roster renewal attempt or command commitment differs')
        challenges.add(challenge)
        if (directory / (prefix + '.rejection')).exists():
            sdk.require(read(prefix + '.rejection', 32) == b'Rejected(Validity)'
                        and op == operation and cmd == command and state == before and applied == 0
                        and index < expired_end - 1,
                        'roster renewal expiry did not refuse the original pending command')
            rejected += 1
            continue
        rs = envelope(read(prefix + '.reply', 3659), b'QPANRS01', 282)
        sdk.require(rs[8:40] == authority and rs[40:136] == subject
                    and rs[136:168] == commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1', rq)
                    and rs[168:200] == cmd and rs[249] == 1, 'roster renewal reply binding differs')
        if op[0] == 1:
            sdk.require(op == b'\x01' + bytes(96) and rs[200] == 1, 'roster renewal query mutated state')
        else:
            sdk.require(op == operation and cmd == command and state == before and rejected == 2
                        and rs[200] == 2 and applied == 0 and index >= refreshed_end,
                        'roster renewal replaced or repeated the pending advance')
            state = after
            applied += 1
        sdk.require(rs[201:249] + rs[250:282] == state, 'roster renewal reply lost head, fence or last command')
        if index in (expired_end - 1, refreshed_end - 1, end - 1):
            sdk.require(op[0] == 1 and state == (after if index == end - 1 else before),
                        'roster renewal omitted a signed phase query readback')
    sdk.require(rejected == 2 and applied == 1 and state == after, 'roster renewal recovery trace incomplete')
    actual = set()
    for path in directory.iterdir():
        sdk.require(path.is_file() and not path.is_symlink(), 'roster renewal evidence must contain plain public files')
        actual.add(path.name)
    sdk.require(actual == public.keys(), 'roster renewal evidence has missing or unexpected files')
    return dict(report, scope=SCOPE, journal=original_id.hex(), original_command=command.hex(),
                rejected_attempts=rejected, logical_advances=applied, public_readbacks=public)


def export(directory: Path, destination: Path) -> dict:
    """Copy only the fully checked public closure and re-verify the exported bytes."""
    result = verify(directory)
    destination.mkdir(mode=0o700)
    for name in result['public_readbacks']:
        sdk.copy(directory / name, destination / name, maximum=65536)
    sdk.require(verify(destination) == result, 'exported roster renewal evidence changed')
    return result
