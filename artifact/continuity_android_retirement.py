"""Android-created replacement and restricted retirement public bindings.

Native execution verifies signatures and the private report MAC. This reader checks
complete public framing, original-operation linkage and process execution receipts.
"""
from pathlib import Path
import hashlib
import continuity_android_contract as contract
from continuity_c_witness import commit
import rust_sdk_profile as sdk

TEST = "android_retirement::original_android_retirement"

ORIGINAL_STEPS = (
    ("original.request", "policy-create"), ("authority-created", "authority-create"),
    ("prepared", "policy-prepare"), ("activated.request", "policy-activate"),
    ("original.identity", "policy-identity"),
    ("roster-peer-unassociated", "roster-witness-peer-unassociated"),
    ("roster-peer-associated", "authority-peer-associate"),
    ("roster-connected", "roster-witness-peer-connect"),
    ("roster-unknown", "roster-witness-peer-uncertain"),
) + tuple(("retirement-" + name, "retired-owned-" + mode) for name, mode in (
    ("inventory", "inventory"), ("cancelled", "cancelled"),
    ("report-proposal", "prepare-report"), ("report-unknown", "report-unknown"),
    ("report-reopened", "report-reopen"), ("tampered-report", "ack-tampered"),
    ("ack-proposal", "prepare-ack"), ("wrong-purpose", "erase-wrong-purpose"),
    ("journal-unknown", "journal-unknown"), ("signer-unknown", "signer-unknown"),
    ("verified", "verify"), ("operational-denied", "operational-denied")))
SUCCESSOR_STEPS = (
    ("original.request", "policy-create"), ("authority-created", "authority-create"),
    ("prepared", "policy-prepare"), ("activated.request", "policy-activate"),
    ("reopened.request", "policy-activate"), ("original.identity", "policy-identity"),
    ("peer-unassociated", "roster-witness-peer-unassociated"),
    ("peer-associated", "authority-peer-associate"),
    ("peer-connected", "roster-witness-peer-connect"),
    ("peer-unknown", "roster-witness-peer-uncertain"),
    ("peer-acknowledged", "roster-witness-peer-retry"))
CUT_MODES = frozenset("retired-owned-" + name + "-unknown" for name in ("report", "journal", "signer"))

def _retired_records(read):
    def fixed(name, length):
        value = read(name)
        sdk.require(len(value) == length, 'width: ' + name)
        return value

    def envelope(name, expected):
        wire = fixed('inputs/' + name, 4 + len(expected) + 3373)
        sdk.require(int.from_bytes(wire[:4], 'big') == len(expected)
                and wire[4:-3373] == expected, 'receipt binding: ' + name)

    sdk.require(fixed('process-count', 8) == (21).to_bytes(8, 'big'), 'process census')
    witness = fixed('inputs/witness-id', 32) + fixed('inputs/witness-public', 1985)
    binding = commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1', witness)
    subject = fixed('inputs/witness-subject', 96)
    replacement = read('inputs/retirement-proposal')
    sdk.require(replacement.startswith(b'QPDRPL01' + binding), 'replacement authority')
    replacement_id = commit(b'Q-PERIAPT-CONTINUITY-DEVICE-REPLACEMENT-CANDIDATE/v1', replacement)
    receipt = fixed('inputs/retirement-receipt', 3754)
    body = receipt[4:-3373]
    sdk.require(int.from_bytes(receipt[:4], 'big') == 377
            and body.startswith(b'QPDRTR01' + binding + replacement_id + subject), 'retirement authority')
    inventory = fixed('retirement-inventory', 313)
    sdk.require(inventory.startswith(b'QPRCLP01' + binding + replacement_id + subject)
            and inventory[168:200] == body[249:281] and inventory[200:248] == body[168:216]
            and inventory[280] in (0, 1), 'original frozen inventory')
    envelope('retirement-inventory-receipt', inventory)
    proposal = fixed('retirement-report-proposal', 353)
    sdk.require(proposal.startswith(b'QPRRPT01' + inventory) and any(proposal[321:]), 'report proposal')
    sdk.require(read('inputs/retirement-report-proposal') == proposal
            and read('retirement-ack-proposal') == proposal, 'original report proposal changed')
    envelope('retirement-report-receipt', proposal)
    envelope('retirement-ack', b'QPRACK01' + proposal[8:])
    report = read('retirement-complete-report')
    sdk.require(323 <= len(report) <= 8388608 and report[:8] in (b'QPRDMD01', b'QPRDMD02', b'QPRDMD03')
            and report[8:321] == inventory, 'complete report inventory')
    sdk.require(read('retirement-verified') == report, 'complete report changed across erasure')
    sdk.require(read('retirement-report-reopened') == proposal[321:] + (1).to_bytes(4, 'big') + report,
            'reopened complete report')
    for name in ('report', 'journal', 'signer'):
        sdk.require(fixed('retirement-' + name + '-unknown', 32) == proposal[321:], 'cut report identity')
    for name, code in (('cancelled', 302), ('tampered-report', 208), ('wrong-purpose', 102), ('operational-denied', 215)):
        sdk.require(fixed('retirement-' + name, 4) == code.to_bytes(4, 'big'), 'refusal: ' + name)
    sdk.require(read('original.request') == read('activated.request'), 'original request changed')
    identity = fixed('original.identity', 64)
    prepared = fixed('prepared', 164)
    sdk.require(prepared[:4] == (2).to_bytes(4, 'big') and identity[32:] == prepared[4:36]
            and prepared[36:132] == subject, 'original journal or subject changed')
    sdk.require(fixed('inputs/successor-journal', 32) != identity[32:]
            and fixed('inputs/successor-subject', 96) != subject, 'generation replacement reused original state')
    effect = read('roster-effect-before')
    sdk.require(bool(effect) and read('retirement-effect-after') == effect, 'original business effect changed')
    return {'processes': 21, 'process_cuts': 3, 'report_bytes': len(report),
            'report_sha256': hashlib.sha256(report).hexdigest(), 'report_id': proposal[321:].hex(),
            'complete_report_preserved': True, 'old_business_effect_preserved': True}


def _replacement_records(read):
    original = _retired_records(read)
    def new(name):
        return read('successor/' + name)
    sdk.require(new('process-count') == (11).to_bytes(8, 'big'), 'successor process census')
    sdk.require(new('original.request') == new('activated.request') == new('reopened.request')
            == read('inputs/successor-request'), 'successor original request changed')
    identity = new('original.identity')
    sdk.require(len(identity) == 64 and identity[:32] != read('original.identity')[:32]
            and identity[32:] == read('inputs/successor-journal')
            and identity[32:] != read('original.identity')[32:], 'successor identity or journal reused')
    intent = new('inputs/enrollment-intent')
    old = read('inputs/enrollment-intent')
    sdk.require(len(intent) == len(old) == 72 and intent[:16] == old[:16]
            and int.from_bytes(intent[16:24], 'big') == int.from_bytes(old[16:24], 'big') + 1
            and intent[24:] == old[24:], 'successor device generation scope')
    prepared = new('prepared')
    sdk.require(len(prepared) == 164 and prepared[:4] == (2).to_bytes(4, 'big')
            and prepared[4:36] == identity[32:] and prepared[36:132] == read('inputs/successor-subject'),
            'successor original prepared subject')
    sdk.require(new('inputs/grant-certificate') == read('inputs/successor-certificate')
            and new('inputs/grant-roster') == read('inputs/successor-roster'), 'successor grant changed')
    sdk.require(new('roster-peer-admitted.stdout') == b'peer-roster-admitted\n'
            and new('roster-peer-admitted.stderr') == b'', 'explicit receiver roster admission')
    session = new('peer-connected')
    pending = new('peer-unknown')
    sdk.require(len(session) == 32 and session == new('inputs/connection-session')
            and session != read('inputs/connection-session') and len(pending) == 64
            and pending[:32] == session and pending[32:] == new('inputs/connection-message')
            and pending[32:] != read('inputs/connection-message'), 'successor traffic identities')
    sdk.require(new('peer-acknowledged') == pending, 'successor retry changed original message')
    effect = new('effect-before')
    sdk.require(effect == pending + b'persisted before process exit' and new('effect-after') == effect
            and new('effect-count') == (2).to_bytes(8, 'big'), 'successor business effects')
    sdk.require(read('retirement-effect-after-successor') == read('roster-effect-before'), 'old effect changed')
    return dict(original, processes=32, successor_processes=11, successor_session=session.hex(),
                successor_message=pending[32:].hex(), successor_same_counterparty=True,
                fresh_successor_effects=1, total_counterparty_effects=2)


def verify_records(directory: Path, profile: str) -> dict:
    sdk.require(profile in ("fixed", "recoverable"), "unknown retirement trust profile")
    public = {}

    def read(name):
        value = sdk.snapshot(directory / name, maximum=8 * 1024 * 1024)
        public[name] = {"sha256": value.sha256, "bytes": value.size}
        return value.data

    result = _replacement_records(read)
    sdk.require(len(ORIGINAL_STEPS) == 21 and len(SUCCESSOR_STEPS) == 11, "retirement step definition")
    for prefix, steps in (("", ORIGINAL_STEPS), ("successor/", SUCCESSOR_STEPS)):
        for label, mode in steps:
            expected = b"" if mode in CUT_MODES else f"{profile}:{mode}:passed\n".encode()
            sdk.require(read(prefix + label + ".stdout") == expected
                        and read(prefix + label + ".stderr") == b"", "retirement process outcome: " + prefix + label)
    result["foreign_processes"] = result.pop("processes")
    result["public_readbacks"] = public
    return result


def verify_execution(stdout: bytes, directory: Path, *, catalog=contract.TESTS) -> dict:
    contract.verify_single(stdout, TEST, catalog=catalog)
    results = {}
    for profile in ("fixed", "recoverable"):
        marker = (f"qualified Android-owned retirement signed-{profile}: 32 Java processes; "
                  "3 actual process cuts; Android-owned successor traffic; original complete report and one peer effect")
        sdk.require(stdout.decode().splitlines().count(marker) == 1, "retirement profile outcome missing/duplicated")
        results[profile] = verify_records(directory / ("signed-" + profile), profile)
    return results


def qualify(binary: Path, consumer: Path, installed: Path, output: Path, profile: str, runtime: dict, run) -> dict:
    cases = installed / "retirement-cases"
    stdout = run([str(binary), "--exact", TEST, "--nocapture"], profile + "-retirement",
                 consumer, dict(runtime, QPC_ANDROID_CASES=str(cases)))
    result = verify_execution(stdout, cases)
    exported = output / ("android-jni-" + profile + "-retirement")
    for trust, record in result.items():
        for name in record["public_readbacks"]:
            sdk.copy(cases / ("signed-" + trust) / name, exported / ("signed-" + trust) / name)
    sdk.require(verify_execution(stdout, exported) == result, "retirement public export differs")
    return result
