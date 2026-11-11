#!/usr/bin/env python3
"""Recompute a budget decision record from committed existing observations.

This reads data and source only. It does not execute a native workload, change
the product contract, or promote historical measurements to a release receipt.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
from statistics import median

HERE = Path(__file__).resolve().parent
EVIDENCE = 'research/sdk-alpha1/evidence/'
CORE = 'research/continuity-identity-candidate/'
LIMITS = {
    'signed_body_bytes': ('src/contract.rs', 'MAX_SIGNED_BODY_BYTES'),
    'bootstrap_bundle_bytes': ('src/contract.rs', 'MAX_BOOTSTRAP_BUNDLE_BYTES'),
    'bootstrap_field_bytes': ('src/contract.rs', 'MAX_BOOTSTRAP_FIELD_BYTES'),
    'plaintext_bytes': ('src/contract.rs', 'MAX_PLAINTEXT_BYTES'),
    'associated_data_bytes': ('src/contract.rs', 'MAX_ASSOCIATED_DATA_BYTES'),
    'skipped_keys_per_direction_epoch': ('src/contract.rs', 'MAX_SKIPPED_MESSAGE_KEYS'),
    'outstanding_messages_per_direction_epoch': ('src/contract.rs', 'MAX_OUTSTANDING_MESSAGES'),
    'retained_traffic_epochs': ('src/contract.rs', 'MAX_TRAFFIC_EPOCHS'),
    'control_body_bytes': ('src/contract.rs', 'MAX_CONTROL_BYTES'),
    'connection_frame_bytes': ('src/contract.rs', 'MAX_CONNECTION_FRAME_BYTES'),
    'session_operation_records': ('src/contract.rs', 'MAX_SESSION_OPERATION_RECORDS'),
    'retained_fanout_records': ('src/contract.rs', 'MAX_RETAINED_FANOUT_RECORDS'),
    'prekey_records': ('src/contract.rs', 'MAX_PREKEY_RECORDS'),
    'account_roster_records': ('src/contract.rs', 'MAX_ACCOUNT_ROSTER_RECORDS'),
    'device_history_per_account': ('src/contract.rs', 'MAX_DEVICE_HISTORY_PER_ACCOUNT'),
    'journal_image_bytes': ('src/contract.rs', 'MAX_JOURNAL_IMAGE_BYTES'),
    'network_exchanges': ('src/contract.rs', 'MAX_NETWORK_EXCHANGES'),
    'run_timeout_seconds': ('src/contract.rs', 'MAX_RUN_TIMEOUT_SECONDS'),
    'connect_timeout_seconds': ('src/contract.rs', 'MAX_CONNECT_TIMEOUT_SECONDS'),
    'roster_devices': ('src/identity.rs', 'MAX_DEVICES'),
    'manifest_prekeys': ('src/manifest.rs', 'MAX_PREKEYS'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fraction(value):
    return Fraction(value['numerator'], value['denominator'])


def number_expression(source):
    def parse(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return parse(node.left) * parse(node.right)
        raise ValueError('unexpected source constant expression')
    return parse(ast.parse(source, mode='eval').body)


def check_summary(samples, result, name):
    values = sorted(sample[name] for sample in samples)
    require(result['minimum'] == values[0] and result['maximum'] == values[-1]
            and result['median'] == median(values), 'summary mismatch ' + name)
    if 'samples' in result:
        require(result['samples'] == len(values), 'summary sample count')
    if 'empirical_p95_nearest_rank' in result:
        expected = values[(95 * len(values) + 99) // 100 - 1] if len(values) >= 20 else None
        require(result['empirical_p95_nearest_rank'] == expected, 'empirical p95 mismatch')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', type=Path, default=HERE.parents[3])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = args.repository.resolve()
    identity = read(HERE / 'SOURCE_INPUTS.json')
    for entry in identity['files']:
        data = (root / entry['path']).read_bytes()
        require(len(data) == entry['bytes'] and hashlib.sha256(data).hexdigest() == entry['sha256'],
                'source snapshot changed ' + entry['path'])
        require(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                == entry['git_blob_sha1'], 'source Git blob ' + entry['path'])

    budgets = read(root / 'docs/continuity/BUDGETS_V1.json')
    require(budgets['schema_version'] == 3 and budgets['frozen_product_contract'] is False,
            'candidate budget status changed')
    require(set(budgets['maximums']) == set(LIMITS), 'budget inventory')
    hard_limits = []
    for key, (path, symbol) in LIMITS.items():
        source = (root / CORE / path).read_text()
        match = re.search(r'pub const ' + symbol + r': (?:usize|u16|u64) = ([^;]+);', source)
        require(match is not None and number_expression(match[1]) == budgets['maximums'][key],
                'implemented constant differs ' + key)
        hard_limits.append({'field': key, 'value': budgets['maximums'][key],
                            'kind': 'implemented_hard_limit', 'source': CORE + path,
                            'symbol': symbol})
    descriptor = (root / CORE / 'examples/contract_report.rs').read_text()
    require(all(symbol in descriptor for _, symbol in LIMITS.values()), 'descriptor constant coverage')
    require('ApplicationSendBudget::new(1024)?' in (root / CORE / 'tests/owned_connection.rs').read_text(),
            'installed fixture send-budget identity')

    phases = read(root / EVIDENCE / '20261106-installed-throughput/PHASE_SUMMARY.json')
    phase_rows = []
    for group in phases:
        samples = group['all_phase_samples']
        require(len(samples) == group['repetitions'] == 4, 'phase repetitions')
        require({s['round'] for s in samples} == {1, 2, 3, 4}, 'phase round identity')
        for sample in samples:
            require(sample['end_ns'] - sample['start_ns'] == sample['elapsed_ns'], 'phase duration')
            require(sample['measured_operation_wall_ns'] + sample['outside_operation_spans_ns']
                    == sample['elapsed_ns'], 'phase complete denominator')
        check_summary(samples, group['elapsed_ns'], 'elapsed_ns')
        total_ns = sum(s['elapsed_ns'] for s in samples)
        deliveries = sum(s['confirmed_deliveries'] for s in samples)
        plaintext = sum(s['delivered_plaintext_bytes'] for s in samples)
        require(total_ns == group['total_elapsed_ns'] and deliveries == group['confirmed_deliveries']
                and plaintext == group['delivered_plaintext_bytes'], 'phase totals')
        require(fraction(group['pooled_rates']['confirmed_deliveries_per_second'])
                == Fraction(deliveries * 10**9, total_ns), 'pooled delivery rate')
        require(fraction(group['pooled_rates']['delivered_plaintext_bytes_per_second'])
                == Fraction(plaintext * 10**9, total_ns), 'pooled plaintext rate')
        for field in ['witness_exchanges', 'witness_exchanges_outside_operation_spans',
                      'outside_operation_spans_ns', 'measured_operation_wall_ns',
                      'retired_aggregates', 'control_updates']:
            require(sum(s[field] for s in samples) == group[field], 'phase accounting ' + field)
        if group['phase'] == 'ordinary-workload':
            maximum_ns = group['elapsed_ns']['maximum']
            # The selected engineering policy, not a measured statistic: multiply
            # the retained maximum by 1.25 and round up to a whole second.
            selected_seconds = (maximum_ns * 5 + 4 * 10**9 - 1) // (4 * 10**9)
            require(selected_seconds == {('lifecycle', 'local'): 11,
                                         ('lifecycle', 'witness'): 19,
                                         ('fanout', 'local'): 6,
                                         ('fanout', 'witness'): 11}[(group['kind'], group['profile'])],
                    'selected regression interval budget')
            phase_rows.append({
                'kind': group['kind'], 'profile': group['profile'], 'repetitions': 4,
                'deliveries_per_repeat': deliveries // 4,
                'retired_aggregates_per_repeat': group['retired_aggregates'] // 4,
                'control_updates_per_repeat': group['control_updates'] // 4,
                'elapsed_ns': group['elapsed_ns'], 'total_elapsed_ns': total_ns,
                'observed_pooled_deliveries_per_second': float(Fraction(deliveries * 10**9, total_ns)),
                'observed_plaintext_kib_per_second': float(Fraction(plaintext * 10**9, total_ns * 1024)),
                'observed_per_repeat_delivery_rate': {k: float(fraction(v)) for k, v in group['per_run_delivery_rate'].items()},
                'witness_exchanges_per_repeat': group['witness_exchanges'] // 4,
                'observed_witness_framed_bytes_per_repeat': sum(s['witness_framed_bytes'] for s in samples) // 4,
                'selected_reference_interval_ceiling_seconds': selected_seconds,
                'selected_reference_delivery_rate_floor': float(Fraction(deliveries // 4, selected_seconds)),
                'policy_status': 'selected',
            })

    operations = read(root / EVIDENCE / '20261106-resource-repeats/OPERATION_SUMMARY.json')
    selected_operations = []
    for group in operations:
        samples = group['all_samples']
        for field in ['elapsed_ns', 'cpu_user_us', 'cpu_system_us']:
            check_summary(samples, group[field], field)
        require({str(k): v for k, v in Counter(s['round'] for s in samples).items()}
                == group['round_sample_counts'], 'operation round accounting')
        for field, distribution in [('witness_exchanges', 'witness_exchange_distribution'),
                                    ('witness_framed_bytes', 'witness_framed_byte_distribution')]:
            require({str(k): v for k, v in Counter(s[field] for s in samples).items()}
                    == group[distribution], 'operation witness accounting')
        representative = (
            group['kind'] == 'lifecycle' and group['operation'] in
            ['establish', 'traffic_independent_rekey', 'retry_original_after_reopen']
            or group['operation'] == 'retire_account_operation'
            or group['epoch'] == 1 and group['payload_bytes'] == 1024
            and group['associated_data_bytes'] == 32 and group['operation'] in
            ['send_confirmed', 'deliver_account_member'])
        if representative:
            selected_operations.append({k: group[k] for k in
                ['kind', 'profile', 'operation', 'epoch', 'member_order', 'payload_bytes',
                 'associated_data_bytes', 'elapsed_ns', 'cpu_user_us', 'cpu_system_us',
                 'witness_exchange_distribution', 'witness_framed_byte_distribution']})

    memory = read(root / EVIDENCE / '20261106-resource-repeats/MEMORY_SUMMARY.json')
    memory_rows = {}
    for group in memory:
        samples = group['all_samples']
        for field, expected in group['observed_stage_maximums'].items():
            if isinstance(expected, list):
                actual = [max(s[field][i] for s in samples) for i in range(len(expected))]
            else:
                actual = max(s[field] for s in samples)
            require(actual == expected, 'sampled memory maximum ' + field)
        key = group['kind'] + '/' + group['profile']
        out = memory_rows.setdefault(key, {'kind': group['kind'], 'profile': group['profile'],
                                         'sampled_stages': 0, 'samples': 0,
                                         'resident_bytes': 0, 'physical_footprint_bytes': 0,
                                         'journal_database_bytes': [0] * len(samples[0]['journal_database_bytes'])})
        out['sampled_stages'] += 1
        out['samples'] += len(samples)
        for field in ['resident_bytes', 'physical_footprint_bytes']:
            out[field] = max(out[field], max(s[field] for s in samples))
        out['journal_database_bytes'] = [max(previous, max(s['journal_database_bytes'][i] for s in samples))
                                        for i, previous in enumerate(out['journal_database_bytes'])]

    capacity = read(root / EVIDENCE / '20261104-installed-resource-baseline/SUMMARY.json')
    require(capacity['completed'] and len(capacity['cases']) == 4, 'capacity cohort completion')
    max_rss = max(c['process_resources']['max_rss_bytes'] for c in capacity['cases'])
    max_database = max(stage['journal_file_bytes'] for c in capacity['cases']
                       for stage in c['resources'].values())
    mib = 1024**2
    capacity_result = {
        'source_commit': capacity['source_commit'], 'cohorts': 4,
        'business_effects_checked': capacity['business_effects_checked'],
        'negative_controls_rejected_in_retained_execution': capacity['negative_controls_rejected'],
        'observed_peak_whole_process_rss_bytes': max_rss,
        'observed_maximum_sender_database_bytes': max_database,
        'selected_capacity_fixture_rss_ceiling_bytes': ((max_rss * 5 + 4 * mib - 1) // (4 * mib)) * mib,
        'selected_capacity_fixture_database_ceiling_bytes': ((max_database * 5 + 4 * mib - 1) // (4 * mib)) * mib,
        'policy_status': 'selected',
        'scope': 'Existing capacity/recovery workload, including both endpoints and observer; the database maximum is a physical file measurement, separate from the encoded-image hard cap.'}
    require(capacity_result['selected_capacity_fixture_rss_ceiling_bytes'] == 200 * mib
            and capacity_result['selected_capacity_fixture_database_ceiling_bytes'] == 15 * mib,
            'selected capacity resource budgets')

    result = {
        'schema': 'qperiapt.supported_workload_budget_review/1',
        'status': 'recomputed', 'decision_status': 'selected', 'decision_date': '2026-11-09',
        'final_chosen_artifact_verification_status': 'pending_existing_admission_sequence',
        'coordinated_freeze_status': 'pending_existing_admission_sequence',
        'current_source_commit': identity['base_commit'], 'current_source_tree': identity['base_tree'],
        'frozen_product_contract': False, 'performance_qualified': False, 'release_claim_eligible': False,
        'new_native_executions': 0,
        'source_inputs_verified': len(identity['files']), 'implemented_hard_limits': hard_limits,
        'send_budget': {'implemented_range': [1, 65535], 'unsigned_default': None,
                        'installed_reference_fixture_B': 1024,
                        'selection_status': 'retained_issuer_selected_B',
                        'control_responsibility': 'Application/connection owner advances required PQ control so application work can continue within the signed allowance.',
                        'new_fixed_B_or_control_cadence': None},
        'measured_source_commit': '5678d1019861fa1b04f3a219ba3fde7e0ddaaba8',
        'whole_workload_observations_and_selected_budgets': phase_rows,
        'representative_operation_observations': selected_operations,
        'sampled_memory_observations': list(memory_rows.values()),
        'capacity_observations_and_selected_budgets': capacity_result,
        'selected_budget_rule': 'Selected 0.2.0 desktop reference regression policy: 1.25 times the maximum retained complete interval or capacity-fixture resource value, rounded up to one second or one MiB. This is an engineering allowance, not a statistical confidence bound.',
        'selected_scope': 'Exactly the defined installed desktop reference workloads and capacity/recovery fixture. Existing platform functional scope is retained. Larger-recipient quantitative envelopes and mobile energy add no admission requirement.',
        'runtime_limits_changed': False, 'new_ci_gate': False,
        'verification': {'phase_groups_recomputed': len(phases), 'phase_samples': sum(len(x['all_phase_samples']) for x in phases),
                         'operation_groups_recomputed': len(operations), 'operation_samples': sum(len(x['all_samples']) for x in operations),
                         'memory_groups_recomputed': len(memory), 'memory_samples': sum(len(x['all_samples']) for x in memory)},
        'checker_sha256': digest(Path(__file__))}
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end='')


if __name__ == '__main__':
    main()
