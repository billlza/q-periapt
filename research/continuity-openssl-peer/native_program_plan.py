"""Bounded, source-bound program replacement for the successor restart fixture.

This controls test processes, not protocol negotiation or a product updater.
There is no fallback to another executable when validation or reopening fails.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from pathlib import Path
import re

from evidence_io import parse_strict_json_bytes, read_regular_snapshot


CUTS = ('approved', 'reply', 'final', 'active', 'receive', 'outbox', 'ack',
        'rekey-response', 'rekey-receipt', 'new-epoch')


def require(condition, message):
    if not condition:
        raise ValueError('native program plan: ' + message)


def canonical(value):
    require(type(value) is str, 'path must be a string')
    path = Path(value)
    require(path.is_absolute() and path == path.resolve(strict=True), 'path must be canonical')
    return path


def snapshot(path, maximum=16 * 1024**2):
    return read_regular_snapshot(path, maximum=maximum, label='native program plan input')


class NativeProgramPlan:
    def __init__(self, path, initial):
        self.path = canonical(str(path))
        captured = snapshot(self.path, 64 * 1024)
        self.sha256 = captured.sha256
        value = parse_strict_json_bytes(captured.data, label='native program plan')
        require(type(value) is dict and set(value) == {'schema_version', 'programs', 'restarts'},
                'unexpected plan fields')
        require(type(value['schema_version']) is int and value['schema_version'] == 1, 'schema version')
        programs = value['programs']
        require(type(programs) is dict and set(programs) == {'before', 'after'}, 'two program identities required')
        self.programs = {}
        for name, item in programs.items():
            require(type(item) is dict and set(item) ==
                    {'executable', 'installation_report', 'installation_report_sha256'}, 'program fields')
            executable = canonical(item['executable'])
            report_path = canonical(item['installation_report'])
            report_bytes = snapshot(report_path)
            require(report_bytes.sha256 == item['installation_report_sha256'], 'installation report hash differs')
            report = parse_strict_json_bytes(report_bytes.data, label='native installation report')
            require(type(report) is dict and report.get('kind') == 'qperiapt.independent_installed_counterpart'
                    and report.get('completed') is True and report.get('sources_unchanged') is True,
                    'incomplete installed counterpart build')
            commit = report.get('source_commit')
            require(type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit), 'source commit identity')
            binary = snapshot(executable, 256 * 1024**2)
            require(binary.sha256 == report.get('native_sha256'), 'executable differs from installed build')
            self.programs[name] = {'executable': str(executable), 'sha256': binary.sha256,
                                   'source_commit': commit, 'installation_report': str(report_path),
                                   'installation_report_sha256': report_bytes.sha256}
        require(all(len({p[key] for p in self.programs.values()}) == 2
                    for key in ('executable', 'sha256', 'source_commit')), 'programs must be distinct builds')
        require(canonical(str(initial)) == Path(self.programs['before']['executable']), 'initial executable differs')
        self.steps = value['restarts']
        require(type(self.steps) is list and len(self.steps) == len(CUTS), 'exact restart census required')
        for label, step in zip(CUTS, self.steps, strict=True):
            require(type(step) is dict and set(step) == {'case', 'program'} and step['case'] == label
                    and type(step['program']) is str and step['program'] in self.programs,
                    'restart order or target differs')
        targets = ['before', *(s['program'] for s in self.steps)]
        require(('before', 'after') in list(zip(targets, targets[1:]))
                and ('after', 'before') in list(zip(targets, targets[1:])), 'both replacement directions required')
        self.index = 0
        self.current = 'before'

    def check_inputs(self):
        require(snapshot(self.path, 64 * 1024).sha256 == self.sha256, 'plan changed')
        for item in self.programs.values():
            require(snapshot(Path(item['installation_report'])).sha256 == item['installation_report_sha256'],
                    'installation report changed')
            require(snapshot(Path(item['executable']), 256 * 1024**2).sha256 == item['sha256'], 'executable changed')

    def select(self, label, current):
        self.check_inputs()
        require(self.index < len(self.steps), 'extra restart')
        step = self.steps[self.index]
        require(step['case'] == label and Path(current) == Path(self.programs[self.current]['executable']),
                'unexpected process or cut')
        target = step['program']
        return Path(self.programs[target]['executable']), {
            'plan_sha256': self.sha256, 'index': self.index, 'from': self.current, 'to': target,
            'old': self.programs[self.current], 'new': self.programs[target]}

    def reopened(self, label, executable):
        # Commit plan progress only after the actual new process opened the
        # unchanged original fixture. Failed starts leave the cut incomplete.
        selected, _ = self.select(label, self.programs[self.current]['executable'])
        require(Path(executable) == selected, 'reopened executable differs')
        self.current = self.steps[self.index]['program']
        self.index += 1

    def finish(self):
        self.check_inputs()
        require(self.index == len(self.steps), 'missing restart')
        return {'completed': True, 'plan_sha256': self.sha256, 'programs': self.programs,
                'restarts': self.steps, 'final_program': self.current,
                'scope': 'Program replacement over original current-format state; no backup restoration, '
                         'legacy schema migration, power-loss or general rollback support claim.'}
