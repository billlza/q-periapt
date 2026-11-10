"""Bounded dependency acquisition followed by a strict, locked offline check.

Only the Windows package producer uses this coordinator. The supplied executor
retains each command's original stdout/stderr/receipt and rejects ALL warnings.
A rejected network attempt is never relabelled successful; build, compiler,
checksum, authentication and unknown failures are not retried here.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Callable, Mapping, Sequence

from evidence_io import parse_strict_json_bytes

# A deliberately small retry budget, separate from Cargo's own retry loop.
MAX_ATTEMPTS = 2
_CURL_FAILURE = re.compile(r"^\[(?:6|7|18|28|52|55|56)\] [^\r\n]+$")
_TRANSIENT = re.compile(
    r"^warning: spurious network error \([0-9]+ (?:tries|try) remaining\): "
    r"\[(?:6|7|18|28|52|55|56)\] [^\r\n]+$"
)
_FATAL = re.compile(
    r"checksum|certificate|authentication|unauthori[sz]ed|forbidden|"
    r"permission denied|no space left|read-only file system|"
    r"failed to select a version|lock file .*needs to be updated|"
    r"failed to parse|failed to verify|unsupported|corrupt|"
    r"(?:HTTP|status(?: code)?)\s*[:=]?\s*(?:400|401|403|404|407)\b",
    re.IGNORECASE,
)
_DOWNLOAD_ERROR = re.compile(r"^error: failed to (?:download|get) .+$")
_PROGRESS = re.compile(
    r"^(?:Updating crates\.io index|Downloading crates \.\.\.|"
    r"Downloaded [A-Za-z0-9_-]+ v[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?)$"
)


def retryable_network_failure(stdout: bytes, stderr: bytes) -> bool:
    """Classify only an explicit Cargo fetch transport failure.

    Unknown diagnostics fail closed. HTTP authentication and TLS certificate
    verification failures must never be turned into a network retry policy.
    A clean later offline command remains mandatory even for admitted retries.
    """
    try:
        text = stderr.decode('utf-8', errors='strict')
        if stdout.strip() or _FATAL.search(text) or '\x1b' in text or '\x00' in text:
            return False
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        saw_transport_warning = False
        # With CARGO_NET_RETRY=0, Cargo can report only the final download
        # error and a curl cause, without a spurious-network warning. OpenSSL's
        # nested `error:...` is part of the curl diagnostic, not a Cargo error.
        # Account for every nonempty line, including diagnostics without an
        # `error:` prefix. A network warning cannot hide a panic or an unknown
        # failure. Only the pinned producer's crates.io progress is allowed.
        for index, line in enumerate(lines):
            if _TRANSIENT.fullmatch(line):
                saw_transport_warning = True
                continue
            if _PROGRESS.fullmatch(line):
                continue
            if _DOWNLOAD_ERROR.fullmatch(line):
                return (len(lines) == index + 3 and lines[index + 1] == 'Caused by:'
                        and _CURL_FAILURE.fullmatch(lines[index + 2]) is not None)
            return False
        return saw_transport_warning
    except UnicodeDecodeError:
        return False


def fetch_locked(
    argv: Sequence[str], output: Path, cwd: Path, environment: Mapping[str, str], *,
    execute: Callable, read: Callable[[Path], bytes], write_json: Callable,
    command_errors: tuple[type[Exception], ...],
) -> bytes:
    """Execute only a retained locked fetch and a final clean offline admission.

    `execute(argv, label, cwd, env=...)` is the existing strict SDK command runner.
    `read` must use the producer's existing safe snapshot implementation. The
    caller must own the fresh output directory and isolated Cargo home.
    """
    argv = list(argv)
    if any(not isinstance(kind, type) or not issubclass(kind, Exception)
           for kind in command_errors):
        raise ValueError('only explicit command exception types may be retried')
    if (not argv or not all(type(x) is str and x for x in argv)
            or any('\x00' in x for x in argv) or not command_errors):
        raise ValueError('invalid dependency acquisition invocation')
    fetch_index = 2 if len(argv) > 1 and argv[1].startswith('+') else 1
    if (len(argv) <= fetch_index or argv[fetch_index] != 'fetch'
            or argv.count('fetch') != 1 or argv.count('--locked') != 1
            or argv.count('--manifest-path') != 1
            or '--offline' in argv or '--frozen' in argv):
        raise ValueError('dependency acquisition requires one explicit locked fetch')
    index = argv.index('--manifest-path') + 1
    if index >= len(argv):
        raise ValueError('missing fetch manifest path')
    manifest = Path(argv[index])
    if not manifest.is_absolute():
        manifest = cwd / manifest
    lock = manifest.parent / 'Cargo.lock'
    original = read(lock)
    # Prevent a changed manifest from silently changing the resolver contract too.
    original_manifest = read(manifest)
    rows = []
    accepted = False
    failure = None
    primary = None
    final = None

    def unchanged():
        if read(lock) != original or read(manifest) != original_manifest:
            raise ValueError('locked fetch changed its original manifest or lockfile')

    def retained(label, command):
        # Exactly the receipt written by sdk.command; no stale/partial files.
        metadata = parse_strict_json_bytes(read(output / (label + '.json')),
                                           label='dependency command receipt')
        if (type(metadata) is not dict or set(metadata) != {'argv', 'cwd', 'returncode'}
                or metadata['argv'] != command or metadata['cwd'] != str(cwd)
                or type(metadata['returncode']) is not int):
            raise ValueError('dependency command receipt differs')
        stdout = read(output / (label + '.stdout'))
        stderr = read(output / (label + '.stderr'))
        row = {'label': label, 'returncode': metadata['returncode'],
               'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
               'stderr_sha256': hashlib.sha256(stderr).hexdigest()}
        return row, stdout, stderr

    # The runner uses exclusive JSON receipt creation. Refuse a reused directory
    # before launching commands, rather than consuming a stale failed transcript.
    labels = ['fetch'] + [f'fetch-network-{n:02}' for n in range(1, MAX_ATTEMPTS + 1)]
    if any((output / (label + suffix)).exists() or (output / (label + suffix)).is_symlink()
           for label in labels for suffix in ('.json', '.stdout', '.stderr')):
        raise ValueError('dependency command outputs already exist')
    if (output / 'fetch-attempts.json').exists() or (output / 'fetch-attempts.json').is_symlink():
        raise ValueError('dependency acquisition receipt already exists')
    try:
        online = dict(environment, CARGO_NET_OFFLINE='false', CARGO_NET_RETRY='0',
                      CARGO_HTTP_TIMEOUT='45', CARGO_TERM_COLOR='never')
        for attempt in range(1, MAX_ATTEMPTS + 1):
            label = f'fetch-network-{attempt:02}'
            unchanged()
            try:
                execute(argv, label, cwd, env=online)
            except command_errors:
                unchanged()
                row, stdout, stderr = retained(label, argv)
                row['accepted'] = False
                row['retryable_transport'] = (row['returncode'] in (0, 101)
                                              and retryable_network_failure(stdout, stderr))
                rows.append(row)
                if not row['retryable_transport'] or attempt == MAX_ATTEMPTS:
                    raise
                # Retry this exact acquisition only. No cache fallback or new lock.
            else:
                unchanged()
                row, stdout, stderr = retained(label, argv)
                if row['returncode'] != 0 or any('warning:' in stream.decode().casefold()
                                                for stream in (stdout, stderr)):
                    raise ValueError('strict fetch runner accepted a failed or warning-bearing command')
                rows.append(dict(row, accepted=True, retryable_transport=False))
                break
        offline = [*argv, '--offline']
        final = 'fetch'
        result = execute(offline, final, cwd,
                         env=dict(environment, CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never'))
        unchanged()
        row, stdout, stderr = retained(final, offline)
        if (row['returncode'] != 0 or result != stdout
                or any('warning:' in stream.decode().casefold() for stream in (stdout, stderr))):
            raise ValueError('offline dependency admission is not clean')
        rows.append(dict(row, accepted=True, retryable_transport=False, offline=True))
        accepted = True
        return result
    except BaseException as error:
        primary = error
        failure = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        receipt = {'schema_version': 1, 'accepted': accepted, 'maximum_network_attempts': MAX_ATTEMPTS,
                   'lock_sha256': hashlib.sha256(original).hexdigest(),
                   'manifest_sha256': hashlib.sha256(original_manifest).hexdigest(),
                   'attempts': rows, 'offline_label': final, 'failure': failure}
        try:
            write_json(output / 'fetch-attempts.json', receipt)
        except BaseException as receipt_error:
            if primary is not None:
                raise BaseExceptionGroup('dependency fetch and evidence recording failed',
                                         [primary, receipt_error])
            raise
