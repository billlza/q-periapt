#!/usr/bin/env python3
"""Build an isolated publication-fault counterpart from the selected native source."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
from bounded_process import run
from git_provenance import git_commit, run_git_bytes

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'research/continuity-openssl-peer/native'
STAGES = ('staging', 'file', 'prepared', 'published', 'synced')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_inputs():
    prefix = SOURCE.relative_to(ROOT).as_posix()
    listed = run_git_bytes(ROOT, ['ls-files', '--cached', '-z', '--', prefix + '/Cargo.toml',
                                 prefix + '/Cargo.lock', prefix + '/src'])
    names = [name.decode() for name in listed.split(b'\0') if name]
    required = {prefix + '/' + name for name in ('Cargo.toml', 'Cargo.lock', 'src/main.rs', 'src/approval.rs')}
    if not required.issubset(names) or any((ROOT / name).is_symlink() or not (ROOT / name).is_file() for name in names):
        raise ValueError('native fault source census differs')
    return {name: digest(ROOT / name) for name in names}


def instrument(text):
    anchors = (
        ('        .tempdir_in(public)?;', 'staging'),
        ('        file.sync_all()?;', 'file'),
        ('    fs::File::open(staging.path())?.sync_all()?;', 'prepared'),
        ('    fs::rename(staging.path(), &destination)?;', 'published'),
    )
    for anchor, stage in anchors:
        if text.count(anchor) != 1:
            raise ValueError('publication boundary requires review: ' + stage)
        text = text.replace(anchor, anchor + f'\n    approval_fault(public, kind, "{stage}", control)?;')
    final = '    matches(&destination, &rows)\n}'
    if text.count(final) != 1:
        raise ValueError('publication boundary requires review: synced')
    text = text.replace(final, '    approval_fault(public, kind, "synced", control)?;\n' + final)
    return text + '''
// Isolated qualification copy only; the unmodified counterpart has no selector.
fn approval_fault(public: &Path, kind: Kind, stage: &str, request: &[u8]) -> Result<()> {
    let lane = match kind { Kind::First => "first", Kind::Later => "later", Kind::Unactivated => "unactivated" };
    let evidence = public.parent().ok_or("fault evidence parent")?;
    let selected = crate::restart::read(&evidence.join("approval-fault-selection"), 64)?;
    let kill = selected == format!("{lane}:{stage}:kill").as_bytes();
    let io = selected == format!("{lane}:{stage}:io").as_bytes();
    if !kill && !io { return Ok(()); }
    let pid = std::process::id().to_string();
    let fault = if kill { "kill" } else { "io" };
    crate::fixture::save(evidence, "approval-fault-request", request)?;
    crate::fixture::save(evidence, "approval-fault-marker", format!("{lane}\\n{stage}\\n{fault}\\n{pid}\\n").as_bytes())?;
    if io { return Err(std::io::Error::other("injected approval publication I/O failure").into()); }
    std::process::Command::new("/bin/kill").args(["-KILL", &pid]).status()?;
    Err("diagnostic SIGKILL did not terminate original process".into())
}
'''


def prepare(output, target, native):
    if Path.cwd().resolve() != ROOT:
        raise ValueError('fault builds require the selected repository as cwd')
    changed = instrument((SOURCE / 'src/approval.rs').read_text())
    hashes = source_inputs()
    native_hash = digest(native)
    output.mkdir(parents=True)
    copied = output / 'source'
    for name in hashes:
        relative = (ROOT / name).relative_to(SOURCE)
        destination = copied / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination)
    manifest = (SOURCE / 'Cargo.toml').read_text()
    manifest = re.sub(r'path = "([^"]+)"',
                      lambda match: 'path = ' + json.dumps(str((SOURCE / match[1]).resolve(strict=True))), manifest)
    (copied / 'Cargo.toml').write_text(manifest)
    (copied / 'src/approval.rs').write_text(changed)
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target))
    environment['RUSTFLAGS'] = environment.get('RUSTFLAGS', '') + ' -D warnings'
    command = ['cargo', 'build', '--locked', '--release', '--manifest-path', str(copied / 'Cargo.toml')]
    with (output / 'build.stderr').open('xb') as stderr:
        built = run(command, timeout_seconds=900, stderr=stderr.fileno(), environment=environment)
    if built.returncode != 0:
        raise ValueError(f'native fault build failed ({built.returncode}): {output / "build.stderr"}')
    if any(digest(ROOT / name) != value for name, value in hashes.items()):
        raise ValueError('native source changed during fault build')
    if digest(native) != native_hash:
        raise ValueError('original native binary changed during fault build')
    shutil.copy2(target / 'release/q-periapt-independent-peer-counterpart', output / 'fault-counterpart')
    shutil.copy2(native, output / 'original-counterpart')
    report = {
        'completed_build': True, 'runtime_qualified': False,
        'source_commit': git_commit(ROOT),
        'source_inputs': hashes,
        'worktree_dirty': bool(run_git_bytes(ROOT, ['status', '--porcelain'])),
        'instrumenter_sha256': digest(Path(__file__)),
        'instrumented_source_sha256': digest(copied / 'src/approval.rs'),
        'native_sha256': digest(output / 'original-counterpart'),
        'fault_native_sha256': digest(output / 'fault-counterpart'),
        'command': command, 'stages': STAGES,
        'scope': 'Only the source copy has fault selectors; both binaries are retained. No runtime or release qualification from building.'}
    (output / 'BUILD.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'target', 'native'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    prepare(args.output.absolute(), args.target.absolute(), args.native.resolve(strict=True))
    print('NATIVE_APPROVAL_FAULT_BUILD_PASS runtime_qualified=false')
