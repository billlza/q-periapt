#!/usr/bin/env python3
"""Portable public input interoperability and historical/current permission split."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def exercise(args, label):
    from fixture_inputs import load, load_witness_pin
    from peer.bootstrap_bundle import BootstrapBundle, decode, MAX_BUNDLE
    from peer.bootstrap import Initiator
    from peer.durable import Session, owner_binding
    from peer.journal import Scope
    from peer.witness_session import WitnessSession
    from peer.wire import SigningKey, digest, require
    from cryptography.exceptions import InvalidSignature
    from run import Counterpart
    out = args.output / label; out.mkdir(); (out / 'native').mkdir()
    native = Counterpart(args.native, out / 'native', required_witness=label == 'witness')
    checks = []; imports = []; signer = SigningKey()
    def reject(name, function, reason=None):
        try: function()
        except (ValueError, InvalidSignature) as error:
            if reason is not None: require(reason in str(error), 'wrong refusal: ' + name + ': ' + str(error))
            checks.append({'case': name, 'error': str(error), 'type': type(error).__name__})
        else: raise ValueError('missing refusal: ' + name)
    try:
        require(native.transfer(signer.public().raw) == b'\1ready', 'native readiness')
        public = out / 'native/public'; pin = load_witness_pin(public) if label == 'witness' else None
        pins, materials, original = load(public, 150, witness_pin=pin)
        bundle = BootstrapBundle.from_materials(materials); (out / 'bundle.bin').write_bytes(bundle.wire)
        require(bundle.verify(pins, materials.sdk_document, materials.sdk_signature, materials.policy, 150,
                              required_quality=2, witness_pin=pin) == original, 'same independently authenticated context')
        def historical(value=bundle, *, now=401, expected=original.digest, selected=pins):
            return value.verify_original(selected, materials.sdk_document, materials.sdk_signature, materials.policy, now,
                                         original_context=expected, required_quality=2, witness_pin=pin)
        for now in [150, 170, 210, 401]: require(historical(now=now) == original, 'same original snapshot')
        reject('future-original', lambda: historical(now=99), 'future')
        reject('wrong-original-context', lambda: historical(expected=b'x' * 32), 'context commitment')
        reject('wrong-directory', lambda: historical(selected=replace(pins, directory=b'x' * 32)))
        reject('current-advertisement-expiry', lambda: bundle.verify(pins, materials.sdk_document, materials.sdk_signature,
               materials.policy, 170, required_quality=2, witness_pin=pin), 'expired')
        reject('expired-historical-snapshot-not-new-bootstrap', lambda: Initiator(historical(), signer, 401),
               'required-witness' if pin is not None else 'expired')
        work = Path(tempfile.mkdtemp(prefix='qperiapt-public-original-')).resolve(); work.chmod(0o700)
        (out / 'private-fixture-path').write_text(str(work) + '\n')
        scope = Scope(os.urandom(32), owner_binding(original), original.digest)
        if pin is None:
            reject('expired-original-cannot-create-session', lambda: Session.create(work, scope, os.urandom(32), historical(), signer, 401), 'expired')
            reject('missing-active-state-is-not-first-use', lambda: Session.open(work, scope, os.urandom(32), historical()), 'missing active image')
        else:
            reject('expired-original-cannot-provision', lambda: WitnessSession.provision(work, scope, os.urandom(32), historical(), signer, 401), 'expired')
        require(not list(work.iterdir()), 'rejected original snapshot created private state')
        # Every truncation is rejected by bounded framing without any crypto call.
        for length in range(len(bundle.wire)):
            try: BootstrapBundle(bundle.wire[:length])
            except ValueError: pass
            else: raise ValueError('accepted truncation: ' + str(length))
        for name, value in [('extension', bundle.wire + b'\0'), ('oversized', b'QPBNDL01' + bytes(MAX_BUNDLE)),
                            ('unknown-quality', bundle.wire[:8] + b'\5' + bundle.wire[9:]),
                            ('empty-required', bundle.wire[:9] + b'\0\0' + bundle.wire[11:]),
                            ('oversized-field', bundle.wire[:9] + (8193).to_bytes(2, 'big') + bundle.wire[11:])]:
            reject('outer-' + name, lambda value=value: BootstrapBundle(value))
        _, fields = decode(bundle.wire)
        for quality in (1, 3, 4):
            values = fields[:7] + ((fields[5] if quality in (1, 4) else b''), (fields[6] if quality in (1, 3) else b''))
            value = BootstrapBundle(b'QPBNDL01' + bytes([quality]) + b''.join(len(x).to_bytes(2, 'big') + x for x in values))
            reject('required-quality-' + str(quality), lambda value=value: value.verify(pins, materials.sdk_document,
                   materials.sdk_signature, materials.policy, 150, required_quality=2, witness_pin=pin), 'required prekey quality')
            reject('unsupported-quality-' + str(quality), lambda value=value, quality=quality: value.verify(pins,
                   materials.sdk_document, materials.sdk_signature, materials.policy, 150, required_quality=quality,
                   witness_pin=pin), 'not implemented')
        mutations = {}
        for index in range(7):
            values = list(fields); values[index] = values[index][:-1] + bytes([values[index][-1] ^ 1])
            value = BootstrapBundle(b'QPBNDL01\2' + b''.join(len(x).to_bytes(2, 'big') + x for x in values))
            mutations['tampered-' + str(index)] = value.wire
            reject('historical-tampered-' + str(index), lambda value=value: historical(value))
        # Adapt only test-genesis filenames to the unchanged public native importer.
        trust = out / 'native-import-trust'; trust.mkdir()
        for source, destination in {'sdk-document':'bootstrap-sdk-policy.toml', 'sdk-signature':'bootstrap-sdk-policy.sig',
            'pin-sdk-root':'bootstrap-sdk-root.pub', 'pin-policy-root':'bootstrap-policy.pub', 'pin-policy-head':'bootstrap-policy-checkpoint.bin',
            'policy':'bootstrap-policy.bin', 'pin-directory':'bootstrap-directory.bin', 'expected-context':'bootstrap-context.digest',
            'pin-i-root':'bootstrap-i-root.pub', 'pin-i-head':'bootstrap-i-expectation.bin',
            'pin-r-root':'bootstrap-r-root.pub', 'pin-r-head':'bootstrap-r-expectation.bin'}.items():
            (trust / destination).write_bytes((public / source).read_bytes())
        (trust / 'bootstrap-family.bin').write_bytes(digest(b'POLICY-AUTHORITY', pins.policy_root.raw))
        def imported(name, data, quality, now, valid):
            path = out / (name + '.bundle'); path.write_bytes(data)
            command = [str(args.importer), str(trust), str(path), str(quality), str(now)]
            result = subprocess.run(command, capture_output=True, timeout=30)
            (out / (name + '.stdout')).write_bytes(result.stdout); (out / (name + '.stderr')).write_bytes(result.stderr)
            imports.append({'case': name, 'command': command, 'exit': result.returncode,
                            'input_sha256': hashlib.sha256(data).hexdigest(),
                            'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()})
            if valid: require(result.returncode == 0 and not result.stderr and result.stdout.strip().decode() == original.digest.hex(), 'native exact imported context')
            else:
                error = 'Scope' if name == 'native-wrong-quality' else ('Validity' if name == 'native-expired-advertisement' else 'Authentication')
                require(result.returncode == 1 and not result.stdout and result.stderr == ('Error: ' + error + '\n').encode(), 'native exact typed refusal')
        imported('native-valid', bundle.wire, 2, 150, True)
        imported('native-wrong-quality', bundle.wire, 1, 150, False)
        imported('native-expired-advertisement', bundle.wire, 2, 170, False)
        for name, value in mutations.items(): imported('native-' + name, value, 2, 150, False)
        result = {'context': original.digest.hex(), 'bundle_bytes': len(bundle.wire), 'bundle_sha256': hashlib.sha256(bundle.wire).hexdigest(),
                  'every_truncation_refused': len(bundle.wire), 'refusals': checks, 'native_imports': imports,
                  'scope': 'Actual native importer and independent verifier agree on public context. Original snapshot has no current grant. Explicit fixture trust remains separate; no installed/deployed registration or native runtime-owner equivalence.'}
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n'); return result
    finally:
        (out / 'REFUSALS.json').write_text(json.dumps(checks, indent=2) + '\n')
        (out / 'IMPORTS.json').write_text(json.dumps(imports, indent=2) + '\n')
        native.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['provider-root', 'native', 'importer', 'output']: parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(); args.output = args.output.resolve(); args.native = args.native.resolve(); args.importer = args.importer.resolve()
    sys.path.append(str(Path(__file__).resolve().parent))
    from provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    from peer.wire import require
    root = Path(__file__).resolve().parent
    files = [*sorted((root / 'peer').glob('*.py')), *sorted(root.glob('*.py')), *sorted((root / 'native/src').glob('*.rs')),
             root / 'native/Cargo.toml', root / 'native/Cargo.lock', root / 'requirements.txt']
    def sources(): return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    source_files = sources(); native = hashlib.sha256(args.native.read_bytes()).hexdigest(); importer = hashlib.sha256(args.importer.read_bytes()).hexdigest()
    args.output.mkdir(); result = {'source_files': source_files, 'native_sha256': native, 'importer_sha256': importer,
        'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()}}
    (args.output / 'INPUTS.json').write_text(json.dumps(result, indent=2) + '\n')
    for label in ['local', 'witness']:
        r = exercise(args, label); result[label] = {k: r[k] for k in ['context', 'bundle_bytes', 'every_truncation_refused']}
    require(sources() == source_files and hashlib.sha256(args.native.read_bytes()).hexdigest() == native
            and hashlib.sha256(args.importer.read_bytes()).hexdigest() == importer, 'qualification inputs changed')
    (args.output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({k:v for k,v in result.items() if k != 'source_files'}))


if __name__ == '__main__': main()
