#!/usr/bin/env python3
"""Independent verification of native policy approvals from original installations.

This checks public proof interoperability only, not independent durable adoption.
The native producer preserves both original installations and private issuer files.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def scenario(public, after_g):
    from cryptography.exceptions import InvalidSignature
    from qperiapt_continuity_reference.authority import (
        PolicyPins, PolicyMaterials, authenticate_policy, authenticate_historical_policy)
    from qperiapt_continuity_reference.identity import DevicePin, verify_device
    from qperiapt_continuity_reference.policy_renewal_proof import (
        Scope, APPROVAL_BYTES, verify_current, verify_historical, statement_body)
    from qperiapt_continuity_reference.renewal import verify as verify_credential_renewal
    from qperiapt_continuity_reference.wire import VerificationKey, require

    read = lambda name: (public / name).read_bytes()
    root = VerificationKey(read("pin-policy-root"))
    account = VerificationKey(read("account-root"))
    pins = {}
    histories = {}
    materials = {}
    for version in range(1, 8):
        head = read(f"policy-head-{version}")
        require(int.from_bytes(head[:8], "big") == version, "independent policy checkpoint")
        pins[version] = PolicyPins(read("pin-sdk-root"), read("pin-sdk-state"), root, version, head[8:])
        materials[version] = PolicyMaterials(read("sdk-document"), read("sdk-signature"), read(f"policy-{version}"))
        histories[version] = authenticate_historical_policy(pins[version], materials[version].policy)
    refusals = []

    def refuses(name, action, reason=None):
        try:
            action()
        except (ValueError, InvalidSignature) as error:
            require(reason is None or reason in str(error), f"unexpected refusal {name}: {error}")
            refusals.append({"case": name, "error": str(error), "type": type(error).__name__})
        else:
            raise ValueError("missing refusal: " + name)

    results = []
    original_scope = None
    previous_statement = None
    for cycle, now in ((1, 190), (2, 270)):
        item = public / f"renewal-{cycle}"
        get = lambda name: (item / name).read_bytes()
        prior = get("previous-authorization")
        require(len(prior) == 33 and prior[0] == (cycle == 2), "native predecessor flag")
        scope = Scope(get("operation"), get("journal"), get("owner"),
                      get("original-credential-digest"), get("current-credential-digest"),
                      get("current-roster-head"), get("original-policy-head"), get("previous-policy-head"),
                      prior[1:] if prior[0] else None)
        require(scope.previous_authorization == previous_statement, "actual native adopted predecessor")
        immutable = (scope.journal, scope.original_owner, scope.original_credential)
        require(original_scope is None or original_scope == immutable, "native changed original installation")
        original_scope = immutable
        devices = []
        for role in ("original", "current"):
            head = get(f"{role}-roster-head")
            pin = DevicePin(account, read("account"), int.from_bytes(head[:8], "big"), head[8:], bytes([1]) * 16, 1)
            # Native fixture retains the real initial issuance interval. This is
            # historical signature reconstruction, never a current owner call.
            devices.append(verify_device(pin, get(f"{role}-credential"), get(f"{role}-roster"),
                                         histories[1].family, 150))
        original, current = devices
        require((original.credential != current.credential) == after_g, "native real credential renewal profile")
        if after_g:
            grant = verify_credential_renewal(read("prior-credential-grant"), original,
                histories[1].family, histories[1].digest, scope.current_roster, now=now)
            require(grant.successor.digest == current.credential, "native prior real grant differs")
        target = authenticate_policy(pins[cycle + 1], materials[cycle + 1], now)
        args = (scope, histories[1], histories[cycle], target, original, current)
        approval = get("approval")
        approved = verify_current(approval, *args, now)
        require(approved.statement == get("statement") and approved.target == histories[cycle + 1].checkpoint(),
                "native and independent policy approval commitments differ")
        resigned = verify_current(get("approval-resigned"), *args, now)
        require(resigned.statement == approved.statement, "randomized signatures changed statement identity")
        require(verify_historical(approval, scope, histories[1], histories[cycle], histories[cycle + 1],
                                 original, current).statement == approved.statement,
                "historical and current proof disagree")
        label = lambda name: f"P{cycle}-{name}"
        refuses(label("expired-predecessor-is-not-current-policy"),
                lambda: authenticate_policy(pins[cycle], materials[cycle], now), "expired")
        refuses(label("expired-target-does-not-grant-current-authority"),
                lambda: verify_current(approval, *args, target.validity.end), "expired")
        refuses(label("premature-target"), lambda: verify_current(approval, *args, 99), "premature")
        refuses(label("historical-metadata-cannot-substitute-current-target"),
                lambda: verify_current(approval, scope, histories[1], histories[cycle],
                                       target.history, original, current, now), "current target")
        refuses(label("missing-account-root"), lambda: verify_current(approval[2 + APPROVAL_BYTES:], *args, now))
        refuses(label("missing-policy-root"), lambda: verify_current(approval[:-APPROVAL_BYTES - 2], *args, now))
        split = 8 + 2 + APPROVAL_BYTES
        swapped = approval[:8] + approval[split:] + approval[8:split]
        refuses(label("swapped-approval-roles"), lambda: verify_current(swapped, *args, now))
        for name, changed in (("truncated", approval[:-1]), ("trailing", approval + b"\0"),
                              ("wrong-container", b"INVALID!" + approval[8:])):
            refuses(label(name), lambda changed=changed: verify_current(changed, *args, now))
        # Each independent signature component is necessary. Corrupt a canonical
        # payload byte for PQ and the signature scalar for classical signatures.
        for name, offset in (("account-pq", 10 + 4 + 426), ("account-classical", split - 1),
                             ("policy-pq", split + 2 + 4 + 426), ("policy-classical", len(approval) - 1)):
            mutated = bytearray(approval)
            mutated[offset] ^= 1
            refuses(label(name), lambda changed=bytes(mutated): verify_current(changed, *args, now))
        for field in ("operation", "journal", "original_owner", "original_credential", "current_credential"):
            different = replace(scope, **{field: bytes([97]) * 32})
            refuses(label("different-" + field), lambda different=different:
                    verify_current(approval, different, *args[1:], now))
        for field in ("current_roster", "original_policy", "previous_policy"):
            def changed_scope(field=field):
                value = getattr(scope, field)[:8] + bytes([96]) * 32
                different = replace(scope, **{field: value})
                return verify_current(approval, different, *args[1:], now)
            refuses(label("different-" + field), changed_scope)
        refuses(label("wrong-predecessor-authorization"), lambda:
                verify_current(approval, replace(scope, previous_authorization=bytes([95]) * 32), *args[1:], now))
        if cycle == 2:
            refuses(label("missing-predecessor-authorization"), lambda: replace(scope, previous_authorization=None))
        for field, value in (("version", 99), ("digest", bytes([94]) * 32), ("budget", 9),
                             ("validity", replace(target.validity, end=target.validity.end + 1))):
            falsified = replace(target.history, **{field: value})
            refuses(label("forged-policy-metadata-" + field), lambda falsified=falsified:
                    statement_body(scope, histories[1], histories[cycle], falsified, original, current), "metadata")
        refuses(label("mismatched-current-policy-snapshot"), lambda: replace(target, budget=target.budget + 1))
        for version, name in ((4, "no-expiry-extension"), (5, "send-budget"),
                              (6, "validity-start"), (7, "prekey-modes")):
            incompatible = histories[version]
            refuses(label("authentic-policy-changes-" + name), lambda incompatible=incompatible:
                    statement_body(scope, histories[1], histories[cycle], incompatible, original, current))
        refuses(label("target-as-original-policy"), lambda:
                verify_current(approval, scope, target.history, histories[cycle], target, original, current, now))
        refuses(label("different-account-root"), lambda:
                verify_current(approval, scope, histories[1], histories[cycle], target,
                               original, replace(current, pin=replace(current.pin, root=root)), now))
        if after_g:
            refuses(label("old-credential-substituted-for-adopted-G"), lambda:
                    verify_current(approval, scope, histories[1], histories[cycle], target, original, original, now))
        previous_statement = approved.statement
        results.append({"cycle": cycle, "now": now, "statement": approved.statement.hex(),
                        "approval_sha256": hashlib.sha256(approval).hexdigest(),
                        "target_version": cycle + 1, "unchanged_original_installation": True})
    return {"prior_real_credential_renewal": after_g, "approvals": results, "refusals": refusals,
            "scope": "Independent two-root proof verification; native scopes derive from real local enrollment/journal adoption. No independent durable policy adoption, witness or traffic claim."}


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments()
    crypto, backend = load_provider(args.provider_root)
    root = Path(__file__).resolve().parent
    sources = [Path(__file__).resolve(), root / "native/examples/policy_renewal_fixture.rs",
               *sorted((root / "qperiapt_continuity_reference").glob("*.py"))]
    def inventory():
        return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    before = inventory()
    output = args.output.resolve()
    output.mkdir()
    native_hash = hashlib.sha256(args.native.read_bytes()).hexdigest()
    with (output / "native.stdout").open("xb") as stdout, (output / "native.stderr").open("xb") as stderr:
        subprocess.run([str(args.native.resolve()), str(output / "public")],
                       stdout=stdout, stderr=stderr, check=True, timeout=90)
    from qperiapt_continuity_reference.wire import require
    require(not (output / "native.stderr").read_bytes(), "native policy fixture diagnostic")
    profiles = [scenario(output / "public" / name, after_g) for name, after_g in
                (("unchanged-credential", False), ("after-credential-renewal", True))]
    require(before == inventory() and native_hash == hashlib.sha256(args.native.read_bytes()).hexdigest(),
            "source or native executable changed during policy proof checks")
    report = {"source_files": before, "native_sha256": native_hash, "profiles": profiles,
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"profiles": len(profiles), "approvals": sum(len(p["approvals"]) for p in profiles),
                      "refusals": [len(p["refusals"]) for p in profiles]}))


if __name__ == "__main__":
    main()
