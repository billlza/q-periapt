#!/usr/bin/env python3
"""Native-signed complete account transitions in the independent authority model."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def scenario(args, output, count):
    from cryptography.exceptions import InvalidSignature
    from qperiapt_continuity_reference.account_state import AccountState
    from qperiapt_continuity_reference.account_request import AccountRequest
    from qperiapt_continuity_reference.identity import DevicePin, verify_device
    from qperiapt_continuity_reference.renewal import verify, verify_account, verify_established_peer
    from qperiapt_continuity_reference.wire import VerificationKey, require
    output.mkdir()
    public = output / "public"
    with (output / "native.stdout").open("xb") as stdout, (output / "native.stderr").open("xb") as stderr:
        subprocess.run([str(args.native.resolve()), str(public), str(count)],
                       stdout=stdout, stderr=stderr, check=True, timeout=60)
    require(not (output / "native.stderr").read_bytes(), "native fixture diagnostic")
    read = lambda name: (public / name).read_bytes()
    key = VerificationKey(read("root"))
    first = read("checkpoint-1")
    pin = DevicePin(key, read("account"), 1, first[8:], bytes([1]) * 16, 1)
    family, policy = read("family"), read("policy")
    original = AccountState.initial(pin, family, policy, read("roster-1"), first)
    images = {"initial": original.encode()}
    grants1 = tuple(read(f"grant-1-{i}") for i in range(1, count + 1))
    grants2 = tuple(read(f"grant-2-{i}") for i in range(1, count + 1))
    refusals = []

    def refuses(name, action, reason=None):
        try:
            action()
        except (ValueError, InvalidSignature) as error:
            require(reason is None or reason in str(error), f"unexpected refusal {name}: {error}")
            refusals.append({"case": name, "type": type(error).__name__, "error": str(error)})
        else:
            raise ValueError("missing refusal: " + name)

    def advance(state, version, grants=(), now=310):
        return state.advance(read(f"roster-{version}"), read(f"checkpoint-{version}"), grants, now=now)

    for name, grants in [
        ("missing-local", grants1[1:]), ("missing-companion", grants1[:-1]),
        ("duplicate", (grants1[0],) + grants1), ("mixed-target", grants1[:-1] + (grants2[-1],)),
    ]:
        refuses(name, lambda grants=grants: advance(original, 2, grants, 210))
        require(original.encode() == images["initial"], "failed transition changed predecessor")
    current = advance(original, 2, grants1, 210)
    images["first"] = current.encode()
    require(advance(original, 2, tuple(reversed(grants1)), 210).encode() == images["first"],
            "input order changed canonical account record")
    require(AccountState.read(images["first"], pin, family, policy).encode() == images["first"],
            "first account state roundtrip")
    roles = []
    for identity in (1, 2):
        device_pin = DevicePin(key, pin.account, 1, first[8:], bytes([identity]) * 16, 1)
        device = verify_device(device_pin, read(f"credential-1-{identity}"), read("roster-1"), family, 150)
        view = current.view(device, local=identity == 1)
        view.check(210)
        require(view.listing is current.listing, "role owns an independent roster copy")
        require(view.renewal.statement == read(f"grant-1-{identity}-statement"),
                "independent statement differs from native")
        roles.append(device)
    resigned = verify_account(read("grant-1-1-resigned"), pin, family, policy, read("checkpoint-2"), now=210)
    require(resigned.statement == current.renewals[0].statement
            and resigned.operation == current.renewals[0].operation,
            "semantic re-signing changes grant identity")
    request = AccountRequest.parse(grants1[0], grants1[1:], roles[0], family, policy, read("checkpoint-2"))
    request_bytes = request.encode()
    require(request.apply(original, 210).encode() == images["first"], "complete account request target")
    require(request.expires_at() == 275 and request.local.successor.validity.end == 300,
            "earliest companion expiry was lost")
    refuses("expired-companion-with-live-local-credential", lambda: request.apply(original, 280),
            "expired or premature")
    retry = AccountRequest.parse(read("grant-1-1-resigned"), tuple(reversed(grants1[1:])),
                                 roles[0], family, policy, read("checkpoint-2"))
    require(request.same_request(retry) and request.encode() == request_bytes,
            "semantic retry changed original account request")
    require(AccountRequest.read(request_bytes, roles[0], family, policy).encode() == request_bytes,
            "account request canonical roundtrip")
    changed = AccountRequest.parse(
        grants1[0], (grants1[1], read("grant-1-3-other-operation"), *grants1[3:]),
        roles[0], family, policy, read("checkpoint-2"))
    require(not request.same_request(changed), "different companion decision kept request identity")
    missing = AccountRequest.parse(grants1[0], grants1[1:-1], roles[0], family, policy, read("checkpoint-2"))
    refuses("incomplete-request-cannot-produce-target", lambda: missing.apply(original, 210))
    refuses("another-device-request-cannot-restore-local-owner",
            lambda: AccountRequest.read(request_bytes, roles[1], family, policy), "original identity")
    refuses("request-trailing-bytes",
            lambda: AccountRequest.read(request_bytes + b"\0", roles[0], family, policy))
    rebound = (grants2[0], read("grant-2-2-rebound-origin")) + grants2[2:]
    refuses("changed-original-lineage", lambda: advance(current, 3, rebound), "original lineage")
    second = advance(current, 3, grants2)
    images["second"] = second.encode()
    for identity, device in enumerate(roles, 1):
        second.view(device, local=identity == 1).check(310)
    intermediate_pin = DevicePin(key, pin.account, 2, read("checkpoint-2")[8:], bytes([2]) * 16, 1)
    intermediate = verify_device(intermediate_pin, read("credential-2-2"), read("roster-2"), family, 250)
    second.view(intermediate).check(310)
    refuses("intermediate-is-not-original-local-owner", lambda: second.view(intermediate, local=True), "local owner")
    refuses("strict-verifier-keeps-original-local-owner",
            lambda: verify(grants2[1], intermediate, family, policy, read("checkpoint-3"), now=310),
            "key/original")
    verify_established_peer(grants2[1], intermediate, family, policy, read("checkpoint-3"), now=310)
    revoked = advance(second, 4)
    images["revoked"] = revoked.encode()
    # Reopening after revocation must preserve the old generation even when its
    # identity is not one of the two active session roles.
    reopened = AccountState.read(images["revoked"], pin, family, policy)
    refuses("root-signed-old-generation-resurrection", lambda: advance(reopened, 5),
            "generation, revocation or credential")
    replaced = advance(reopened, 6)
    images["new-generation"] = replaced.encode()
    require(replaced.history[-1][1] == 2 and len(replaced.history) == count,
            "new generation did not retain common history")
    refuses("root-signed-generation-rollback", lambda: advance(replaced, 7),
            "generation, revocation or credential")
    refuses("stale-original-target", lambda: advance(second, 2, grants1), "rollback or fork")
    refuses("another-policy", lambda: AccountState.read(images["second"], pin, family, bytes([99]) * 32))
    for name, payload in images.items():
        require(AccountState.read(payload, pin, family, policy).encode() == payload, "canonical " + name)
        (output / f"{name}.account").write_bytes(payload)
    corrupt = bytearray(images["second"])
    history_at = 10 + int.from_bytes(corrupt[8:10], "big")
    corrupt[history_at:history_at + 2] = (257).to_bytes(2, "big")
    refuses("history-capacity", lambda: AccountState.read(bytes(corrupt), pin, family, policy), "history capacity")
    refuses("trailing-bytes", lambda: AccountState.read(images["second"] + b"\0", pin, family, policy))
    if count == 32:
        saturated = second
        for version in range(10, 17):
            saturated = advance(saturated, version)
            saturated = AccountState.read(saturated.encode(), pin, family, policy)
        require(len(saturated.history) == 256, "history fixture did not reach the actual bound")
        retained = saturated.encode()
        refuses("root-signed-history-overflow", lambda: advance(saturated, 17), "history capacity")
        require(saturated.encode() == retained, "capacity refusal changed the existing account")
    require(original.encode() == images["initial"], "pure transition mutated original state")
    return {"members": count, "refusals": refusals,
            "request_bytes": len(request_bytes), "request_binding": request.binding().hex(),
            "record_bytes": {name: len(payload) for name, payload in images.items()},
            "records": {name: hashlib.sha256(payload).hexdigest() for name, payload in images.items()},
            "scope": "Independent pure account state and real native root signatures, explicit fixture times150/210/310. No journal, registered owner, witness, traffic or installed-package qualification."}


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments()
    crypto, backend = load_provider(args.provider_root)
    root = Path(__file__).resolve().parent
    sources = [root / "account_state_checks.py", root / "native/examples/account_authority_fixture.rs",
               *sorted((root / "qperiapt_continuity_reference").glob("*.py"))]
    def inventory():
        return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    before = inventory()
    output = args.output.resolve()
    output.mkdir()
    results = [scenario(args, output / str(count), count) for count in (3, 32)]
    from qperiapt_continuity_reference.wire import require
    require(before == inventory(), "source changed during account-state checks")
    report = {"source_files": before, "native_sha256": hashlib.sha256(args.native.read_bytes()).hexdigest(),
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()},
              "profiles": results}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({str(result["members"]): result["record_bytes"] for result in results}))


if __name__ == "__main__":
    main()
