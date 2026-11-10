"""Exercise the extracted service executables with fresh, private local state.

Each call starts a new process. The public receipt records installation checks;
the state and signing keys stay outside the distributable archive and evidence.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes


def identifier(value: int) -> str:
    return base64.urlsafe_b64encode(bytes([value]) * 32).rstrip(b"=").decode()


def private_file(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def exercise(installed: Path, state: Path, run) -> dict:
    """Use only the installed paths; ``run`` preserves both successful/refused calls."""
    state.mkdir(mode=0o700)
    sdk_cli = installed / "bin/q-periapt-sdk-policy-authority"
    publisher = installed / "bin/q-periapt-policy-publisher"
    witness = installed / "bin/q-periapt-continuity-witness"
    directory = installed / "bin/q-periapt-prekey-directory"
    device = installed / "bin/q-periapt-native-device"

    def call(binary, arguments, label, *, refused=False, error_contains=None):
        output = run([str(binary), *map(str, arguments)], label, cwd=state,
                     expected_exit=1 if refused else 0, expected_stderr=error_contains)
        return None if refused else parse_strict_json_bytes(output, label=label)

    sdk_db, sdk_id = state / "sdk.redb", identifier(1)
    original = call(sdk_cli, ["init", sdk_db, sdk_id], "sdk-init")
    sdk.require(original == call(sdk_cli, ["prepare", sdk_db, sdk_id], "sdk-reopen"),
                "installed SDK authority changed on reopen")
    call(sdk_cli, ["authority", sdk_db, identifier(2)], "sdk-wrong-identity", refused=True,
         error_contains="SDK authority identity, schema or version inventory differs")
    sdk.require(original == call(sdk_cli, ["authority", sdk_db, sdk_id], "sdk-after-refusal"),
                "installed SDK authority changed after refused identity")

    policy = state / "policy.toml"
    private_file(policy, b'schema_version=1\npolicy_version=1\nmin_nist_level=3\n'
                 b'default_profile="ContextBound"\nallowed_kems=["ML-KEM-768","X25519"]\n'
                 b'allowed_sigs=["ML-DSA-65"]\ndeprecated=[]\n')
    first, repeated = state / "sdk-export", state / "sdk-readback"
    first.mkdir(mode=0o700); repeated.mkdir(mode=0o700)
    operation = identifier(3)
    issued = call(sdk_cli, ["issue", sdk_db, sdk_id, operation, policy, first], "sdk-issue")
    sdk.require(issued == call(sdk_cli, ["result", sdk_db, sdk_id, operation, repeated], "sdk-result"),
                "installed SDK publication changed on readback")
    exports = ("sdk-root", "sdk-state", "sdk-document", "sdk-signature")
    sdk.require({path.name for path in first.iterdir()} == set(exports)
                and {path.name for path in repeated.iterdir()} == set(exports),
                "installed SDK export inventory differs")
    public_exports = {}
    for name in exports:
        value = sdk.snapshot(first / name)
        sdk.require(value.data == sdk.snapshot(repeated / name).data,
                    "installed SDK export bytes changed on readback")
        public_exports[name] = {"bytes": value.size, "sha256": value.sha256}

    publisher_db, publisher_id = state / "publisher.redb", identifier(4)
    authority = call(publisher, ["init", publisher_db, publisher_id, *[first / name for name in exports]],
                     "publisher-init")
    sdk.require(authority == call(publisher, ["prepare", publisher_db, publisher_id], "publisher-reopen"),
                "installed publisher changed on reopen")
    call(publisher, ["authority", publisher_db, identifier(5)], "publisher-wrong-identity", refused=True,
         error_contains="Publisher identity, schema or version inventory differs")
    sdk.require(authority == call(publisher, ["authority", publisher_db, publisher_id], "publisher-after-refusal"),
                "installed publisher changed after refused identity")

    witness_db, witness_id = state / "witness.redb", identifier(6)
    pin = call(witness, ["init", witness_db, witness_id], "witness-init")
    sdk.require(pin == call(witness, ["prepare", witness_db, witness_id], "witness-reopen"),
                "installed witness changed on reopen")
    call(witness, ["pin", witness_db, identifier(7)], "witness-wrong-identity", refused=True,
         error_contains="Witness host identity or schema differs")
    sdk.require(pin == call(witness, ["pin", witness_db, witness_id], "witness-after-refusal"),
                "installed witness changed after refused identity")

    wrapping, signer = state / "directory.wrap", state / "directory.signer"
    run([str(device), "provision-key", str(wrapping)], "directory-wrapping", cwd=state)
    directory_id, signing_id = identifier(8), identifier(9)
    key_args = [directory_id, signing_id, wrapping, signer]
    directory_pin = call(directory, ["prepare-key", *key_args], "directory-key")
    sdk.require(directory_pin == call(directory, ["show-key", *key_args], "directory-key-reopen"),
                "installed directory signer changed on reopen")
    pin_file, directory_db = state / "directory-pin.json", state / "directory.redb"
    private_file(pin_file, (json.dumps(directory_pin) + "\n").encode())
    initialized = call(directory, ["init", pin_file, directory_db, "1"], "directory-init")
    sdk.require(initialized.get("initialized") is True, "installed directory was not initialized")
    original_ledger = sdk.snapshot(directory_db).sha256
    call(directory, ["init", pin_file, directory_db, "1"], "directory-existing-refusal", refused=True)
    sdk.require(sdk.snapshot(directory_db).sha256 == original_ledger, "refused directory init changed the original ledger")
    missing = state / "missing-receipt"
    call(directory, ["lookup", pin_file, directory_db, identifier(10), missing],
         "directory-original-empty-lookup", refused=True, error_contains="Unknown original operation")
    sdk.require(not missing.exists(), "empty directory lookup produced a receipt")
    sdk.require(directory_pin == call(directory, ["show-key", *key_args], "directory-after-refusal"),
                "installed directory identity changed after refused reinitialization")
    return {"sdk_authority_reopened": True, "sdk_original_publication_readback": public_exports,
            "protocol_publisher_reopened": True, "witness_reopened": True,
            "directory_signer_reopened": True, "directory_existing_ledger_refused": True,
            "directory_original_empty_lookup_refused": True, "wrong_identity_refusals": 3,
            "private_state_in_archive": False}
