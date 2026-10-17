"""Public readback of fresh enrollment and original-session loss accounting.

Native public APIs verify signatures and private storage. This reader checks
public framing and cross-file bindings, not a second protocol implementation.
"""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes
from continuity_enrollment import REGISTRATION_FILES, _readers, _registration
from continuity_c_recovery import ciphertext_digest

ROLES = ("old", "new")
FILES = frozenset({"result.json", "old-effect", "new-effect", "old-journal", "new-journal",
                   "request", "reopened-request", "old-signing-id", "new-signing-id",
                   "loss-report", "loss-id", "loss-complete", "loss-verified",
                   "old-ciphertext", "loss-ciphertext-digest"})
FLAGS = frozenset({"request_reopened", "old_generation_refused", "same_account_root",
                  "independent_new_owner", "old_effect_unchanged"})
COUNTS = {"old_generation": 1, "new_generation": 2, "old_acknowledged": 0,
          "old_unconfirmed": 1, "receiver_exit": 77, "cleanup_exit": 77}
IDENTITIES = ("old_session", "new_session", "old_message", "new_message")
SCOPE = ("native Rust same-host public enrollment of a new device generation, original "
         "unknown delivery and durable loss accounting across process exit, trusted peer "
         "roster admission and a fresh TLS session; local-only witness profile; "
         "signatures and private state checked by native APIs, public structural readback; "
         "no account-root replacement, global revocation or secret-migration claim")


def verify(directory: Path) -> dict:
    sdk.require(directory.is_dir() and not directory.is_symlink() and
                {p.name for p in directory.iterdir()} == FILES | set(ROLES),
                "device replacement public inventory differs")
    for role in ROLES:
        folder = directory / role
        sdk.require(folder.is_dir() and not folder.is_symlink() and
                    {p.name for p in folder.iterdir()} == REGISTRATION_FILES and
                    all(p.is_file() and not p.is_symlink() for p in folder.iterdir()),
                    "replacement enrollment inventory differs")
    sdk.require(all((directory / name).is_file() and not (directory / name).is_symlink() for name in FILES),
                "replacement readback is not a regular file")
    public, read_role, fixed = _readers(directory)
    roles = {role: _registration(role, read_role, fixed)[0] for role in ROLES}
    old, new = roles["old"], roles["new"]
    for key in ("account", "device", "family"):
        sdk.require(old[key] == new[key], "replacement changed original " + key)
    sdk.require(old["generation"] == 1 and new["generation"] == 2 and
                old["roster_version"] == 1 and new["roster_version"] == 2,
                "replacement did not advance the exact original generation and roster")
    for key in ("signer_id", "public_key_sha256", "credential", "journal"):
        sdk.require(old[key] != new[key], "replacement reused original " + key)
    old_key, new_key = (read_role(role, "public-key") for role in ROLES)
    sdk.require(old_key[:1952] != new_key[:1952] and old_key[1952:] != new_key[1952:],
                "replacement reused a device signing component")
    sdk.require(read_role("old", "local-root") == read_role("new", "local-root"),
                "replacement changed the independent account root")

    def read(name, maximum=65536):
        item = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = dict(sha256=item.sha256, bytes=item.size)
        return item.data

    report = parse_strict_json_bytes(read("result.json"), label="device replacement result")
    sdk.require(isinstance(report, dict) and set(report) == set(IDENTITIES) | FLAGS | set(COUNTS),
                "replacement result shape differs")
    for name in IDENTITIES:
        sdk.require(isinstance(report[name], str) and re.fullmatch(r"[0-9a-f]{64}", report[name])
                    and any(bytes.fromhex(report[name])), "replacement correlation identity differs")
    sdk.require(report["old_session"] != report["new_session"] and
                report["old_message"] != report["new_message"], "replacement reused old traffic identity")
    sdk.require(all(report[name] is True for name in FLAGS), "replacement path did not complete")
    sdk.require(all(type(report[name]) is int and report[name] == value for name, value in COUNTS.items()),
                "replacement outcome, generation or process cut differs")
    for role, payload in (("old", b"old device effect with unavailable receipt"),
                          ("new", b"fresh replacement session")):
        sdk.require(read(role + "-effect") == bytes.fromhex(report[role + "_session"] + report[role + "_message"]) + payload,
                    "replacement application effect binding differs")
        sdk.require(read(role + "-journal", 32) == bytes.fromhex(roles[role]["journal"])
                    and read(role + "-signing-id", 32) == bytes.fromhex(roles[role]["signer_id"]),
                    "replacement owner alias differs")
    sdk.require(read("request") == read("reopened-request") == read_role("new", "request"),
                "replacement original enrollment request was not retained")
    loss = read("loss-id", 32)
    sdk.require(len(loss) == 32 and any(loss) and loss == read("loss-complete", 32) == read("loss-verified", 32),
                "replacement lost the original durable accounting identity")
    accounting = read("loss-report")
    sdk.require(accounting.startswith(b"SessionClosure { session: " + str(list(bytes.fromhex(report["old_session"]))).encode())
                and b"report: SessionClosureId(" + str(list(loss)).encode() + b")" in accounting
                and accounting.endswith(b" }\n"), "replacement retained another host loss report")
    sdk.require(read("loss-ciphertext-digest", 32).hex() == ciphertext_digest(read("old-ciphertext")),
                "replacement lost the original unconfirmed ciphertext identity")
    sdk.require(len(public) == len(FILES) + 2 * len(REGISTRATION_FILES),
                "replacement evidence left files unchecked")
    return dict(completed=True, scope=SCOPE, roles=roles, outcomes=report, loss_id=loss.hex(),
                public_readbacks=public, required_witness_qualified=False, cross_language_qualified=False,
                physical_platform_qualified=False, release_claim_eligible=False)


def export(directory: Path, destination: Path) -> dict:
    checked = verify(directory)
    destination.mkdir(mode=0o700, parents=True)
    for name, row in checked["public_readbacks"].items():
        item = sdk.snapshot(directory / name, maximum=65536)
        sdk.require(item.sha256 == row["sha256"], "replacement source changed before export")
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(item.data)
    sdk.require(verify(destination) == checked, "replacement exported readback differs")
    return checked
