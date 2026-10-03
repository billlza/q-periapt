"""Read back public enrollment, activation, restart and connection evidence.

Native public APIs verify the enrollment proof and issuer signatures. This reader
checks their framing, commitments and cross-file bindings; it is not another
signature verifier or a source of account authorization or roster freshness.
"""
from pathlib import Path

import rust_sdk_profile as sdk
from continuity_c_witness import commit
from continuity_roster_renewal import envelope

SCOPE = ("archive-shipped native Rust public enrollment, original installation and "
         "connection restart on one host; separate enrollment-lease contenders; "
         "structural public readback with signatures verified by native APIs; "
         "independent trust inputs and an existing wrapping key are required; "
         "no independent protocol implementation or foreign-binding enrollment claim")
ROLES = ("initiator", "responder")
FILES = frozenset({
    "request", "reopened-request", "signer-id", "public-key", "local-account",
    "local-root", "local-device", "local-generation", "enrollment-validity",
    "family", "local-certificate", "local-roster", "local-roster-version",
    "local-roster-digest", "accepted-journal", "active-journal", "reopened-journal",
    "session", "forward-message", "reverse-message", "forward-effect",
    "reverse-effect", "lease-observation",
})
PUBLIC_KEY_BYTES = 1985
MAX_DEVICES = 32
MAX_U64 = 2**64 - 1
FORWARD_PAYLOAD = b"persisted before process exit"
REVERSE_PAYLOAD = b"reverse after original installation restart"


def _inventory(directory: Path) -> None:
    sdk.require(directory.is_dir() and not directory.is_symlink(),
                "enrollment evidence root must be a plain directory")
    sdk.require({path.name for path in directory.iterdir()} == set(ROLES),
                "enrollment evidence role inventory differs")
    for role in ROLES:
        folder = directory / role
        sdk.require(folder.is_dir() and not folder.is_symlink(),
                    "enrollment evidence role must be a plain directory")
        entries = list(folder.iterdir())
        sdk.require({path.name for path in entries} == FILES,
                    "enrollment public file inventory differs")
        sdk.require(all(path.is_file() and not path.is_symlink() for path in entries),
                    "enrollment evidence must contain only plain public files")


def _validity(data: bytes) -> tuple[int, int]:
    sdk.require(len(data) == 16, "enrollment validity width differs")
    start, end = int.from_bytes(data[:8], "big"), int.from_bytes(data[8:], "big")
    sdk.require(start < end < MAX_U64, "enrollment validity interval differs")
    return start, end


def verify(directory: Path) -> dict:
    """Require the complete fixed public closure and bind both connection ends."""
    _inventory(directory)
    public, roles = {}, {}

    def read(role: str, name: str, maximum: int = 8192) -> bytes:
        relative = f"{role}/{name}"
        item = sdk.snapshot(directory / relative, maximum=maximum)
        public[relative] = dict(sha256=item.sha256, bytes=item.size)
        return item.data

    def fixed(role: str, name: str, width: int, *, nonzero: bool = False) -> bytes:
        value = read(role, name, width)
        sdk.require(len(value) == width and (not nonzero or any(value)),
                    f"enrollment {name} width or identity differs")
        return value

    for role in ROLES:
        identity = fixed(role, "signer-id", 32, nonzero=True)
        key = fixed(role, "public-key", PUBLIC_KEY_BYTES)
        root = fixed(role, "local-root", PUBLIC_KEY_BYTES)
        sdk.require(key[1952] in (2, 3) and root[1952] in (2, 3)
                    and key[:1952] != root[:1952] and key[1952:] != root[1952:],
                    "enrollment public key shape or role separation differs")
        account = fixed(role, "local-account", 32, nonzero=True)
        sdk.require(account == commit(b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1", root),
                    "enrollment account root commitment differs")
        device = fixed(role, "local-device", 16, nonzero=True)
        generation_bytes = fixed(role, "local-generation", 8)
        generation = int.from_bytes(generation_bytes, "big")
        sdk.require(0 < generation < MAX_U64, "enrollment device generation differs")
        validity = fixed(role, "enrollment-validity", 16)
        start, end = _validity(validity)
        family = fixed(role, "family", 32, nonzero=True)
        metadata = account + device + generation_bytes + validity + family

        # enrollment.rs: REQUEST_BODY = tag + SigningKeyId + intent metadata + key.
        wire = read(role, "request")
        request = envelope(wire, b"QPENRQ01", 144 + PUBLIC_KEY_BYTES)
        sdk.require(request == b"QPENRQ01" + identity + metadata + key,
                    "enrollment request identity, approved metadata or public key differs")
        sdk.require(wire == read(role, "reopened-request"),
                    "enrollment restart changed the original signed request")
        # identity.rs: Credential::encode uses the same metadata without SigningKeyId.
        certificate = envelope(read(role, "local-certificate"), b"QPCERT01", 112 + PUBLIC_KEY_BYTES)
        sdk.require(certificate == b"QPCERT01" + metadata + key,
                    "enrollment credential differs from the original request")
        credential = commit(b"Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1", certificate)

        version_bytes = fixed(role, "local-roster-version", 8)
        version = int.from_bytes(version_bytes, "big")
        sdk.require(0 < version < MAX_U64, "enrollment roster version differs")
        roster_digest = fixed(role, "local-roster-digest", 32, nonzero=True)
        roster_wire = read(role, "local-roster")
        size = int.from_bytes(roster_wire[:4], "big")
        sdk.require(66 <= size <= 66 + 56 * MAX_DEVICES, "enrollment roster size differs")
        roster = envelope(roster_wire, b"QPROST01", size)
        count = int.from_bytes(roster[64:66], "big")
        sdk.require(0 < count <= MAX_DEVICES and size == 66 + 56 * count
                    and roster[8:40] == account and roster[40:48] == version_bytes
                    and roster_digest == commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", roster),
                    "enrollment roster account, checkpoint or framing differs")
        roster_start, roster_end = _validity(roster[48:64])
        sdk.require(max(start, roster_start) < min(end, roster_end),
                    "enrollment roster and credential have no shared validity")
        previous, found = None, False
        for offset in range(66, size, 56):
            member = roster[offset:offset + 56]
            member_id, member_generation, member_credential = member[:16], member[16:24], member[24:]
            sdk.require(any(member_id) and (previous is None or previous < member_id)
                        and 0 < int.from_bytes(member_generation, "big") < MAX_U64
                        and any(member_credential), "enrollment roster member grammar differs")
            previous = member_id
            if member_id == device:
                sdk.require(member_generation == generation_bytes and member_credential == credential,
                            "enrollment roster contains another device credential")
                found = True
        sdk.require(found, "enrollment roster omitted the original device")

        journal = fixed(role, "accepted-journal", 32, nonzero=True)
        sdk.require(journal == fixed(role, "active-journal", 32)
                    == fixed(role, "reopened-journal", 32),
                    "enrollment activation or restart replaced the original journal")
        session = fixed(role, "session", 32, nonzero=True)
        forward = fixed(role, "forward-message", 32, nonzero=True)
        reverse = fixed(role, "reverse-message", 32, nonzero=True)
        sdk.require(read(role, "forward-effect") == session + forward + FORWARD_PAYLOAD
                    and read(role, "reverse-effect") == session + reverse + REVERSE_PAYLOAD,
                    "enrollment connection application readback differs")
        lease = fixed(role, "lease-observation", 16)
        child, parent = int.from_bytes(lease[:8], "big"), int.from_bytes(lease[8:], "big")
        sdk.require(child > 0 and parent > 0 and child != parent,
                    "enrollment lease observation lacks a separate contender")
        roles[role] = dict(signer_id=identity.hex(), public_key_sha256=public[f"{role}/public-key"]["sha256"],
                           account=account.hex(), device=device.hex(), generation=generation,
                           validity=dict(from_time=start, until_time=end), family=family.hex(),
                           credential=credential.hex(), roster_version=version,
                           roster_digest=roster_digest.hex(), journal=journal.hex(),
                           session=session.hex(), forward_message=forward.hex(), reverse_message=reverse.hex(),
                           lease_child_pid=child, lease_parent_pid=parent)

    for name in ("session", "forward_message", "reverse_message"):
        sdk.require(roles["initiator"][name] == roles["responder"][name],
                    "enrollment peers disagree on connection identities")
    _inventory(directory)
    sdk.require(set(public) == {f"{role}/{name}" for role in ROLES for name in FILES},
                "enrollment public readback incomplete")
    return dict(scope=SCOPE, roles=roles, public_readbacks=public)


def export(directory: Path, destination: Path) -> dict:
    """Copy only the verified fixed public inventory and re-read the exported bytes."""
    result = verify(directory)
    destination.mkdir(mode=0o700)
    for role in ROLES:
        (destination / role).mkdir(mode=0o700)
    for name in sorted(result["public_readbacks"]):
        sdk.copy(directory / name, destination / name, maximum=8192)
    sdk.require(verify(destination) == result, "exported enrollment evidence changed")
    return result
