#!/usr/bin/env python3
"""Independent bootstrap terminal-confirmation controls on public synthetic inputs.

The native KEM and signature algorithms are outside this small experiment.
Signature fields are opaque wire bytes; the retained native alias execution
establishes the separately stated same-body valid-signature premise. This code
checks exact SHA3/HKDF/HMAC equations, parser scopes and theorem boundary cases.
It also checks every reviewed source against its recorded Git blob and SHA-256.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

BOOTSTRAP = b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/"
KDF = b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-KDF-CANDIDATE/v1/"
MESSAGES = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/"


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def sha3(label: bytes, data: bytes) -> bytes:
    domain = BOOTSTRAP + label
    return hashlib.sha3_256(
        len(domain).to_bytes(8, "big") + domain
        + len(data).to_bytes(8, "big") + data
    ).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    if not 0 < length <= 255 * 32:
        raise ValueError("invalid HKDF output length")
    prk = mac(salt, ikm)
    previous = b""
    output = bytearray()
    for block in range(1, (length + 31) // 32 + 1):
        previous = mac(prk, previous + info + bytes([block]))
        output.extend(previous)
    return bytes(output[:length])


def derive(ikm: bytes, salt: bytes, label: bytes) -> bytes:
    return hkdf(salt, ikm, KDF + label, 32)


def envelope(body: bytes, signature: bytes) -> bytes:
    return len(body).to_bytes(4, "big") + body + signature


def final_prefix(context: bytes, initial: bytes, reply: bytes) -> bytes:
    return b"QPBSF001" + context + sha3(b"initial-wire", initial) + sha3(b"reply-wire", reply)


def initial_material(root: bytes, session: bytes, context: bytes) -> bytes:
    return hkdf(session, root, MESSAGES + b"initial/HKDF-SHA256/ChaCha20Poly1305" + context, 160)


@dataclass(frozen=True)
class Transcript:
    context: bytes
    initial: bytes
    reply: bytes
    seed: bytes
    ki: bytes
    kr: bytes
    core: bytes

    @property
    def prefix(self) -> bytes:
        return final_prefix(self.context, self.initial, self.reply)

    @property
    def session(self) -> bytes:
        return sha3(b"session-id", self.prefix)

    @property
    def root(self) -> bytes:
        return derive(self.seed, self.session, b"session-root/" + self.context)

    @property
    def material(self) -> bytes:
        return initial_material(self.root, self.session, self.context)

    @property
    def ack_a(self) -> bytes:
        return self.material[96:128]

    @property
    def ack_b(self) -> bytes:
        return self.material[128:160]

    @property
    def final(self) -> bytes:
        return self.prefix + mac(self.ki, sha3(b"final-core", self.prefix))


def fixture(alias: int = 0) -> Transcript:
    context = bytes([4]) * 32
    # Public fixture fields have the native lengths. They are not live signatures,
    # KEM ciphertexts, or a proof that an arbitrary changed signature is valid.
    initial_body = b"QPBSI001" + context + bytes([5]) * 32 + bytes([6]) * 1216
    initial_body += bytes([7]) * 1120 + bytes([8]) * 32
    initial = envelope(initial_body, bytes([9]) * 3373)
    core = b"QPBSR001" + context + sha3(b"initial-wire", initial) + bytes([10]) * 32
    core += bytes([11]) * 1120
    t1 = sha3(b"reply-core", core)
    ikm = bytes([1]) * 32 + bytes([2]) * 32
    seed = derive(ikm, t1, b"handshake-seed")
    kr = derive(ikm, t1, b"confirmation-responder")
    ki = derive(ikm, t1, b"confirmation-initiator")
    body = core + mac(kr, t1)
    # ML-DSA prefix is held fixed; only the opaque 64-byte classical field varies.
    signature = bytes([12]) * 3309 + bytes([13 + alias]) * 64
    reply = envelope(body, signature)
    check((len(initial), len(reply)) == (5817, 4633), "native envelope sizes")
    return Transcript(context, initial, reply, seed, ki, kr, t1)


def accept_final(retained: Transcript, final: bytes, *, compare_prefix: bool = True) -> bool:
    if len(final) != 136:
        return False
    if compare_prefix and final[:104] != retained.prefix:
        return False
    # compare_prefix=False is an explicit hypothetical mutation used below.
    return hmac.compare_digest(final[104:], mac(retained.ki, sha3(b"final-core", final[:104])))


def acknowledgement(session: bytes, direction: int, epoch: int, floor: int, key: bytes) -> bytes:
    if direction not in (1, 2) or not 0 <= epoch < 2**64 - 1 or not 0 <= floor < 2**64:
        raise ValueError("ACK fixture scope")
    prefix = (b"QPCMACK1" if epoch == 0 else b"QPCMACK2") + session + bytes([direction])
    if epoch:
        prefix += epoch.to_bytes(8, "big")
    prefix += floor.to_bytes(8, "big")
    return prefix + mac(key, MESSAGES + b"acknowledgement" + prefix)


def accepts_ready(expected: Transcript, remote_id: bytes, proof: bytes, *, sent: int = 0) -> bool:
    # The connection accepts only the epoch-zero encoding, then the common
    # Traffic verifier checks session, directional sender, MAC and sent ceiling.
    if remote_id != expected.session or len(proof) != 81 or proof[:8] != b"QPCMACK1":
        return False
    if proof[8:40] != expected.session or proof[40] != 1:
        return False
    if not hmac.compare_digest(proof[49:], mac(expected.ack_a, MESSAGES + b"acknowledgement" + proof[:49])):
        return False
    return int.from_bytes(proof[41:49], "big") <= sent


class ProtectedFamily:
    """Finite event model for the theorem's declared online/stopped interface.

    The dependency labels below are public model names, not native key material.
    The same seed reaches two different full-wire classes; one derived root has
    no inverse edge back to that seed. A record needs its independent guard.
    """

    recipes = (
        (frozenset(("s0", "s1")), "seed"),
        (frozenset(("seed",)), "root0"),
        (frozenset(("seed",)), "root1"),
        (frozenset(("root0",)), "ack0"),
        (frozenset(("root1",)), "ack1"),
        (frozenset(("record0", "wrap0")), "root0"),
    )

    def __init__(self, limit: int = 2) -> None:
        self.limit = limit
        self.protected: set[int] = set()
        self.used: set[int] = set()
        self.disclosed: set[str] = set()
        self.stopped = False

    @classmethod
    def closure(cls, assets: set[str]) -> set[str]:
        reached = set(assets)
        while True:
            previous = len(reached)
            for parents, child in cls.recipes:
                if parents <= reached:
                    reached.add(child)
            if len(reached) == previous:
                return reached

    def register(self, transcript: int) -> bool:
        if self.stopped or transcript not in (0, 1):
            return False
        if transcript in self.protected:
            return True
        if transcript in self.used or len(self.protected) >= self.limit:
            return False
        if f"ack{transcript}" in self.closure(self.disclosed):
            return False
        self.protected.add(transcript)
        return True

    def use(self, transcript: int) -> bool:
        # A use event includes private computation at either endpoint.
        if self.stopped:
            return False
        self.used.add(transcript)
        return True

    def reveal(self, asset: str) -> bool:
        if self.stopped:
            return False
        proposed = self.disclosed | {asset}
        closure = self.closure(proposed)
        if any(f"ack{transcript}" in closure for transcript in self.protected):
            self.stopped = True
            return False
        self.disclosed = proposed
        return True


def verify_sources(source_root: Path, manifest_path: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for row in manifest["files"]:
        path = Path(row["path"])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("noncanonical source path")
        data = (source_root / path).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        check(blob == row["git_blob_sha"], f"Git blob mismatch: {path}")
        check(hashlib.sha256(data).hexdigest() == row["sha256"], f"SHA-256 mismatch: {path}")
        check(len(data) == row["bytes"], f"source length mismatch: {path}")
    return {"commit": manifest["commit"], "tree": manifest["tree"], "checked_files": len(manifest["files"])}


def run_controls() -> dict:
    controls = []
    def record(name: str, condition: bool, scope: str) -> None:
        check(condition, name)
        controls.append({"name": name, "status": "passed", "scope": scope})

    # Recompute the exact public vectors already asserted by native Rust tests.
    ikm = bytes([1]) * 32 + bytes([2]) * 32
    salt = bytes([3]) * 32
    seed = derive(ikm, salt, b"handshake-seed")
    vectors = {
        "bootstrap_seed": (seed.hex(), "e2c777bf03f765fe3b3ac4a6391e577e4dde8f0882a68830eed7b9dc26cd54f7"),
        "bootstrap_responder_key": (derive(ikm, salt, b"confirmation-responder").hex(), "cafff40b1d46ccfdd6ca696cbebc5567a1f008c17ccb5d7ca1589f104e4c406c"),
        "bootstrap_initiator_key": (derive(ikm, salt, b"confirmation-initiator").hex(), "b23f2dc706de4bee05b6e0989f816de58bfe754e17df20af02744000265b1685"),
        "bootstrap_responder_mac": (mac(derive(ikm, salt, b"confirmation-responder"), salt).hex(), "93d5e7c82e65e20984d4172073ba80b05781da6ef8e3dd1cdc5b475d88791472"),
    }
    prefix = final_prefix(bytes([4])*32, b"initial-test", b"reply-test")
    sid = sha3(b"session-id", prefix)
    vectors["bootstrap_session"] = (sid.hex(), "8d4558a28f45f0546808519c0eae01f2f699114436c5bcef4d0cba8ac0e8c81d")
    vectors["bootstrap_root"] = (derive(seed, sid, b"session-root/"+bytes([4])*32).hex(), "59f448cc11216e01b6b5ee2f2f9f9dd4609eaf4d2ca0c0b226054ee0b1dfa96e")
    material = initial_material(bytes([7])*32, bytes([9])*32, bytes([11])*32)
    vectors["initial_rekey_and_chains"] = (material[:96].hex(), "c94afb4355b05a32f9cf8682a7231596c40e5d5fd8a6b9328d13109a5cd6e33e99fda0772b0f13582050c1f206a8ba3dfd8ec32ec2b35f6d86ff647e4bef6aa4f588f6ad682062e0df2c21e474aaa8b77ca58f3ca5e37e4e42c0acb0374d95e1")
    vectors["initial_direction_two_ack"] = (acknowledgement(bytes([9])*32, 2, 0, 0, material[128:160]).hex(), "5150434d41434b310909090909090909090909090909090909090909090909090909090909090909020000000000000000d7011dd0974bf86048eedd1cdb1aafe537a48ef6c0f08e3145b960fc11efa172")
    for name, (actual, expected) in vectors.items():
        record(name, actual == expected, "recomputed existing native public vector")

    original, alias = fixture(0), fixture(1)
    body_len = int.from_bytes(original.reply[:4], "big")
    body = slice(4, 4 + body_len)
    record("alias_keeps_reply_body_and_confirmation", original.reply[body] == alias.reply[body] and original.seed == alias.seed and original.kr == alias.kr and original.ki == alias.ki, "same-body premise with opaque signature fields")
    record("alias_changes_final_root_and_ack_key", original.prefix != alias.prefix and original.session != alias.session and original.root != alias.root and original.ack_a != alias.ack_a, "executed exact schedule")
    record("honest_final_accepted", accept_final(original, original.final), "post-authentication final parser")
    record("alias_final_rejected", not accept_final(original, alias.final), "complete signed-wire prefix check")
    record("prefix_check_removal_exposes_alias", accept_final(original, alias.final, compare_prefix=False), "explicit hypothetical mutation; no product code changed")
    good = acknowledgement(original.session, 1, 0, 0, original.ack_a)
    record("honest_ready_accepted", accepts_ready(original, original.session, good), "epoch-zero peer-direction MAC")
    record("public_id_only_rejected", not accepts_ready(alias, alias.session, b""), "connection terminal gate")
    public_claim = sha3(b"session-id", alias.final[:104])
    record("public_id_only_mutation_exposes_alias", public_claim == alias.session and not accept_final(original, alias.final), "explicit ID-only mutation reproduces the shape of retained native defect")
    fake = acknowledgement(alias.session, 1, 0, 0, alias.ack_a)[:-32] + bytes(32)
    record("zero_tag_ready_rejected", not accepts_ready(alias, alias.session, fake), "correct public fields with unknown ACK key")
    record("original_ready_does_not_confirm_alias", not accepts_ready(alias, alias.session, good), "original peer-origin transcript differs")
    graft = good[:8] + alias.session + good[40:]
    record("session_id_graft_rejected", not accepts_ready(alias, alias.session, graft), "old MAC over another full transcript")
    reflection = acknowledgement(original.session, 2, 0, 0, original.ack_b)
    record("own_direction_reflection_rejected", not accepts_ready(original, original.session, reflection), "opposite directional oracle")
    rewritten = reflection[:40] + b"\x01" + reflection[41:]
    record("reflected_direction_rewrite_rejected", not accepts_ready(original, original.session, rewritten), "direction belongs to authenticated prefix")
    next_epoch = acknowledgement(original.session, 1, 1, 0, original.ack_a)
    record("positive_epoch_proof_rejected", not accepts_ready(original, original.session, next_epoch), "connector requires original epoch zero")
    impossible = acknowledgement(original.session, 1, 0, 1, original.ack_a)
    record("uncommitted_consumption_ceiling_rejected", not accepts_ready(original, original.session, impossible), "valid MAC still respects original sent count")
    record("exact_original_ready_replay_accepted", accepts_ready(original, original.session, good) and accepts_ready(original, original.session, good), "historical activation; no new peer-liveness assertion")
    leaked_root = original.root
    derived_ack = initial_material(leaked_root, original.session, original.context)[96:128]
    leaked_proof = acknowledgement(original.session, 1, 0, 0, derived_ack)
    record("root_disclosure_constructs_terminal_proof", accepts_ready(original, original.session, leaked_proof), "constructive counterexample when the theorem's secrecy condition is removed")
    wrong_material = initial_material(original.material[:32], original.session, original.context)
    wrong_proof = acknowledgement(original.session, 1, 0, 0, wrong_material[96:128])
    record("rekey_value_is_not_the_bootstrap_root_input", not accepts_ready(original, original.session, wrong_proof), "specific substitution check; no general inversion claim")

    family = ProtectedFamily()
    record("online_registration_precedes_private_use", family.register(0) and family.use(0), "stated proof-game event interface")
    record("exact_retry_retains_original_registration", family.register(0) and family.use(0) and family.protected == {0}, "one logical class and one protected key")
    record("local_signing_disclosure_stays_in_view", family.reveal("local_signing_identity") and not family.stopped, "identity-only disclosure does not add an ACK recipe")
    record("rekey_output_disclosure_stays_distinct", family.reveal("R0") and not family.stopped, "no inverse edge from an HKDF output block")
    record("protected_root_disclosure_stops_before_release", not family.reveal("root0") and family.stopped and "root0" not in family.disclosed, "common stop before recipe output")
    record("stopped_game_has_no_later_use_or_registration", not family.use(0) and not family.register(1) and family.protected == {0}, "no surviving-class postselection")
    late = ProtectedFamily()
    record("late_protection_is_rejected", late.use(0) and not late.register(0) and not late.protected, "unprotected prior private use stays real")
    prior = ProtectedFamily()
    record("prior_recipe_blocks_registration", prior.reveal("seed") and not prior.register(0), "registration checks the existing disclosure closure")
    overlap = ProtectedFamily()
    record("two_full_wire_classes_register_monotonically", overlap.register(0) and overlap.register(1) and overlap.protected == {0, 1}, "distinct wire aliases retain shared source dependencies")
    record("shared_source_disclosure_stops_protected_family", overlap.reveal("s0") and not overlap.reveal("s1") and overlap.stopped and "s1" not in overlap.disclosed, "two disclosed contribution recipes jointly reconstruct both targets")
    guarded = ProtectedFamily()
    record("encrypted_record_alone_stays_in_view", guarded.register(0) and guarded.reveal("record0") and not guarded.stopped, "unmet independent wrapping guard")
    record("later_guard_stops_before_record_readability", not guarded.reveal("wrap0") and guarded.stopped and "wrap0" not in guarded.disclosed, "late guard acquisition is an exposure event")
    sibling = ProtectedFamily()
    record("unprotected_derived_root_does_not_invert_shared_seed", sibling.register(1) and sibling.reveal("root0") and not sibling.stopped, "real unprotected class remains in the joint auxiliary view")
    bounded = ProtectedFamily(limit=1)
    record("family_size_bound_is_enforced", bounded.register(0) and not bounded.register(1) and bounded.protected == {0}, "fixed family budget")

    # Exhaustive finite scope matrix: four transcript classes, two directions,
    # two epochs, three consumed floors, four source keys = 192 cases.
    classes = [fixture(i) for i in range(4)]
    accepted = []
    total = 0
    for transcript in range(4):
        for direction in (1, 2):
            for epoch in (0, 1):
                for floor in (0, 1, 2):
                    for key_source in range(4):
                        key = classes[key_source].ack_a if direction == 1 else classes[key_source].ack_b
                        proof = acknowledgement(classes[transcript].session, direction, epoch, floor, key)
                        actual = accepts_ready(original, original.session, proof, sent=1)
                        expected = transcript == 0 and direction == 1 and epoch == 0 and floor <= 1 and key_source == 0
                        check(actual == expected, f"scope matrix mismatch: {(transcript,direction,epoch,floor,key_source)}")
                        total += 1
                        if actual:
                            accepted.append([transcript, direction, epoch, floor, key_source])
    check(total == 192 and len(accepted) == 2, "scope census")
    return {
        "named_controls": controls,
        "named_control_count": len(controls),
        "scope_matrix": {"cases": total, "accepted": accepted, "rejected": total-len(accepted)},
        "synthetic_transcript": {
            "initial_bytes": len(original.initial), "reply_bytes": len(original.reply),
            "final_bytes": len(original.final), "ack_bytes": len(good),
            "original_session": original.session.hex(), "alias_session": alias.session.hex(),
            "same_body": True,
        },
        "scope": "Pure Python public synthetic schedule/parser controls. No native KEM/signature execution, no new hosted CI claim, and no computational hardness theorem inferred from finite cases.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("source-manifest.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {"schema_version": 1, "source_binding": verify_sources(args.source_root, args.manifest), "controls": run_controls(), "status": "passed"}
    result["checker_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    print(json.dumps({"status":result["status"], "checked_sources":result["source_binding"]["checked_files"], "named_controls":result["controls"]["named_control_count"], "scope_cases":result["controls"]["scope_matrix"]["cases"]}))


if __name__ == "__main__":
    main()
