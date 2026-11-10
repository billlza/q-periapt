"""Reviewed models, proof certificates and complete verdict inventories."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class Certificate:
    member: str
    sha256: str
    heap_gib: int
    threads: int
    all_traces: tuple[str, ...]
    exists_traces: tuple[str, ...]
    verified: tuple[str, ...]
    compose_proofs: bool = False

    def expected_results(self) -> dict[str, tuple[str, str]]:
        return {
            name: (mode, "verified" if name in self.verified else "analysis incomplete")
            for mode, names in (("all-traces", self.all_traces), ("exists-trace", self.exists_traces))
            for name in names
        }


@dataclass(frozen=True)
class RecoveryProfile:
    name: str
    main: str
    model: str
    model_sha256: str
    archive: str
    archive_sha256: str
    archive_maximum_bytes: int
    cases: Mapping[str, Certificate]


RECORD_WITNESSES = (
    "recovery_is_executable",
    "pre_cut_generation_reservation_remains_exposed",
    "later_storage_access_defeats_fresh_reservations",
)
INDEPENDENT_MAIN = "clean_reservation_recovers_symbolic_message_secrecy"
INDEPENDENT_PROPERTIES = (
    "traffic_key_derivation_requires_prior_root",
    "message_derivation_requires_prior_traffic_key",
    "response_confirmation_has_origin_or_prior_root",
    "computed_root_identifies_session",
    "accepted_root_has_origin_or_prior_derivation",
    "signing_secret_derivation_origin",
    "generation_secret_derivation_origin",
    "signing_secret_origin",
    "generation_secret_origin",
    "encapsulation_uses_authenticated_generation",
    "encapsulation_derivation_requires_session_leak",
    "accepted_root_has_authenticated_origin",
    "message_root_has_authenticated_origin",
    "root_constructor_requires_prior_coins_or_snapshot",
    "computed_root_derivation_requires_session_leak",
    "message_derivation_requires_session_leak",
    "retained_record_has_saved_origin",
    "stored_records_follow_fresh_reservations",
    "encapsulation_secret_requires_session_leak",
    INDEPENDENT_MAIN,
)
INDEPENDENT = RecoveryProfile(
    name="independent",
    main=INDEPENDENT_MAIN,
    model="research/continuity-recovery-symbolic/protected-state.spthy",
    model_sha256="7802d0a937cd3f1afd75cb256c4cadc17b714f042f4894f4d471b3ea3d7bf902",
    archive="research/sdk-alpha1/evidence/20261015-recovery-positive-symbolic/CAPTURE.zip",
    archive_sha256="e207e57e480608b408823bff1c3ce28a805214df24e651a599b02150684dcea9",
    archive_maximum_bytes=4 * 1024 * 1024,
    cases=MappingProxyType({
        "positive": Certificate(
            "proof/final-positive-53-proof.spthy",
            "91dd31801ee8c208d295a5a02efc1721c794fc8dd32bb1430d303fcb18199707",
            12, 2, INDEPENDENT_PROPERTIES, RECORD_WITNESSES, INDEPENDENT_PROPERTIES,
        ),
        "witnesses": Certificate(
            "prior/original-witnesses-export-36.spthy",
            "3e217d9c6d535739826799f46078137328dda6bbc23d984ca88556095eacb8d2",
            2, 2, ("generation_secret_origin", INDEPENDENT_MAIN), RECORD_WITNESSES, RECORD_WITNESSES,
        ),
    }),
)

KEY_SCOPED_MAIN = "key_scoped_reservations_recover_symbolic_message_secrecy"
CROSS_ROLE_WITNESS = "cross_role_sibling_disclosure_exposes_target_message"
UNRELATED_KEY_WITNESS = "recovery_premises_allow_unrelated_identity_disclosure"
KEY_SCOPED_PROPERTIES = (
    "traffic_key_derivation_requires_prior_root",
    "message_derivation_requires_prior_traffic_key",
    "response_confirmation_has_origin_or_prior_root",
    "computed_root_identifies_session",
    "accepted_root_has_origin_or_prior_derivation",
    "signing_secret_derivation_origin",
    "generation_secret_derivation_origin",
    "signing_secret_origin",
    "generation_secret_origin",
    "encapsulation_uses_authenticated_generation",
    "accepted_root_has_authenticated_origin",
    "message_root_has_authenticated_origin",
    "encapsulation_derivation_requires_key_or_session_leak",
    "root_constructor_requires_prior_coins_or_snapshot",
    "computed_root_derivation_requires_key_or_session_leak",
    "message_derivation_requires_key_or_session_leak",
    "retained_record_has_saved_origin",
    "stored_records_follow_fresh_reservations",
    "encapsulation_secret_requires_key_or_session_leak",
    KEY_SCOPED_MAIN,
)
KEY_SCOPED = RecoveryProfile(
    name="key-scoped",
    main=KEY_SCOPED_MAIN,
    model="research/continuity-recovery-symbolic/key-scoped.spthy",
    model_sha256="4f425a97517302603b18e4cb007677614c13b0e341b7619c485a6345af04fd04",
    archive="research/sdk-alpha1/evidence/20261015-recovery-key-scoped/CAPTURE.zip",
    archive_sha256="97e974de0ce875f61f8d5d54708c393f342f73872e0f27a0e82957640f8affde",
    # The reviewed archive is 5,664,151 bytes. Only the named small certificates
    # are read; the large diagnostic trace graphs are never extracted by the gate.
    archive_maximum_bytes=8 * 1024 * 1024,
    cases=MappingProxyType({
        "positive": Certificate(
            "experiments/final-37-proof.spthy",
            "39f17d2cc5eed8697d0022a35fff2e8d32fea3f9787aad84afc850f496d2a7f7",
            12, 1, KEY_SCOPED_PROPERTIES, (*RECORD_WITNESSES, CROSS_ROLE_WITNESS), KEY_SCOPED_PROPERTIES,
        ),
        "attack": Certificate(
            "experiments/cross-role-replay-09-proof.spthy",
            "f5eaab40815985bd82d999733365f2eaa678aeac022bbc51738ea920c926b532",
            6, 1, (
                "signing_secret_derivation_origin", "generation_secret_derivation_origin",
                "signing_secret_origin", "generation_secret_origin",
                "encapsulation_uses_authenticated_generation",
                "encapsulation_derivation_requires_key_or_session_leak", KEY_SCOPED_MAIN,
            ), (*RECORD_WITNESSES, CROSS_ROLE_WITNESS), (CROSS_ROLE_WITNESS,),
        ),
        "execution": Certificate(
            "experiments/honest-sharing-replay-28-proof.spthy",
            "feb67b6081b5dd27558cb554ad55adc5d2c03c23400902d7fed70f47d06e071f",
            6, 1, KEY_SCOPED_PROPERTIES,
            (*RECORD_WITNESSES, CROSS_ROLE_WITNESS, UNRELATED_KEY_WITNESS), (UNRELATED_KEY_WITNESS,),
        ),
    }),
)
SHARED_STORAGE_ATTACK = "sibling_wrapping_key_unseals_target_record"
SHARED_STORAGE_EXECUTION = "recovery_with_shared_storage_is_executable"
SHARED_OWNER_EXECUTION = "shared_device_identity_and_storage_recovery_is_executable"
SHARED_STORAGE_PROVENANCE = (
    "signing_secret_derivation_origin", "generation_secret_derivation_origin",
    "signing_secret_origin", "generation_secret_origin",
    "encapsulation_uses_authenticated_generation",
    "encapsulation_derivation_requires_key_or_session_leak", KEY_SCOPED_MAIN,
)
SHARED_STORAGE = RecoveryProfile(
    name="shared-storage",
    main=KEY_SCOPED_MAIN,
    model="research/continuity-recovery-symbolic/shared-storage.spthy",
    model_sha256="146f0db14ce78d5d54bae1a8265584f471a8637e31aa3a19264151c571dc2046",
    archive="research/sdk-alpha1/evidence/20261015-recovery-shared-storage-positive/CAPTURE.zip",
    archive_sha256="9655446a492219424eee05614fd2b4589072e07c07293dc92323bbefb170c0be",
    archive_maximum_bytes=4 * 1024 * 1024,
    cases=MappingProxyType({
        "positive": Certificate(
            "experiments/final-12-proof.spthy",
            "0f0a04ec5764fec3017b3a04e0b40debce99b39f84dbba592e9c05048b2c5da6",
            12, 1, KEY_SCOPED_PROPERTIES, (*RECORD_WITNESSES, CROSS_ROLE_WITNESS), KEY_SCOPED_PROPERTIES,
            compose_proofs=True,
        ),
        "attack": Certificate(
            "prior/sibling-replay-07-proof.spthy",
            "c23d023b31f364b528abcdc63c29c525b0d652f85da372a27cfc3e4d5df9e5fa",
            6, 1, SHARED_STORAGE_PROVENANCE,
            (*RECORD_WITNESSES, CROSS_ROLE_WITNESS, SHARED_STORAGE_ATTACK, SHARED_STORAGE_EXECUTION),
            (SHARED_STORAGE_ATTACK,),
        ),
        "execution": Certificate(
            "experiments/owner-replay-19-proof.spthy",
            "85bd2a6b5dd4936ffdabdd87873a01ff1835c140a1fadf040f31de9fb100154e",
            6, 1, SHARED_STORAGE_PROVENANCE,
            (*RECORD_WITNESSES, CROSS_ROLE_WITNESS, SHARED_OWNER_EXECUTION), (SHARED_OWNER_EXECUTION,),
        ),
    }),
)
PROFILES = MappingProxyType({profile.name: profile for profile in (INDEPENDENT, KEY_SCOPED, SHARED_STORAGE)})
