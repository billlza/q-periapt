"""Exact C root route census and public approval readback; no signature-verification claim."""
import rust_sdk_profile as sdk

VARIANTS = ("transition", "bound-transition", "adoption")
TAIL = ("activation-unknown", "inventory", "prepare-report", "report", "prepare-ack", "journal", "signer", "verify")
TAIL_CUTS = frozenset(("inventory", "report", "prepare-ack", "journal", "signer"))


def layout(variant: str):
    sdk.require(variant in VARIANTS, "unknown C root alternative")
    if variant == "adoption":
        return ("begin", "preparing", "adopt", "adopt-retry", *TAIL), TAIL_CUTS | {"begin", "adopt"}
    prefix = ("begin", "preparing", *(("freeze-original",) if variant == "bound-transition" else ()),
              "transition", "transition-retry", "retain", "retain-retry")
    cuts = TAIL_CUTS | {"begin", "transition", "retain"}
    return (*prefix, *TAIL), cuts | ({"freeze-original"} if variant == "bound-transition" else set())


def marker(variant: str) -> bytes:
    stages, cuts = layout(variant)
    return (f"ROOT_C_LIFECYCLE processes={len(stages)} sigkill={len(cuts)} witness_unknown=218 native_readbacks=3 "
            "original_revision=2 report_preserved=true cleanup_keeps_successor=true "
            f"close_revokes_successor=true application_traffic=true route={variant}\n").encode()


def verify(read, variant: str):
    layout(variant)
    original = read("public/approved-plan", 8192)
    approved = read("public/alternative-approved", 8192)
    noncommit = read("public/original-noncommit", 65536)
    receipt = read("public/alternative-receipt", 65536)
    proposal = read("public/bound-proposal", 65536)
    old_target = read("public/original-target-account", 32)
    target = read("public/target-account", 32)
    sdk.require(len(old_target) == 32 and any(old_target) and len(target) == 32 and any(target),
                "alternative target identity absent")
    # The installed child authenticates signatures. This replay only binds the
    # public evidence to the selected route and refuses truncation/substitution.
    sdk.require(original.startswith(b"QPAFPL01") and original != approved and len(noncommit) == 3449,
                "original noncommit or separate approval absent")
    if variant == "adoption":
        sdk.require(approved == proposal and approved.startswith(b"QPARPL02")
                    and receipt == read("public/retirement-receipt", 8192),
                    "adoption did not retain its independently approved winner")
    else:
        sdk.require(approved.startswith(b"QPAFPL01") and old_target != target
                    and receipt == read("public/freeze-receipt", 65536),
                    "transition did not retain its independently approved next target")
        if variant == "bound-transition":
            previous = read("public/original-bound-proposal", 65536)
            sdk.require(previous.startswith(b"QPARPL02") and previous != proposal,
                        "bound transition lost the original proposal")
    return {"route": variant, "exact_approval_retained": True,
            "new_local_winner_preparation": variant != "adoption", "release_claim_eligible": False}
