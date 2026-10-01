"""Explicit capture targets; only emulator profiles authorize owned AVDs."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


DEFAULT_RUNTIME_PROFILE = "api35-16k"


@dataclass(frozen=True)
class RuntimeProfile:
    sdk: int
    page_size: int
    avds: Mapping[tuple[str, str], str]
    page_size_operation: str = "page-size"
    clock_operation: str = "device-time"
    kind: str = "emulator"
    physical_abis: frozenset[str] = frozenset()

    def target(self, abi: str) -> dict[str, object]:
        supported = self.physical_abis if self.kind == "physical" else frozenset(selected for _, selected in self.avds)
        if abi not in supported:
            raise ValueError("Android runtime profile does not support the selected ABI")
        return {"kind": self.kind, "abi": abi, "sdk": self.sdk, "page_size": self.page_size}


RUNTIME_PROFILES: Mapping[str, RuntimeProfile] = MappingProxyType({
    DEFAULT_RUNTIME_PROFILE: RuntimeProfile(35, 16384, MappingProxyType({
        ("macos-account", "arm64-v8a"): "QPeriapt_Release_16K_API_35_V1",
        ("linux-system", "x86_64"): "QPeriapt_Release_16K_API_35_CI_V1",
    })),
    "api23-4k": RuntimeProfile(23, 4096, MappingProxyType({
        ("linux-system", "x86_64"): "QPeriapt_SDK_4K_API_23_CI_V1",
    }), page_size_operation="page-size-auxv", clock_operation="device-time-calendar"),
})


# Independent caller selection, never inferred from a submitted device proof.
# This adds one actual physical qualification target without expanding legacy
# profiles or admitting physical names to the owned-AVD launcher/recovery map.
PHYSICAL_RUNTIME_PROFILE = "physical-api36-4k"
CAPTURE_RUNTIME_PROFILES: Mapping[str, RuntimeProfile] = MappingProxyType({
    **RUNTIME_PROFILES,
    PHYSICAL_RUNTIME_PROFILE: RuntimeProfile(36, 4096, MappingProxyType({}),
        kind="physical", physical_abis=frozenset({"arm64-v8a"})),
})


def capture_runtime_profile(value: object) -> RuntimeProfile:
    if not isinstance(value, str) or value not in CAPTURE_RUNTIME_PROFILES:
        raise ValueError("unknown Android capture runtime profile")
    return CAPTURE_RUNTIME_PROFILES[value]


def runtime_profile(value: object) -> RuntimeProfile:
    if not isinstance(value, str) or value not in RUNTIME_PROFILES:
        raise ValueError("unknown Android runtime profile")
    return RUNTIME_PROFILES[value]


def owned_avd_profile(adb_profile: str, abi: str, name: str) -> str:
    """Recover the admitted target of a recorded AVD, never from ambient options.

    This only selects cleanup scope. Proof acceptance still requires the
    verifier's independent expected runtime profile.
    """
    if not all(isinstance(value, str) and value for value in (adb_profile, abi, name)):
        raise ValueError("owned Android AVD requires explicit profile, ABI and name")
    for profile, spec in RUNTIME_PROFILES.items():
        if spec.avds.get((adb_profile, abi)) == name:
            return profile
    raise ValueError("owned Android AVD is not admitted for its adb profile and ABI")
