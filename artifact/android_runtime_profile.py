"""Closed emulator targets shared by launch, recovery and SDK verification."""

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

    def target(self, abi: str) -> dict[str, object]:
        if not any(selected_abi == abi for _, selected_abi in self.avds):
            raise ValueError("Android runtime profile does not support the selected ABI")
        return {"kind": "emulator", "abi": abi, "sdk": self.sdk, "page_size": self.page_size}


RUNTIME_PROFILES: Mapping[str, RuntimeProfile] = MappingProxyType({
    DEFAULT_RUNTIME_PROFILE: RuntimeProfile(35, 16384, MappingProxyType({
        ("macos-account", "arm64-v8a"): "QPeriapt_Release_16K_API_35_V1",
        ("linux-system", "x86_64"): "QPeriapt_Release_16K_API_35_CI_V1",
    })),
    "api23-4k": RuntimeProfile(23, 4096, MappingProxyType({
        ("linux-system", "x86_64"): "QPeriapt_SDK_4K_API_23_CI_V1",
    })),
})


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
