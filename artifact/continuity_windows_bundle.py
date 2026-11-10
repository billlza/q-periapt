"""Resource admission for the fixed nine-SDK-crate Windows consumer closure.

The single-package limit remains 1024 members. The Windows input contains ten
independently validated packages plus a bounded facade; each package retains
that limit. The shared archive still enforces 64 MiB compressed and expanded,
the exact file inventory, regular canonical entries and every expected hash.
"""
from installed_rust_graph import require
from rust_sdk_profile import CONSUMER_CRATES, VERSION as SDK_VERSION
from continuity_package import NAME, VERSION as CANDIDATE_VERSION
from continuity_package_archive import MAX_MEMBERS

MAX_CONSUMER_MEMBERS = 256


def components(versions: dict[str, str]) -> dict[str, int]:
    expected = {name: SDK_VERSION for name in CONSUMER_CRATES}
    expected[NAME] = CANDIDATE_VERSION
    require(type(versions) is dict and versions == expected,
            "Windows bundle must contain the exact SDK and candidate cohort")
    return {'': MAX_CONSUMER_MEMBERS,
            **{f'packages/{name}-{version}/': MAX_MEMBERS for name, version in expected.items()}}
