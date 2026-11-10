"""Portable installed Cargo graph checks, shared by Unix and Windows consumers."""
from pathlib import Path
import hashlib
import re
import tomllib


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def external_lock(lock: bytes) -> dict:
    packages = tomllib.loads(lock.decode())["package"]
    result = {}
    for package in packages:
        if "source" not in package or package["name"].startswith("q-periapt"):
            continue
        identity = (package["name"], package["version"])
        checksum = package.get("checksum")
        require(identity not in result and package["source"] == "registry+https://github.com/rust-lang/crates.io-index"
                and isinstance(checksum, str) and re.fullmatch(r"[a-f0-9]{64}", checksum) is not None,
                "external dependency identity/source/checksum is invalid")
        result[identity] = (package["source"], checksum)
    return result


def verify_resolution(metadata: dict, consumer: Path, lock: bytes, original_lock: bytes,
                              *, consumer_name: str, versions: dict[str, str]) -> dict:
    rows = [row for row in metadata["packages"] if row["name"].startswith("q-periapt")]
    local = {row["name"]: row for row in rows}
    require(len(local) == len(rows) and set(local) == set(versions) | {consumer_name},
            "installed consumer resolved a mixed product graph")
    require(Path(local[consumer_name]["manifest_path"]).resolve() == consumer / "Cargo.toml"
            and local[consumer_name]["source"] is None, "installed consumer manifest origin differs")
    for name, version in versions.items():
        expected = consumer / "packages" / f"{name}-{version}" / "Cargo.toml"
        require(Path(local[name]["manifest_path"]).resolve() == expected
                and local[name]["version"] == version and local[name]["source"] is None,
                "installed consumer resolved checkout or mixed-version crates")
    resolved, original = external_lock(lock), external_lock(original_lock)
    require(all(original.get(key) == value for key, value in resolved.items()),
            "installed consumer changed external dependency versions, sources or checksums")
    return {"product_crates": len(versions), "external_packages": len(resolved),
            "lockfile_sha256": hashlib.sha256(lock).hexdigest()}

