"""Authenticate exact upstream notices omitted from six selected registry crates."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path, PurePosixPath
import tarfile

import rust_sdk_profile as sdk
import third_party_licenses as licenses
from evidence_io import parse_strict_json_bytes

PINS = "artifact/continuity_service_license_pins.json"
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"


def verify_crate(data: bytes, pin: dict) -> None:
    sdk.require(hashlib.sha256(data).hexdigest() == pin["registry_checksum"],
                "service notice registry archive checksum differs")
    prefix = pin["name"] + "-" + pin["version"]
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        sdk.require(len(members) <= 4096, "service notice source archive member bound differs")
        vcs = [member for member in members if member.name == prefix + "/.cargo_vcs_info.json"]
        sdk.require(len(vcs) == 1 and vcs[0].isfile() and 0 < vcs[0].size <= 16384,
                    "service notice source archive lacks one VCS identity")
        stream = archive.extractfile(vcs[0])
        sdk.require(stream is not None, "service notice VCS member is unreadable")
        with stream:
            data = stream.read(16385)
        sdk.require(parse_strict_json_bytes(data, label="service notice VCS identity") == pin["vcs"],
                    "service notice upstream revision differs from registry archive")
        sdk.require(not any(PurePosixPath(member.name).parent.as_posix() == prefix
                    and PurePosixPath(member.name).name.upper().startswith(licenses.LICENSE_PREFIXES)
                    for member in members), "service notice override no longer describes an omitted license")


def select(root: Path, metadata: dict, cargo_home: Path) -> tuple[dict, dict]:
    pins = parse_strict_json_bytes(sdk.snapshot(root / PINS).data, label="service upstream license pins")
    sdk.require(set(pins) == {"schema_version", "kind", "packages"} and pins["schema_version"] == 1
                and pins["kind"] == "qperiapt.continuity_service_upstream_licenses",
                "service upstream license pin schema differs")
    ids, packages = licenses._production_dependency_ids(metadata, "q-periapt-continuity-reference-app")
    selected = {(packages[key]["name"], packages[key]["version"]): packages[key]
                for key in ids if packages[key].get("source") is not None}
    locked = licenses._lock_checksums(root / "research/continuity-reference-app")
    overrides, origins = {}, []
    sdk.require(type(pins["packages"]) is list and 0 < len(pins["packages"]) <= 16,
                "service upstream license pin count differs")
    for pin in pins["packages"]:
        identity = pin["name"], pin["version"]
        sdk.require(identity not in overrides and identity in selected,
                    "service upstream license dependency is duplicated or absent")
        package = selected[identity]
        sdk.require(package["source"] == SOURCE and package["license"] == pin["license_expression"]
                    and package["repository"] == pin["repository"]
                    and locked.get((*identity, SOURCE)) == pin["registry_checksum"],
                    "service upstream notice does not match the selected locked package")
        package_root = Path(package["manifest_path"]).parent
        vcs = parse_strict_json_bytes(sdk.snapshot(package_root / ".cargo_vcs_info.json").data,
                                     label="cached service dependency VCS identity")
        sdk.require(vcs == pin["vcs"], "cached service dependency VCS identity differs")
        crate = cargo_home / "registry/cache" / package_root.parent.name / ("-".join(identity) + ".crate")
        verify_crate(sdk.snapshot(crate).data, pin)
        files = []
        for entry in pin["files"]:
            relative = PurePosixPath(entry["path"])
            sdk.require(not relative.is_absolute() and ".." not in relative.parts
                        and relative.parts[:2] == ("LICENSES", "continuity-services"),
                        "service upstream notice path differs")
            path = root.joinpath(*relative.parts)
            observed = sdk.snapshot(path, maximum=licenses.MAX_LICENSE_BYTES)
            blob = hashlib.sha1(b"blob " + str(observed.size).encode() + b"\0" + observed.data).hexdigest()
            sdk.require(observed.sha256 == entry["sha256"] and observed.size == entry["bytes"]
                        and blob == entry["git_blob"], "service upstream notice bytes differ")
            files.append(path)
        overrides[identity] = tuple(files)
        repository = pin["repository"].removesuffix(".git")
        copied_files = [{**entry, "packaged_path": "LICENSES/dependencies/THIRD_PARTY/rust/" + "-".join(identity)
                        + "/" + PurePosixPath(entry["path"]).name,
                        "upstream_url": repository + "/blob/" + pin["vcs"]["git"]["sha1"] + "/" + entry["upstream_path"]}
                       for entry in pin["files"]]
        origins.append({**pin, "files": copied_files,
                        "crate_url": "https://static.crates.io/crates/" + pin["name"] + "/" + "-".join(identity) + ".crate",
                        "source_url": repository + "/tree/" + pin["vcs"]["git"]["sha1"] + "/" + pin["vcs"]["path_in_vcs"],
                        "registry_archive_omits_license_text": True})
    return overrides, {"schema_version": 1, "kind": "qperiapt.continuity_service_upstream_license_origins",
                       "packages": origins}


def verify_inventory(inventory: dict, origins: dict) -> None:
    """Bind the copied bytes to the authenticated notices, including across reads."""
    packages = {(row["name"], row["version"]): row for row in inventory["packages"]}
    for pin in origins["packages"]:
        row = packages.get((pin["name"], pin["version"]))
        sdk.require(row is not None, "service upstream notice was omitted from license inventory")
        copied = {(PurePosixPath(item["path"]).name, item["bytes"], item["sha256"]) for item in row["license_files"]}
        expected = {(PurePosixPath(item["path"]).name, item["bytes"], item["sha256"]) for item in pin["files"]}
        sdk.require(copied == expected, "copied service upstream notice differs from authenticated bytes")
