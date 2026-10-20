"""Inspect the closed, source-bound independent Python reference wheel."""
from __future__ import annotations

import base64
import csv
from email.parser import BytesParser
import hashlib
import io
from pathlib import PurePosixPath
import re
import stat
import zipfile

from evidence_io import parse_strict_json_bytes

PACKAGE = "qperiapt_continuity_reference"
DIST = PACKAGE + "-0.0.0.dist-info"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_roster_profiles(result: dict, *, boundary: bool) -> None:
    """Require all original-owner workloads, including the native trusted clock."""
    profiles = result.get("profiles")
    require(isinstance(profiles, list) and len(profiles) == 4, "roster cohort incomplete")
    selected = [(True, False), (True, True), (False, False), (False, True)] if boundary else [
        (3, False), (3, True), (32, False), (32, True)]
    for row, (group, witnessed) in zip(profiles, selected, strict=True):
        require(isinstance(row, dict) and type(row.get("witnessed")) is bool
                and row["witnessed"] == witnessed, "roster profile differs")
        if boundary:
            workers = {(True, False): 17, (True, True): 23, (False, False): 21, (False, True): 35}
            require(type(row.get("before_g")) is bool and row["before_g"] == group
                    and type(row.get("workers")) is int and row["workers"] == workers[(group, witnessed)],
                    "roster boundary workload differs")
        else:
            expected = {"members": group, "workers": 38 if witnessed else 32,
                        "process_kills": 4 if witnessed else 3, "native_trusted_time": 355}
            require(all(type(row.get(key)) is int and row[key] == value for key, value in expected.items()),
                    "roster original-owner workload or clock differs")
        identities = ["journal", "session", "original_message_sha256"]
        if not boundary:
            identities += ["native_journal", "original_offer_sha256"]
        require(all(isinstance(row.get(name), str) and re.fullmatch(r"[0-9a-f]{64}", row[name])
                    and any(c != '0' for c in row[name]) for name in identities),
                "roster original identity missing")


def verify_roster_capacity(result: dict) -> None:
    """Require actual full business stores through R and the following G."""
    profiles=result.get("profiles")
    require(isinstance(profiles,list) and len(profiles)==2,"full roster cohort incomplete")
    refused=["R-cannot-select-nine","R-wire-cannot-downgrade","R-missing-marker",
             "R-cannot-adopt-policy-version","R-metadata-cannot-expand-business",
             "R-aggregate-bound","R-allocation-cannot-fund-send"]
    for row,witnessed in zip(profiles,(False,True),strict=True):
        require(isinstance(row,dict) and type(row.get("witnessed")) is bool
                and row["witnessed"]==witnessed,"full roster profile differs")
        expected={"members":32,"traffic_bytes":2031616,"rows":123,
                  "native_trusted_time":355,"process_kills":4 if witnessed else 3}
        require(all(type(row.get(k)) is int and row[k]==v for k,v in expected.items()),
                "full roster workload or clock differs")
        require(type(row.get("roster_payload_bytes")) is int and row["roster_payload_bytes"]>2*1024**2
                and type(row.get("roster_intent_bytes")) is int
                and row["roster_intent_bytes"]>row["roster_payload_bytes"],"full roster target missing")
        history=row.get("original_inventory")
        require(isinstance(history,dict) and type(history.get("traffic_bytes")) is int
                and history["traffic_bytes"]==2031616 and type(history.get("outboxes")) is int
                and history["outboxes"]==123 and isinstance(history.get("epoch_record_hashes"),list)
                and len(history["epoch_record_hashes"])==2
                and all(isinstance(item,list) and len(item)==2 and type(item[0]) is int and item[0]==epoch
                        and isinstance(item[1],str) and re.fullmatch(r"[0-9a-f]{64}",item[1])
                        for epoch,item in enumerate(history["epoch_record_hashes"])),"full roster original epochs missing")
        require(isinstance(row.get("refusals"),list) and len(row["refusals"])==len(refused)
                and all(isinstance(item,dict) and set(item)=={"case","error","type"}
                        and isinstance(item["error"],str) and item["error"] and item["type"]=="ValueError"
                        for item in row["refusals"])
                and [item.get("case") for item in row["refusals"]]==refused,
                "full roster refusal coverage differs")
        require(all(isinstance(row.get(k),str) and re.fullmatch(r"[0-9a-f]{64}",row[k])
                    and any(c!='0' for c in row[k]) for k in
                    ["journal","native_journal","session","original_message_sha256","original_last_message_sha256"]),
                "full roster original identities missing")


def verify_roster_revocation(result: dict) -> None:
    """Require a live native sender before removal and fresh rejection afterward."""
    rows=result.get("profiles")
    require(isinstance(rows,list) and len(rows)==4,"peer revocation cohort incomplete")
    denials=["removed-peer-denies-next-id","removed-peer-denies-old-output",
             "removed-peer-denies-old-input","removed-peer-denies-fresh-input"]
    for row,(members,witnessed) in zip(rows,[(3,False),(3,True),(32,False),(32,True)],strict=True):
        require(isinstance(row,dict) and type(row.get("witnessed")) is bool and row["witnessed"]==witnessed,
                "peer revocation profile differs")
        expected={"members":members,"workers":50 if witnessed else 42,
                  "process_kills":5 if witnessed else 4,"native_trusted_time":355}
        require(all(type(row.get(k)) is int and row[k]==v for k,v in expected.items()),
                "peer revocation owner workload differs")
        removed=row.get("after_renewal")
        require(isinstance(removed,dict) and removed.get("kind")=="actual_common_account_peer_removal"
                and type(removed.get("target_version")) is int and removed["target_version"]==19
                and all(removed.get(k) is True for k in ["positive_native_receive",
                        "same_generation_resurrection_refused","original_enrollment_retained"])
                and removed.get("denied_operations")==denials,"peer revocation permission checks differ")
        for values,keys in [(row,["journal","native_journal","session","original_message_sha256","original_offer_sha256"]),
                            (removed,["before_wire_sha256","after_wire_sha256","target_sha256"])]:
            require(all(isinstance(values.get(k),str) and re.fullmatch(r"[0-9a-f]{64}",values[k])
                        and any(c!='0' for c in values[k]) for k in keys),"peer revocation original identity missing")
        require(removed["before_wire_sha256"]!=removed["after_wire_sha256"],
                "removed native sender did not produce a fresh message")


def verify_extension_session(result: dict, *, implementation: str, native_sha256: str) -> None:
    """Require the completed post-expiry workload from the selected installed owners."""
    require(result.get("schema_version") == 1 and type(result.get("schema_version")) is int
            and result.get("kind") == "qperiapt.enrollment_extension_session"
            and result.get("completed") is True and result.get("provider") == "48.0.1"
            and result.get("implementation") == implementation
            and result.get("native_sha256") == native_sha256,
            "extension session implementation or completion differs")
    profiles = result.get("profiles")
    require(isinstance(profiles, list) and len(profiles) == 2,
            "extension session profiles differ")
    refusals = ["expired-original-policy", "selected-installation-refuses-extension", "extended-credential-expiry"]
    for row, label, commands, witness in zip(profiles, ("local", "witness"), (13, 125), (0, 110), strict=True):
        expected = {"completed": True, "profile": label, "native_commands": commands,
                    "witness_requests": witness, "refusal_cases": refusals,
                    "bootstrap_time": 210, "traffic_time": 220, "original_expiry": 160,
                    "extended_expiry": 300, "confirmed_epoch": 1}
        require(isinstance(row, dict) and row == expected
                and all(type(row[key]) is type(value) for key, value in expected.items()),
                "extension session workload, time or refusal boundary differs")


def verify_record(files: dict[str, bytes]) -> None:
    records = list(csv.reader(io.StringIO(files[DIST + "/RECORD"].decode("utf-8"), newline="")))
    require(all(len(row) == 3 for row in records) and len(records) == len(files)
            and len({row[0] for row in records}) == len(records)
            and {row[0] for row in records} == set(files), "reference RECORD inventory differs")
    for name, digest, size in records:
        if name == DIST + "/RECORD":
            require(digest == size == "", "reference RECORD self-entry differs")
        else:
            expected_digest = base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).rstrip(b"=").decode()
            require(digest == "sha256=" + expected_digest and size == str(len(files[name])),
                    "reference RECORD content differs: " + name)


def inspect_wheel(data: bytes, sources: dict[str, bytes], licenses: dict[str, bytes], readme: bytes) -> dict[str, bytes]:
    """Return verified members; installation is still performed by standard pip."""
    require(0 < len(data) <= 1024 * 1024, "reference wheel size exceeds bound")
    require("__init__.py" in sources and all(
        re.fullmatch(r"(?:__init__|[a-z][a-z0-9_]*)\.py", name) for name in sources),
        "reference module inventory differs")
    require(set(licenses) == {"LICENSE-APACHE", "LICENSE-MIT"}, "reference license inventory differs")
    expected = {PACKAGE + "/" + name: body for name, body in sources.items()}
    expected.update({DIST + "/licenses/" + name: body for name, body in licenses.items()})
    metadata_names = {DIST + "/" + name for name in ("METADATA", "WHEEL", "RECORD")}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        items = archive.infolist()
        require(len(items) == len({i.filename for i in items}) <= 128
                and sum(i.file_size for i in items) <= 4 * 1024**2,
                "reference wheel duplicate or excessive members")
        require({i.filename for i in items} == set(expected) | metadata_names,
                "reference wheel includes missing or unexpected files")
        for item in items:
            path = PurePosixPath(item.filename)
            require(not path.is_absolute() and ".." not in path.parts and str(path) == item.filename
                    and not item.is_dir() and not item.flag_bits & 1
                    and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG),
                    "reference wheel member type or path differs")
        files = {item.filename: archive.read(item) for item in items}
    require(all(files[name] == body for name, body in expected.items()),
            "reference wheel source or license differs")
    metadata = BytesParser().parsebytes(files[DIST + "/METADATA"])
    for field, value in {
        "Metadata-Version": "2.5", "Name": "qperiapt-continuity-reference", "Version": "0.0.0",
        "Requires-Python": ">=3.14,<3.15", "License-Expression": "Apache-2.0 OR MIT",
        "Classifier": "Private :: Do Not Upload", "Requires-Dist": "cryptography==48.0.1",
        "Import-Name": PACKAGE,
    }.items():
        require(metadata.get_all(field) == [value], "reference metadata differs: " + field)
    require(metadata.get_all("License-File") == ["LICENSE-APACHE", "LICENSE-MIT"]
            # Flit 4.1.0 common.py writes the description plus one newline.
            and files[DIST + "/METADATA"].partition(b"\n\n")[2] == readme + b"\n",
            "reference metadata licenses or README differ")
    wheel = BytesParser().parsebytes(files[DIST + "/WHEEL"])
    for field, value in {"Wheel-Version": "1.0", "Generator": "flit 4.1.0",
                         "Root-Is-Purelib": "true", "Tag": "py3-none-any"}.items():
        require(wheel.get_all(field) == [value], "reference wheel metadata differs: " + field)
    verify_record(files)
    return files


def verify_installation(files: dict[str, bytes], wheel_files: dict[str, bytes], *, wheel_url: str, digest: str) -> None:
    """Admit pip's three metadata additions, never editable or changed sources."""
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "reference wheel digest differs")
    extras = {DIST + "/" + name for name in ("INSTALLER", "REQUESTED", "direct_url.json")}
    require(set(files) == set(wheel_files) | extras, "reference installation inventory differs")
    require(all(files[name] == body for name, body in wheel_files.items() if name != DIST + "/RECORD"),
            "reference installed source or metadata differs")
    require(files[DIST + "/INSTALLER"] == b"pip\n" and files[DIST + "/REQUESTED"] == b"",
            "reference installer metadata differs")
    origin = parse_strict_json_bytes(files[DIST + "/direct_url.json"], label="reference installation origin")
    require(origin == {"url": wheel_url, "archive_info": {
        "hash": "sha256=" + digest, "hashes": {"sha256": digest}}},
        "reference installation origin differs")
    verify_record(files)
