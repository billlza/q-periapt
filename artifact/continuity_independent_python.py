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
