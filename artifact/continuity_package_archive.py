"""Bounded deterministic archives for installed Continuity foreign consumers."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import stat
import zipfile
import rust_sdk_profile as sdk

MAX_PACKAGE = 64 * 1024**2


def archive(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            zipped.writestr(entry, data)
    result = output.getvalue()
    sdk.require(len(result) <= MAX_PACKAGE, "Continuity package exceeds bound")
    return result


def unpack(data: bytes, expected: dict[str, str], destination: Path) -> None:
    sdk.require(len(data) <= MAX_PACKAGE and not destination.exists(), "Continuity package input or destination differs")
    with zipfile.ZipFile(io.BytesIO(data)) as zipped:
        entries = zipped.infolist()
        names = [entry.filename for entry in entries]
        sdk.require(len(entries) <= 1024 and len(names) == len(set(names)) and set(names) == set(expected),
                    "Continuity package file set differs")
        sdk.require(sum(entry.file_size for entry in entries) <= MAX_PACKAGE, "Continuity expanded package exceeds bound")
        selected = {}
        for entry in entries:
            path = PurePosixPath(entry.filename)
            sdk.require(not path.is_absolute() and path.parts and ".." not in path.parts
                        and "\\" not in entry.filename and str(path) == entry.filename
                        and stat.S_ISREG(entry.external_attr >> 16) and not entry.flag_bits & 1,
                        "Continuity package entry is not a canonical regular file")
            content = zipped.read(entry)
            sdk.require(hashlib.sha256(content).hexdigest() == expected[entry.filename], "Continuity package file hash differs")
            selected[path] = content
    destination.mkdir(mode=0o700)
    for name, content in selected.items():
        path = destination.joinpath(*name.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
        path.chmod(0o644)
