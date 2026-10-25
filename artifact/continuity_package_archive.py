"""Bounded deterministic archives for installed Continuity foreign consumers."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import stat
import zipfile
from installed_rust_graph import require

MAX_PACKAGE = 64 * 1024**2
MAX_MEMBERS = 1024
MAX_COMPONENTS = 16


def _admit_members(names, components):
    if components is None:
        require(len(names) <= MAX_MEMBERS,
                f"Continuity package member count exceeds bound: {len(names)} > {MAX_MEMBERS}")
        return
    require(type(components) is dict and 0 < len(components) <= MAX_COMPONENTS,
            "Continuity component inventory differs")
    prefixes = [p for p in components if p]
    for prefix, limit in components.items():
        require(type(prefix) is str and type(limit) is int and 0 < limit <= MAX_MEMBERS,
                "Continuity component member bound differs")
        if prefix:
            path = PurePosixPath(prefix.removesuffix('/'))
            require(prefix.endswith('/') and not path.is_absolute() and path.parts
                    and '..' not in path.parts and '\\' not in prefix and str(path) + '/' == prefix,
                    "Continuity component prefix is not canonical")
    require(all(not p.startswith(q) for p in prefixes for q in prefixes if p != q),
            "Continuity component prefixes overlap")
    namespaces = {p.split('/', 1)[0] for p in prefixes}
    counts = dict.fromkeys(components, 0)
    for name in names:
        selected = [p for p in prefixes if name.startswith(p)]
        if selected:
            prefix = selected[0]
        else:
            require('' in components and name.split('/', 1)[0] not in namespaces,
                    "Continuity package contains an unknown component")
            prefix = ''
        counts[prefix] += 1
    for prefix, limit in components.items():
        require(0 < counts[prefix] <= limit,
                f"Continuity component member count differs: {prefix or 'consumer'} ({counts[prefix]}, limit {limit})")


def archive(files: dict[str, bytes], *, components: dict[str, int] | None = None) -> bytes:
    _admit_members(list(files), components)
    require(sum(map(len, files.values())) <= MAX_PACKAGE, "Continuity expanded package exceeds bound")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            zipped.writestr(entry, data)
    result = output.getvalue()
    require(len(result) <= MAX_PACKAGE, "Continuity package exceeds bound")
    return result


def unpack(data: bytes, expected: dict[str, str], destination: Path, *,
           components: dict[str, int] | None = None) -> None:
    require(len(data) <= MAX_PACKAGE and not destination.exists(), "Continuity package input or destination differs")
    with zipfile.ZipFile(io.BytesIO(data)) as zipped:
        entries = zipped.infolist()
        names = [entry.filename for entry in entries]
        require(len(names) == len(set(names)) and set(names) == set(expected),
                    "Continuity package file set differs")
        _admit_members(names, components)
        require(sum(entry.file_size for entry in entries) <= MAX_PACKAGE, "Continuity expanded package exceeds bound")
        selected = {}
        for entry in entries:
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and path.parts and ".." not in path.parts
                        and "\\" not in entry.filename and str(path) == entry.filename
                        and stat.S_ISREG(entry.external_attr >> 16) and not entry.flag_bits & 1,
                        "Continuity package entry is not a canonical regular file")
            content = zipped.read(entry)
            require(hashlib.sha256(content).hexdigest() == expected[entry.filename], "Continuity package file hash differs")
            selected[path] = content
    destination.mkdir(mode=0o700)
    for name, content in selected.items():
        path = destination.joinpath(*name.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
        path.chmod(0o644)
