"""Build one relocatable Apple static archive with only the qpc-owner ABI visible."""
from pathlib import Path
import re

import continuity_c_consumer as owner
import rust_sdk_profile as sdk


def common_storage(symbols: bytes) -> bytes:
    """Allocate Mach-O tentative definitions before making them local to the object."""
    assembly = []
    for line in symbols.splitlines():
        if b" (common) " not in line:
            continue
        match = re.fullmatch(
            rb"([0-9a-fA-F]+) \(common\) \(alignment 2\^([0-9]+)\) "
            rb"(?:private )?external (_[A-Za-z0-9_.$]+)", line.strip())
        sdk.require(match is not None, "unrecognized Mach-O tentative definition")
        size, alignment, name = match.groups()
        sdk.require(int(size, 16) > 0 and int(alignment) <= 15, "invalid Mach-O common storage")
        symbol = name.decode("ascii")
        assembly.extend((f".globl {symbol}", f".zerofill __DATA,__common,{symbol},{int(size, 16)},{int(alignment)}"))
    return "".join(line + "\n" for line in assembly).encode("ascii")


def verify_public_symbols(data: bytes) -> None:
    # BSD nm -gU lists every defined external, including private externs and
    # common symbols. The published owner entry points must all be functions.
    expected = {"_" + name for name in owner.EXPORTS}
    names = []
    for line in data.decode("ascii").splitlines():
        if not line.strip() or line.endswith(":"):
            continue
        fields = line.split()
        sdk.require(len(fields) == 3 and fields[1] == "T", "unexpected external in Apple owner archive")
        names.append(fields[2])
    sdk.require(len(names) == len(expected) and set(names) == expected, "Apple owner public symbol set differs")


def isolate_archive(source: Path, work: Path, arch: str, platform: tuple, run) -> Path:
    """Resolve references between archive members before restricting their visibility."""
    work.mkdir(parents=True)
    sdk_name, link_platform, minimum = {
        ("macos", None): ("macosx", "macos", "13.0"),
        ("ios", None): ("iphoneos", "ios", "16.0"),
        ("ios", "simulator"): ("iphonesimulator", "ios-simulator", "16.0"),
    }[platform]

    def tool(args: list[str], label: str) -> bytes:
        return run(["/usr/bin/xcrun", "--sdk", sdk_name, *args], work.name + "-" + label, work)

    exports = sorted("_" + name for name in owner.EXPORTS)
    (work / "exports.txt").write_text("".join(name + "\n" for name in exports), encoding="ascii")
    sdk_version = tool(["--show-sdk-version"], "sdk-version").decode("ascii").strip()
    link = ["ld", "-r", "-S", "-arch", arch, "-platform_version", link_platform, minimum, sdk_version,
            "-exported_symbols_list", "exports.txt"]
    roots = [arg for name in exports for arg in ("-u", name)]
    tool([*link, *roots, str(source), "-o", "owner.rel.o"], "resolve")

    # Export lists alone leave tentative globals coalescible with another Rust
    # staticlib. Give each its original size and alignment, then localize it.
    definitions = common_storage(tool(["nm", "-m", "-gU", "owner.rel.o"], "definitions"))
    if definitions:
        (work / "common.s").write_bytes(definitions)
        triple = f"{arch}-apple-{platform[0]}{minimum}" + ("-simulator" if platform[1] else "")
        tool(["clang", "-target", triple, "-c", "common.s", "-o", "common.o"], "common")
        tool([*link, "owner.rel.o", "common.o", "-o", "CQPCOwner.o"], "localize")
    else:
        (work / "owner.rel.o").rename(work / "CQPCOwner.o")
    tool(["libtool", "-static", "-D", "-o", source.name, "CQPCOwner.o"], "archive")
    verify_public_symbols(tool(["nm", "-gU", source.name], "public-symbols"))
    return work / source.name
