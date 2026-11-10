#!/usr/bin/env python3
"""Read selected SDK image components as data; never boot, mount or execute them.

The guest cannot read lmkd on current API 35 images. This separate diagnostic
records the installed image, its selected AVD config (when supplied), and the
exact lmkd/build.prop bytes. It is not proof of the running process's identity.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct

from android_runtime_state import registered_sdk_root
from bounded_process import capture_output
from evidence_io import consume_regular_snapshot, read_regular_snapshot

TOOL_HASHES = frozenset({
    "74b0910e50ea44d9760a57fada2192cfd530ba8bffbe7b47c412a464b796cabf",  # 26.03 macOS
    "3d52c92deb7e9f1bd059692eefc33f86a144cdc548acc4b6f4c809a4dd7bc369",  # 26.03 Linux x64
})
LICENSE_HASH = "1790374e5352329cedb46ee3808930a88e9ca2f08b82b10fcf5cf605d2c301b1"
MAX_IMAGE = 8 * 1024**3
MAX_COMPONENT = 4 * 1024**2
INPUT_LIMITS = {"system.img": MAX_IMAGE, "kernel-ranchu": 256 * 1024**2,
                "ramdisk.img": 256 * 1024**2, "source.properties": 65536}
COMPONENTS = ("system/bin/lmkd", "system/build.prop")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def properties(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in data.decode("utf-8", errors="strict").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        require("=" in line, "malformed properties line")
        key, value = (part.strip() for part in line.split("=", 1))
        require(bool(key) and key not in result, "empty or duplicate property")
        result[key] = value
    return result


def listing(data: bytes, expected_type: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    text = data.decode("utf-8", errors="strict").replace("\r\n", "\n")
    require(text.count("\n--\n") == 1 and text.count("\n----------\n") == 1,
            "archive listing sections differ")
    header, body = text.split("\n--\n", 1)[1].split("\n----------\n", 1)

    def fields(block: str, *, strict: bool) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in block.splitlines():
            if " = " not in line:
                require(not strict or not line.strip(), "unexpected archive entry line")
                continue
            key, value = line.split(" = ", 1)
            require(key not in result, "duplicate archive listing field")
            result[key] = value
        return result

    metadata = fields(header, strict=False)
    require(metadata.get("Type") == expected_type, "archive format differs")
    entries = []
    for block in body.strip("\n").split("\n\n"):
        block = block.strip("\n")
        if re.fullmatch(r"Warnings: [0-9]+", block):
            continue
        entry = fields(block, strict=True)
        require(bool(entry.get("Path")), "archive entry path missing")
        entries.append(entry)
    require(len({entry["Path"] for entry in entries}) == len(entries), "duplicate archive entry")
    return metadata, entries


def number(fields: dict[str, str], key: str) -> int:
    value = fields.get(key, "")
    require(re.fullmatch(r"[0-9]+", value) is not None, f"invalid archive {key}")
    return int(value)


def verify_layout(gpt: bytes, lp: bytes, ext: bytes, image_size: int) -> dict:
    gpt_header, partitions = listing(gpt, "GPT")
    require(number(gpt_header, "Physical Size") == image_size, "GPT image size differs")
    require(len(partitions) == 1 and re.fullmatch(r"[0-9]+\.super\.img", partitions[0]["Path"]) is not None,
            "selected GPT super partition differs")
    super_partition = partitions[0]
    super_offset, super_size = (number(super_partition, key) for key in ("Offset", "Size"))
    require(0 < super_offset < super_offset + super_size <= image_size, "super partition outside image")
    lp_header, logical = listing(lp, "LP")
    require(number(lp_header, "Offset") == super_offset and number(lp_header, "Physical Size") == super_size,
            "LP image does not match GPT super partition")
    require(len(logical) == 1 and logical[0]["Path"] == "system.img", "selected system partition differs")
    system = logical[0]
    require(system.get("Method") == "RAW" and number(system, "Blocks") == 1,
            "diagnostic requires one contiguous raw system extent")
    offset, size = number(system, "Offset"), number(system, "Size")
    require(0 < offset < offset + size <= super_size, "system extent outside super partition")
    ext_header, files = listing(ext, "Ext")
    require(number(ext_header, "Offset") == super_offset + offset,
            "scanned filesystem is not the selected system partition")
    require(0 < number(ext_header, "Physical Size") <= size, "filesystem exceeds system extent")
    require({item["Path"] for item in files} == set(COMPONENTS), "selected component files differ")
    for item in files:
        require(item.get("Folder") == "-" and item.get("Symbolic Link") == ""
                and item.get("Mode", "").startswith("-") and number(item, "Links") == 1,
                "component must be one regular file")
        require(0 < number(item, "Size") <= MAX_COMPONENT, "component size outside bound")
    return {"super": super_partition, "system": system, "filesystem": ext_header, "files": files}


def verify_avd(data: bytes, sdk: Path, abi: str) -> dict[str, str]:
    config = properties(data)
    relative = f"system-images/android-35/google_apis_ps16k/{abi}/"
    require(config.get("image.sysdir.1") in {relative, str(sdk / relative) + "/"},
            "AVD does not select the inspected image")
    require(config.get("abi.type") == abi, "AVD ABI differs")
    for key in ("image.sysdir.2", "disk.systemPartition.initPath", "disk.systemPartition.path",
                "disk.ramdisk.path", "kernel.path"):
        require(not config.get(key), f"AVD has an uninspected image override: {key}")
    return {key: config[key] for key in ("image.sysdir.1", "abi.type")}


def inspect(sdk: Path, abi: str, tool: Path, output: Path, avd_config: Path | None = None) -> dict:
    require(abi in {"arm64-v8a", "x86_64"}, "unsupported image ABI")
    require(not output.is_symlink() and output.parent.resolve(strict=True) == output.parent,
            "diagnostic output parent must be canonical")
    output.mkdir(mode=0o700)
    report: dict = {"schema": 1, "kind": "qperiapt.android_installed_image_runtime",
                    "started_utc": datetime.now(timezone.utc).isoformat(), "completed": False,
                    "release_claim_eligible": False, "abi": abi, "commands": [],
                    "scope": "installed SDK image and optional preboot AVD selection; not running-process attestation"}

    def digest(path: Path, maximum: int) -> dict:
        snapshot = consume_regular_snapshot(path, maximum=maximum, label="SDK image diagnostic input")
        require(snapshot.size > 0, "empty diagnostic input")
        return {"path": str(path), "bytes": snapshot.size, "sha256": snapshot.sha256}

    try:
        image_dir = sdk / "system-images/android-35/google_apis_ps16k" / abi
        image = image_dir / "system.img"
        inputs = {name: digest(image_dir / name, maximum) for name, maximum in INPUT_LIMITS.items()}
        report["inputs"] = inputs
        source = read_regular_snapshot(image_dir / "source.properties", maximum=65536, label="SDK properties").data
        props = properties(source)
        require(props.get("AndroidVersion.ApiLevel") == "35" and props.get("SystemImage.Abi") == abi,
                "SDK package API or ABI differs")
        require("page_size_16kb" in props.get("SystemImage.TagId", "").split(","), "SDK page-size tag differs")
        (output / "source.properties").write_bytes(source)
        if avd_config is not None:
            avd = read_regular_snapshot(avd_config, maximum=65536, label="selected AVD config")
            report["avd_selection"] = {"path": str(avd_config), "sha256": avd.sha256,
                                       "fields": verify_avd(avd.data, sdk, abi)}
        frozen_tool = read_regular_snapshot(tool, maximum=16 * 1024**2, label="image inspection tool")
        require(frozen_tool.sha256 in TOOL_HASHES, "7-Zip 26.03 executable digest differs")
        license_file = read_regular_snapshot(tool.parent / "License.txt", maximum=65536, label="tool license")
        require(license_file.sha256 == LICENSE_HASH, "tool license digest differs")
        (output / "7zz").write_bytes(frozen_tool.data)
        (output / "7zz").chmod(0o500)
        (output / "7zip-LICENSE.txt").write_bytes(license_file.data)
        report["tool_sha256"] = frozen_tool.sha256

        def command(name: str, mode: str, kind: str, paths: tuple[str, ...]) -> bytes:
            argv = [str(output / "7zz"), mode, "-t" + kind]
            argv += ["-slt"] if mode == "l" else ["-so"]
            argv += [str(image), *paths]
            entry = {"name": name, "argv": argv, "returncode": None}
            report["commands"].append(entry)
            result = capture_output(argv, timeout_seconds=30, maximum_stdout_bytes=MAX_COMPONENT,
                                    maximum_stderr_bytes=65536,
                                    environment={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
            entry["returncode"] = result.returncode
            with (output / name).open("xb") as out, (output / (name + ".stderr")).open("xb") as err:
                out.write(result.stdout)
                err.write(result.stderr)
            require(result.returncode == 0, f"image tool failed: {name}")
            return result.stdout

        gpt = command("gpt.txt", "l", "GPT", ("*.super.img",))
        lp = command("lp.txt", "l", "LP", ("system.img",))
        ext = command("ext.txt", "l", "Ext", COMPONENTS)
        report["layout"] = verify_layout(gpt, lp, ext, inputs["system.img"]["bytes"])
        for name, path in (("lmkd.elf", COMPONENTS[0]), ("build.prop", COMPONENTS[1])):
            data = command(name, "x", "Ext", (path,))
            expected = next(item for item in report["layout"]["files"] if item["Path"] == path)
            require(len(data) == number(expected, "Size"), "extracted component size differs")
        elf = (output / "lmkd.elf").read_bytes()
        require(len(elf) >= 64 and elf[:4] == b"\x7fELF" and elf[5] == 1, "lmkd is not little-endian ELF")
        machine = struct.unpack_from("<H", elf, 18)[0]
        require((elf[4], machine) in ({(1, 3), (2, 62)} if abi == "x86_64" else {(1, 40), (2, 183)}),
                "lmkd ELF architecture differs")
        build = properties((output / "build.prop").read_bytes())
        fingerprint = build.get("ro.system.build.fingerprint")
        require(bool(fingerprint), "system build fingerprint missing")
        report["system_build_fingerprint"] = fingerprint
        report["lmkd_elf_machine"] = machine
        require({name: digest(image_dir / name, maximum) for name, maximum in INPUT_LIMITS.items()} == inputs,
                "SDK input changed during inspection")
        if avd_config is not None:
            require(read_regular_snapshot(avd_config, maximum=65536, label="AVD config recheck").sha256
                    == report["avd_selection"]["sha256"], "AVD config changed during inspection")
        report["completed"] = True
    except BaseException as error:
        report["failure"] = {"kind": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        report["files_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in sorted(output.iterdir()) if path.is_file()}
        with (output / "REPORT.json").open("x") as stream:
            stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--abi", choices=("arm64-v8a", "x86_64"), required=True)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--avd-config", type=Path)
    args = parser.parse_args()
    report = inspect(registered_sdk_root(args.sdk), args.abi, args.tool, args.output, args.avd_config)
    print(json.dumps({"completed": report["completed"], "system_build_fingerprint": report["system_build_fingerprint"]}))


if __name__ == "__main__":
    main()
