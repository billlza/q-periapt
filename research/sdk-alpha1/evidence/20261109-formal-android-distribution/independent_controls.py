"""Independent structural/race controls for the formal Android distribution.

These controls use synthetic containers and copied source fixtures. They do not
compile or execute Android code and do not produce release evidence.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from unittest import mock
import warnings
import zipfile


def demand(condition, message):
    if not condition:
        raise AssertionError(message)


def rejects(action):
    try:
        action()
    except Exception as error:
        return type(error).__name__ + ": " + str(error)
    raise AssertionError("fault fixture was accepted")


def main():
    root = Path(sys.argv[1]).resolve(strict=True)
    sys.path.insert(0, str(root / "artifact"))
    import android_elf
    import continuity_android_classes as classes
    import continuity_android_distribution as distribution

    observations = {}
    required_headers = (
        "GNU_RELRO 0x0 0x0 0x0 0x100 0x100 R 0x1\n"
        "GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x0\n"
    )
    load = "LOAD 0x0 0x0 0x0 0x100 0x100 R E 0x4000\n"
    android_elf.verify_program_headers(load + required_headers, Path("fixture.so"))
    observations["shared_elf"] = {
        "valid_16k_accepted": True,
        "non_power_two_rejected": rejects(lambda: android_elf.verify_program_headers(
            load.replace("0x4000", "0x6000") + required_headers, Path("fixture.so"))),
        "incongruent_load_rejected": rejects(lambda: android_elf.verify_program_headers(
            "LOAD 0x1000 0x2000 0x2000 0x100 0x100 R E 0x4000\n" + required_headers,
            Path("fixture.so"))),
    }

    def archive(rows):
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as container:
                for name, mode in rows:
                    entry = zipfile.ZipInfo(name)
                    entry.create_system = 3
                    entry.external_attr = mode << 16
                    container.writestr(entry, b"abc")
        return stream.getvalue()

    regular = stat.S_IFREG | 0o644
    archive_faults = {
        "duplicate": [("a", regular), ("a", regular)],
        "case_alias": [("a", regular), ("A", regular)],
        "parent_traversal": [("../a", regular)],
        "backslash": [("a\\b", regular)],
        "symlink": [("a", stat.S_IFLNK | 0o777)],
        "directory": [("a/", stat.S_IFDIR | 0o755)],
    }
    observations["archives"] = {
        name: rejects(lambda encoded=archive(rows): distribution.zip_entries(encoded))
        for name, rows in archive_faults.items()
    }
    with mock.patch.object(distribution, "MAX_ENTRY", 2):
        observations["archives"]["entry_size"] = rejects(
            lambda: distribution.zip_entries(archive([("a", regular)])))
    with mock.patch.object(distribution, "MAX_MEMBERS", 1):
        observations["archives"]["member_count"] = rejects(
            lambda: distribution.zip_entries(archive([("a", regular), ("b", regular)])))

    adapter = distribution.ADAPTER
    java_prefix = adapter + "/src/main/java/"
    source_paths = sorted(path.relative_to(root).as_posix()
                          for path in (root / adapter / "src/main/java").rglob("*.java"))
    source_paths += [
        "research/continuity-identity-candidate/Cargo.toml",
        distribution.CONSUMER + "/qpc_owner.h",
        distribution.CONSUMER + "/" + distribution.c_abi.CONTRACT,
        adapter + "/consumer-rules.pro", adapter + "/jni/continuity_jni.c",
        "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt", "LICENSES/Rust-1.98.1-library.html",
    ]
    with tempfile.TemporaryDirectory(prefix="independent-android-source-") as temporary:
        fixture = Path(temporary)
        for relative in source_paths:
            destination = fixture / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, destination)
        subprocess.run(["git", "init", "-q", str(fixture)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(fixture), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(fixture), "-c", "user.name=Independent control",
                        "-c", "user.email=control@example.invalid", "commit", "-qm", "source fixture"],
                       check=True, capture_output=True)
        with mock.patch.object(distribution, "ROOT", fixture):
            paths = distribution.repository_paths(fixture)
            selected = distribution.source_identity(paths=paths)
            contract = distribution.source_contract(paths)
            demand(distribution.source_identity(paths=paths, pinned_files=contract["pinned"]) == selected,
                   "unmodified consumed source differs")
            target = fixture / java_prefix / "dev/qperiapt/continuity/android/Native.java"
            original = target.read_bytes()
            actual_reader = distribution.read_regular_snapshot
            attacked = []

            def replace_read_restore(path, **kwargs):
                if path == target:
                    target.write_bytes(original + b"\n// independent transient snapshot fixture\n")
                    try:
                        snapshot = actual_reader(path, **kwargs)
                        attacked.append(snapshot.data)
                        return snapshot
                    finally:
                        target.write_bytes(original)
                return actual_reader(path, **kwargs)

            with mock.patch.object(distribution, "read_regular_snapshot", side_effect=replace_read_restore):
                changed_contract = distribution.source_contract(paths)
            changed_identity = distribution.source_identity(paths=paths, pinned_files=changed_contract["pinned"])
            demand(len(attacked) == 1 and attacked[0] != original, "content fixture did not mutate one capture")
            demand(target.read_bytes() == original, "content fixture did not restore selected source")
            demand(changed_identity != selected, "transient consumed-byte mutation escaped selected identity")

            omitted_relative = next(path for path in paths if path.startswith(java_prefix)
                                    and path.endswith(".java") and not path.endswith("/Native.java"))
            omitted = fixture / omitted_relative
            omitted_bytes = omitted.read_bytes()
            omitted.unlink()
            try:
                omission_result = rejects(lambda: distribution.source_contract(paths))
            finally:
                omitted.write_bytes(omitted_bytes)
            demand(distribution.source_identity(paths=paths) == selected, "omission fixture did not restore tree")
            short_paths = [path for path in paths if path != omitted_relative]
            short_contract = distribution.source_contract(short_paths)
            inventory_result = rejects(lambda: distribution.source_identity(
                paths=short_paths, pinned_files=short_contract["pinned"]))
            observations["source_binding"] = {
                "unmodified_source_matches": True,
                "java_sources": len(contract["java"]),
                "consumed_source_snapshots": len(contract["pinned"]),
                "replace_read_restore_changes_bound_digest": True,
                "restored_source_disk_matches_selected_identity": True,
                "captured_inventory_file_absence_rejected": omission_result.replace(str(fixture), "<source-fixture>"),
                "shortened_inventory_after_restore_rejected": inventory_result,
            }

    bridge = (root / adapter / "jni/continuity_jni.c").read_text()
    header = (root / adapter / "jni/bridge.h").read_text()
    native_java = (root / java_prefix / "dev/qperiapt/continuity/android/Native.java").read_text()
    rows = re.findall(r'\{"([A-Za-z][A-Za-z0-9_]*)", "([^"]+)", \(void \*\)([a-z_]+)\}', bridge)
    demand(len(rows) == 23, "registration inventory differs")
    c_types = {"jlong": "J", "jint": "I", "jboolean": "Z", "jobjectArray": "[[B",
               "jlongArray": "[J", "jobject": "Ljava/lang/Object;", "jbyteArray": "[B", "void": "V"}
    java_types = {"long": "J", "int": "I", "boolean": "Z", "byte[][]": "[[B", "long[]": "[J",
                  "Object": "Ljava/lang/Object;", "byte[]": "[B", "void": "V", "String": "Ljava/lang/String;"}
    for name, descriptor, function in rows:
        declaration = re.findall(r"(?m)^\s*(?:static\s+)?(jlong|jbyteArray|void)\s+" + re.escape(function)
                                 + r"\s*\((.*?)\)\s*(?:;|\{)", bridge + "\n" + header, re.S)
        demand(len(declaration) == 1, "C prototype must be unique: " + function)
        result, arguments = declaration[0]
        parameters = [argument.strip() for argument in arguments.split(",")]
        demand(re.match(r"^JNIEnv\s*\*", parameters[0]) and re.match(r"^jclass\b", parameters[1]),
               "JNI C receiver differs: " + function)
        actual = "(" + "".join(c_types[argument.split()[0]] for argument in parameters[2:]) + ")" + c_types[result]
        demand(actual == descriptor, "JNI descriptor differs from C prototype: " + name)
        declaration = re.findall(r"static\s+native\s+(\S+)\s+" + re.escape(name) + r"\(([^)]*)\);", native_java)
        demand(len(declaration) == 1, "Java native declaration must be unique: " + name)
        result, arguments = declaration[0]
        actual = "(" + "".join(java_types[argument.strip().split()[0]] for argument in arguments.split(",") if argument.strip()) + ")" + java_types[result]
        demand(actual == descriptor, "JNI descriptor differs from Java source declaration: " + name)
    _, callbacks = classes.jni_contract(bridge)
    for name, descriptor in callbacks.items():
        declarations = re.findall(r"private\s+static\s+(\S+)\s+" + re.escape(name) + r"\(([^)]*)\)\s*\{", native_java)
        demand(len(declarations) == 1, "Java callback declaration must be unique: " + name)
        result, arguments = declarations[0]
        actual = "(" + "".join(java_types[argument.strip().split()[0]] for argument in arguments.split(",") if argument.strip()) + ")" + java_types[result]
        demand(actual == descriptor, "JNI callback differs from Java source declaration: " + name)
    observations["jni_source_correspondence"] = {
        "registered_static_methods": len(rows), "c_prototypes_and_java_source_descriptors_match": True,
        "callback_descriptors_match_java_source": callbacks,
    }
    observations["reviewed_files"] = {
        relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
        for relative in ["artifact/continuity_android_distribution.py", "artifact/continuity_android_classes.py",
                         "artifact/android_elf.py", "artifact/test_continuity_android_distribution.py",
                         "artifact/test_android_elf.py", adapter + "/jni/continuity_jni.c", adapter + "/jni/bridge.h",
                         java_prefix + "dev/qperiapt/continuity/android/Native.java"]
    }
    observations["scope"] = "synthetic structural controls and copied-source race fixtures; no native compile or runtime"
    print(json.dumps(observations, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
