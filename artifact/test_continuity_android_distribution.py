"""Synthetic structural controls; these do not build or execute Android code."""
from __future__ import annotations

import copy
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import continuity_android_classes as classes
import continuity_android_distribution as aar
import continuity_release_manifest as release
from evidence_io import EvidenceIOError


def class_bytes(name: str, methods: list[tuple[str, str, int]] = ()) -> bytes:
    pool = []
    def utf(value):
        encoded = value.encode()
        pool.append(b"\x01" + struct.pack(">H", len(encoded)) + encoded)
        return len(pool)
    identity = utf(name); pool.append(b"\x07" + struct.pack(">H", identity)); this = len(pool)
    parent = utf("java/lang/Object"); pool.append(b"\x07" + struct.pack(">H", parent)); parent = len(pool)
    code = utf("Code")
    records = []
    for method, descriptor, flags in methods:
        attributes = b""
        count = 0
        if not flags & (0x0100 | 0x0400):
            instructions = b"\xb1" if descriptor.endswith("V") else b"\x03\xac"
            body = struct.pack(">HHI", 1, 16, len(instructions)) + instructions + b"\x00\x00\x00\x00"
            attributes = struct.pack(">HI", code, len(body)) + body
            count = 1
        records.append(struct.pack(">HHHH", flags, utf(method), utf(descriptor), count) + attributes)
    return (b"\xca\xfe\xba\xbe\x00\x00\x00\x37" + struct.pack(">H", len(pool) + 1) + b"".join(pool)
            + struct.pack(">HHHHHH", 0x0030, this, parent, 0, 0, len(records))
            + b"".join(records) + b"\x00\x00")


def native_bytes() -> bytes:
    data = bytearray(512)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 183, 1, 0, 64, 128, 0, 64, 56, 1, 64, 3, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, len(data), len(data), 16384)
    names = b"\0.shstrtab\0.note.android.ident\0"
    data[320:320 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 192, 1, 3, 0, 0, 320, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 256, 11, 7, 0, 0, 352, 152, 0, 0, 4, 0)
    struct.pack_into("<III", data, 352, 8, 132, 1)
    data[364:372] = b"Android\0"
    struct.pack_into("<I", data, 372, 23)
    data[376:379] = b"r29"
    data[440:448] = b"14206865"
    return bytes(data)


def license_bytes() -> bytes:
    name = "THIRD_PARTY/rust/fixture-1.0.0/LICENSE"
    text = b"Synthetic license fixture; not a distributed dependency.\n"
    inventory = {"schema_version": 1, "kind": "qperiapt.third_party_rust_licenses",
        "root_package": "q-periapt-continuity-c-consumer", "target": aar.TARGET,
        "packages": [{"name": "fixture", "version": "1.0.0", "source": "registry+fixture", "checksum": "f" * 64,
                      "license_expression": "MIT", "license_files": [aar.reference(name, text)]}]}
    return aar.zip_bytes({name: text, "THIRD_PARTY/rust/INVENTORY.json": aar.canonical(inventory)})


def readelf_output(library: str) -> bytes:
    needed = ["libc.so", "libdl.so"] + ([aar.C_LIBRARY] if library == aar.JNI_LIBRARY else [])
    return ("LOAD 0x0 0x0 0x0 0x200 0x200 R E 0x4000\n"
            "GNU_RELRO 0x0 0x0 0x0 0x0 0x0 R 0x0\n"
            "GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x0\n"
            " [1] .dynsym DYNSYM\n"
            f" 0x000e (SONAME) Library soname: [{library}]\n"
            + "".join(f" 0x0001 (NEEDED) Shared library: [{name}]\n" for name in needed)
            + " 0x001e (FLAGS) BIND_NOW\n").encode()


class DistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_paths = sorted(path.relative_to(aar.ROOT).as_posix()
                                  for path in (aar.ROOT / aar.ADAPTER / "src/main/java").rglob("*.java"))
        cls.contract = aar.source_contract(cls.source_paths)
        cls.registered, cls.callbacks = classes.jni_contract(cls.contract["bridge"])
        cls.native_methods = [(name, descriptor, 0x010a) for name, descriptor in cls.registered.items()]
        cls.callback_methods = [(name, descriptor, 0x000a) for name, descriptor in cls.callbacks.items()]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = {"commit": "a" * 40, "tree": "d" * 40, "tree_sha256": "b" * 64}
        self.classes = {name.removesuffix(".java") + ".class": class_bytes(name.removesuffix(".java"))
                        for name in self.contract["java"]}
        self.native_class = "dev/qperiapt/continuity/android/Native.class"
        self.classes[self.native_class] = class_bytes(self.native_class[:-6], self.native_methods + self.callback_methods)
        self.inputs = {"c": native_bytes(), "jni": native_bytes(), "classes": aar.zip_bytes(self.classes),
                       "licenses": license_bytes()}
        self.selection = {"schema_version": 1, "kind": aar.INPUT_KIND, "name": aar.NAME, "version": aar.VERSION,
                          "abi": aar.ABI, "target": aar.TARGET, "source": self.source, "native_package_id": "continuity-native",
                          "native": {role: aar.reference(role + ".so", self.inputs[role]) for role in ("c", "jni")},
                          "classes": aar.reference("classes.jar", self.inputs["classes"]),
                          "licenses": aar.reference("licenses.zip", self.inputs["licenses"])}
        for role, package, artifacts, toolchain in (
            ("native", "q-periapt-continuity", {**self.selection["native"], "licenses": self.selection["licenses"]},
             {"rust": "1.98.1", "ndk": aar.NDK, "target": aar.TARGET}),
            ("classes", aar.NAME, {"classes": self.selection["classes"]}, {"java_major": 25, "release": 11}),
        ):
            self.inputs[role + "_receipt"] = aar.canonical({"schema_version": 1,
                "kind": f"qperiapt.continuity_android_{role}_build", "completed": True,
                "source": self.source, "package": {"name": package, "version": aar.VERSION},
                "artifacts": artifacts, "toolchain": toolchain})
            self.selection[role + "_receipt"] = aar.reference(role + "-build.json", self.inputs[role + "_receipt"])
        self.write_inputs()

    def write_inputs(self):
        refs = {**self.selection["native"], **{key: self.selection[key]
                for key in ("classes", "licenses", "native_receipt", "classes_receipt")}}
        for key, ref in refs.items():
            path = self.root / ref["path"]; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.inputs[key])

    def validate(self, selection=None):
        data = aar.canonical(self.selection if selection is None else selection)
        return aar.validate_selection(data, self.root, expected_sha256=aar.sha(data), source=self.source)

    def tools(self, argv, **kwargs):
        self.assertEqual(kwargs["environment"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"})
        library = Path(argv[-1]).name
        exports = self.contract["exports"] if library == aar.C_LIBRARY else {"JNI_OnLoad"}
        output = ("".join(name + " T 0 1\n" for name in sorted(exports)).encode()
                  if "llvm-nm" in argv[0] else readelf_output(library))
        return SimpleNamespace(returncode=0, stdout=output, stderr=b"")

    def verify(self, entries=None, inputs=None):
        selected = self.inputs if inputs is None else inputs
        if entries is None:
            entries = aar.zip_entries(aar.make_aar(self.selection, selected, self.contract), canonical_aar=True)
        with mock.patch.object(aar, "capture_output", side_effect=self.tools):
            return aar.verify_contents(entries, self.selection, selected, self.contract,
                                       {name: Path(name) for name in ("llvm-nm", "llvm-readelf")})

    def test_current_source_contract_and_synthetic_package_pass(self):
        selection, contents = self.validate()
        self.assertEqual(selection, self.selection); self.assertEqual(contents, self.inputs)
        result = self.verify()
        self.assertEqual(result["native"]["c"]["exports"], 158)
        self.assertEqual(result["classes"]["native_methods"], 23)
        self.assertEqual(len(self.contract["java"]), 68)
        self.assertEqual(result["classes"]["callbacks"], self.callbacks)

    def test_vendored_mlkem_notices_are_required_exact_current_source_bytes(self):
        entries = aar.zip_entries(aar.make_aar(self.selection, self.inputs, self.contract), canonical_aar=True)
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md"):
            path = "META-INF/licenses/mlkem-native/" + name
            self.assertEqual(entries[path], (aar.ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name).read_bytes())
            missing = dict(entries); del missing[path]
            with self.subTest(name=name, change="missing"), self.assertRaises(ValueError): self.verify(missing)
            replaced = {**entries, path: b"unrelated notice"}
            with self.subTest(name=name, change="replaced"), self.assertRaises(ValueError): self.verify(replaced)

    def test_selection_rejects_legacy_version_source_and_extra_fields_after_rehash(self):
        for key, value in (("version", "0.0.0"), ("abi", "sdk/2"), ("target", "x86_64-linux-android"),
                           ("source", {**self.source, "commit": "c" * 40}), ("schema_version", True), ("extra", 1)):
            with self.subTest(key=key):
                selection = copy.deepcopy(self.selection); selection[key] = value
                with self.assertRaises(ValueError): self.validate(selection)

    def test_independent_selection_pin_and_actual_input_bytes_must_match(self):
        data = aar.canonical(self.selection)
        with self.assertRaisesRegex(ValueError, "selection digest"):
            aar.validate_selection(data, self.root, expected_sha256="0" * 64, source=self.source)
        (self.root / "c.so").write_bytes(b"substituted")
        with self.assertRaisesRegex(ValueError, "input bytes differ"): self.validate()

    def test_compilation_receipt_rejects_rebound_legacy_incomplete_or_mismatched_inputs(self):
        original = aar.parse_strict_json_bytes(self.inputs["native_receipt"], label="fixture")
        for change in ({"package": {"name": "q-periapt-continuity", "version": "0.0.0"}},
                       {"completed": False}, {"completed": 1}, {"failure": "failed"},
                       {"source": {**self.source, "commit": "c" * 40}},
                       {"artifacts": {**original["artifacts"], "c": self.selection["native"]["jni"]}},
                       {"toolchain": {**original["toolchain"], "ndk": "29.0.1"}}):
            with self.subTest(change=change):
                data = aar.canonical({**original, **change})
                (self.root / "native-build.json").write_bytes(data)
                selection = copy.deepcopy(self.selection)
                selection["native_receipt"] = aar.reference("native-build.json", data)
                with self.assertRaisesRegex(ValueError, "compilation receipt"): self.validate(selection)

    def test_pin_paths_reject_alias_traversal_and_symlink(self):
        for name in ("../outside", "/tmp/absolute", "nested//input", "./c.so"):
            with self.subTest(name=name), self.assertRaises(ValueError): aar.safe_path(name)
        selected = copy.deepcopy(self.selection); selected["native"]["jni"] = selected["native"]["c"]
        with self.assertRaisesRegex(ValueError, "alias"): self.validate(selected)
        (self.root / "c.so").unlink(); (self.root / "c.so").symlink_to(self.root / "jni.so")
        with self.assertRaises(EvidenceIOError): self.validate()

    def test_class_parser_rejects_wrong_version_truncation_and_trailing_bytes(self):
        original = self.classes[self.native_class]
        for data in (original[:7] + b"\x45" + original[8:], original[:-1], original + b"trailer",
                     b"\xca\xfe\xba\xbe\x00\x00\x00\x37\x00\x02\x05" + b"\0" * 8):
            with self.subTest(size=len(data)), self.assertRaises(ValueError): classes.class_identity(data)

    def test_class_reader_rejects_jni_descriptor_static_and_callback_drift(self):
        method, descriptor, flags = self.native_methods[0]
        variants = [self.native_methods[1:] + self.callback_methods,
                    [(method, "()V", flags)] + self.native_methods[1:] + self.callback_methods,
                    [(method, descriptor, flags & ~8)] + self.native_methods[1:] + self.callback_methods,
                    self.native_methods + self.callback_methods[1:],
                    self.native_methods + [(name, descriptor, 0x010a) for name, descriptor in self.callbacks.items()]]
        for methods in variants:
            with self.subTest(methods=len(methods)):
                entries = {**self.classes, self.native_class: class_bytes(self.native_class[:-6], methods)}
                with self.assertRaises(ValueError): classes.verify_classes(entries, set(self.contract["java"]), self.contract["bridge"])

    def test_class_reader_rejects_extra_native_missing_class_and_wrong_path(self):
        ordinary = next(name for name in self.classes if name != self.native_class)
        variants = [dict(self.classes), dict(self.classes), dict(self.classes)]
        variants[0][ordinary] = class_bytes(ordinary[:-6], [("surprise", "()V", 0x010a)])
        del variants[1][ordinary]
        variants[2][ordinary] = class_bytes("dev/qperiapt/other/Substitution")
        for entries in variants:
            with self.subTest(entries=len(entries)), self.assertRaises(ValueError):
                classes.verify_classes(entries, set(self.contract["java"]), self.contract["bridge"])

    def test_aar_exact_inventory_rejects_additional_abi_loader_metadata_rules_and_license_changes(self):
        original = aar.zip_entries(aar.make_aar(self.selection, self.inputs, self.contract), canonical_aar=True)
        for name, data in (("jni/x86_64/extra.so", native_bytes()), ("proguard.txt", b""),
                           ("AndroidManifest.xml", aar.MANIFEST.replace(b"0.2.0", b"0.0.0")),
                           (aar.METADATA, b"{}"), ("META-INF/licenses/MIT.txt", b"substituted")):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "exact member inventory"):
                self.verify({**original, name: data})

    def test_archive_reader_rejects_unsafe_entry_and_noncanonical_outer_framing(self):
        with self.assertRaises(aar.elf.AndroidVerificationError): aar.zip_bytes({"../outside": b"x"})
        encoded = aar.make_aar(self.selection, self.inputs, self.contract)
        for data in (b"prefix" + encoded, encoded + b"trailer"):
            with self.subTest(size=len(data)), self.assertRaises(aar.elf.AndroidVerificationError): aar.zip_entries(data, canonical_aar=True)

    def test_license_inventory_rejects_rehashed_text_mutation(self):
        licenses = aar.zip_entries(self.inputs["licenses"])
        licenses["THIRD_PARTY/rust/fixture-1.0.0/LICENSE"] = b"changed license\n"
        inputs = {**self.inputs, "licenses": aar.zip_bytes(licenses)}
        with self.assertRaisesRegex(ValueError, "license bytes differ"): self.verify(inputs=inputs)

    def test_android_note_and_load_geometry_reject_actual_binary_mutations(self):
        original = native_bytes()
        self.assertEqual(aar.android_note(original), {"compile_api": 23, "ndk": aar.NDK})
        self.assertEqual(aar.load_segments(original), 1)
        for offset, fmt, value in ((372, "<I", 24), (376, "<B", ord("x")), (440, "<B", ord("0")), (356, "<I", 131)):
            data = bytearray(original); struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError): aar.android_note(bytes(data))
        for offset, value in ((112, 0x1000), (112, 0x6000), (80, 0x1000), (96, 513), (104, 511)):
            data = bytearray(original); struct.pack_into("<Q", data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError): aar.load_segments(bytes(data))

    def test_native_reader_rejects_export_dependency_rpath_debug_and_tool_failure(self):
        original = self.tools
        def mutate(change):
            def run(argv, **kwargs):
                result = original(argv, **kwargs)
                return change(result, argv)
            return run
        def add(output):
            return lambda result, argv: SimpleNamespace(returncode=0, stderr=b"",
                stdout=result.stdout + output if "readelf" in argv[0] else result.stdout)
        mutations = [add(b" 0x1 (NEEDED) Shared library: [libunexpected.so]\n"),
                     add(b" 0x1d (RUNPATH) Library runpath: [/tmp/private]\n"), add(b" [2] .debug_info PROGBITS\n"),
                     lambda result, argv: SimpleNamespace(returncode=1, stdout=result.stdout, stderr=b""),
                     lambda result, argv: SimpleNamespace(returncode=0, stdout=result.stdout, stderr=b"warning"),
                     lambda result, argv: SimpleNamespace(returncode=0, stderr=b"", stdout=result.stdout + b"unexpected T 0 1\n"
                         if "llvm-nm" in argv[0] else result.stdout)]
        path = self.root / aar.C_LIBRARY; path.write_bytes(native_bytes())
        for index, change in enumerate(mutations):
            with self.subTest(index=index), mock.patch.object(aar, "capture_output", side_effect=mutate(change)), self.assertRaises((ValueError, aar.elf.AndroidVerificationError)):
                aar.verify_native(path, role="c", tools={name: Path(name) for name in ("llvm-nm", "llvm-readelf")},
                                  exports=self.contract["exports"])

    def test_maven_reader_rejects_rehashed_wrong_coordinates_sources_and_extra_files(self):
        encoded = aar.make_aar(self.selection, self.inputs, self.contract)
        original = aar.maven_files(encoded, self.contract)
        aar.verify_maven(original, encoded, self.contract)
        for suffix in (".pom", "-sources.jar"):
            files = dict(original); name = f"{aar.MAVEN}/{aar.PREFIX}{suffix}"
            files[name] = (files[name].replace(b"0.2.0", b"0.0.0") if suffix == ".pom"
                           else aar.zip_bytes({"Unexpected.java": b"class Unexpected {}"}))
            for algorithm in ("md5", "sha1", "sha256", "sha512"):
                files[name + "." + algorithm] = (aar.hashlib.new(algorithm, files[name]).hexdigest() + "\n").encode()
            with self.subTest(suffix=suffix), self.assertRaises(ValueError): aar.verify_maven(files, encoded, self.contract)
        with self.assertRaises(ValueError): aar.verify_maven({**original, "maven/extra": b"x"}, encoded, self.contract)

    def capsule(self):
        encoded = aar.make_aar(self.selection, self.inputs, self.contract)
        files = aar.maven_files(encoded, self.contract)
        files["PACKAGE_IDENTITY.json"] = aar.canonical(aar.distribution_identity(self.selection, files))
        selection_data = aar.canonical(self.selection)
        files.update({"INPUT_SELECTION.json": selection_data, "native-build.json": self.inputs["native_receipt"],
                      "classes-build.json": self.inputs["classes_receipt"]})
        result = {"schema_version": 1, "kind": "qperiapt.continuity_android_distribution", "completed": True,
                  "tool_sha256": {"llvm-nm": "c" * 64, "llvm-readelf": "d" * 64}, "physical_device_executed": False}
        # Minimal synthetic result tests capsule equality; execute() supplies all
        # fixed identity, provenance and static verification fields in production.
        record = {**result, "files": {name: aar.reference(name, data) for name, data in sorted(files.items())}}
        return record, result, files, selection_data

    def test_capsule_readback_binds_all_files_claims_and_receipts(self):
        record, result, files, selection_data = self.capsule()
        output = self.root / "capsule"
        aar.write_capsule(output, record, files, selection_data=selection_data, inputs=self.inputs, contract=self.contract)
        observed, contents = aar.read_capsule(output, aar.sha(aar.canonical(record)))
        aar.verify_capsule_record(observed, contents, result=result, selection_data=selection_data,
                                  inputs=self.inputs, contract=self.contract)
        with self.assertRaisesRegex(ValueError, "receipt digest"):
            aar.read_capsule(output, "0" * 64)
        for change in ({"physical_device_executed": True}, {"completed": 1}, {"extra": "claim"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                aar.verify_capsule_record({**observed, **change}, contents, result=result, selection_data=selection_data,
                                          inputs=self.inputs, contract=self.contract)
        (output / "unrecorded").write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "unexpected capsule file"):
            aar.read_capsule(output, aar.sha(aar.canonical(record)))

    def test_failed_capsule_write_cleans_only_owned_output(self):
        record, _, files, selection_data = self.capsule(); output = self.root / "capsule"
        retained = self.root / "retained"; retained.write_bytes(b"retained")
        with mock.patch.object(aar, "verify_capsule_record", side_effect=ValueError("injected readback failure")):
            with self.assertRaisesRegex(ValueError, "injected readback failure"):
                aar.write_capsule(output, record, files, selection_data=selection_data, inputs=self.inputs, contract=self.contract)
        self.assertFalse(output.exists()); self.assertEqual(retained.read_bytes(), b"retained")
        output.mkdir(); (output / "existing").write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            aar.write_capsule(output, record, files, selection_data=selection_data, inputs=self.inputs, contract=self.contract)
        self.assertEqual((output / "existing").read_bytes(), b"existing")

    def source_fixture(self):
        root = self.root / "source"; root.mkdir()
        (root / ".gitignore").write_text("target/\n")
        for relative, data in self.contract["pinned"].items():
            path = root / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        for command in (["git", "init", "-q", str(root)], ["git", "-C", str(root), "add", "."],
                        ["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@invalid.local",
                         "commit", "-qm", "fixture"]):
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return root

    def test_consumed_source_replace_read_restore_changes_bound_digest(self):
        root = self.source_fixture()
        with mock.patch.object(aar, "ROOT", root):
            paths = aar.repository_paths(root)
            original = aar.source_identity(paths=paths)
            selected = root / self.source_paths[0]
            retained = selected.read_bytes()
            selected.write_bytes(retained + b"\n// transient source substitution\n")
            consumed = aar.source_contract(paths)
            selected.write_bytes(retained)
            self.assertEqual(aar.source_identity(paths=paths), original)
            self.assertNotEqual(aar.source_identity(paths=paths, pinned_files=consumed["pinned"]), original)

    def execution_fixture(self):
        root = self.source_fixture()
        with mock.patch.object(aar, "ROOT", root):
            source = aar.source_identity(paths=aar.repository_paths(root))
        self.selection["source"] = self.source = source
        for key in ("native_receipt", "classes_receipt"):
            receipt = aar.parse_strict_json_bytes(self.inputs[key], label="fixture")
            receipt["source"] = source
            self.inputs[key] = aar.canonical(receipt)
            self.selection[key] = aar.reference(self.selection[key]["path"], self.inputs[key])
        self.write_inputs()
        selection_data = aar.canonical(self.selection)
        (self.root / "INPUT_SELECTION.json").write_bytes(selection_data)
        directory = self.root / "inspection-fixture"; directory.mkdir()
        tools = {}
        for name in ("llvm-nm", "llvm-readelf"):
            tools[name] = directory / name
            tools[name].write_bytes(b"Synthetic inspection double; never executed.\n")
        args = SimpleNamespace(command="produce", output=root / "target/capsule", inputs=self.root,
                               selection="INPUT_SELECTION.json", selection_sha256=aar.sha(selection_data),
                               source_commit=source["commit"], source_tree=source["tree"],
                               source_tree_sha256=source["tree_sha256"], ndk=directory,
                               capsule=None, distribution_sha256=None)
        return root, args, tools

    def test_execute_produces_and_independently_reads_full_synthetic_capsule(self):
        root, args, tools = self.execution_fixture()
        with mock.patch.object(aar, "ROOT", root), mock.patch.object(aar, "native_tools", return_value=tools), \
                mock.patch.object(aar, "capture_output", side_effect=self.tools):
            produced = aar.execute(args)
            self.assertTrue(produced["completed"])
            self.assertEqual(len(produced["files"]), 19)
            self.assertFalse(produced["native_compilation_executed"])
            self.assertFalse(produced["physical_device_executed"])
            output = args.output
            document = (output / "PACKAGE_IDENTITY.json").read_bytes()
            identity = aar.parse_strict_json_bytes(document, label="fixture distribution identity")
            row = {"id": "continuity-android", "role": "android", "format": "distribution", "workspace": None,
                   "metadata": aar.reference("PACKAGE_IDENTITY.json", document), **identity}
            release._package_identity(row, release.Inputs(output), {}, {}, {key: self.source[key] for key in ("commit", "tree")})
            args.command, args.output, args.capsule = "verify", None, output
            args.distribution_sha256 = aar.sha((output / "DISTRIBUTION.json").read_bytes())
            verified = aar.execute(args)
            self.assertEqual(verified["aar"], produced["aar"])
            self.assertEqual(verified["verification"], produced["verification"])

    def test_execute_rejects_input_or_selection_changes_after_capture(self):
        root, args, tools = self.execution_fixture()
        initial_selection = (self.root / "INPUT_SELECTION.json").read_bytes()
        for changed in ("c.so", "INPUT_SELECTION.json"):
            self.write_inputs(); (self.root / "INPUT_SELECTION.json").write_bytes(initial_selection)
            called = False
            def inspecting(argv, **kwargs):
                nonlocal called
                if not called:
                    (self.root / changed).write_bytes(b"changed after selected snapshot\n")
                    called = True
                return self.tools(argv, **kwargs)
            with self.subTest(changed=changed), mock.patch.object(aar, "ROOT", root), \
                    mock.patch.object(aar, "native_tools", return_value=tools), \
                    mock.patch.object(aar, "capture_output", side_effect=inspecting):
                with self.assertRaisesRegex(ValueError, "input bytes differ|input selection changed"):
                    aar.execute(args)
            self.assertFalse(args.output.exists())

    def test_selected_source_inventory_cannot_silently_omit_temporarily_missing_java(self):
        root = self.source_fixture()
        with mock.patch.object(aar, "ROOT", root):
            paths = aar.repository_paths(root)
            original = aar.source_identity(paths=paths)
            selected = root / self.source_paths[0]
            retained = selected.read_bytes(); selected.unlink()
            try:
                with self.assertRaises(EvidenceIOError): aar.source_contract(paths)
            finally:
                selected.write_bytes(retained)
            self.assertEqual(aar.source_identity(paths=paths), original)


if __name__ == "__main__":
    unittest.main()
