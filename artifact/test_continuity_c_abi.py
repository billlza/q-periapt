"""Header drift and incomplete compiled layout evidence must fail admission."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_abi as abi
import continuity_c_consumer as consumer


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = consumer.FIXTURE
        cls.header = (cls.fixture / "qpc_owner.h").read_text()
        cls.document = json.loads((cls.fixture / abi.CONTRACT).read_bytes())
        cls.contract = abi.load(cls.fixture)

    def check_copy(self, *, header=None, document=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "abi").mkdir()
            (root / abi.CONTRACT).write_text(json.dumps(self.document if document is None else document))
            (root / "qpc_owner.h").write_text(self.header if header is None else header)
            return abi.load(root)

    def test_complete_header_and_existing_export_census_agree(self):
        self.assertEqual(set(self.contract["functions"]), consumer.EXPORTS)
        self.assertEqual((len(self.contract["functions"]), len(self.contract["records"]),
                          len(self.contract["callbacks"]), len(self.contract["constants"])), (158, 70, 1, 112))

    def test_only_whitespace_and_comments_may_change_without_contract_review(self):
        header = self.header.replace("int32_t qpc_", "int32_t  /* declaration */\nqpc_")
        self.assertEqual(self.check_copy(header=header), self.contract)

    def test_parameter_width_pointer_constness_record_and_callback_changes_are_refused(self):
        mutations = [
            ("uint64_t parent, uint8_t id[32]", "uint32_t parent, uint8_t id[32]"),
            ("const uint8_t *root;", "uint8_t *root;"),
            ("int32_t code;", "uint32_t code;"),
            ("uint8_t message[512];", "uint8_t message[511];"),
            ("uint32_t length;\n    uint32_t truncated;", "uint32_t truncated;\n    uint32_t length;"),
            ("typedef int32_t (*qpc_commit_v1)", "typedef uint32_t (*qpc_commit_v1)"),
            ("QPC_CLOSED = 2", "QPC_CLOSED = 8"),
            ("QPC_CLOSURE_ARCHIVE_BYTES = 362", "QPC_CLOSURE_ARCHIVE_BYTES = 363"),
        ]
        for old, new in mutations:
            with self.subTest(change=new):
                self.assertIn(old, self.header)
                with self.assertRaisesRegex(ValueError, "reviewed declaration snapshot"):
                    self.check_copy(header=self.header.replace(old, new, 1))

    def test_added_omitted_duplicate_and_conditional_declarations_are_refused(self):
        signature = "int32_t qpc_owner_v1_close(uint64_t handle, qpc_error_v1 *error);"
        self.assertIn(signature, self.header)
        cases = [self.header.replace(signature, "", 1),
                 self.header.replace(signature, signature + "\n" + signature, 1),
                 self.header.replace(signature, signature + "\nint32_t qpc_unreviewed(void);", 1),
                 self.header.replace(signature, "#if 0\n" + signature + "\n#endif", 1),
                 self.header.replace("#include <stdint.h>", "#include <stdint.h>\n#pragma pack(1)"),
                 self.header.replace("#include <stdint.h>", "#include <stdint.h>\n#include <other.h>"),
                 self.header.replace("typedef struct {", "typedef struct __attribute__((packed)) {", 1)]
        for header in cases:
            with self.subTest(header=header[-100:]), self.assertRaises(ValueError):
                self.check_copy(header=header)

    def test_snapshot_cannot_claim_product_admission_or_different_identity(self):
        for key, value in (("schema_version", True), ("schema_version", 2),
                           ("abi", "2"), ("package_version", "0.0.0"),
                           ("frozen_product_contract", True), ("extra", 1)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check_copy(document=dict(self.document, **{key: value}))

    def test_probe_retains_all_real_symbol_references_and_field_observations(self):
        source = abi.c_probe(self.contract).decode()
        for function in consumer.EXPORTS:
            self.assertIn(f" = {function};", source)
            self.assertIn(f"if (probe_{function} == NULL)", source)
        for record, fields in self.contract["records"].items():
            for field in fields:
                self.assertIn(f"offsetof({record}, {field})", source)

    def test_reader_and_snapshot_are_bound_to_package_sources(self):
        import continuity_package as package
        inputs = package.source_inputs()["files"]
        for relative in ("artifact/continuity_c_abi.py", "artifact/test_continuity_c_abi.py",
                         "bindings/c/ContinuityPackageConsumer/" + abi.CONTRACT,
                         "bindings/c/ContinuityPackageConsumer/src/abi_contract.rs"):
            self.assertEqual(inputs[relative], consumer.sdk.snapshot(package.ROOT / relative).sha256)


class LayoutTests(unittest.TestCase):
    contract = {"records": {"qpc_example_v1": ["first", "second"]},
                "callbacks": {"qpc_commit_v1": "callback"},
                "field_types": {"qpc_example_v1": {"first": "u64", "second": "u32"}},
                "signatures": {"qpc_commit_v1": ["i32", "*mutcore::ffi::c_void"]}}
    report = (b"QPC_ABI target 8 8\nQPC_ABI qpc_commit_v1 8 8\n"
              b"QPC_ABI_FUNCTION qpc_commit_v1 i32 *mutcore::ffi::c_void\n"
              b"QPC_ABI qpc_example_v1 16 8 first:0:8:u64 second:8:4:u32\n")

    def native(self, report=None):
        return (f"\nrunning 1 test\ntest {abi.TEST} ... ".encode()
                + (self.report if report is None else report)
                + b"QPC_ABI_NATIVE qpc_example_v1 fixture::Example\n"
                + b"QPC_ABI_NATIVE qpc_commit_v1 core::option::Option<fixture::Callback>\n"
                + b"ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.00s\n")

    def test_both_compilers_must_report_the_same_complete_shape(self):
        abi.compare(abi.layouts(self.report, self.contract, rust=False),
                    abi.layouts(self.native(), self.contract, rust=True), self.contract)

    def test_missing_extra_duplicate_and_out_of_record_fields_are_refused(self):
        cases = [self.report.replace(b" second:8:4:u32", b""),
                 self.report.replace(b" second:8:4", b" second:14:4"),
                 self.report.replace(b" second:8:4", b" first:8:4"),
                 self.report.replace(b" second:8:4", b" second:4:4"),
                 self.report.replace(b" second:8:4:u32", b" second:8:4:u32 extra:12:4:u32"),
                 self.report.replace(b"qpc_example_v1", b"qpc_other_v1"),
                 self.report + self.report.splitlines(keepends=True)[0],
                 b"".join(self.report.splitlines(keepends=True)[1:]),
                 self.report.replace(b"16 8", b"16 3"),
                 self.report + b"warning: fabricated success\n"]
        for output in cases:
            with self.subTest(output=output), self.assertRaises(ValueError):
                abi.layouts(output, self.contract, rust=False)

    def test_skipped_or_failed_native_type_test_is_not_layout_evidence(self):
        for summary in (b"0 passed; 0 failed; 1 ignored", b"0 passed; 1 failed; 0 ignored",
                        b"2 passed; 0 failed; 0 ignored"):
            output = b"running 1 test\n" + self.report + b"test result: ok. " + summary + b"; 0 measured; 58 filtered out;\n"
            with self.subTest(summary=summary), self.assertRaises(ValueError):
                abi.layouts(output, self.contract, rust=True)

    def test_missing_identity_duplicate_or_contradictory_summaries_are_refused(self):
        original = self.native()
        summary = original.splitlines(keepends=True)[-1]
        for output in (original.replace(f"test {abi.TEST} ... ".encode(), b""),
                       original + summary,
                       original + b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.00s\n",
                       original.replace(b"QPC_ABI_NATIVE qpc_example_v1 fixture::Example\n", b""),
                       original.replace(b"QPC_ABI_FUNCTION qpc_commit_v1 i32 *mutcore::ffi::c_void\n", b"")):
            with self.subTest(output=output[-160:]), self.assertRaises(ValueError):
                abi.layouts(output, self.contract, rust=True)

    def test_same_size_field_function_and_callback_type_changes_are_refused(self):
        c = abi.layouts(self.report, self.contract, rust=False)
        for old, new in ((b"second:8:4:u32", b"second:8:4:i32"),
                         (b"i32 *mutcore::ffi::c_void", b"i32 *constcore::ffi::c_void"),
                         (b"qpc_commit_v1 i32", b"qpc_commit_v1 u32")):
            native = abi.layouts(self.native(self.report.replace(old, new)), self.contract, rust=True)
            with self.subTest(change=new), self.assertRaises(ValueError):
                abi.compare(c, native, self.contract)

    def test_pointer_to_array_extent_is_not_erased_when_both_sides_declare_it(self):
        contract = copy.deepcopy(self.contract)
        contract["signatures"]["qpc_commit_v1"] = ["i32", "*const[u8;32]"]
        c = abi.layouts(self.report.replace(b"*mutcore::ffi::c_void", b"*const[u8;32]"), contract, rust=False)
        for actual in (b"*const[u8;32]", b"*constu8"):
            native = abi.layouts(self.native(self.report.replace(b"*mutcore::ffi::c_void", actual)), contract, rust=True)
            abi.compare(c, native, contract)
        native = abi.layouts(self.native(self.report.replace(b"*mutcore::ffi::c_void", b"*const[u8;64]")), contract, rust=True)
        with self.assertRaisesRegex(ValueError, "function or callback types"):
            abi.compare(c, native, contract)

    def test_const_record_pointers_resolve_to_the_actual_native_record(self):
        contract = copy.deepcopy(self.contract)
        contract["field_types"]["qpc_example_v1"]["second"] = "*constqpc_example_v1"
        contract["signatures"]["qpc_commit_v1"] = ["i32", "*constqpc_example_v1"]
        c_bytes = self.report.replace(b"second:8:4:u32", b"second:8:8:*constqpc_example_v1").replace(
            b"*mutcore::ffi::c_void", b"*constqpc_example_v1")
        native_bytes = c_bytes.replace(b"*constqpc_example_v1", b"*constfixture::Example")
        abi.compare(abi.layouts(c_bytes, contract, rust=False),
                    abi.layouts(self.native(native_bytes), contract, rust=True), contract)


if __name__ == "__main__":
    unittest.main()
