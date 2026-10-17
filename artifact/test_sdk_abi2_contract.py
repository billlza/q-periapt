"""Mutations must not turn additive ABI compatibility into an export bypass."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import c_abi_contract as abi
import sdk_abi2_spec as sdk


class SDKABI2ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent.parent
        cls.contract_path = cls.root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2-sdk-020.json"
        cls.contract = abi.load_contract(cls.contract_path)
        cls.header = cls.root / "crates/q-periapt-ffi/include/q_periapt.h"
        cls.old = abi.load_contract(cls.root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json")

    def test_current_header_is_additive_with_exactly_retained_legacy_declarations(self):
        abi.verify_header(self.contract, self.header)
        self.assertEqual(self.contract.document["abi"]["major"], 2)
        self.assertEqual(len(self.contract.export_names), 51)
        self.assertEqual(self.contract.document["package"]["semver"], sdk.PACKAGE_SEMVER)
        for name, signature in self.old.declarations.items():
            self.assertEqual(self.contract.declarations[name], signature)
        abi.verify_header(self.old, self.root / "crates/q-periapt-ffi/abi/v0.1.5/q_periapt.h")

    def test_contract_mutations_cannot_authorize_unknown_surface_or_abi_major(self):
        original = self.contract.document
        mutations = []
        changed = copy.deepcopy(original); changed["abi"]["major"] = 3; mutations.append(changed)
        for version in ("0.2.1", "0.2.0-alpha.1"):
            changed = copy.deepcopy(original); changed["package"]["semver"] = version; mutations.append(changed)
        changed = copy.deepcopy(original); changed["abi"]["exports"].pop(); mutations.append(changed)
        changed = copy.deepcopy(original); changed["abi"]["macros"]["Q_PERIAPT_SDK_MAX_CALLS"] = True; mutations.append(changed)
        changed = copy.deepcopy(original); changed["abi"]["native_structs"]["QPeriaptInput"] = "typedef void *QPeriaptInput;"; mutations.append(changed)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "contract.json"
            for document in mutations:
                with self.subTest(document=document):
                    path.write_text(json.dumps(document))
                    with self.assertRaises(abi.CAbiContractError):
                        abi.load_contract(path)

    def test_packing_extra_exports_changed_fields_and_attributes_are_rejected(self):
        original = self.header.read_text()
        mutations = [
            original.replace("#pragma once", "#pragma once\n#pragma pack(1)"),
            original.replace("uintptr_t len;", "uint32_t len;", 1),
            original.replace("typedef struct {", "__attribute__((aligned(32))) typedef struct {", 1),
            original + "\nint32_t q_periapt_sdk_secret_import(const uint8_t *bytes);\n",
            original.replace("uint32_t q_periapt_sdk_extension_version(void);", "uint64_t q_periapt_sdk_extension_version(void);"),
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "q_periapt.h"
            for text in mutations:
                with self.subTest(header_sha256=abi.hashlib.sha256(text.encode()).hexdigest()):
                    path.write_text(text)
                    with self.assertRaises(abi.CAbiContractError):
                        abi.verify_header(self.contract, path)


if __name__ == "__main__":
    unittest.main()
