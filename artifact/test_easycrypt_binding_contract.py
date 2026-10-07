"""Mutation tests for the declared binding proof contract, not proof validity."""
from __future__ import annotations

import copy
import json
import re
import unittest
import easycrypt_binding_contract as contract


class BindingContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = contract.ROOT / "formal" / "easycrypt"
        self.sources = {name: (self.directory / name).read_text() for name in contract.SOURCE_NAMES}
        self.expected = json.loads((self.directory / "BindingContract.json").read_text())

    def reject_binding(self, source: str) -> None:
        self.sources["BindingViaCR.ec"] = source
        with self.assertRaises(contract.ContractError):
            contract.verify(self.sources, self.expected)

    def test_current_sources_have_seven_reviewed_assumptions(self) -> None:
        result = contract.verify(self.sources, self.expected)
        self.assertEqual(result, {"sources": 2, "axioms": 7, "lemmas": 59})
        self.assertEqual(contract.inventory(self.sources["JRejectionCountermodel.ec"])["axioms"], {})

    def test_new_axiom_is_rejected(self) -> None:
        self.reject_binding(self.sources["BindingViaCR.ec"] + "\naxiom unchecked : false.\n")

    def test_changed_assumption_is_rejected(self) -> None:
        self.reject_binding(self.sources["BindingViaCR.ec"].replace("size (be8 n) = 8", "size (be8 n) = 9"))

    def test_deleted_assumption_requires_review(self) -> None:
        self.reject_binding(re.sub(r"(?m)^axiom jrej_inj[^\n]*\n", "", self.sources["BindingViaCR.ec"]))

    def test_deleted_main_theorem_is_rejected_even_with_a_comment_decoy(self) -> None:
        source = self.sources["BindingViaCR.ec"]
        match = re.search(r"(?ms)^lemma bind_le_cr \(.*?^qed\.", source)
        self.assertIsNotNone(match)
        statement = match.group(0)
        self.reject_binding(source.replace(statement, "(* " + statement + " *)"))

    def test_changed_theorem_statement_is_rejected(self) -> None:
        source = self.sources["BindingViaCR.ec"]
        source, count = re.subn(r"(?ms)(^lemma bind_le_cr \(.*? :\n).*?\.\nproof\.", r"\1true.\nproof.", source, count=1)
        self.assertEqual(count, 1)
        self.reject_binding(source)

    def test_duplicate_declaration_cannot_overwrite_inventory(self) -> None:
        self.reject_binding(self.sources["BindingViaCR.ec"] + "\naxiom be8_size n : false.\n")

    def test_nested_comments_cannot_add_declarations(self) -> None:
        source = self.sources["BindingViaCR.ec"] + "\n(* axiom decoy : false. (* lemma fake : false. proof. *) *)\n"
        self.sources["BindingViaCR.ec"] = source
        contract.verify(self.sources, self.expected)

    def test_comments_do_not_join_code_tokens(self) -> None:
        self.assertEqual(contract.strip_comments("a(* x *)b"), "a       b")

    def test_malformed_comments_are_rejected(self) -> None:
        for text in ("(* unfinished", "*) unmatched"):
            with self.subTest(text=text), self.assertRaises(contract.ContractError):
                contract.inventory(text)

    def test_dependency_changes_and_proof_escapes_are_rejected(self) -> None:
        original = self.sources["BindingViaCR.ec"]
        for addition in ("require import Unreviewed.\n", "clone Unreviewed.\n", "admit.\n", "sorry.\n", "abort.\n", "declare op hidden : bool.\n", "op hidden : bool axiomatized by assumption.\n"):
            with self.subTest(addition=addition):
                self.reject_binding(original + addition)

    def test_unsupported_declaration_forms_fail_closed(self) -> None:
        for source in ("local lemma x : true. proof. trivial. qed.", 'op text = "lemma hidden : true. proof.".', "axiom x : true. axiom y : true.\n"):
            with self.subTest(source=source), self.assertRaises(contract.ContractError):
                contract.inventory(source)

    def test_bounds_are_checked_before_declaration_scanning(self) -> None:
        for source in (" " * (256 * 1024 + 1), "\n".join(f"axiom a{i} : true." for i in range(129))):
            with self.assertRaises(contract.ContractError):
                contract.inventory(source)

    def test_contract_shape_and_source_set_are_closed(self) -> None:
        for mutation in ("schema", "extra", "missing_source"):
            altered = copy.deepcopy(self.expected)
            if mutation == "schema":
                altered["schema_version"] = True
            elif mutation == "extra":
                altered["unreviewed"] = {}
            else:
                altered["sources"].pop("BindingViaCR.ec")
            with self.subTest(mutation=mutation), self.assertRaises(contract.ContractError):
                contract.verify(self.sources, altered)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(contract.ContractError):
            json.loads('{"sources": {}, "sources": {}}', object_pairs_hook=contract.no_duplicate_keys)

    def test_compiler_and_inventory_are_unconditional_ci_gates(self) -> None:
        source = (contract.ROOT / ".github/workflows/ci.yml").read_text()
        job = source.split("  formal-easycrypt:\n", 1)[1].split("\n  tamarin-proof:", 1)[0]
        step = job.split("      - name: Verify binding proof assumptions and statements\n", 1)[1].split("      - ", 1)[0]
        self.assertEqual(step.strip(), "run: sh artifact/python-run.sh artifact/easycrypt_binding_contract.py")
        self.assertIn("make EC=easycrypt check", job)
        source = (self.directory / "Makefile").read_text()
        checked = re.search(r"(?m)^SRC := (.+)$", source)
        self.assertIsNotNone(checked)
        self.assertEqual(checked.group(1).split(), ["BindingViaCR.ec", "MigrationBindingV2.ec", "JRejectionCountermodel.ec"])
