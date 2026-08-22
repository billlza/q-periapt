#!/usr/bin/env python3
"""Fail-closed tests for the schema-1 stable crates.io receipt."""

from __future__ import annotations

import copy
import unittest

import crates_io_publication_contract as contract


SOURCE_PARENT = "1" * 40
TAG_COMMIT = "2" * 40
TAG_TREE = "3" * 40
SOURCE_TREE = "4" * 64
TRANSCRIPT_SHA256 = "5" * 64


def receipt_fixture(published_count: int = 10) -> dict[str, object]:
    crates: list[dict[str, object]] = []
    for index, (name, dependencies) in enumerate(
        contract.CRATE_PUBLICATION_TOPOLOGY, start=1
    ):
        digest = f"{index:064x}"
        crate: dict[str, object] = {
            "crate_file": f"{name}-{contract.PRODUCT_VERSION}.crate",
            "crate_sha256": digest,
            "crate_size": 1000 + index,
            "dependencies": list(dependencies),
            "name": name,
            "state": contract.CRATE_STATUS_ABSENT,
            "version": contract.PRODUCT_VERSION,
        }
        if index <= published_count:
            crate.update(
                {
                    "crates_io_api": {
                        "checksum": digest,
                        "version": contract.PRODUCT_VERSION,
                        "yanked": False,
                    },
                    "sparse_index": {
                        "checksum": digest,
                        "version": contract.PRODUCT_VERSION,
                        "yanked": False,
                    },
                    "state": contract.CRATE_STATUS_PUBLISHED_VERIFIED,
                    "verified_at": "2026-08-15T01:00:00Z",
                }
            )
        crates.append(crate)
    return {
        "boundary": contract.CRATES_IO_PUBLICATION_BOUNDARY,
        "crates": crates,
        "identity": {
            "abi_version": contract.ABI_VERSION,
            "product_version": contract.PRODUCT_VERSION,
            "publication_key": contract.CRATES_IO_PUBLICATION_KEY,
            "registry": contract.CRATES_IO_REGISTRY,
        },
        "kind": contract.CRATES_IO_PUBLICATION_KIND,
        "observation": {
            "observed_at": "2026-08-15T02:00:00Z",
            "package_contract": {
                "completed_at": "2026-08-14T23:00:00Z",
                "handoff_sha256": "4" * 64,
                "source_commit": SOURCE_PARENT,
                "transcript_sha256": TRANSCRIPT_SHA256,
            },
            "source": {
                "canonical_source_tree_sha256": SOURCE_TREE,
                "source_parent_commit": SOURCE_PARENT,
                "tag_commit": TAG_COMMIT,
                "tag_tree": TAG_TREE,
            },
        },
        "schema_version": contract.CRATES_IO_PUBLICATION_SCHEMA_VERSION,
        "status": (
            contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED
            if published_count == len(contract.CRATE_PUBLICATION_TOPOLOGY)
            else contract.PUBLICATION_STATUS_PARTIAL
        ),
    }


class CratesIoPublicationContractTests(unittest.TestCase):
    def test_exact_partial_and_complete_receipts_pass(self) -> None:
        for published_count in (0, 1, 5, 10):
            with self.subTest(published_count=published_count):
                contract.validate_crates_io_publication_receipt(
                    receipt_fixture(published_count)
                )

    def test_topology_is_exactly_the_package_contract_order(self) -> None:
        self.assertEqual(10, len(contract.PUBLISHABLE_CRATES))
        self.assertEqual(
            contract.PUBLISHABLE_CRATES,
            contract.RUST_PUBLISHABLE_CRATES,
        )
        receipt = receipt_fixture(2)
        crates = receipt["crates"]
        crates[0], crates[1] = crates[1], crates[0]
        with self.assertRaisesRegex(
            contract.CratesIoPublicationContractError, "name/order differs"
        ):
            contract.validate_crates_io_publication_receipt(receipt)

    def test_missing_duplicate_and_nonprefix_crates_fail(self) -> None:
        mutations = []

        missing = receipt_fixture(1)
        missing["crates"].pop()
        mutations.append(("exactly ten", missing))

        duplicate = receipt_fixture(1)
        duplicate["crates"][1] = copy.deepcopy(duplicate["crates"][0])
        mutations.append(("name/order differs", duplicate))

        nonprefix = receipt_fixture(1)
        later = copy.deepcopy(receipt_fixture(3)["crates"][2])
        nonprefix["crates"][2] = later
        mutations.append(("exact topology prefix", nonprefix))

        for expected, receipt in mutations:
            with self.subTest(expected=expected), self.assertRaisesRegex(
                contract.CratesIoPublicationContractError, expected
            ):
                contract.validate_crates_io_publication_receipt(receipt)

    def test_remote_checksum_yanked_and_version_mismatches_fail(self) -> None:
        mutations = (
            ("crates_io_api", "checksum", "f" * 64, "checksum differs"),
            ("sparse_index", "checksum", "e" * 64, "checksum differs"),
            ("crates_io_api", "yanked", True, "yanked=false"),
            ("sparse_index", "version", "0.1.3", "version differs"),
        )
        for remote, field, value, expected in mutations:
            with self.subTest(remote=remote, field=field):
                receipt = receipt_fixture()
                receipt["crates"][0][remote][field] = value
                with self.assertRaisesRegex(
                    contract.CratesIoPublicationContractError, expected
                ):
                    contract.validate_crates_io_publication_receipt(receipt)

    def test_source_and_package_transcript_must_crosslink(self) -> None:
        receipt = receipt_fixture()
        receipt["observation"]["package_contract"]["source_commit"] = "9" * 40
        with self.assertRaisesRegex(
            contract.CratesIoPublicationContractError,
            "source differs from the source parent",
        ):
            contract.validate_crates_io_publication_receipt(receipt)

        for mutation in ("invalid", None):
            with self.subTest(handoff_sha256=mutation):
                receipt = receipt_fixture()
                package_contract = receipt["observation"]["package_contract"]
                if mutation is None:
                    del package_contract["handoff_sha256"]
                else:
                    package_contract["handoff_sha256"] = mutation
                with self.assertRaises(
                    contract.CratesIoPublicationContractError
                ):
                    contract.validate_crates_io_publication_receipt(receipt)

        receipt = receipt_fixture()
        receipt["observation"]["source"]["tag_commit"] = SOURCE_PARENT
        with self.assertRaisesRegex(
            contract.CratesIoPublicationContractError,
            "results-only successor",
        ):
            contract.validate_crates_io_publication_receipt(receipt)

    def test_unknown_state_cannot_become_verified_aggregate(self) -> None:
        receipt = receipt_fixture(9)
        receipt["crates"][9]["state"] = "upload_outcome_unknown"
        receipt["status"] = contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED
        with self.assertRaisesRegex(
            contract.CratesIoPublicationContractError, "unknown state"
        ):
            contract.validate_crates_io_publication_receipt(receipt)

        receipt = receipt_fixture(9)
        receipt["status"] = contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED
        with self.assertRaisesRegex(
            contract.CratesIoPublicationContractError,
            "aggregate status differs",
        ):
            contract.validate_crates_io_publication_receipt(receipt)

    def test_schema_and_exact_source_keys_are_frozen(self) -> None:
        receipt = receipt_fixture()
        receipt["schema_version"] = 2
        with self.assertRaisesRegex(
            contract.CratesIoPublicationContractError, "schema differs"
        ):
            contract.validate_crates_io_publication_receipt(receipt)

        receipt = receipt_fixture()
        receipt["observation"]["source"]["verifier_commit"] = TAG_COMMIT
        with self.assertRaisesRegex(
            contract.CratesIoPublicationContractError, "keys differ"
        ):
            contract.validate_crates_io_publication_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
