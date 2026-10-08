"""Closed Maven/runtime identity and complete execution evidence for the JVM adapter."""
import fnmatch
import hashlib
import json
import shlex
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

import continuity_kotlin_consumer as kotlin
import test_continuity_c_consumer as c_tests
import test_continuity_c_account as account_tests


class KotlinConsumerTests(unittest.TestCase):
    @staticmethod
    def report(name, names):
        suite = ET.Element("testsuite", name="dev.qperiapt.continuity." + name,
            tests=str(len(names)), failures="0", errors="0", skipped="0")
        for case in sorted(names):
            ET.SubElement(suite, "testcase", name=case + "()", classname=suite.get("name"))
        return ET.tostring(suite)

    def independent_reports(self, root):
        for name, names in kotlin.INDEPENDENT_TEST_SUITES.items():
            (root / f"TEST-dev.qperiapt.continuity.{name}.xml").write_bytes(self.report(name, names))

    def test_retains_every_verified_suite_for_build_and_installed_profiles(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            suites = {"OwnerTests": kotlin.TEST_NAMES, "CredentialRenewalTests": kotlin.RENEWAL_TEST_NAMES,
                      "PolicyContinuationTests": kotlin.POLICY_TEST_NAMES, **kotlin.INDEPENDENT_TEST_SUITES}
            for name, names in suites.items():
                (root / f"TEST-dev.qperiapt.continuity.{name}.xml").write_bytes(self.report(name, names))
            labels = {"owner-tests", "credential-renewal-tests", "policy-continuation-tests",
                      "independent-policy-tests", "policy-renewal-tests", "roster-resolution-tests", "roster-refresh-tests",
                      "retirement-tests"}
            emitted = []
            for profile in ("", "debug", "release"):
                output = root / (profile or "build"); output.mkdir()
                checked = kotlin.retain_test_reports(root, output, profile=profile)
                suffix = "-" + profile if profile else ""
                self.assertEqual({p.name for p in output.iterdir()}, {"kotlin-" + label + suffix + ".xml" for label in labels})
                self.assertEqual({hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir()},
                                 {row["report_sha256"] for row in checked["suites"].values()})
                self.assertEqual({row["report_file"] for row in checked["suites"].values()},
                                 {p.name for p in output.iterdir()})
                for row in checked["suites"].values():
                    self.assertEqual(hashlib.sha256((output / row["report_file"]).read_bytes()).hexdigest(),
                                     row["report_sha256"])
                self.assertEqual(checked["tests"], 54)
                emitted.extend(p.name for p in output.iterdir())
                with self.assertRaises(FileExistsError): kotlin.retain_test_reports(root, output, profile=profile)
            with self.assertRaisesRegex(ValueError, "profile"):
                kotlin.retain_test_reports(root, root / "unused", profile="../../outside")
            workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml").read_text()
            upload = workflow.split("- name: Retain native packages and selected public execution evidence\n", 1)[1]
            upload = upload.split("if-no-files-found:", 1)[0]
            prefix = "target/continuity-installed-swift/"
            patterns = [line.strip() for line in upload.splitlines() if line.strip().startswith(prefix)]
            missing = sorted(name for name in emitted if not any(
                fnmatch.fnmatchcase(prefix + name, pattern) for pattern in patterns))
            self.assertEqual(missing, [], "CI upload omits verified JVM test reports")

    def test_renewal_suite_is_required_and_cannot_be_replaced_by_owner_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.independent_reports(root)
            owner = root / "TEST-dev.qperiapt.continuity.OwnerTests.xml"
            renewal = root / "TEST-dev.qperiapt.continuity.CredentialRenewalTests.xml"
            owner.write_bytes(self.report("OwnerTests", kotlin.TEST_NAMES))
            (root / "TEST-dev.qperiapt.continuity.PolicyContinuationTests.xml").write_bytes(
                self.report("PolicyContinuationTests", kotlin.POLICY_TEST_NAMES))
            with self.assertRaisesRegex(ValueError, "report set differs"):
                kotlin.verify_test_reports(root)
            good = self.report("CredentialRenewalTests", kotlin.RENEWAL_TEST_NAMES)
            renewal.write_bytes(good)
            self.assertEqual(kotlin.verify_test_reports(root)["tests"], 54)
            for invalid in (good.replace(b'skipped="0"', b'skipped="1"'),
                            good.replace(b"CredentialRenewalTests", b"OwnerTests"),
                            good.replace(b"renewalIdentitiesAreDistinctImmutableAndNonzero", b"unrelated")):
                renewal.write_bytes(invalid)
                with self.assertRaisesRegex(ValueError, "all execute"):
                    kotlin.verify_test_reports(root)

    def test_policy_suite_is_required_with_exact_reports_and_case_names(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.independent_reports(root)
            for name, names in (("OwnerTests", kotlin.TEST_NAMES),
                                ("CredentialRenewalTests", kotlin.RENEWAL_TEST_NAMES)):
                (root / f"TEST-dev.qperiapt.continuity.{name}.xml").write_bytes(self.report(name, names))
            with self.assertRaisesRegex(ValueError, "report set differs"):
                kotlin.verify_test_reports(root)
            policy = root / "TEST-dev.qperiapt.continuity.PolicyContinuationTests.xml"
            good = self.report("PolicyContinuationTests", kotlin.POLICY_TEST_NAMES)
            policy.write_bytes(good)
            checked = kotlin.verify_test_reports(root)
            self.assertEqual(checked["tests"], 54)
            self.assertEqual(set(checked["suites"]), {"OwnerTests", "CredentialRenewalTests", "PolicyContinuationTests", *kotlin.INDEPENDENT_TEST_SUITES})
            self.assertEqual(checked["suites"]["PolicyContinuationTests"], {
                "tests": 5, "report_sha256": hashlib.sha256(good).hexdigest()})
            for change in ("missing", "extra", "duplicate", "unrelated"):
                suite = ET.fromstring(good)
                if change == "missing":
                    suite.remove(suite[0]); suite.set("tests", "4")
                elif change == "extra":
                    ET.SubElement(suite, "testcase", name="unrelated()", classname=suite.get("name"))
                    suite.set("tests", "6")
                else:
                    suite[0].set("name", suite[1].get("name") if change == "duplicate" else "unrelated()")
                policy.write_bytes(ET.tostring(suite))
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "all execute"):
                    kotlin.verify_test_reports(root)
            policy.write_bytes(good)
            (root / "TEST-dev.qperiapt.continuity.UnlistedPolicyTests.xml").write_bytes(good)
            with self.assertRaisesRegex(ValueError, "report set differs"):
                kotlin.verify_test_reports(root)

    def test_policy_suite_rejects_failed_skipped_or_diagnostic_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.independent_reports(root)
            for name, names in (("OwnerTests", kotlin.TEST_NAMES),
                                ("CredentialRenewalTests", kotlin.RENEWAL_TEST_NAMES),
                                ("PolicyContinuationTests", kotlin.POLICY_TEST_NAMES)):
                (root / f"TEST-dev.qperiapt.continuity.{name}.xml").write_bytes(self.report(name, names))
            policy = root / "TEST-dev.qperiapt.continuity.PolicyContinuationTests.xml"
            good = policy.read_bytes()
            for counter, child in (("failures", "failure"), ("errors", "error"), ("skipped", "skipped")):
                for declared in (True, False):
                    suite = ET.fromstring(good)
                    if declared:
                        suite.set(counter, "1")
                    else:
                        ET.SubElement(suite[0], child)
                    policy.write_bytes(ET.tostring(suite))
                    with self.subTest(counter=counter, declared=declared), self.assertRaisesRegex(ValueError, "all execute"):
                        kotlin.verify_test_reports(root)
            for tag in ("system-out", "system-err"):
                suite = ET.fromstring(good)
                ET.SubElement(suite, tag).text = "native policy owner cleanup failed"
                policy.write_bytes(ET.tostring(suite))
                with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "unexpected diagnostics"):
                    kotlin.verify_test_reports(root)
            for changed in (good.replace(b"PolicyContinuationTests", b"CredentialRenewalTests"),
                            b'<!DOCTYPE testsuite [<!ENTITY x "test">]>' + good):
                policy.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, "all execute|external declarations"):
                    kotlin.verify_test_reports(root)

    def test_account_parent_collection_cannot_be_inferred_from_account_delivery_alone(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            account_tests.fixture(root)
            result = root / "initiator/c-account-result.json"
            document = json.loads(result.read_bytes()); document["language"] = "Kotlin"
            result.write_text(json.dumps(document))
            leaf = "initiator/kotlin-account-parent-lifetime"
            valid = (b"QPC-JVM-ACCOUNT/1 collections=2\n"
                     b"public-parent-queued peers-activated close-winner=1 closed-aliases-held slots=64 store-reopened\n")
            account_tests.put(root, leaf, valid)
            checked = kotlin.verify_account_execution(account_tests.STDOUT, root)
            self.assertEqual(len(checked["public_readbacks"]), 11)
            for changed in (valid[:-1], valid.replace(b"collections=2", b"collections=1"),
                            valid.replace(b"collections=2", b"collections=1025"),
                            valid.replace(b"close-winner=1", b"close-winner=2"),
                            valid.replace(b"slots=64", b"slots=63"), valid.replace(b"closed-aliases-held", b"aliases-dropped")):
                account_tests.put(root, leaf, changed)
                with self.assertRaisesRegex(ValueError, "parent collection and close workload"):
                    kotlin.verify_account_execution(account_tests.STDOUT, root)

    def test_inflight_receipts_bind_gc_and_returned_slots_to_original_delivery(self):
        stdout = (f"test {kotlin.c.SERVER_TEST} ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n").encode()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = c_tests.ContinuityCConsumerTests().server_evidence(root)
            report["scope"] = kotlin.c.SERVER_SCOPE.replace("C server", "Kotlin server")
            (root / "c-server-public-result.json").write_text(json.dumps(report))
            messages = report["messages"]
            receipts = {}
            for mode, message in [("fail-before", messages[0]), ("uncertain", messages[1]),
                                  ("crash-after", messages[2]), ("uncertain", messages[3]),
                                  *(("message", messages[index]) for index in (0, 1, 2, 4))]:
                payload = bytes.fromhex(report["session"] + message) + b"persisted before process exit"
                receipts[f"kotlin-gc-callback-{mode}-{message}"] = b"QPC-JVM-INFLIGHT/1 callback collections=5\n" + payload
                if mode != "crash-after":
                    receipts[f"kotlin-gc-return-{mode}-{message}"] = b"QPC-JVM-INFLIGHT/1 returned slots=64 copied-delivery-valid\n" + payload
            for leaf, data in receipts.items():
                (root / "responder" / leaf).write_bytes(data)
            observed = kotlin.verify_inflight_execution(stdout, root)
            self.assertEqual(observed["inflight_gc"]["callbacks"], 8)
            self.assertEqual(observed["inflight_gc"]["returned_native_slot_checks"], 7)
            for leaf, data in receipts.items():
                path = root / "responder" / leaf
                for changed in (data[:-1], data + b"extra", data.replace(bytes.fromhex(report["session"]), b"x" * 32),
                                data.replace(b"collections=5", b"collections=0").replace(b"slots=64", b"slots=63")):
                    path.write_bytes(changed)
                    with self.subTest(leaf=leaf), self.assertRaisesRegex(ValueError, "receipt differs"):
                        kotlin.verify_inflight_execution(stdout, root)
                path.write_bytes(data)
            extra = root / "responder" / ("kotlin-gc-return-crash-after-" + messages[2])
            extra.write_bytes(b"false return evidence")
            with self.assertRaisesRegex(ValueError, "receipt set differs"):
                kotlin.verify_inflight_execution(stdout, root)

    def test_inflight_requires_compilation_for_each_real_server_invocation(self):
        modes = ["message"] * 5 + ["uncertain"] * 2 + ["fail-before", "crash-after", "bootstrap", "pre-cancel", "deadline", "rekey"]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); evidence = root / "evidence"
            for index, mode in enumerate(modes):
                log = ET.Element("hotspot_log")
                arguments = ET.SubElement(log, "vm_arguments")
                ET.SubElement(arguments, "args").text = shlex.join(kotlin.inflight_vm_flags("Serial", root))
                ET.SubElement(arguments, "command").text = f"consumer.ContinuityClientKt --gc-in-flight serve {evidence / 'responder'} {mode}" + (" " + "11" * 32 if mode == "rekey" else "")
                for method in kotlin.INFLIGHT_METHODS:
                    ET.SubElement(log, "nmethod", compiler="c2", method=method + " fixture-signature")
                (root / f"jit-{index}.xml").write_bytes(ET.tostring(log))
            self.assertEqual(len(kotlin.verify_inflight_compilation(root, evidence, collector="Serial")), 13)
            path = root / "jit-0.xml"; original = path.read_bytes()
            for changed in (original.replace(b'compiler="c2"', b'compiler="c1"'),
                            original.replace(b"--gc-in-flight", b"--other"),
                            original.replace(b"UseSerialGC", b"UseG1GC"),
                            original.replace(b" message", b" uncertain")):
                path.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, "compiled|invocation differs|workload differs|configuration differs"):
                    kotlin.verify_inflight_compilation(root, evidence, collector="Serial")
            path.unlink()
            with self.assertRaisesRegex(ValueError, "log count differs"):
                kotlin.verify_inflight_compilation(root, evidence, collector="Serial")

    def test_gc_evidence_requires_observed_collection_and_complete_native_capacity_checks(self):
        valid = b"QPC-JVM-GC/1 rounds=16 forgotten=1024 queued=1024 live=1024 stale=1024 collections=32\n"
        self.assertEqual(kotlin.verify_gc_execution(valid)["observed_collections"], 32)
        for changed in (valid[:-1], valid + b"extra\n", valid.replace(b"queued=1024", b"queued=0"),
                        valid.replace(b"rounds=16", b"rounds=1"),
                        valid.replace(b"live=1024", b"live=1023"), valid.replace(b"stale=1024", b"stale=0"),
                        valid.replace(b"collections=32", b"collections=0"),
                        valid.replace(b"collections=32", b"collections=31"),
                        valid.replace(b"collections=32", b"collections=032"),
                        valid.replace(b"collections=32", b"collections=16385")):
            with self.subTest(stdout=changed), self.assertRaisesRegex(ValueError, "did not execute completely"):
                kotlin.verify_gc_execution(changed)

    def test_every_owner_test_must_execute_without_skips_or_diagnostics(self):
        suite = ET.Element("testsuite", name="dev.qperiapt.continuity.OwnerTests", tests="20",
                           failures="0", errors="0", skipped="0")
        for name in sorted(kotlin.TEST_NAMES):
            ET.SubElement(suite, "testcase", name=name + "()", classname=suite.get("name"))
        data = ET.tostring(suite)
        self.assertEqual(kotlin.verify_tests(data)["tests"], 20)
        suite.remove(suite[0])
        with self.assertRaisesRegex(ValueError, "did not all execute"):
            kotlin.verify_tests(ET.tostring(suite))
        suite = ET.fromstring(data)
        ET.SubElement(suite[0], "skipped")
        with self.assertRaisesRegex(ValueError, "did not all execute"):
            kotlin.verify_tests(ET.tostring(suite))
        suite = ET.fromstring(data)
        ET.SubElement(suite, "system-err").text = "native owner cleanup failed"
        with self.assertRaisesRegex(ValueError, "unexpected diagnostics"):
            kotlin.verify_tests(ET.tostring(suite))
        with self.assertRaisesRegex(ValueError, "external declarations"):
            kotlin.verify_tests(b'<!DOCTYPE testsuite [<!ENTITY x "test">]>' + data)

    def test_tool_identity_covers_implementation_not_only_launchers(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "jdk"
            (root / "bin").mkdir(parents=True); (root / "lib").mkdir()
            (root / "bin/java").write_bytes(b"not executed launcher fixture")
            (root / "lib/modules").write_bytes(b"original implementation fixture")
            original = kotlin.tool_identity(root)
            self.assertEqual(set(original["files"]), {"bin/java", "lib/modules"})
            (root / "lib/modules").write_bytes(b"different implementation fixture")
            self.assertNotEqual(kotlin.tool_identity(root), original)
            (root / "lib/link").symlink_to("modules")
            self.assertEqual(kotlin.tool_identity(root)["files"]["lib/link"]["target"], "lib/modules")
            (root / "lib/link").unlink()
            outside = root.parent / "outside"; outside.write_bytes(b"outside tool authority")
            (root / "lib/link").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "escapes"):
                kotlin.tool_identity(root)

    def test_runtime_requires_exact_coordinates_bytes_and_outside_distribution(self):
        with tempfile.TemporaryDirectory() as folder:
            outside = Path(folder).resolve(); distribution = outside / "installed"
            (distribution / "lib").mkdir(parents=True)
            repository = outside / "repository"; repository.mkdir()
            coordinate = kotlin.maven_contract().coordinate
            components = [(coordinate, "sdk.jar"), ("org.jetbrains.kotlin:kotlin-stdlib:2.4.20", "kotlin.jar"),
                          ("org.jetbrains:annotations:13.0", "annotations.jar")]
            rows = []
            for name, leaf in components:
                data = ("not executed JAR fixture: " + name).encode()
                path = repository / leaf; path.write_bytes(data)
                (distribution / "lib" / leaf).write_bytes(data)
                rows.append(f"{name}\t{path}\t{hashlib.sha256(data).hexdigest()}\n")
            (distribution / "lib/continuity-installed-consumer.jar").write_bytes(b"consumer fixture")
            encoded = "".join(rows).encode(); digest = hashlib.sha256((repository / "sdk.jar").read_bytes()).hexdigest()
            self.assertEqual(set(kotlin.runtime_closure(encoded, distribution, digest, outside)), {name for name, _ in components})
            for changed in (encoded + rows[0].encode(), "".join(rows[:-1]).encode(), encoded.replace(b":2.4.20\t", b":2.+\t")):
                with self.assertRaisesRegex(ValueError, "coordinate|closure"):
                    kotlin.runtime_closure(changed, distribution, digest, outside)
            noncanonical = encoded.replace(str(repository / "sdk.jar").encode(),
                                           str(repository / "../repository/sdk.jar").encode())
            with self.assertRaisesRegex(ValueError, "location differs"):
                kotlin.runtime_closure(noncanonical, distribution, digest, outside)
            (distribution / "lib/sdk.jar").write_bytes(b"substituted installed dependency")
            with self.assertRaisesRegex(ValueError, "differs from resolution"):
                kotlin.runtime_closure(encoded, distribution, digest, outside)
            (distribution / "lib/sdk.jar").write_bytes((repository / "sdk.jar").read_bytes())
            (distribution / "lib/unlisted.jar").write_bytes(b"extra runtime implementation")
            with self.assertRaisesRegex(ValueError, "unqualified dependency"):
                kotlin.runtime_closure(encoded, distribution, digest, outside)

if __name__ == "__main__":
    unittest.main()
