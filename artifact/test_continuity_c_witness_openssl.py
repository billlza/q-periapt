"""Synthetic receipt controls only; runtime TLS/signature evidence comes from peers."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_witness_openssl as interop
from test_continuity_c_witness_tls import fixture as native_fixture


def output(kind):
    return (f"test {interop.TESTS[kind]} ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;\n").encode()


def receipt(**extra):
    return dict(completed=True, independent_tls_implementation=True,
                independent_witness_engine=False, release_claim_eligible=False, **extra)


def fixture(root, kind):
    if kind == "server":
        _, old = native_fixture(root)
        (root / "c-witness-tls-public-result.json").unlink()
        for path in root.glob("*/witness-tls-*.std*"):
            name = path.name.replace("witness-tls-", "witness-openssl-")
            if any(part in name for part in ("missing-key", "wrong-name", "wrong-subject")):
                path.unlink()
            else:
                path.rename(path.with_name(name.replace("owner-kind", "kind").replace("cleanup-cancel", "cancel")))
        report = receipt(session=old["session"], message=old["message"], witness_exchanges=142)
        (root / "openssl-witness-server.stderr").write_text("".join(
            f"OPENSSL_WITNESS_OK role=server tls=1.3 group=X25519MLKEM768 alpn=q-periapt-anchor/1 exchange={i}\n"
            for i in range(1, 143)))
    elif kind == "rejections":
        report = receipt(cases=list(interop.REJECTIONS), store_calls=0)
        for case, reason in interop.REJECTIONS.items():
            (root / case).mkdir()
            (root / case / "openssl-witness-server.stderr").write_text(f"OPENSSL_WITNESS_ERROR {reason}\n")
    else:
        report = receipt(exchanges=2, outcomes=[1, 2])
        (root / "initiator").mkdir()
        authority_subject = b"i" * 128
        before = (1).to_bytes(8, "big") + (2).to_bytes(8, "big") + b"b" * 32
        after = before[:8] + (3).to_bytes(8, "big") + bytes([47]) * 32
        for label, operation, observed, outcome in (("query", b"\1" + bytes(96), before, 1),
                                                   ("advance", b"\2" + before + after, after, 2)):
            command = interop.commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority_subject + operation)
            body = b"QPANRQ01" + authority_subject + command + bytes([outcome]) * 32 + operation
            attempt = interop.commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", body)
            reply = b"QPANRS01" + authority_subject + attempt + command + bytes([outcome]) + observed + b"\1" + command
            request = (297).to_bytes(4, "big") + body + bytes(3373)
            wire = (3659).to_bytes(4, "big") + (282).to_bytes(4, "big") + reply + bytes(3373)
            (root / "initiator" / f"openssl-{label}.request").write_bytes(request)
            (root / "initiator" / f"openssl-{label}.reply").write_bytes(wire)
            (root / "initiator" / f"openssl-{label}.stderr").write_text(
                "OPENSSL_WITNESS_OK role=client tls=1.3 group=X25519MLKEM768 alpn=q-periapt-anchor/1 exchange=1\n")
    (root / interop.REPORTS[kind]).write_text(json.dumps(report))
    return output(kind), report


class OpenSslWitnessEvidenceTests(unittest.TestCase):
    def test_identity_checks_both_cli_version_forms_without_accepting_mismatch(self):
        version = "OpenSSL 3.6.4 25 Aug 2026"
        text = f"OPENSSL_HEADER {version}\nOPENSSL_RUNTIME {version}\n"
        for cli in (version, f"{version} (Library: {version})"):
            self.assertEqual(interop.verify_versions(cli, text), version)
        for cli, value in ((version + " other", text), (version, text.replace("HEADER OpenSSL 3.6.4", "HEADER OpenSSL 3.5.0")),
                           (f"{version} (Library: OpenSSL 3.5.0)", text), (version, text + text)):
            with self.subTest(cli=cli, identity=value), self.assertRaises(ValueError):
                interop.verify_versions(cli, value)

    def test_executed_tests_and_scope_flags_cannot_be_forged_by_receipt(self):
        for kind in interop.TESTS:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                stdout, report = fixture(root, kind)
                interop.verify_execution(kind, stdout, root)
                for altered in (b"", stdout + stdout, stdout.replace(b"10 filtered out", b"5 filtered out")):
                    self.assertNotEqual(altered, stdout)
                    with self.subTest(kind=kind), self.assertRaises(ValueError):
                        interop.verify_execution(kind, altered, root)
                for field, value in (("completed", 1), ("release_claim_eligible", True),
                                     ("independent_witness_engine", True), ("independent_tls_implementation", 1)):
                    (root / interop.REPORTS[kind]).write_text(json.dumps(dict(report, **{field: value})))
                    with self.subTest(kind=kind, field=field), self.assertRaises(ValueError):
                        interop.export_public(kind, stdout, root, root / "export")
                    self.assertFalse((root / "export").exists())

    def test_negotiation_and_authenticated_attempt_readbacks_are_required(self):
        for kind, name, offset in (("server", "openssl-witness-server.stderr", 70),
                                   ("server", "responder/c-loss-report", 0),
                                   ("client", "initiator/openssl-advance.request", 175),
                                   ("client", "initiator/openssl-query.reply", 150),
                                   ("rejections", "wrong-subject/openssl-witness-server.stderr", 0)):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                stdout, _ = fixture(root, kind)
                interop.verify_execution(kind, stdout, root)
                path = root / name
                value = bytearray(path.read_bytes())
                value[offset] ^= 1
                path.write_bytes(value)
                with self.subTest(kind=kind, name=name), self.assertRaises(ValueError):
                    interop.export_public(kind, stdout, root, root / "export")
                self.assertFalse((root / "export").exists())

    def test_exports_omit_credentials_and_cannot_promote_scope(self):
        for kind, count in (("server", 29), ("client", 7), ("rejections", 5)):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                stdout, _ = fixture(root, kind)
                (root / "private.key").write_bytes(b"synthetic secret")
                exported = interop.export_public(kind, stdout, root, root / "export")
                self.assertEqual(len(exported), count)
                self.assertFalse((root / "export/private.key").exists())
                checked = interop.verify_execution(kind, stdout, root / "export")
                self.assertFalse(checked["independent_witness_engine"])
                self.assertFalse(checked["cross_host_qualified"])

    def test_tool_bytes_are_rechecked_after_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "library"
            path.write_bytes(b"first")
            identities = {str(path): interop.sdk.snapshot(path).sha256}
            interop.verify_dependencies(identities)
            path.write_bytes(b"other")
            with self.assertRaises(ValueError):
                interop.verify_dependencies(identities)


if __name__ == "__main__":
    unittest.main(warnings="error")
