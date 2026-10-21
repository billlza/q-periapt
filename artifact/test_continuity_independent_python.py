import base64
import csv
import hashlib
import io
import json
import unittest
import zipfile

from continuity_independent_python import DIST, PACKAGE, inspect_wheel, verify_installation, verify_extension_session, verify_roster_profiles, verify_roster_capacity, verify_roster_revocation
from continuity_independent_python import verify_local_policy_profiles, verify_local_policy_boundary
from continuity_independent_python import verify_witness_policy_profiles, verify_witness_policy_boundary


class WitnessPolicyReceiptTests(unittest.TestCase):
    def profiles(self):
        return {"profiles": [{"members": members, "workers": 60, "process_kills": 7, "confirmed_epoch": 1,
            **{k: "a" * 64 for k in ("journal", "native_journal", "session", "original_wire_sha256")},
            "adopted": [{"version": v, "now": at, "admission_kinds": [1, 1, 15, 1, 15],
                **{k: digit * 64 for k in ("operation", "proposal", "statement")}}
                for v, at, digit in [(2, 190, "b"), (4, 340, "c")]],
            "refusals": [{"case": f"p{v}-release-withholds-output", "error": "unavailable", "type": "TimeoutError"}
                         for v in (2, 4)],
            "native_refusals": [{"case": "different-statement-witness-refused", "error": "policy witness: Protocol(Scope)"},
                {"case": "closed-version-witness-floor-refused", "error": "policy witness: Protocol(Retired)"}],
            "denied_operations": ["old-policy-permission-denied", "p2-pending-blocks-session", "p2-unapproved-commit-refused",
                "p2-lost-actual-commit-reply", "p2-lost-actual-ack-reply", "p2-unavailable-admission-denies-output",
                "p3-pending-blocks-session", "p3-unapproved-commit-refused", "p3-closed-does-not-admit-expired-predecessor",
                "closed-version-floor-refused", "p4-pending-blocks-session", "p4-unapproved-commit-refused",
                "p4-unavailable-admission-denies-output", "expired-current-policy-denied"]} for members in (3, 32)]}

    def boundary(self):
        return {"profile": {"members": 32, "traffic_bytes": 2031616, "rows": 123, "workers": 24,
            "process_kills": 5, "payload_bytes": 2091796, "prepared_intent_bytes": 2092400, "expiry_kinds": [12],
            **{k: "a" * 64 for k in ("journal", "native_journal", "session")},
            "original_inventory": {"traffic_bytes": 2031616, "outboxes": 123,
                "epoch_record_hashes": [[0, "b" * 64], [1, "c" * 64]]},
            "denied_operations": ["expired-prepared-target-cannot-commit", "historical-closure-is-not-permission",
                                  "current-policy-expiry-denies-full-output"],
            "refusals": [{"case": name, "error": "refused", "type": "ValueError"} for name in [
                "parent-close-withholds-policy-proposal", "witness-policy-control-cannot-be-removed",
                "witness-policy-rejects-local-time-floor", "witness-policy-overall-capacity", "policy-metadata-cannot-fund-business"]]}}

    def test_complete_witness_original_workloads(self):
        verify_witness_policy_profiles(self.profiles())
        verify_witness_policy_boundary(self.boundary())

    def test_missing_fresh_release_or_native_floor_cannot_qualify(self):
        for mutate in [lambda r: r["adopted"][0].update(admission_kinds=[1, 15]),
                       lambda r: r["adopted"][0].update(admission_kinds=[1, 1, 15, 1]),
                       lambda r: r["adopted"][0].update(admission_kinds=[1, 1, 15, 1, 1, 15]),
                       lambda r: r["adopted"][0].update(admission_kinds=[1, 1, 4, 1, 1, 4]),
                       lambda r: r["native_refusals"].pop(), lambda r: r["refusals"].pop(),
                       lambda r: r["denied_operations"].pop(), lambda r: r.update(process_kills=0),
                       lambda r: r.update(confirmed_epoch=0)]:
            report = self.profiles(); mutate(report["profiles"][0])
            with self.assertRaises(ValueError): verify_witness_policy_profiles(report)

    def test_reused_adoption_or_partial_cohort_is_rejected(self):
        for mutate in [lambda r: r["profiles"].pop(),
                       lambda r: r["profiles"][1]["adopted"][1].update(statement="b" * 64),
                       lambda r: r["profiles"][0]["adopted"][0].update(now=True)]:
            report = self.profiles(); mutate(report)
            with self.assertRaises(ValueError): verify_witness_policy_profiles(report)

    def test_expired_dispatch_or_partial_original_store_is_rejected(self):
        for mutate in [lambda r: r.update(expiry_kinds=[12, 11]), lambda r: r.update(expiry_kinds=[]),
                       lambda r: r.update(workers=True), lambda r: r.update(prepared_intent_bytes=10),
                       lambda r: r["original_inventory"].update(traffic_bytes=1),
                       lambda r: r["original_inventory"]["epoch_record_hashes"].pop(),
                       lambda r: r["refusals"][1].update(error=""), lambda r: r["denied_operations"].pop()]:
            report = self.boundary(); mutate(report["profile"])
            with self.assertRaises(ValueError): verify_witness_policy_boundary(report)


class LocalPolicyReceiptTests(unittest.TestCase):
    def profiles(self):
        return {"profiles": [{"members": n, "workers": 52, "process_kills": 7,
            **{k: "a" * 64 for k in ("journal", "native_journal", "session", "original_wire_sha256")},
            "approvals": [{"version": v, "now": now, **{k: digit * 64 for k in
                ("operation", "statement", "approval_sha256")}} for v, now, digit in [(2, 190, "b"), (3, 270, "c")]],
            "denied_operations": ["expired-p0-refused", "policy-2-other-journal-refused",
                "policy-2-pending-blocks-session", "original-reservation-remains-exclusive",
                "policy-3-other-journal-refused", "policy-3-pending-blocks-session", "expired-adopted-policy-refused"]}
            for n in (3, 32)]}

    def boundary(self):
        return {"profile": {"members": 32, "traffic_bytes": 2031616, "rows": 123, "time_floor": 261,
            "workers": 32, "process_kills": 6, "policy_payload_bytes": 2091948,
            "active_pending_payload_bytes": 2117447,
            **{k: "a" * 64 for k in ("journal", "native_journal", "session")},
            "original_inventory": {"traffic_bytes": 2031616, "outboxes": 123,
                "epoch_record_hashes": [[0, "b" * 64], [1, "c" * 64]]},
            "denied_operations": ["expired-target-cannot-commit", "unknown-is-not-no-commit",
                "abandoned-operation-cannot-reissue", "historical-expiry-does-not-admit-old-policy",
                "time-floor-refuses-backdated-target", "expired-adopted-policy-refuses-old-output",
                "expired-final-policy-refuses-output"],
            "refusals": [{"case": c, "type": "ValueError", "error": "refused"} for c in [
                "parent-close-withholds-pending-result", "policy-marker-cannot-be-removed", "empty-policy-wrapper",
                "wrong-policy-journal", "policy-base-capacity", "policy-wrapper-cannot-expand-business",
                "policy-aggregate-capacity", "policy-allocation-cannot-fund-business"]]}}

    def test_complete_original_policy_and_full_store_workloads(self):
        verify_local_policy_profiles(self.profiles())
        verify_local_policy_boundary(self.boundary())

    def test_missing_cohort_or_replayed_approval_cannot_qualify(self):
        for mutate in [lambda r: r["profiles"].pop(), lambda r: r["profiles"][0]["approvals"].pop(),
                       lambda r: r["profiles"][0]["approvals"][1].update(operation="b" * 64),
                       lambda r: r["profiles"][0]["approvals"][1].update(now=170),
                       lambda r: r["profiles"][1].update(original_wire_sha256="0" * 64)]:
            report = self.profiles(); mutate(report)
            with self.assertRaises(ValueError): verify_local_policy_profiles(report)

    def test_missing_crash_and_permission_boundaries_are_rejected(self):
        for verify, make, key in [(verify_local_policy_profiles, self.profiles, "profiles"),
                                  (verify_local_policy_boundary, self.boundary, "profile")]:
            for name, value in [("process_kills", 0), ("workers", True), ("denied_operations", []),
                                ("journal", ""), ("members", 32.0)]:
                with self.subTest(key=key, name=name):
                    report = make(); row = report[key][0] if key == "profiles" else report[key]
                    row[name] = value
                    with self.assertRaises(ValueError): verify(report)

    def test_partial_business_inventory_or_single_policy_record_cannot_qualify(self):
        for mutate in [lambda r: r.update(active_pending_payload_bytes=2091948),
                       lambda r: r.update(time_floor=190), lambda r: r.update(rows=122),
                       lambda r: r["original_inventory"].update(traffic_bytes=1),
                       lambda r: r["original_inventory"]["epoch_record_hashes"].pop(),
                       lambda r: r["original_inventory"]["epoch_record_hashes"][1].__setitem__(0, 0),
                       lambda r: r["refusals"].pop(),
                       lambda r: r["refusals"][0].update(error="")]:
            report = self.boundary(); mutate(report["profile"])
            with self.assertRaises(ValueError): verify_local_policy_boundary(report)


class RosterRevocationReceiptTests(unittest.TestCase):
    def report(self):
        rows=[]
        for count,witnessed in [(3,False),(3,True),(32,False),(32,True)]:
            rows.append({"members":count,"witnessed":witnessed,"workers":50 if witnessed else 42,
                         "process_kills":5 if witnessed else 4,"native_trusted_time":355,
                         **{k:"d"*64 for k in ["journal","native_journal","session",
                            "original_message_sha256","original_offer_sha256"]},
                         "after_renewal":{"kind":"actual_common_account_peer_removal","target_version":19,
                            "positive_native_receive":True,"same_generation_resurrection_refused":True,
                            "original_enrollment_retained":True,"denied_operations":["removed-peer-denies-next-id",
                                "removed-peer-denies-old-output","removed-peer-denies-old-input","removed-peer-denies-fresh-input"],
                            "before_wire_sha256":"a"*64,"after_wire_sha256":"b"*64,"target_sha256":"c"*64}})
        return {"profiles":rows}

    def test_original_live_then_revoked_profiles(self):
        verify_roster_revocation(self.report())

    def test_missing_positive_control_or_refusal_cannot_qualify(self):
        for name,value in [("positive_native_receive",False),("original_enrollment_retained",1),
                           ("same_generation_resurrection_refused",False),("target_version",19.0),
                           ("denied_operations",[]),("target_sha256","")]:
            with self.subTest(name=name):
                report=self.report();report["profiles"][0]["after_renewal"][name]=value
                with self.assertRaises(ValueError): verify_roster_revocation(report)

    def test_replayed_wire_partial_cohort_or_old_clock_is_rejected(self):
        for change in [lambda r:r["profiles"].pop(),
                       lambda r:r["profiles"][1].update(native_trusted_time=170),
                       lambda r:r["profiles"][0]["after_renewal"].update(after_wire_sha256="a"*64)]:
            report=self.report();change(report)
            with self.assertRaises(ValueError): verify_roster_revocation(report)


class RosterCapacityReceiptTests(unittest.TestCase):
    def report(self):
        refusals=["R-cannot-select-nine","R-wire-cannot-downgrade","R-missing-marker",
                  "R-cannot-adopt-policy-version","R-metadata-cannot-expand-business",
                  "R-aggregate-bound","R-allocation-cannot-fund-send"]
        def row(witnessed):
            return {"witnessed":witnessed,"members":32,"traffic_bytes":2031616,"rows":123,
                    "native_trusted_time":355,"process_kills":4 if witnessed else 3,
                    "roster_payload_bytes":3048961,"roster_intent_bytes":3049550,
                    "original_inventory":{"traffic_bytes":2031616,"outboxes":123,
                        "epoch_record_hashes":[[0,"a"*64],[1,"b"*64]]},
                    "refusals":[{"case":name,"error":"refused","type":"ValueError"} for name in refusals],
                    **{k:"c"*64 for k in ["journal","native_journal","session",
                       "original_message_sha256","original_last_message_sha256"]}}
        return {"profiles":[row(False),row(True)]}

    def test_both_full_roster_profiles(self):
        verify_roster_capacity(self.report())

    def test_partial_business_or_recovery_cannot_qualify(self):
        for field,value in [("traffic_bytes",1024),("rows",122),("members",3),
                            ("native_trusted_time",170),("process_kills",0),("witnessed",1),
                            ("roster_payload_bytes",True),("roster_intent_bytes",1),
                            ("original_last_message_sha256","")]:
            with self.subTest(field=field):
                report=self.report();report["profiles"][1][field]=value
                with self.assertRaises(ValueError): verify_roster_capacity(report)

    def test_missing_epoch_refusal_or_profile_is_rejected(self):
        for change in [lambda r:r["profiles"].pop(),
                       lambda r:r["profiles"][0]["original_inventory"]["epoch_record_hashes"].pop(),
                       lambda r:r["profiles"][0]["original_inventory"].update(outboxes=123.0),
                       lambda r:r["profiles"][1]["refusals"].pop(),
                       lambda r:r["profiles"][1]["refusals"][0].update(error=""),
                       lambda r:r["profiles"][1]["refusals"].append(None)]:
            report=self.report();change(report)
            with self.assertRaises(ValueError): verify_roster_capacity(report)


class RosterReceiptTests(unittest.TestCase):
    def report(self, boundary=False):
        identities = {name: "1" * 64 for name in ("journal", "session", "native_journal",
                      "original_message_sha256", "original_offer_sha256")}
        if boundary:
            return {"profiles": [dict(identities, before_g=before, witnessed=witnessed, workers=workers)
                    for before,witnessed,workers in [(True,False,17),(True,True,23),(False,False,21),(False,True,35)]]}
        return {"profiles": [dict(identities, members=count, witnessed=witnessed,
                 workers=38 if witnessed else 32, process_kills=4 if witnessed else 3, native_trusted_time=355)
                 for count in (3,32) for witnessed in (False,True)]}

    def test_complete_owner_and_boundary_cohorts(self):
        for boundary in (False, True):
            verify_roster_profiles(self.report(boundary), boundary=boundary)

    def test_stale_native_clock_partial_cohort_and_wrong_identity_are_refused(self):
        for field,value in [("native_trusted_time",170),("members",3),("process_kills",0),
                            ("witnessed",1),("native_journal",""),("workers",True)]:
            with self.subTest(field=field):
                report=self.report(); report["profiles"][-1][field]=value
                with self.assertRaises(ValueError): verify_roster_profiles(report,boundary=False)
        for boundary in (False,True):
            report=self.report(boundary); report["profiles"].pop()
            with self.assertRaises(ValueError): verify_roster_profiles(report,boundary=boundary)

    def test_missing_closed_boundary_cannot_qualify(self):
        for field,value in [("before_g",True),("before_g",0),("workers",34),("journal","0"*64)]:
            with self.subTest(field=field):
                report=self.report(True); report["profiles"][-1][field]=value
                with self.assertRaises(ValueError): verify_roster_profiles(report,boundary=True)


class ExtensionSessionReceiptTests(unittest.TestCase):
    def report(self):
        return {"schema_version":1,"kind":"qperiapt.enrollment_extension_session","completed":True,
                "provider":"48.0.1","implementation":"/installed/client.py","native_sha256":"a"*64,
                "profiles":[{"completed":True,"profile":name,"native_commands":commands,
                    "witness_requests":witness,"bootstrap_time":210,"traffic_time":220,
                    "original_expiry":160,"extended_expiry":300,"confirmed_epoch":1,
                    "refusal_cases":["expired-original-policy","selected-installation-refuses-extension","extended-credential-expiry"]}
                    for name,commands,witness in [("local",13,0),("witness",125,110)]]}

    def verify(self, report):
        verify_extension_session(report,implementation="/installed/client.py",native_sha256="a"*64)

    def test_both_complete_profiles(self):
        self.verify(self.report())

    def test_old_clock_partial_work_or_false_types_cannot_claim_extension_session(self):
        for field,value in [("bootstrap_time",150),("traffic_time",170),("original_expiry",300),
                            ("confirmed_epoch",0),("confirmed_epoch",True),("completed",1),
                            ("witness_requests",0),("native_commands",124),("refusal_cases",[])]:
            with self.subTest(field=field,value=value):
                report=self.report(); report["profiles"][1][field]=value
                with self.assertRaisesRegex(ValueError,"workload, time or refusal"):
                    self.verify(report)

    def test_wrong_native_installed_owner_or_missing_profile_is_rejected(self):
        for field,value in [("native_sha256","b"*64),("implementation","/checkout/client.py"),
                            ("completed",False),("profiles",[]),("schema_version",True)]:
            with self.subTest(field=field):
                report=self.report(); report[field]=value
                with self.assertRaises(ValueError): self.verify(report)


class WheelBoundaryTests(unittest.TestCase):
    sources = {"__init__.py": b'"""Reference package."""\n', "wire.py": b"VALUE = 1\n"}
    licenses = {"LICENSE-APACHE": b"Apache text\n", "LICENSE-MIT": b"MIT text\n"}
    readme = b"Reference scope.\n"

    @staticmethod
    def record(files):
        record = io.StringIO(newline="")
        writer = csv.writer(record)
        for name, body in files.items():
            if name == DIST + "/RECORD":
                continue
            digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
            writer.writerow([name, "sha256=" + digest, str(len(body))])
        writer.writerow([DIST + "/RECORD", "", ""])
        return record.getvalue().encode()

    def wheel(self, mutate=lambda files: None):
        files = {PACKAGE + "/" + n: b for n, b in self.sources.items()}
        files.update({DIST + "/licenses/" + n: b for n, b in self.licenses.items()})
        files[DIST + "/METADATA"] = (
            "Metadata-Version: 2.5\nName: qperiapt-continuity-reference\nVersion: 0.0.0\n"
            "Requires-Python: >=3.14,<3.15\nLicense-Expression: Apache-2.0 OR MIT\n"
            "Classifier: Private :: Do Not Upload\nRequires-Dist: cryptography==48.0.1\n"
            "Import-Name: qperiapt_continuity_reference\nLicense-File: LICENSE-APACHE\n"
            "License-File: LICENSE-MIT\n\n").encode() + self.readme + b"\n"
        files[DIST + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: flit 4.1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        mutate(files)
        files[DIST + "/RECORD"] = self.record(files)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in files.items():
                archive.writestr(name, body)
        return output.getvalue()

    def test_closed_source_package(self):
        files = inspect_wheel(self.wheel(), self.sources, self.licenses, self.readme)
        self.assertEqual(files[PACKAGE + "/wire.py"], self.sources["wire.py"])

    def test_valid_record_does_not_authorize_changed_source(self):
        with self.assertRaisesRegex(ValueError, "source or license differs"):
            inspect_wheel(self.wheel(lambda f: f.update({PACKAGE + "/wire.py": b"VALUE = 2\n"})),
                          self.sources, self.licenses, self.readme)

    def test_added_import_hook_is_not_installed(self):
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            inspect_wheel(self.wheel(lambda f: f.update({"reference.pth": b"import hidden_hook\n"})),
                          self.sources, self.licenses, self.readme)

    def test_dependency_pin_cannot_be_widened(self):
        def change(files):
            name = DIST + "/METADATA"
            files[name] = files[name].replace(b"cryptography==48.0.1", b"cryptography>=48")
        with self.assertRaisesRegex(ValueError, "Requires-Dist"):
            inspect_wheel(self.wheel(change), self.sources, self.licenses, self.readme)

    def test_description_bytes_cannot_be_rewritten(self):
        def change(files):
            name = DIST + "/METADATA"
            files[name] = files[name].replace(self.readme, b"Different support promise.\n")
        with self.assertRaisesRegex(ValueError, "README differ"):
            inspect_wheel(self.wheel(change), self.sources, self.licenses, self.readme)

    def test_stale_record_is_rejected(self):
        with zipfile.ZipFile(io.BytesIO(self.wheel())) as original:
            files = {name: original.read(name) for name in original.namelist()}
        name = DIST + "/WHEEL"
        files[name] += b"\n"
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, body in files.items():
                archive.writestr(name, body)
        with self.assertRaisesRegex(ValueError, "RECORD content"):
            inspect_wheel(output.getvalue(), self.sources, self.licenses, self.readme)

    def installed(self, mutate=lambda files: None):
        wheel = self.wheel()
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            original = {name: archive.read(name) for name in archive.namelist()}
        files = dict(original)
        digest = hashlib.sha256(wheel).hexdigest()
        url = "file:///private/reference.whl"
        files[DIST + "/INSTALLER"] = b"pip\n"
        files[DIST + "/REQUESTED"] = b""
        files[DIST + "/direct_url.json"] = json.dumps({"url": url, "archive_info": {
            "hash": "sha256=" + digest, "hashes": {"sha256": digest}}}).encode()
        mutate(files)
        files[DIST + "/RECORD"] = self.record(files)
        return files, original, url, digest

    def test_pip_metadata_is_bound_to_selected_wheel(self):
        files, original, url, digest = self.installed()
        verify_installation(files, original, wheel_url=url, digest=digest)

    def test_editable_install_is_not_a_wheel_consumer(self):
        def change(files):
            files[DIST + "/direct_url.json"] = b'{"url":"file:///checkout","dir_info":{"editable":true}}'
        files, original, url, digest = self.installed(change)
        with self.assertRaisesRegex(ValueError, "origin differs"):
            verify_installation(files, original, wheel_url=url, digest=digest)

    def test_valid_installed_record_does_not_authorize_source_change(self):
        files, original, url, digest = self.installed(lambda f: f.update({PACKAGE + "/wire.py": b"VALUE = 2\n"}))
        with self.assertRaisesRegex(ValueError, "installed source or metadata differs"):
            verify_installation(files, original, wheel_url=url, digest=digest)
