"""Actual uncertain outcomes on both implementations and original-report recovery."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import hmac
import json

from application_fixture import record
from control_scenario import ControlScenario
from peer.resolution import ciphertext_digest
from peer.state_codec import encode, decode
from peer.traffic import DOMAIN, message_id
from peer.wire import Reader, ldh
from traffic_checks import application


class ResolutionScenario(ControlScenario):
    def bootstrap(self):
        self.steps, self.codec_refusals, self.decisions = [], 0, []
        initial = self.output_bytes("original-initial", "initial", now=150)
        reply = self.native_call("bootstrap-response", 4, initial)
        final = self.output_bytes("bootstrap-final", "finish", (reply,), now=150)
        self.session = self.native_call("bootstrap-complete", 5, final)
        self.native_call("native-activate", 6, expected=self.session)
        self.require(self.output_bytes("independent-activate", "activate") == self.session, "session activation")

    def settle(self, target, prefix):
        step = self.advance(1, prefix + "-start", target)
        recipient = 2
        for index in range(6):
            if step[1] is None:
                break
            step = self.receive(recipient, prefix + "-receive-" + str(index), step[1])
            recipient = 3 - recipient
        else:
            raise ValueError("control exchange bound")
        for role in (1, 2):
            self.require(self.advance(role, prefix + "-confirmed-" + str(role), target) == (target, None), "exact target confirmation")

    def native_report(self, name, epoch=0):
        reader = Reader(self.native_call(name, 24, epoch.to_bytes(8, "big")))
        result = {"id": reader.take(32).hex()}
        for key in ("epoch", "acknowledged_before", "sent", "consumed_before", "received", "peer_sent"):
            result[key] = reader.integer(8)
        result["outgoing"] = [{"id": reader.take(32).hex(), "ciphertext_digest": reader.take(32).hex()}
                              for _ in range(reader.integer(2))]
        result["incoming"] = []
        for _ in range(reader.integer(2)):
            identity, index, length = reader.take(32), reader.integer(8), reader.integer(4)
            self.require(length <= 16384, "native report plaintext bound")
            result["incoming"].append({"id": identity.hex(), "index": index, "plaintext": reader.take(length).hex()})
        result["skipped"] = [reader.integer(8) for _ in range(reader.integer(2))]
        reader.finish()
        (self.output / (name + ".report.json")).write_text(json.dumps(result, indent=2) + "\n")
        return result

    def application_decision(self, name, role, report):
        result = record(self.private / name, self.session, role, report)
        (self.output / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        self.decisions.append({"name": name, "role": role, "report_id": report["id"], "sha256": result["sha256"]})
        return result

    def traffic_fixture(self):
        self.sent, self.received = [], []
        for index in range(4):
            identity = self.output_bytes("send-id-" + str(index), "next_id")
            plain = (b"retained native plaintext" if index == 2 else b"outcome-" + bytes([index]))
            wire = self.output_bytes("send-" + str(index), "send", (identity, plain, b"resolution"))
            self.sent.append((identity, wire, plain))
            if index != 1:
                self.native_call("receive-" + str(index), 7, application(b"resolution", wire), plain)
            if index in (0, 3):
                ack = self.native_call("consume-" + str(index), 10, identity)
                self.worker("accept-ACK-" + str(index), "accept_acknowledgement", (ack,))
        for index in range(4):
            identity = self.native_call("native-id-" + str(index), 8)
            plain = bytes(range(256)) * 64 if index == 2 else b"peer-outcome-" + bytes([index])
            wire = self.native_call("native-send-" + str(index), 9, identity + application(b"resolution", plain))
            self.received.append((identity, wire, plain))
            if index != 1:
                self.require(self.worker("independent-receive-" + str(index), "receive", (wire, b"resolution"))
                             == [identity.hex(), plain.hex()], "actual retained receive")
            if index in (0, 3):
                ack = self.output_bytes("independent-consume-" + str(index), "consume", (identity,))
                self.native_call("native-accept-ACK-" + str(index), 11, ack)
        self.old_ack = ack

    def report_expected(self, report, outgoing, incoming):
        self.require([report[k] for k in ("epoch", "acknowledged_before", "sent", "consumed_before", "received", "peer_sent")]
                     == [0, 1, 4, 1, 4, 4], "original counters/floors changed")
        self.require(report["outgoing"] == [{"id": i.hex(), "ciphertext_digest": ciphertext_digest(w).hex()} for i, w, _p in outgoing[1:]], "unconfirmed report inventory")
        self.require(report["incoming"] == [{"id": incoming[2][0].hex(), "index": 2, "plaintext": incoming[2][2].hex()}]
                     and report["skipped"] == [1], "unconsumed/skipped report inventory")

    def codec_and_commitment(self, report):
        def check(snapshot, state):
            traffic, resolution = state.traffic.traffic(0), state.traffic.resolutions[0]
            body = bytearray(self.session + b"\1")
            for n in (0, 1, 4, 1, 4, 4):
                body.extend(n.to_bytes(8, "big"))
            body.extend((3).to_bytes(2, "big"))
            for index, (intent, wire) in sorted(traffic._outbox.items()):
                body.extend(message_id(self.session, 1, index, 0) + intent + ciphertext_digest(wire))
            body.extend((2).to_bytes(2, "big"))
            for index, (intent, plain) in sorted(traffic._inbox.items()):
                value = b"" if plain is None else plain
                body.extend(message_id(self.session, 2, index, 0) + index.to_bytes(8, "big") + intent
                            + bytes([plain is None]) + len(value).to_bytes(4, "big")
                            + ldh(DOMAIN + b"resolution-plaintext/v1", value))
            body.extend((1).to_bytes(2, "big") + (1).to_bytes(8, "big"))
            expected = hmac.digest(resolution.key, DOMAIN + b"closed-epoch-resolution/v1" + body, "sha256")
            self.require(expected.hex() == report["id"], "specified keyed report commitment")
            self.require(ldh(DOMAIN + b"closed-epoch-resolution/v1", body) != expected, "unkeyed draft ID used")
            self.require(resolution.key.hex() not in json.dumps(report), "private report key released")
            targets = (resolution.identity, resolution.key, self.sent[2][1], self.received[2][2])
            for selected in targets:
                offset = snapshot.payload.index(selected)
                altered = bytearray(snapshot.payload); altered[offset + len(selected) - 1] ^= 1
                try:
                    decoded = decode(bytes(altered), self.context)
                except ValueError:
                    self.codec_refusals += 1
                else:
                    decoded.close(); raise ValueError("changed frozen report admitted")
            for version in (2, 3):
                state.format_version = version
                try:
                    encode(state)
                except ValueError as error:
                    self.require("snapshot version four" in str(error), "wrong resolution downgrade refusal")
                    self.codec_refusals += 1
                else:
                    raise ValueError("resolution silently omitted by old format")
        self.inspect(check)

    def run(self):
        self.bootstrap()
        self.traffic_fixture()
        self.settle(1, "epoch-1")
        self.require(self.worker("old-format", "storage_format") == 3, "archived version-three writer")
        self.unchanged_refusal("old-resolution-refused", "begin_closed_epoch_resolution", (bytes(8),), "explicit snapshot upgrade")
        def old_reads(snapshot, state):
            old = self.old.decode(snapshot.payload, self.context)
            try:
                self.require(old.format_version == 3 and old.traffic.traffic(0)._send_floor == 1
                             and len(old.traffic.traffic(0)._outbox) == 3, "original closed history")
            finally:
                old.close()
        self.inspect(old_reads)
        self.worker("upgrade-result-lost", "upgrade_format", cut="protocol:format-upgraded")
        self.require(self.worker("upgrade-reconciled", "upgrade_format") == 5, "explicit resolution upgrade")
        def old_rejects(snapshot, _state):
            try:
                self.old.decode(snapshot.payload, self.context)
            except ValueError:
                return
            raise ValueError("version-three reader admitted new format")
        self.inspect(old_rejects)
        self.unchanged_refusal("current-epoch-refused", "begin_closed_epoch_resolution", ((1).to_bytes(8, "big"),), "epoch still open")
        self.advance(1, "pending-request-2", 2)
        self.unchanged_refusal("pending-control-refused", "begin_closed_epoch_resolution", (bytes(8),), "pending control")
        self.settle(2, "epoch-2")
        self.unchanged_refusal("missing-report-refused", "acknowledge_closed_epoch_resolution", (bytes(8), bytes([7]) * 32), "not requested")
        fresh_id = self.output_bytes("fresh-id", "next_id")
        self.worker("fresh-send-reserved", "send", (fresh_id, b"fresh during frozen epoch", b"fresh"), cut="protocol:send-reserved")
        self.worker("freeze-before-intent-lost", "begin_closed_epoch_resolution", (bytes(8),), cut="stage-synced:intent")
        self.require(self.worker("uncommitted-freeze-status", "closed_epoch_resolution_status", (bytes(8),)) == ["Unrequested", None], "staging orphan acquired report authority")
        self.worker("freeze-publication-lost", "begin_closed_epoch_resolution", (bytes(8),), cut="published:head")
        self.report = self.worker("report-recovered", "begin_closed_epoch_resolution", (bytes(8),))
        self.report_expected(self.report, self.sent, self.received)
        self.codec_and_commitment(self.report)
        self.identity = bytes.fromhex(self.report["id"])
        stable = (self.path / "head").read_bytes()
        self.require(self.worker("report-replayed", "begin_closed_epoch_resolution", (bytes(8),)) == self.report, "report replay changed")
        self.require((self.path / "head").read_bytes() == stable, "report replay rewrote state")
        self.require(self.worker("frozen-status", "status", (self.sent[1][0],)) == "ResolutionPending", "frozen send status")
        self.unchanged_refusal("expired-report", "begin_closed_epoch_resolution", (bytes(8),), "expired", now=200)
        self.unchanged_refusal("expired-resolution-ACK", "acknowledge_closed_epoch_resolution", (bytes(8), self.identity), "expired", now=200)
        self.require(self.worker("expired-report-status", "closed_epoch_resolution_status", (bytes(8),), now=200)
                     == ["Pending", self.identity.hex()], "read-only pending resolution status")
        fresh_wire = self.output_bytes("fresh-send-resumed", "resume", (fresh_id,))
        self.native_call("fresh-received", 7, application(b"fresh", fresh_wire), b"fresh during frozen epoch")
        fresh_ack = self.native_call("fresh-consumed", 10, fresh_id)
        self.worker("fresh-ACK", "accept_acknowledgement", (fresh_ack,))
        self.fence_checks("frozen")
        self.advance(1, "pending-offer-3", 3)
        self.require(self.worker("report-during-control", "begin_closed_epoch_resolution", (bytes(8),)) == self.report, "cached report during control")
        self.unchanged_refusal("wrong-report-ID", "acknowledge_closed_epoch_resolution", (bytes(8), bytes([9]) * 32), "conflicting resolution")
        from peer.durable import Session
        owner = Session.open(self.path, self.scope, self.key, self.context)
        try:
            before = (self.path / "head").read_bytes()
            for mutable in (bytearray(self.identity), memoryview(self.identity)):
                try:
                    owner.acknowledge_closed_epoch_resolution(0, mutable, 170)
                except ValueError as error:
                    self.require("acknowledgement scope" in str(error), "wrong mutable-ID refusal")
                else:
                    raise ValueError("mutable acknowledgement identity admitted")
            self.require((self.path / "head").read_bytes() == before, "mutable ID changed report")
            self.checks.append("bytearray and memoryview acknowledgement IDs refused before mutation; only immutable bytes are admitted")
        finally:
            owner.close()
        self.application_decision("python-application", 1, self.report)
        self.worker("resolution-ACK-before-intent-lost", "acknowledge_closed_epoch_resolution", (bytes(8), self.identity), cut="stage-synced:intent")
        self.require(self.worker("application-decision-pending-report", "begin_closed_epoch_resolution", (bytes(8),)) == self.report, "application decision changed frozen report")
        self.worker("resolution-ACK-lost", "acknowledge_closed_epoch_resolution", (bytes(8), self.identity), cut="protocol:resolution-acknowledged")
        self.terminal_checks()

    def fence_checks(self, label):
        cases = [("resume", (self.sent[1][0],)), ("send", (self.sent[1][0], self.sent[1][2], b"resolution")),
                 ("receive", (self.received[2][1], b"resolution")), ("consume", (self.received[2][0],)),
                 ("acknowledgement_for_epoch", (bytes(8),)), ("accept_acknowledgement", (self.native_call(label + "-native-ACK", 20, bytes(8)),))]
        for action, args in cases:
            self.unchanged_refusal(label + "-" + action, action, args, "resolution freezes")

    def terminal_checks(self):
        self.require(self.worker("unknown-send", "status", (self.sent[1][0],)) == "DeliveryUnknown", "unconfirmed send relabeled delivered")
        self.require(self.worker("previously-acknowledged-send", "status", (self.sent[0][0],)) == "Acknowledged", "original floor changed")
        stable = (self.path / "head").read_bytes()
        self.worker("resolution-ACK-replayed", "acknowledge_closed_epoch_resolution", (bytes(8), self.identity))
        self.require((self.path / "head").read_bytes() == stable, "acknowledgement replay rewrote state")
        self.unchanged_refusal("retired-report", "begin_closed_epoch_resolution", (bytes(8),), "report retired")
        self.fence_checks("acknowledged")
        native = self.native_report("native-report")
        self.report_expected(native, self.received, self.sent)
        self.native_call("native-pending-send", 27, self.received[1][0], b"ResolutionPending")
        self.application_decision("native-application", 2, native)
        self.native_call("native-resolution-ACK", 25, bytes(8) + bytes.fromhex(native["id"]), bytes.fromhex(native["id"]))
        self.native_call("native-reopened", 12, expected=b"reopened")
        self.native_call("native-unknown-send", 27, self.received[1][0], b"DeliveryUnknown")
        self.native_call("native-old-floor", 27, self.received[0][0], b"Acknowledged")
        self.native_call("native-retired-report", 24, bytes(8), status=2)
        def erased(_snapshot, state):
            traffic = state.traffic.traffic(0)
            self.require((traffic._send_floor, traffic._sent, traffic._receive_floor, traffic._received) == (1, 4, 1, 4), "resolution forged a floor")
            self.require(not traffic._outbox and not traffic._inbox and not traffic._skipped
                         and not state.traffic.resolutions[0].key and all(x == bytes(32) for x in
                         (traffic._send, traffic._receive, traffic._send_ack, traffic._receive_ack)), "logical retained secret/data cleanup")
            self.require(state.traffic.spent() == 1, "resolution refunded current budget")
        self.inspect(erased)
        for change in ("report-key", "traffic-key", "outbox", "identity"):
            def invalid(_snapshot, state):
                traffic = state.traffic.traffic(0)
                resolution = state.traffic.resolutions[0]
                if change == "report-key":
                    resolution.key = bytes([1]) * 32
                elif change == "traffic-key":
                    traffic._send_ack = bytes([1]) * 32
                elif change == "outbox":
                    traffic._outbox[1] = (bytes(32), self.sent[1][1])
                else:
                    resolution.identity = bytes(32)
                try:
                    encode(state)
                except ValueError:
                    self.codec_refusals += 1
                else:
                    raise ValueError("malformed acknowledged resolution admitted")
            self.inspect(invalid)
        for target in range(3, 7):
            self.settle(target, "epoch-" + str(target))
            self.forward("fresh-epoch-" + str(target))
        self.require(self.worker("collected-old-send", "status", (self.sent[1][0],)) == "Retired", "closed history collection")
        self.unchanged_refusal("collected-report-status", "closed_epoch_resolution_status", (bytes(8),), "retired or unadmitted")
        self.checks.append("unknown outcomes remain unknown; immutable application records precede acknowledgement and survive later collection")
