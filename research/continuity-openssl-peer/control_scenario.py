"""Focused recovery and refusal scenarios shared by the control schedule runner."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib

from durable_rekey_checks import Scenario
from peer.control import inspect
from peer.state_codec import encode, decode
from peer.traffic import message_id
from signing_fixture import read
from traffic_checks import application


class ControlScenario(Scenario):
    def step(self, name, side, result):
        self.require(len(result) == 2 and type(result[0]) is int and result[0] > 0, "control result")
        target, wire = result
        if wire is not None:
            if isinstance(wire, str):
                wire = bytes.fromhex(wire)
            self.require(inspect(wire)[1] == target, "output target binding")
            (self.output / (name + ".wire")).write_bytes(wire)
        self.steps.append({"case": name, "side": side, "target": target, "confirmed": wire is None,
                           "wire_sha256": None if wire is None else hashlib.sha256(wire).hexdigest()})
        return target, wire

    def python(self, name, action, arguments=(), **options):
        return self.step(name, "python", self.worker(name, action, arguments, **options))

    def native_step(self, name, command, payload):
        value = self.native_call(name, command, payload)
        self.require(len(value) >= 9 and value[0] in (0, 1) and (value[0] == 1 or len(value) == 9), "native control framing")
        return self.step(name, "rust", (int.from_bytes(value[1:9], "big"), value[9:] if value[0] else None))

    def advance(self, side, name, target):
        value = target.to_bytes(8, "big")
        return self.python(name, "advance_rekey_control", (value,)) if side == 1 else self.native_step(name, 21, value)

    def receive(self, side, name, wire):
        return self.python(name, "receive_rekey_control", (wire,)) if side == 1 else self.native_step(name, 22, wire)

    def wire(self, step):
        self.require(step[1] is not None, "expected committed control output")
        return step[1]

    def codec_controls(self, label, wire=None):
        from cryptography.exceptions import InvalidSignature
        def verify(snapshot, state):
            request = state.traffic.request
            selected = request.body if wire is None else wire
            start = snapshot.payload.index(selected)
            for at in ([0, 8, 40, 72, 104, 112, 120, 121] if wire is None else [4, len(wire) - 65, len(wire) - 1]):
                altered = bytearray(snapshot.payload)
                altered[start + at] ^= 1
                try:
                    decoded = decode(bytes(altered), self.context)
                except (ValueError, InvalidSignature):
                    self.codec_refusals += 1
                else:
                    decoded.close()
                    raise ValueError("changed persisted control admitted")
            state.format_version = 2
            try:
                encode(state)
            except ValueError as error:
                self.require("snapshot version three" in str(error), "wrong downgrade refusal")
                self.codec_refusals += 1
            else:
                raise ValueError("request silently omitted by old writer")
        self.inspect(verify)
        self.checks.append(label + ": malformed private snapshot and downgrade refused")

    def run(self):
        self.steps, self.codec_refusals = [], 0
        self.require(self.worker("original-format", "storage_format") == 2, "archived writer format")
        initial = self.output_bytes("original-initial", "initial", now=150)
        reply = self.native_call("bootstrap-response", 4, initial)
        final = self.output_bytes("bootstrap-final", "finish", (reply,), now=150)
        self.session = self.native_call("bootstrap-complete", 5, final)
        self.native_call("native-activate", 6, expected=self.session)
        self.require(self.output_bytes("independent-activate", "activate") == self.session, "session activation")
        old_id = self.output_bytes("original-send-id", "next_id")
        original_plain = b"original version-two operation"
        self.worker("old-send-reserved", "send", (old_id, original_plain, b"upgrade"), cut="protocol:send-reserved")
        old_offer = self.output_bytes("old-offer", "prepare_rekey_offer")
        def old_reads(snapshot, state):
            old = self.old.decode(snapshot.payload, self.context)
            try:
                self.require(old.format_version == 2 and old.pending.identity == old_id and
                             old.pending.plaintext == original_plain and old.traffic.plan.offer == old_offer,
                             "original version-two pending state")
            finally:
                old.close()
        self.inspect(old_reads)
        self.unchanged_refusal("old-control-refused", "advance_rekey_control", ((1).to_bytes(8, "big"),), "explicit snapshot upgrade")
        self.worker("upgrade-result-lost", "upgrade_format", cut="protocol:format-upgraded")
        stable = (self.path / "head").read_bytes()
        self.require(self.worker("upgrade-reconciled", "upgrade_format") == 5, "explicit control upgrade")
        self.require((self.path / "head").read_bytes() == stable, "upgrade replay changed head")
        def old_rejects(snapshot, state):
            self.require(state.pending.identity == old_id and state.traffic.plan.offer == old_offer, "upgrade lost operation")
            try:
                self.old.decode(snapshot.payload, self.context)
            except ValueError:
                return
            raise ValueError("old reader accepted version three")
        self.inspect(old_rejects)
        old_wire = self.output_bytes("old-send-resumed", "resume", (old_id,))
        self.native_call("old-send-received", 7, application(b"upgrade", old_wire), original_plain)
        old_ack = self.native_call("old-send-consumed", 10, old_id)
        request1 = self.wire(self.advance(2, "native-request-1", 1))
        self.native_call("native-request-status", 23, expected=b"Committed")
        for index, bad in enumerate((b"", request1[:-1], request1 + b"x", b"\xff" * 8193,
                                     request1[:157] + bytes([request1[157] ^ 1]) + request1[158:])):
            self.unchanged_refusal("bad-control-" + str(index), "receive_rekey_control", (bad,),
                                   "InvalidSignature" if index == 4 else "ValueError")
        offer = self.wire(self.receive(1, "request-1-offer", request1))
        self.require(offer == old_offer, "request replaced original version-two offer")
        response = self.wire(self.receive(2, "control-1-response", offer))
        final = self.wire(self.receive(1, "control-1-final", response))
        self.require(self.wire(self.receive(1, "request-during-final", request1)) == offer, "pending request replay")
        receipt = self.wire(self.receive(2, "control-1-receipt", final))
        self.native_call("native-request-cleared", 23, expected=b"Absent")
        self.require(self.receive(1, "control-1-confirmed", receipt) == (1, None), "control completion")
        stable = (self.path / "head").read_bytes()
        self.require(self.wire(self.receive(1, "completed-request-replay", request1)) == offer, "completed offer replay")
        self.require((self.path / "head").read_bytes() == stable, "completed request started new target")
        self.checks.append("archived version-two writer; pending send and exact offer survive explicit interrupted upgrade")

        for index in range(4):
            self.forward("budget-1-" + str(index))
        self.inspect(lambda _snapshot, state: self.require(state.traffic.spent() == 4
            and not state.traffic.traffic(1)._outbox, "ACKs refunded the signed budget"))
        blocked_id = message_id(self.session, 1, 4, 1)
        self.unchanged_refusal("budget-before-request", "send", (blocked_id, b"no credit", b""), "send capacity or signed budget")
        target2 = ((2).to_bytes(8, "big"),)
        self.worker("request-body-lost", "advance_rekey_control", target2, cut="protocol:rekey-request-prepared")
        self.require(self.worker("prepared-status", "rekey_request_status") == "BodyPrepared", "request preparation status")
        self.codec_controls("prepared request")
        self.unchanged_refusal("prepared-missing-signer", "advance_rekey_control", target2, "signing owner required", with_signer=False)
        original_signer = self.driver.signer_path
        self.driver.signer_path = self.wrong_signer_path
        try:
            self.unchanged_refusal("prepared-wrong-signer", "advance_rekey_control", target2, "signing owner required")
        finally:
            self.driver.signer_path = original_signer
        self.worker("request-commit-lost", "advance_rekey_control", target2, cut="protocol:rekey-request-committed")
        request2 = self.wire(self.python("request-recovered", "advance_rekey_control", target2, with_signer=False))
        self.require(self.worker("committed-status", "rekey_request_status", now=200) == "Committed", "expired status")
        self.codec_controls("committed request", request2)
        self.unchanged_refusal("expired-control-output", "replay_rekey_control", (request2,), "expired", now=200)
        self.unchanged_refusal("budget-after-request", "send", (blocked_id, b"no credit", b""), "send capacity or signed budget")
        self.require(self.wire(self.python("request-exact-replay", "replay_rekey_control", (request2,), with_signer=False)) == request2, "request exact outbox")
        signer, body = read(self.signer_path), request2[4:157]
        for index, at in enumerate((0, 8, 40, 72, 104, 112, 120, 121)):
            altered = bytearray(body); altered[at] ^= 1
            self.native_call("signed-bad-request-" + str(index), 22, signer.sign(13, bytes(altered)), status=2)
        self.native_call("request-wrong-purpose", 22, signer.sign(9, body), status=2)
        for index, at in enumerate((157, len(request2) - 1)):
            altered = bytearray(request2); altered[at] ^= 1
            self.native_call("request-bad-signature-" + str(index), 22, bytes(altered), status=2)
        self.native_call("native-no-rejected-work", 16, expected=b"".join(x.to_bytes(8, "big") for x in (1, 1, 1, 0)))
        offer2 = self.wire(self.receive(2, "request-2-offer", request2))
        self.worker("response-body-lost", "receive_rekey_control", (offer2,), cut="protocol:rekey-response-prepared")
        self.worker("response-commit-lost", "advance_rekey_control", target2, cut="protocol:rekey-response-committed")
        response2 = self.wire(self.python("response-control-recovered", "advance_rekey_control", target2, with_signer=False))
        final2 = self.wire(self.receive(2, "control-2-final", response2))
        self.worker("receipt-body-lost", "receive_rekey_control", (final2,), cut="protocol:rekey-receipt-prepared")
        self.worker("receipt-commit-lost", "advance_rekey_control", target2, cut="protocol:rekey-receipt-committed")
        self.require(self.advance(1, "local-confirmation-2", 2) == (2, None), "local confirmation")
        receipt2 = self.wire(self.python("receipt-delivery-recovered", "start_rekey_control", target2, with_signer=False))
        self.require(self.wire(self.python("receipt-exact-replay", "replay_rekey_control", (receipt2,), with_signer=False)) == receipt2, "receipt replay")
        self.require(self.receive(2, "control-2-confirmed", receipt2) == (2, None), "peer confirmed receipt")
        self.require(self.worker("request-cleared", "rekey_request_status") == "Absent", "completed request retention")
        self.unchanged_refusal("old-request-replay-refused", "replay_rekey_control", (request2,), "outbox absent")
        self.unchanged_refusal("retired-incoming-request", "receive_rekey_control", (request1,), "retired control request")
        self.checks.append("signed request consumes no application credit; every unsigned/committed request and responder stage resumes")

        target3 = ((3).to_bytes(8, "big"),)
        request3 = self.wire(self.advance(2, "native-request-3", 3))
        self.worker("offer-key-lost", "receive_rekey_control", (request3,), cut="protocol:rekey-key-reserved")
        self.worker("offer-commit-lost", "advance_rekey_control", target3, cut="protocol:rekey-offer-committed")
        offer3 = self.wire(self.python("offer-control-recovered", "advance_rekey_control", target3, with_signer=False))
        response3 = self.wire(self.receive(2, "control-3-response", offer3))
        self.worker("final-body-lost", "receive_rekey_control", (response3,), cut="protocol:rekey-final-prepared")
        self.worker("final-commit-lost", "advance_rekey_control", target3, cut="protocol:rekey-final-committed")
        final3 = self.wire(self.python("final-control-recovered", "advance_rekey_control", target3, with_signer=False))
        receipt3 = self.wire(self.receive(2, "control-3-receipt", final3))
        self.worker("receipt-accept-lost", "receive_rekey_control", (receipt3,), cut="protocol:rekey-receipt-accepted")
        self.require(self.advance(1, "control-3-confirmed", 3) == (3, None), "accepted receipt recovery")
        request4 = self.wire(self.advance(1, "unsettled-history-request", 4))
        offer4 = self.wire(self.receive(2, "history-offer", request4))
        self.unchanged_refusal("unsettled-history-offer-refused", "receive_rekey_control", (offer4,), "unsettled history capacity")
        self.require(self.output_bytes("old-send-still-retained", "resume", (old_id,)) == old_wire, "history lost original ciphertext")
        self.worker("old-ACK-unblocks", "accept_acknowledgement", (old_ack,))
        self.checks.append("request asserts no history settlement; old outbox blocks offer until its original ACK")

    def final_checks(self):
        for target in (0, 6, 9, (1 << 64) - 1):
            self.unchanged_refusal("invalid-target-" + str(target), "advance_rekey_control", (target.to_bytes(8, "big"),), "ValueError")
        self.unchanged_refusal("expired-confirmation", "advance_rekey_control", ((7).to_bytes(8, "big"),), "expired", now=200)
        self.require(self.worker("expired-progress", "rekey_progress", now=200) == [7, 7, 7, 0], "read-only completed status")
        self.checks.append("bounded loss/duplication schedule completes both peers without application traffic or implicit next targets")
