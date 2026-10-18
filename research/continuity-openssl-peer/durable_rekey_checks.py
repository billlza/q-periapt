#!/usr/bin/env python3
"""Real-process recovery of independent rekey owners, budgets and old formats."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import zipfile


class Scenario:
    def __init__(self, args):
        from peer.wire import SigningKey, require
        from peer.bootstrap import Initiator
        from peer.durable import Session, owner_binding
        from peer.journal import Journal, Scope
        from fixture_inputs import load
        from run import Counterpart
        from session_driver import SessionDriver
        from signing_fixture import write
        self.require = require
        self.output = args.output.resolve()
        self.output.mkdir()
        (self.output / "native").mkdir()
        self.private = Path(tempfile.mkdtemp(prefix="qperiapt-independent-rekey-")).resolve()
        require(not self.private.is_relative_to(self.output), "private rekey state inside artifact")
        (self.output / "private-fixture-path").write_text(str(self.private) + "\n")
        self.native = Counterpart(args.native.resolve(strict=True), self.output / "native", send_budget=4)
        signer = SigningKey()
        require(self.native.transfer(signer.public().raw) == b"\1ready", "native enrollment")
        _, _, self.context = load(self.output / "native/public", 150)
        require(self.context.send_budget == 4, "actual signed budget differs")
        self.key = os.urandom(32)
        self.scope = Scope(os.urandom(32), owner_binding(self.context), self.context.digest)
        configuration = self.private / "configuration"
        fd = os.open(configuration, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(self.key + self.scope.wire());stream.flush();os.fsync(stream.fileno())
        self.signer_path = self.private / "signer"
        write(self.signer_path, signer)
        self.wrong_signer_path = self.private / "wrong-signer"
        write(self.wrong_signer_path, SigningKey())
        self.path = self.private / "session"
        self.path.mkdir(mode=0o700)
        # Execute the archived old writer, never synthesize a claimed old format.
        archive = Path("research/sdk-alpha1/evidence/20261018-independent-storage/CAPTURE.zip")
        with zipfile.ZipFile(archive) as saved:
            source = saved.read("source/peer/state_codec.py")
        expected = json.loads(archive.with_name("CHECKS.json").read_text())["source_files"]["peer/state_codec.py"]
        require(hashlib.sha256(source).hexdigest() == expected, "old codec source changed")
        self.old_codec_sha256 = expected
        self.old = types.ModuleType("peer.old_snapshot_fixture")
        self.old.__package__ = "peer"
        sys.modules[self.old.__name__] = self.old
        exec(compile(source, "archived-state-codec", "exec"), self.old.__dict__)
        original = self.old.State(Initiator(self.context, signer, 150))
        owner = Journal.create(self.path, self.scope, self.key, self.old.encode(original), Session._validator(self.context))
        owner.close();original.close()
        self.driver = SessionDriver(self.output, args.provider_root.resolve(), self.output / "native/public",
                                    configuration, self.path, self.signer_path)
        self.checks, self.epochs = [], []
        self.worker = self.driver.run

    def native_call(self, name, command, wire=b"", expected=None, status=1):
        return self.native.command(name, command, wire, status, expected)

    def output_bytes(self, name, action, arguments=(), **options):
        return bytes.fromhex(self.worker(name, action, arguments, **options))

    def inspect(self, callback):
        from peer.durable import Session
        owner = Session.open(self.path, self.scope, self.key, self.context)
        try:
            with owner._state() as (snapshot, state):
                return callback(snapshot, state)
        finally:
            owner.close()

    def unchanged_refusal(self, name, action, arguments, reason, **options):
        before = (self.path / "head").read_bytes()
        self.worker(name, action, arguments, refusal=reason, **options)
        self.require((self.path / "head").read_bytes() == before, "refusal changed head: " + name)

    def migration(self):
        initial = self.output_bytes("original-initial", "initial", now=150)
        reply = self.native_call("bootstrap-response", 4, initial)
        final = self.output_bytes("bootstrap-final", "finish", (reply,), now=150)
        self.session = self.native_call("bootstrap-complete", 5, final)
        self.native_call("native-activate", 6, expected=self.session)
        self.require(self.output_bytes("independent-activate", "activate") == self.session, "session activation")
        self.unchanged_refusal("legacy-rekey-refused", "prepare_rekey_offer", (), "explicit snapshot upgrade required")
        self.worker("upgrade-result-lost", "upgrade_format", cut="protocol:format-upgraded")
        stable = (self.path / "head").read_bytes()
        self.require(self.worker("upgrade-reconciled", "upgrade_format") == 2, "upgrade result")
        self.require((self.path / "head").read_bytes() == stable, "upgrade replay rewrote head")
        def old_reader(snapshot, state):
            self.require(state.format_version == 2 and state.operation.session_id() == self.session, "migration changed session")
            try:
                self.old.decode(snapshot.payload, self.context)
            except ValueError:
                return
            raise ValueError("old reader admitted new snapshot")
        self.inspect(old_reader)
        self.checks.append("original archived writer migrated explicitly; old reader refuses new format; upgrade replay idempotent")

    def forward(self, name, *, acknowledge=True, plaintext=b"persisted rekey application"):
        from traffic_checks import application
        identity = self.output_bytes(name+"-id", "next_id")
        wire = self.output_bytes(name+"-send", "send", (identity, plaintext, b"rekey AD"))
        self.native_call(name+"-receive", 7, application(b"rekey AD", wire), plaintext)
        ack = self.native_call(name+"-consume", 10, identity)
        if acknowledge:
            self.worker(name+"-ACK", "accept_acknowledgement", (ack,))
        return identity, wire, ack

    def reverse(self, name):
        from traffic_checks import application
        identity = self.native_call(name+"-id", 8)
        plaintext, ad = bytes(range(256))*64, bytes(range(256))*4
        wire = self.native_call(name+"-send", 9, identity+application(ad, plaintext))
        self.require(self.worker(name+"-receive", "receive", (wire, ad)) == [identity.hex(), plaintext.hex()], "reverse plaintext")
        ack = self.output_bytes(name+"-consume", "consume", (identity,))
        self.native_call(name+"-ACK", 11, ack, (1).to_bytes(8,"big"))

    def initial_budget(self, final):
        from traffic_checks import application
        queued = []
        for index in range(2):
            identity = self.output_bytes(f"budget-{index}-id", "next_id")
            wire = self.output_bytes(f"budget-{index}-send", "send", (identity, b"unconfirmed", b"budget"))
            queued.append((identity, wire))
        blocked = self.output_bytes("budget-blocked-id", "next_id")
        self.unchanged_refusal("budget-before-receipt", "send", (blocked,b"blocked",b"budget"), "aggregate signed send budget")
        self.native_call("future-epoch-before-final", 7, application(b"budget",queued[0][1]), b"Suspended", 2)
        receipt = self.native_call("epoch-1-receipt", 15, final)
        for index,(identity,wire) in enumerate(queued):
            self.native_call(f"budget-{index}-receive",7,application(b"budget",wire),b"unconfirmed")
            ack=self.native_call(f"budget-{index}-consume",10,identity)
            self.worker(f"budget-{index}-ACK","accept_acknowledgement",(ack,))
        self.unchanged_refusal("budget-after-ACK", "send", (blocked,b"blocked",b"budget"), "aggregate signed send budget")
        self.worker("receipt-accept-result-lost","accept_rekey_receipt",(receipt,),cut="protocol:rekey-receipt-accepted")
        self.require(self.worker("receipt-accept-replay","accept_rekey_receipt",(receipt,))==1,"receipt acceptance")
        self.require(self.output_bytes("budget-slot-preserved","next_id")==blocked,"denied send consumed slot")
        self.forward("confirmed-budget")
        self.checks.append("old and unconfirmed epochs share signed budget 4; ACK does not refund; receipt confirmation advances window")
        return receipt

    def propose(self, epoch):
        label=f"epoch-{epoch}-"
        if epoch==1:
            self.worker("offer-key-lost","prepare_rekey_offer",cut="protocol:rekey-key-reserved")
            self.unchanged_refusal("unsigned-offer","rekey_outbox",((1).to_bytes(8,"big"),bytes(8)),"unsigned rekey outbox")
            self.unchanged_refusal("missing-signing-owner","prepare_rekey_offer",(),"current local signing owner required",with_signer=False)
            self.driver.signer_path = self.wrong_signer_path
            try:
                self.unchanged_refusal("different-signing-owner","prepare_rekey_offer",(),"current local signing owner required")
            finally:
                self.driver.signer_path = self.signer_path
            self.worker("offer-output-lost","prepare_rekey_offer",cut="protocol:rekey-offer-committed")
        offer=self.output_bytes(label+"offer","prepare_rekey_offer",with_signer=epoch!=1)
        response=self.native_call(label+"response",14,offer)
        if epoch==1:
            self.worker("final-prepare-lost","accept_rekey_response",(response,),cut="protocol:rekey-final-prepared")
            identity=self.output_bytes("fenced-old-id","next_id")
            self.unchanged_refusal("final-send-fence","send",(identity,b"fenced",b""),"rekey send fence")
            self.worker("final-output-lost","accept_rekey_response",(response,),cut="protocol:rekey-final-committed")
            self.require(self.worker("asymmetric-progress","rekey_progress")==[0,1,0,1],"directional final progress")
            self.codec_controls()
        elif epoch==3:
            self.worker("publication-result-lost","accept_rekey_response",(response,),cut="published:head")
            head=(self.path/"head").read_bytes()
            self.require(self.worker("publication-recovered","rekey_progress")==[2,2,2,3],"publication recovery phase")
            self.require((self.path/"head").read_bytes()==head,"recovery changed exact target")
        final=self.output_bytes(label+"final","accept_rekey_response",(response,),with_signer=epoch!=1)
        if epoch==1:
            receipt=self.initial_budget(final)
        else:
            receipt=self.native_call(label+"receipt",15,final)
            self.worker(label+"accept-receipt","accept_rekey_receipt",(receipt,))
        return offer,response,final,receipt

    def respond(self, epoch):
        label=f"epoch-{epoch}-"
        offer=self.native_call(label+"offer",17)
        if epoch==4:
            self.require(self.output_bytes("retained-old-outbox","resume",(self.old_id,))==self.old_wire,"old outbox lost")
            self.unchanged_refusal("unsettled-prefix","respond_rekey_offer",(offer,),"unsettled history capacity")
            self.worker("recover-old-ACK","accept_acknowledgement",(self.old_ack,))
        if epoch==2:
            self.worker("response-prepare-lost","respond_rekey_offer",(offer,),cut="protocol:rekey-response-prepared")
            self.worker("response-output-lost","respond_rekey_offer",(offer,),cut="protocol:rekey-response-committed")
        response=self.output_bytes(label+"response","respond_rekey_offer",(offer,),with_signer=epoch!=2)
        final=self.native_call(label+"final",18,response)
        if epoch==2:
            self.worker("receipt-prepare-lost","finish_rekey",(final,),cut="protocol:rekey-receipt-prepared")
            identity=self.output_bytes("receipt-fenced-id","next_id")
            self.unchanged_refusal("receipt-send-fence","send",(identity,b"fenced",b""),"rekey send fence")
            self.worker("receipt-output-lost","finish_rekey",(final,),cut="protocol:rekey-receipt-committed")
        receipt=self.output_bytes(label+"receipt","finish_rekey",(final,),with_signer=epoch!=2)
        self.native_call(label+"accept-receipt",19,receipt,epoch.to_bytes(8,"big"))
        return offer,response,final,receipt

    def codec_controls(self):
        from peer.state_codec import decode
        def control(snapshot,state):
            base=41+5817+4633+136+32
            raw=snapshot.payload
            wrong_root=raw[:base]+bytes([raw[base]^1])+raw[base+1:]
            wrong_epoch=raw[:base+40]+bytes(8)+raw[base+48:]
            for name,payload in [("pending-root-binding",wrong_root),("directional-counter-binding",wrong_epoch)]:
                try:decode(payload,self.context)
                except ValueError:self.checks.append(name+" refused")
                else:raise ValueError("invalid snapshot accepted: "+name)
        self.inspect(control)

    def close_before_release(self):
        from peer.durable import Session
        from traffic_checks import application
        def observe(stage):
            if stage == "protocol:send-committed":
                owner.close()
        owner = Session.open(self.path, self.scope, self.key, self.context, observer=observe)
        try:
            identity = owner.next_id(170)
            try:
                owner.send(identity, b"committed before close", b"close", 170)
            except ValueError as error:
                self.require("closed" in str(error), "different release failure")
            else:
                raise ValueError("closed owner released ciphertext")
        finally:
            owner.close()
        wire = self.output_bytes("closed-release-resume", "resume", (identity,))
        self.native_call("closed-release-receive", 7, application(b"close", wire), b"committed before close")
        ack = self.native_call("closed-release-consume", 10, identity)
        self.worker("closed-release-ACK", "accept_acknowledgement", (ack,))
        self.checks.append("close after commit denies output; same original store recovers committed ciphertext")

    def run(self):
        self.migration()
        self.forward("old-first")
        self.old_id,self.old_wire,self.old_ack=self.forward("old-unacknowledged",acknowledge=False)
        for epoch in range(1,9):
            wires=self.propose(epoch)if epoch%2 else self.respond(epoch)
            self.require(self.worker(f"epoch-{epoch}-progress","rekey_progress")==[epoch,epoch,epoch,0],"completed progress")
            for flight,wire in enumerate(wires):
                args=(epoch.to_bytes(8,"big"),flight.to_bytes(8,"big"))
                self.require(self.output_bytes(f"epoch-{epoch}-outbox-{flight}","rekey_outbox",args,with_signer=False)==wire,"control outbox changed")
            if epoch!=1:self.forward(f"epoch-{epoch}-traffic")
            self.reverse(f"epoch-{epoch}-reverse")
            self.epochs.append({"epoch":epoch,"proposer":1 if epoch%2 else 2,"both_directions":True})
        self.require(self.worker("retired-old-status","status",(self.old_id,))=="Retired","old epoch not retired")
        self.unchanged_refusal("retired-old-resume","resume",(self.old_id,),"retired or unadmitted epoch")
        self.close_before_release()
        self.require(self.worker("expired-progress","rekey_progress",now=200)==[8,8,8,0],"expired progress unavailable")
        self.require(self.worker("expired-upgrade-status","storage_format",now=200)==2,"expired upgrade status unavailable")
        self.unchanged_refusal("expired-cached-control","rekey_outbox",((8).to_bytes(8,"big"),(3).to_bytes(8,"big")),"expired or premature authority",now=200)
        self.native_call("close",3,expected=b"closed")
        self.require(self.native.process.wait(timeout=5)==0,"native close")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("provider-root","native","output"):p.add_argument("--"+name,type=Path,required=True)
    args=p.parse_args();peer=Path(__file__).resolve().parent;sys.path.append(str(peer))
    from provider import load_provider
    crypto,backend=load_provider(args.provider_root)
    scenario=Scenario(args)
    try:
        scenario.run()
        sources=[*sorted((peer/"peer").glob("*.py")),*sorted(peer.glob("*.py")),*sorted((peer/"native/src").glob("*.rs")),peer/"native/Cargo.toml",peer/"native/Cargo.lock",peer/"requirements.txt"]
        report={"scope":"Independent local-only multi-epoch journal recovery against a live native journal; no required witnesses, identity renewal or complete installation lifecycle",
                "epochs":scenario.epochs,"checks":scenario.checks,"worker_operations":scenario.driver.operations,
                "process_kills":sum("signal"in x for x in scenario.driver.operations),"native_commands":scenario.native.commands,
                "signed_send_budget":4,"old_codec_sha256":scenario.old_codec_sha256,
                "source_files":{str(p.relative_to(peer)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources},
                "native_sha256":hashlib.sha256(args.native.read_bytes()).hexdigest(),
                "provider":{"cryptography":crypto.__version__,"openssl":backend.openssl_version_text()},
                "identity_signing_key_in_session":False,"native_process_restart":False,"hardware_power_loss":False}
        (scenario.output/"RESULT.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps({"epochs":len(report['epochs']),"worker_operations":len(report['worker_operations']),"process_kills":report['process_kills'],"native_commands":len(report['native_commands'])}))
    finally:scenario.native.close()


if __name__=="__main__":main()
