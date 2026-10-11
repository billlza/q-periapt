// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.file.Path

internal fun rootAuthorizePeer(root: ContinuityAccountAuthority, input: RootInputs, peerPath: String) {
    val peer = FixtureRecords(Path.of(peerPath)); val path = input.publicPath.resolve("traffic"); val records = FixtureRecords(path)
    val pin = AccountPin(AccountID(peer.enrollmentExact("responder-account", 32)), peer.enrollmentExact("responder-root", 1985),
        input.trust.family.encoded(), RosterCheckpoint(enrollmentCounter(peer.enrollmentExact("responder-roster-version", 8)),
            peer.enrollmentExact("responder-roster-digest", 32)))
    val application = ApplicationAccountID(records.enrollmentExact("peer-application", 32))
    val next = root.associate(application, pin, peer.read("responder-certificate"), peer.read("responder-roster"))
    check(next.application == application && next.account == pin.account && next.revision == Counter64.of(1))
    rootNumber(path, "peer-associated-revision", 1)
}
internal fun rootTraffic(device: ContinuityDevice, input: RootInputs, mode: String, peerPath: String, address: String) {
    val path = input.publicPath.resolve("traffic"); val records = FixtureRecords(path)
    val connect = mode == "traffic-connect"; val reject = mode == "traffic-reject-peer"
    val session = if (connect || reject) null else SessionID(records.enrollmentExact("session", 32))
    val peer = if (session == null) device.preparePeer(peerPath, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR)
        else device.preparePeerReopen(peerPath, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR, session)
    peer.use {
        if (reject) {
            refused(setOf(201)) { peer.finishOpen() }; rootNumber(path, "unknown-peer-code", 201); return
        }
        peer.finishOpen()
        if (connect) {
            val value = peer.establish(address, InitiationID(ByteArray(32) { 155.toByte() }))
            check(value.exchanges in 1..8); records.retain("session", value.session.encoded(), true)
        } else {
            val original = requireNotNull(session)
            when (mode) {
                "traffic-receive-cut", "traffic-receive-recover" -> rootReceive(peer, path, records, mode, original)
                "traffic-rekey" -> {
                    check(peer.rekey(address, original, Counter64.of(1)) == Counter64.of(1)); rootNumber(path, "rekey-epoch", 1)
                }
                else -> rootSend(peer, path, records, mode, address, original)
            }
        }
    }
}
private fun rootSend(peer: ContinuityOwner, path: Path, records: FixtureRecords, mode: String, address: String, session: SessionID) {
    val unknown = mode == "traffic-send-cut"; val retry = mode == "traffic-recover"; val after = mode == "traffic-after-rekey"
    check(unknown || retry || after)
    val message = if (retry) {
        MessageID(records.enrollmentExact("message-before", 32)).also {
            check(peer.messageStatus(session, it) == MessageStatus.COMMITTED)
        }
    } else {
        peer.nextMessage(session).also {
            val bytes = it.encoded()
            check(enrollmentCounter(bytes.copyOfRange(0, 8)) == Counter64.of(if (after) 1 else 0) &&
                enrollmentCounter(bytes.copyOfRange(8, 16)) == Counter64.ZERO)
            records.retain(if (after) "message-after" else "message-before", bytes, true)
        }
    }
    val send = { peer.send(address, session, message, "persisted before process exit".toByteArray(), "owned-service".toByteArray()) }
    if (unknown) {
        try { send(); error("receiver loss falsely confirmed") } catch (failure: ContinuityFailure) {
            check(failure.code in setOf(303, 309, 310, 311))
            check(peer.messageStatus(session, message) == MessageStatus.COMMITTED)
            rootNumber(path, "uncertain-code", failure.code.toLong())
        }
        rootPause(path, "sender")
    }
    val result = send()
    check(result.consumption == Consumption.CONFIRMED && result.exchanges in 1..8 &&
        peer.messageStatus(session, message) == MessageStatus.ACKNOWLEDGED)
    rootNumber(path, if (retry) "recovered-status" else "after-status", 3)
}
private fun rootReceive(peer: ContinuityOwner, path: Path, records: FixtureRecords, mode: String, session: SessionID) {
    val cut = mode == "traffic-receive-cut"; var calls = 0; var created = 0
    val port = peer.listen("127.0.0.1:0"); check(port > 0); output("root-listening:$port")
    val event = peer.serve { delivery ->
        calls += 1; check(delivery.session == session); refused(setOf(3)) { peer.close() }
        val payload = delivery.plaintext(); check(payload.contentEquals("persisted before process exit".toByteArray()))
        if (records.retain("application-${hex(delivery.message)}",
                delivery.session.encoded() + delivery.message.encoded() + payload, true)) created += 1
        if (cut) rootPause(path, "receiver")
    }
    check(!cut && event is Served.Message && event.session == session && !event.duplicate && calls == 1 && created == 0)
    records.retain("reply-received", event.message.encoded(), true); rootNumber(path, "reply-created-on-recovery", created.toLong())
}
