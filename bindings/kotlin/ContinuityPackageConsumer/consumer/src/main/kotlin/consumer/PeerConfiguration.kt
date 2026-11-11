// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.file.Path

/** Qualification host only: SDK receives independent copied inputs, never this peer path. */
internal fun peerConfiguration(path: String): PeerConfiguration {
    val records = FixtureRecords(Path.of(path), 65536)
    fun counter(name: String) = Counter64.parse(java.lang.Long.toUnsignedString(ByteBuffer.wrap(records.enrollmentExact(name, 8)).long))
    fun device(prefix: String): PeerDeviceExpectation {
        val pin = AccountPin(AccountID(records.enrollmentExact("$prefix-account", 32)),
            records.enrollmentExact("$prefix-root", 1985), records.enrollmentExact("family", 32),
            RosterCheckpoint(counter("$prefix-roster-version"), records.enrollmentExact("$prefix-roster-digest", 32)))
        return PeerDeviceExpectation(pin, records.enrollmentExact("$prefix-device", 16), counter("$prefix-generation"))
    }
    return PeerConfiguration(device("initiator"), device("responder"), records.enrollmentExact("directory", 32),
        records.read("bootstrap.bundle"), records.read("tls-peer"), records.read("tls-peer-name").decodeToString(throwOnInvalidSequence = true))
}

private data class PreparedPeer(val child: ContinuityOwner, val parent: java.lang.ref.WeakReference<ContinuityDevice>)
private fun preparedWithoutPublicParent(path: String, input: PeerConfiguration, session: SessionID,
    queue: java.lang.ref.ReferenceQueue<ContinuityDevice>): PreparedPeer {
    val device = enrollmentParent(path, WitnessCarrier.Local)
    try {
        val child = device.preparePeerReopen(input, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR, session)
        return PreparedPeer(child, java.lang.ref.WeakReference(device, queue))
    } catch (failure: Throwable) {
        try { device.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        throw failure
    }
}
internal fun peerConfigurationLifetime(args: List<String>): String {
    require(args.size == 4)
    val path = args[1]; val input = peerConfiguration(args[2]); val session = SessionID(decode(args[3]))
    val queue = java.lang.ref.ReferenceQueue<ContinuityDevice>()
    val prepared = preparedWithoutPublicParent(path, input, session, queue)
    prepared.child.use { retained ->
        val before = collectionCount(); var observed = false
        for (round in 0 until 32) {
            pressure()
            queue.poll()?.let { check(it === prepared.parent && queue.poll() == null); observed = true }
            if (observed) break
            Thread.sleep(10)
        }
        check(observed && prepared.parent.get() == null && collectionCount() > before) { "public peer parent was not collected" }
        retained.finishOpen(); retained.nextMessage(session)
    }
    // The public parent was already collected, but its native owner only became
    // unreachable when the child closed. Observe the existing bounded Cleaner
    // backstop through all 64 returned native slots; never retry a storage error.
    requireNativeOwnerTableDrained()
    enrollmentParent(path, WitnessCarrier.Local).use { it.nextAccountOperation() }
    refused(setOf(2)) { prepared.child.nextMessage(session) }
    val retainedChild = enrollmentParent(path, WitnessCarrier.Local).use { original ->
        original.openPeer(input, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR)
    } // Explicit parent close must release the actual stores before returning.
    retainedChild.use { child ->
        refused(setOf(2)) { child.nextMessage(session) }
        enrollmentParent(path, WitnessCarrier.Local).use { it.nextAccountOperation() }
    }
    enrollmentParent(path, WitnessCarrier.Local).use { live ->
        live.preparePeerReopen(input, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR, session).use { pending ->
            pending.cancel(); refused(setOf(302)) { pending.finishOpen() }; live.nextAccountOperation()
        }
    }
    return "QPC_CONFIGURED_PEER_LIFETIME_PASS"
}
