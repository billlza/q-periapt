// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.lang.ref.Reference
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.nio.file.Path
import java.util.HexFormat
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference

/** Test-owned close set. Remove only after confirmed close; preserve every cleanup failure. */
private class AccountOwners : AutoCloseable {
    private val owners = mutableListOf<AutoCloseable>()
    fun <T : AutoCloseable> own(owner: T): T = owner.also { owners.add(it) }
    fun close(owner: AutoCloseable) { owner.close(); check(owners.remove(owner)) }
    fun confirmedClosed(owner: AutoCloseable) { check(owners.remove(owner)) }
    override fun close() {
        var failure: Throwable? = null
        for (owner in owners.asReversed()) try { owner.close() } catch (error: Throwable) {
            if (failure == null) failure = error else failure.addSuppressed(error)
        }
        failure?.let { throw it }
    }
}

private fun accountShapeChecks() = AccountOwners().use { owners ->
    val device = owners.own(ContinuityDevice.prepare("/unused"))
    val peer = owners.own(ContinuityOwner.prepare("/unused", PrekeyQuality.ONE_TIME_BOTH))
    val target = AccountTarget(peer, SessionID(ByteArray(32) { 1 }))
    for ((count, selected) in listOf(0 to 0, 33 to 0, 2 to 2, 2 to -1)) {
        val failure = runCatching {
            device.sendAccountMember(AccountOperationID(ByteArray(32) { 2 }), AccountID(ByteArray(32) { 3 }),
                List(count) { target }, selected, "127.0.0.1:1", byteArrayOf(), byteArrayOf())
        }.exceptionOrNull()
        check(failure is IllegalArgumentException) { "account shape did not refuse at the input boundary: $failure" }
    }
}

private data class PreparedPeers(val peers: List<ContinuityOwner>, val device: WeakReference<ContinuityDevice>)
private fun preparedPeers(args: List<String>, witness: WitnessCarrier,
                          queue: ReferenceQueue<ContinuityDevice>, owners: AccountOwners): PreparedPeers {
    val device = ContinuityDevice.open(args[1], witness)
    try {
        val peers = listOf(owners.own(device.preparePeer(args[2], PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR)),
            owners.own(device.preparePeer(args[3], PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR)))
        return PreparedPeers(peers, WeakReference(device, queue))
    } catch (failure: Throwable) {
        try { device.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        throw failure
    }
}

private fun racePeerClose(peer: ContinuityOwner) {
    val start = CountDownLatch(1)
    val outcomes = List(2) { AtomicReference<Result<Unit>?>() }
    val threads = outcomes.map { outcome -> Thread({ outcome.set(runCatching { start.await(); peer.close() }) }, "continuity-peer-close") }
    threads.forEach { it.start() }
    start.countDown()
    var interrupted: InterruptedException? = null
    for (thread in threads) while (true) {
        try { thread.join(); break } catch (failure: InterruptedException) {
            if (interrupted == null) interrupted = failure else interrupted.addSuppressed(failure)
        }
    }
    if (interrupted != null) { Thread.currentThread().interrupt(); throw interrupted }
    val results = outcomes.map { it.get() ?: error("close thread produced no outcome") }
    check(results.count { it.isSuccess } == 1) { "concurrent peer close did not have one winner" }
    val failure = results.single { it.isFailure }.exceptionOrNull()
    check(failure is ContinuityFailure && failure.code in setOf(2, 3)) { "unexpected alias close failure: $failure" }
    refused(setOf(2)) { peer.cancel() }
}

private fun connectAccount(args: List<String>, witness: WitnessCarrier): String = AccountOwners().use { owners ->
    require(args.size == 8)
    val before = collectionCount()
    val queue = ReferenceQueue<ContinuityDevice>()
    val prepared = preparedPeers(args, witness, queue, owners)
    var observed = false
    repeat(32) {
        if (!observed) { pressure(); observed = queue.poll() === prepared.device }
    }
    check(observed && prepared.device.get() == null) { "public device wrapper was not collected before peer activation" }
    val sessions = prepared.peers.mapIndexed { index, peer ->
        peer.finishOpen()
        peer.establish(args[4 + index], InitiationID(decode(args[6 + index]))).session
    }
    racePeerClose(prepared.peers[0]); owners.confirmedClosed(prepared.peers[0])
    owners.close(prepared.peers[1])
    // Cleaner scheduling is nondeterministic. The existing bounded capacity
    // oracle observes completion; only capacity status 4 is retried, never an
    // installation or protocol operation. Closed aliases remain strongly live.
    requireNativeOwnerTableDrained()
    ContinuityDevice.open(args[1], witness).use { it.nextAccountOperation() }
    for (peer in prepared.peers) refused(setOf(2)) { peer.nextMessage(sessions[0]) }
    Reference.reachabilityFence(prepared.peers)
    val collections = collectionCount() - before
    check(collections in 2..1024) { "account parent fixture did not observe its bounded collections" }
    FixtureRecords(Path.of(args[1])).retain("kotlin-account-parent-lifetime",
        "QPC-JVM-ACCOUNT/1 collections=$collections\npublic-parent-queued peers-activated close-winner=1 closed-aliases-held slots=64 store-reopened\n".toByteArray(), true)
    sessions.joinToString("\n", transform = ::hex)
}

internal fun account(args: List<String>, witness: WitnessCarrier): String {
    require(args.size >= 2)
    accountShapeChecks()
    if (args[0] == "account-connect") return connectAccount(args, witness)
    return AccountOwners().use { owners ->
        val device = owners.own(ContinuityDevice.open(args[1], witness))
        when (args[0]) {
            "account-next" -> { require(args.size == 2); return@use hex(device.nextAccountOperation()) }
            "account-status" -> {
                require(args.size == 3)
                val (state, report) = when (val value = device.accountStatus(AccountOperationID(decode(args[2])))) {
                    AccountStatus.Absent -> 0 to ByteArray(32)
                    AccountStatus.Reserved -> 1 to ByteArray(32)
                    AccountStatus.Committed -> 2 to ByteArray(32)
                    is AccountStatus.Abandoning -> 3 to value.report.encoded()
                    is AccountStatus.Abandoned -> 4 to value.report.encoded()
                    AccountStatus.Retired -> 5 to ByteArray(32)
                }
                return@use "account-status:$state\n${HexFormat.of().formatHex(report)}"
            }
        }
        require(args[0] == "account-send" && args.size in 11..12)
        val sessions = listOf(SessionID(decode(args[3])), SessionID(decode(args[5])))
        val peers = listOf(owners.own(device.reopenPeer(args[2], PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR, sessions[0])),
            owners.own(device.reopenPeer(args[4], PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR, sessions[1])))
        val recipient = AccountID(decode(args[6])); val operation = AccountOperationID(decode(args[7]))
        require(args[8] in setOf("0", "1"))
        var selected = args[8].toInt()
        val targets = peers.mapIndexed { index, peer -> AccountTarget(peer, sessions[index]) }.toMutableList()
        val address = args[9]; val mode = args[10]
        val payload = "persisted before process exit".toByteArray(); val ad = "owned-service".toByteArray()
        if (mode == "unary") {
            require(args.size == 12)
            refused(setOf(215)) { peers[selected].send(address, sessions[selected], MessageID(decode(args[11])), payload, ad) }
            return@use "account-refused:215"
        }
        var expected: Int? = null
        when (mode) {
            "omit" -> { targets.removeAt(1); selected = 0; expected = 106 }
            "duplicate-peer" -> { targets[1] = AccountTarget(peers[0], sessions[1]); expected = 1 }
            "duplicate-session" -> { targets[1] = AccountTarget(peers[1], sessions[0]); expected = 1 }
            "cancel-peer" -> { peers[1].cancel(); expected = 302 }
            "closed-peer" -> { owners.close(peers[1]); expected = 2 }
            "wrong-parent" -> {
                require(args.size == 12)
                val other = owners.own(ContinuityDevice.open(args[11], witness))
                val peer = owners.own(other.reopenPeer(args[11], PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.RESPONDER, sessions[1]))
                targets[1] = AccountTarget(peer, sessions[1]); expected = 211
            }
            "changed-input" -> expected = 211
            "unknown" -> expected = 311
            "reverse-retained" -> { targets.reverse(); selected = 1 - selected }
            "deliver", "retained", "cancel-active" -> Unit
            else -> error("unknown account mode")
        }
        val body = if (mode == "changed-input") "different".toByteArray() else payload
        val invoke = { device.sendAccountMember(operation, recipient, targets, selected, address, body, ad) }
        if (mode == "cancel-active") {
            require(args.size == 12)
            val idle = owners.own(device.reopenPeer(args[2], PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR, sessions[0]))
            val elapsed = cancelledInvocation(302, {
                waitMarker(args[11]); owners.close(idle)
                refused(setOf(3)) { device.close() }
                for (peer in peers) refused(setOf(3)) { peer.close() }
            }, peers[1]::cancel) { invoke() }
            device.nextAccountOperation(); peers[0].nextMessage(sessions[0])
            return@use "account-refused:302\naccount-cancel-active:${cancellationMilliseconds(elapsed)}:3"
        }
        if (expected != null) {
            refused(setOf(expected)) { invoke() }
            return@use "account-refused:$expected"
        }
        val result = invoke()
        check(result.outcome == AccountDeliveryOutcome.Consumed(Consumption.CONFIRMED) && result.session == targets[selected].session)
        check((mode in setOf("retained", "reverse-retained")) == (result.exchanges == 0))
        "account-delivered:1:${result.exchanges}\n${hex(result.session)}\n${hex(result.message)}\n${HexFormat.of().formatHex(result.device.encoded())}"
    }
}
