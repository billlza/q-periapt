// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.HexFormat
import kotlin.system.exitProcess

internal fun decode(value: String): ByteArray {
    require(value.matches(Regex("[0-9a-f]{64}"))) { "noncanonical identity" }
    return HexFormat.of().parseHex(value)
}
internal fun hex(value: ContinuityID): String = HexFormat.of().formatHex(value.encoded())
internal fun refused(expected: Set<Int>, action: () -> Unit) {
    try { action() } catch (error: ContinuityFailure) {
        check(error.code in expected) { "unexpected native failure $error" }
        return
    }
    error("operation unexpectedly succeeded")
}
internal fun waitMarker(name: String) {
    val end = System.nanoTime() + 10_000_000_000L
    while (System.nanoTime() < end) {
        try {
            Files.newByteChannel(Path.of(name), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
                val bytes = ByteBuffer.allocate(2)
                check(channel.read(bytes) == 1 && channel.read(bytes) == -1 && bytes.get(0) == '1'.code.toByte()) {
                    "marker content differs"
                }
                return
            }
        } catch (_: NoSuchFileException) { Thread.sleep(25) }
    }
    error("fixture marker deadline")
}
private fun run(arguments: List<String>): String {
    if (arguments.firstOrNull() == "retired") return retirementCommand(arguments)
    var args = arguments
    val inFlightGC = args.firstOrNull() == "--gc-in-flight"
    if (inFlightGC) args = args.drop(1)
    val interruptOpening = args.firstOrNull() == "--interrupt-opening-controller"
    if (interruptOpening) args = args.drop(1)
    var witness: WitnessCarrier = WitnessCarrier.Local
    if (args.firstOrNull() in setOf("--witness", "--witness-tls")) {
        require(args.size >= 4)
        witness = if (args[0] == "--witness") WitnessCarrier.SignedTCP(args[1], 3000)
            else WitnessCarrier.MutualTLS(args[1], 3000)
        args = args.drop(2)
    }
    val independent = args.firstOrNull() == "--independent-policy-parent"
    val continued = args.firstOrNull() == "--continued-enrollment-parent"
    val enrolled = if (continued || independent || args.firstOrNull() == "--enrollment-parent") {
        require(args.size >= 5) { "registered parent arguments" }
        val role = when (args[2]) {
            "1" -> BootstrapRole.INITIATOR
            "2" -> BootstrapRole.RESPONDER
            else -> error("invalid registered parent role")
        }
        (args[1] to role).also { args = args.drop(3) }
    } else null
    val existing = if (args.firstOrNull() == "--session") {
        require(args.size >= 4) { "existing session arguments" }
        SessionID(decode(args[1])).also { args = args.drop(2) }
    } else null
    require(args.isNotEmpty()) { "command required" }
    val enrolledAccount = args[0] in setOf("account-next", "account-status", "account-send")
    require(!(continued || independent) || existing != null || args[0] == "peer-roster-admit" || enrolledAccount) { "continued enrollment parent requires an original session" }
    require(!(continued || independent) || (args[0] != "connect" && !(args[0] == "serve" && args.getOrNull(2) == "bootstrap"))) {
        "continued enrollment parent cannot bootstrap a fresh session"
    }
    require(enrolled == null || (!inFlightGC && !interruptOpening && args[0] in setOf(
        "connect", "next", "send", "uncertain-send", "status", "rekey", "serve", "serve-rekey",
        "busy-cancel", "cancel-send", "reject-open", "witness-failed-send", "peer-roster-admit",
        "account-next", "account-status", "account-send", "publication-next", "publication-status",
        "publication-prepare", "publication-retry", "publication-retire", "publication-cancel"))) { "registered parent requires an ordinary peer operation" }

    require(existing == null || (!inFlightGC && !args[0].startsWith("recover-") && args[0] !in setOf("self-check", "gc-owner-capacity"))) {
        "existing session requires an ordinary operational command"
    }
    require(!inFlightGC || args[0] == "serve") { "in-flight GC requires a server fixture" }
    require(!interruptOpening || args[0].startsWith("opening-")) { "control interruption requires an opening fixture" }
    if (args[0].startsWith("publication-")) {
        require(enrolled != null && !continued && !independent && existing == null) { "publication requires original registered owner" }
        return publicationCommand(args, enrolled.first, witness)
    }
    if (args[0] == "peer-roster-admit") {
        require(enrolled != null && enrolled.second == BootstrapRole.INITIATOR && existing == null)
        return peerRosterCommand(args, enrolled.first, witness,
            if (independent) EnrollmentPolicy.INDEPENDENT else if (continued) EnrollmentPolicy.JOINT else EnrollmentPolicy.ORIGINAL)
    }
    if (args[0] == "gc-owner-capacity") {
        require(args.size == 1 && witness == WitnessCarrier.Local)
        return gcOwnerCapacity()
    }
    if (args[0] == "self-check") {
        require(args.size == 1)
        repeat(128) { refused(setOf(203)) { ContinuityOwner.open("relative", PrekeyQuality.ONE_TIME_BOTH).close() } }
        ContinuityOwner.prepare("/absent-continuity-consumer", PrekeyQuality.ONE_TIME_BOTH).use {
            it.cancel(); refused(setOf(302)) { it.finishOpen() }
        }
        return "self-check-passed"
    }
    require(args.size >= 2)
    if (inFlightGC) {
        require(args.size in 3..4)
        return serveUnrooted(args[1], args[2], args.getOrNull(3), witness)
    }
    if (args[0].startsWith("opening-")) return opening(args, witness, interruptOpening, existing)
    if (args[0].startsWith("enrollment-")) {
        require(existing == null && enrolled == null)
        return enrollment(args, witness)
    }
    if (args[0] == "credential-peer-check") {
        require(existing == null && enrolled == null && witness == WitnessCarrier.Local)
        return credentialPeerCheck(args)
    }
    if (args[0] == "continued-peer-refused" || args[0] == "continued-peer-admit") {
        require(existing == null && enrolled == null) { "continued peer command owns its original enrollment parent" }
        return if (args[0] == "continued-peer-refused") continuedPeerRefused(args, witness)
            else continuedPeerAdmit(args, witness)
    }
    if (args[0].startsWith("setup-")) {
        require(existing == null)
        return setup(args, witness)
    }
    if (args[0].startsWith("recover-")) return recover(args, witness)
    if (args[0].startsWith("account-")) {
        require(existing == null)
        if (enrolled != null) {
            require(enrolledAccount && enrolled.first == args[1] && enrolled.second == BootstrapRole.INITIATOR) {
                "account requires its original enrollment parent and existing member sessions"
            }
            return enrollmentParent(enrolled.first, witness,
                if (independent) EnrollmentPolicy.INDEPENDENT else if (continued) EnrollmentPolicy.JOINT else EnrollmentPolicy.ORIGINAL
            ).use { account(args, witness, it) }
        }
        return account(args, witness)
    }
    return if (enrolled == null) ordinary(args, witness, existing)
        else enrollmentParent(enrolled.first, witness, if (independent) EnrollmentPolicy.INDEPENDENT else if (continued) EnrollmentPolicy.JOINT else EnrollmentPolicy.ORIGINAL).use { ordinary(args, witness, existing, it, enrolled.second) }
}
private fun ordinary(args: List<String>, witness: WitnessCarrier, existing: SessionID?,
                     device: ContinuityDevice? = null, role: BootstrapRole = BootstrapRole.INITIATOR): String {
    fun openConfigured(): ContinuityOwner = if (device != null) {
        if (existing == null) device.openPeer(args[1], PrekeyQuality.ONE_TIME_BOTH, role)
        else device.reopenPeer(args[1], PrekeyQuality.ONE_TIME_BOTH, role, existing)
    } else if (existing == null) {
        ContinuityOwner.open(args[1], PrekeyQuality.ONE_TIME_BOTH, witness)
    } else {
        ContinuityOwner.reopen(args[1], PrekeyQuality.ONE_TIME_BOTH, existing, witness)
    }
    if (args[0] == "reject-open") {
        require(args.size == 2)
        try { openConfigured().close() }
        catch (failure: ContinuityFailure) { return "rejected:${failure.code}" }
        error("invalid binding admitted")
    }
    return openConfigured().use { owner ->
        when (args[0]) {
            "serve" -> {
                require(args.size in 3..4)
                serve(owner, args[1], args[2], args.getOrNull(3))
            }
            "connect" -> {
                require(args.size == 4)
                hex(owner.establish(args[2], InitiationID(decode(args[3]))).session)
            }
            "next" -> { require(args.size == 3); hex(owner.nextMessage(SessionID(decode(args[2])))) }
            "status" -> {
                require(args.size == 4)
                owner.messageStatus(SessionID(decode(args[2])), MessageID(decode(args[3]))).code.toString()
            }
            "rekey" -> {
                require(args.size == 4)
                check(owner.rekey(args[2], SessionID(decode(args[3])), Counter64.of(1)) == Counter64.of(1))
                "rekey-1-confirmed"
            }
            "send", "uncertain-send", "cancel-send", "busy-cancel", "cancel-witness-send", "witness-failed-send" -> {
                val mode = args[0]
                val witnessCancel = mode == "cancel-witness-send"
                val witnessFailed = mode == "witness-failed-send"
                require(args.size == if (mode == "busy-cancel" || witnessCancel) 6 else 5)
                require(!(witnessCancel || witnessFailed) || witness != WitnessCarrier.Local)
                val session = SessionID(decode(args[3])); val message = MessageID(decode(args[4]))
                val send = { owner.send(args[2], session, message,
                    "persisted before process exit".toByteArray(), "owned-service".toByteArray()) }
                when (mode) {
                    "cancel-send" -> { owner.cancel(); refused(setOf(302)) { send() } }
                    "uncertain-send" -> refused(setOf(303, 309, 310, 311)) { send() }
                    "busy-cancel", "cancel-witness-send" -> {
                        val elapsed = cancelledInvocation(if (witnessCancel) 218 else 302, {
                            waitMarker(args[5]); refused(setOf(3)) { owner.close() }
                        }, owner::cancel) { send() }
                        if (witnessCancel) return@use "witness-cancelled-outcome-unavailable:${cancellationMilliseconds(elapsed)}"
                    }
                    "witness-failed-send" -> {
                        refused(setOf(218)) { send() }
                        return@use "witness-outcome-unavailable"
                    }
                    else -> check(send().consumption == Consumption.CONFIRMED)
                }
                val expected = when (mode) {
                    "cancel-send" -> MessageStatus.ABSENT
                    "uncertain-send", "busy-cancel" -> MessageStatus.COMMITTED
                    else -> MessageStatus.ACKNOWLEDGED
                }
                check(owner.messageStatus(session, message) == expected)
                if (mode == "busy-cancel") {
                    // Reopen follows release by use below; do not close twice.
                    "cancelled-committed"
                } else when (mode) {
                    "cancel-send" -> "cancelled-absent"
                    "uncertain-send" -> "delivery-unknown-committed"
                    else -> "consumed"
                }
            }
            else -> error("unsupported fixture command ${args[0]}")
        }
    }.let { result ->
        if (result == "cancelled-committed") {
            openConfigured().use {
                check(it.messageStatus(SessionID(decode(args[3])), MessageID(decode(args[4]))) == MessageStatus.COMMITTED)
            }
            "cancelled-committed-reopened"
        } else result
    }
}
fun main(args: Array<String>) {
    try { output(run(args.toList())) }
    catch (failure: Throwable) { failure.printStackTrace(System.err); exitProcess(1) }
}
internal fun output(text: String) {
    println(text)
    System.out.flush()
    check(!System.out.checkError()) { "consumer output failed" }
}
