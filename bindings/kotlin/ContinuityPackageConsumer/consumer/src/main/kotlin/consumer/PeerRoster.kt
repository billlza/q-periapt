// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer
import dev.qperiapt.continuity.*
import java.nio.ByteBuffer

internal fun peerRosterCommand(args: List<String>, parent: String, witness: WitnessCarrier, policy: EnrollmentPolicy): String {
    require(args.size in setOf(4, 5, 10) && args[1] == parent)
    val mode = args[3]; val records = FixtureRecords(java.nio.file.Path.of(args[2]))
    fun exact(name: String, count: Int) = records.read(name).also { check(it.size == count) }
    val version = Counter64.parse(java.lang.Long.toUnsignedString(ByteBuffer.wrap(exact("version", 8)).long))
    val pin = AccountPin(AccountID(exact("account", 32)), exact("root", 1985), exact("family", 32), RosterCheckpoint(version, exact("digest", 32)))
    val roster = records.read("roster")
    return AccountOwners().use { owners ->
        val device = owners.own(enrollmentParent(parent, witness, policy))
        val peers = if(mode == "suspend") {
            require(args.size == 10)
            listOf(args[4] to args[5], args[6] to args[7]).map { (path, session) ->
                owners.own(device.preparePeerReopen(path, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR, SessionID(decode(session)))).also { it.finishOpen() }
            }
        } else emptyList()
        check(runCatching { device.admitPeerRoster(byteArrayOf(), pin) }.exceptionOrNull() is IllegalArgumentException)
        val wrong = pin.checkpoint.digest.encoded(); wrong[0] = (wrong[0].toInt() xor 1).toByte()
        val wrongPin = AccountPin(pin.account, pin.root.encoded(), pin.family.encoded(), RosterCheckpoint(version, wrong))
        refused(setOf(105)) { device.admitPeerRoster(roster, wrongPin) }
        when(mode) {
            "cancel-active" -> {
                require(args.size == 5)
                val elapsed = cancelledInvocation(218,
                    { waitMarker(args[4]); refused(setOf(3)) { device.close() } },
                    { device.cancel() }, { device.admitPeerRoster(roster, pin) })
                cancellationMilliseconds(elapsed)
                refused(setOf(302)) { device.nextAccountOperation() }
                "peer-roster-cancelled-after-advance"
            }
            "lost" -> {
                refused(setOf(218)) { device.admitPeerRoster(roster, pin) }
                refused(setOf(202)) { device.nextAccountOperation() }
                "peer-roster-outcome-unavailable"
            }
            "cancel" -> {
                device.cancel(); refused(setOf(302)) { device.admitPeerRoster(roster, pin) }
                "peer-roster-cancelled"
            }
            "admit", "suspend" -> {
                val result = device.admitPeerRoster(roster, pin)
                check(result == pin.checkpoint && device.admitPeerRoster(roster, pin) == result)
                if(mode == "suspend") {
                    val targets = listOf(AccountTarget(peers[0], SessionID(decode(args[5]))), AccountTarget(peers[1], SessionID(decode(args[7]))))
                    refused(setOf(103)) { device.sendAccountMember(AccountOperationID(decode(args[9])), AccountID(decode(args[8])), targets, 1,
                        "127.0.0.1:1", "persisted before process exit".toByteArray(), "owned-service".toByteArray()) }
                    "account-refused:103\npeer-roster-admitted"
                } else "peer-roster-admitted"
            }
            else -> error("unknown peer roster mode")
        }
    }
}
