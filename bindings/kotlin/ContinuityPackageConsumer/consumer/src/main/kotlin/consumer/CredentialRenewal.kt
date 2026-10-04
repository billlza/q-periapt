// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.file.Path
import java.util.HexFormat

private fun renewalWire(records: FixtureRecords): ByteArray = records.read("credential-renewal").also {
    check(it.size in 1..65536) { "credential renewal public input length" }
}
private fun renewalOperation(records: FixtureRecords) =
    CredentialRenewalID(records.enrollmentExact("credential-operation", 32))
private fun renewalStatus(value: CredentialRenewalStatus): String {
    val phase: Int
    val operation: CredentialRenewalID?
    val statement: CredentialRenewalStatementID?
    val checkpoint: RosterCheckpoint?
    val observedAt: Counter64
    when (value) {
        CredentialRenewalStatus.Absent -> {
            phase = 0; operation = null; statement = null; checkpoint = null; observedAt = Counter64.ZERO
        }
        is CredentialRenewalStatus.Pending -> {
            phase = 1; operation = value.operation; statement = value.statement; checkpoint = null; observedAt = Counter64.ZERO
        }
        is CredentialRenewalStatus.Committed -> {
            phase = 2; operation = value.operation; statement = value.statement; checkpoint = value.target; observedAt = Counter64.ZERO
        }
        is CredentialRenewalStatus.Closed -> {
            phase = 4; operation = value.operation; statement = value.statement; checkpoint = value.target; observedAt = Counter64.ZERO
        }
        is CredentialRenewalStatus.ExpiredUncommitted -> {
            phase = 3; operation = value.operation; statement = value.statement
            checkpoint = value.observedHead; observedAt = value.observedAt
        }
    }
    val zero = "0".repeat(64)
    return "credential-phase:$phase\n${operation?.let(::hex) ?: zero}\n${statement?.let(::hex) ?: zero}\n" +
        "credential-head:${checkpoint?.version ?: Counter64.ZERO}\n" +
        "${checkpoint?.let { HexFormat.of().formatHex(it.digest.encoded()) } ?: zero}\ncredential-observed:$observedAt"
}

internal fun credentialEnrollment(owner: ContinuityEnrollment, records: FixtureRecords, mode: String,
                                   original: EnrollmentStatus): String {
    val status = when (mode) {
        "enrollment-credential-activate-refused" -> {
            refused(setOf(104)) { owner.activate().use { error("expired target published a device") } }
            refused(setOf(2)) { owner.credentialRenewalStatus() }
            return "credential-expired-activation-refused"
        }
        "enrollment-credential-status" -> owner.credentialRenewalStatus()
        "enrollment-credential-stage", "enrollment-credential-reject" -> {
            val wire = renewalWire(records)
            val operation = renewalOperation(records)
            val pin = enrollmentPin(records, true)
            enrollmentShapeRefusal { owner.stageCredentialRenewal(ByteArray(0), pin, operation) }
            check(owner.status() == original) { "shape refusal consumed the original enrollment" }
            if (mode == "enrollment-credential-reject") {
                wire[wire.lastIndex] = (wire.last().toInt() xor 1).toByte()
                refused(setOf(102)) { owner.stageCredentialRenewal(wire, pin, operation) }
                refused(setOf(2)) { owner.credentialRenewalStatus() }
                return "credential-signature-refused"
            }
            owner.stageCredentialRenewal(wire, pin, operation).also {
                check(it == owner.credentialRenewalStatus()) { "renewal stage differs from authenticated readback" }
            }
        }
        "enrollment-credential-reconcile" -> {
            val operation = renewalOperation(records)
            val statement = CredentialRenewalStatementID(records.enrollmentExact("credential-statement", 32))
            owner.reconcileExpiredCredentialRenewal(operation, statement).also {
                // The typed registration still owns its original state. No raw
                // device-handle conversion is exposed to this consumer.
                check(owner.status() == original) { "expiry reconciliation transferred or replaced the enrollment" }
            }
        }
        else -> error("unknown credential renewal command")
    }
    return renewalStatus(status)
}

private fun peerRefused(parent: ContinuityDevice, path: String, role: BootstrapRole,
                        session: SessionID?, expected: Int) {
    val child = if (session == null) parent.preparePeer(path, PrekeyQuality.ONE_TIME_BOTH, role)
        else parent.preparePeerReopen(path, PrekeyQuality.ONE_TIME_BOTH, role, session)
    child.use {
        refused(setOf(expected)) { it.finishOpen() }
        refused(setOf(2)) { it.finishOpen() }
    }
}

private fun peerAdmit(parent: ContinuityDevice, path: String, controls: Boolean) {
    val records = FixtureRecords(Path.of(path))
    val wire = renewalWire(records)
    val operation = renewalOperation(records)
    val pin = enrollmentPin(records, true)
    if (controls) {
        enrollmentShapeRefusal { parent.admitPeerCredentialRenewal(ByteArray(0), pin, operation) }
        val digest = pin.checkpoint.digest.encoded().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val wrong = AccountPin(pin.account, pin.root.encoded(), pin.family.encoded(), RosterCheckpoint(pin.checkpoint.version, digest))
        refused(setOf(105)) { parent.admitPeerCredentialRenewal(wire, wrong, operation) }
        val wrongOperation = CredentialRenewalID(operation.encoded().also { it[0] = (it[0].toInt() xor 1).toByte() })
        refused(setOf(211)) { parent.admitPeerCredentialRenewal(wire, pin, wrongOperation) }
    }
    val checkpoint = parent.admitPeerCredentialRenewal(wire, pin, operation)
    check(checkpoint == pin.checkpoint) { "peer renewal did not return independently expected checkpoint" }
    check(parent.admitPeerCredentialRenewal(wire, pin, operation) == checkpoint) { "peer renewal retry changed checkpoint" }
}

internal fun credentialPeerCheck(args: List<String>): String {
    require(args.size == 6) { "credential peer arguments" }
    val local = args[1]
    val session = SessionID(decode(args[4]))
    val message = MessageID(decode(args[5]))
    val wrong = SessionID(session.encoded().also { it[0] = (it[0].toInt() xor 1).toByte() })
    ContinuityDevice.open(local).use { parent ->
        peerRefused(parent, local, BootstrapRole.RESPONDER, session, 104)
        peerAdmit(parent, args[2], true)
        peerRefused(parent, local, BootstrapRole.RESPONDER, null, 104)
        peerRefused(parent, local, BootstrapRole.INITIATOR, session, 211)
        peerRefused(parent, local, BootstrapRole.RESPONDER, wrong, 201)
        val next = parent.reopenPeer(local, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.RESPONDER, session).use { first ->
            check(first.messageStatus(session, message) == MessageStatus.COMMITTED) { "first grant lost original outbox" }
            val originalNext = first.nextMessage(session)
            peerAdmit(parent, args[3], false)
            refused(setOf(211)) { first.nextMessage(session) }
            originalNext
        }
        parent.reopenPeer(local, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.RESPONDER, session).use { current ->
            check(current.messageStatus(session, message) == MessageStatus.COMMITTED) { "second grant lost original outbox" }
            check(current.nextMessage(session) == next) { "refused stale child advanced next message slot" }
        }
    }
    ContinuityDevice.open(local).use { parent ->
        parent.reopenPeer(local, PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.RESPONDER, session).use { current ->
            check(current.messageStatus(session, message) == MessageStatus.COMMITTED) { "restart lost renewed peer or original outbox" }
        }
    }
    return "credential-peer-passed"
}
