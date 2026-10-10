// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Independent policy-only operation; never a credential-renewal operation. */
class PolicyRenewalID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(encoded().any { it != 0.toByte() }) { "policy operation must be nonzero" } }
}
class PolicyRenewalStatementID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(encoded().any { it != 0.toByte() }) { "policy statement must be nonzero" } }
}
/** Previously adopted independent policy statement or joint T. */
class PolicyAuthorizationID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(encoded().any { it != 0.toByte() }) { "policy authorization must be nonzero" } }
}
private fun identity(bytes: ByteArray): PublicBytes {
    val value = PublicBytes(bytes)
    require(value.encoded().let { it.size == 32 && it.any { byte -> byte != 0.toByte() } }) { "identity must be 32 bytes and nonzero" }
    return value
}
/** Independently retained expected scope; incoming approvals cannot select it. */
class PolicyRenewalScope(val operation: PolicyRenewalID, val journal: JournalID,
    originalOwner: ByteArray, originalCredential: ByteArray, currentCredential: ByteArray,
    val currentRoster: RosterCheckpoint, val originalPolicy: PolicyCheckpoint,
    val previousPolicy: PolicyCheckpoint, val previousAuthorization: PolicyAuthorizationID?) {
    val originalOwner = identity(originalOwner)
    val originalCredential = identity(originalCredential)
    val currentCredential = identity(currentCredential)
    init {
        identity(journal.encoded())
        require(if (previousAuthorization == null) previousPolicy == originalPolicy else previousPolicy.version > originalPolicy.version) {
            "policy predecessor and authorization disagree"
        }
    }
}
/** Owned public identities and scope. Construction checks shape only. Native
 * staging re-verifies signatures, independent pins and actual predecessor state.
 * Retain fields and original approvals across restart; native ABI bytes are not
 * a portable request format, proof of user authentication or current permission. */
class PolicyRenewalRequest(val scope: PolicyRenewalScope, val account: AccountID,
    val originalRosterCheckpoint: RosterCheckpoint, originalCredential: ByteArray,
    originalRoster: ByteArray, currentCredential: ByteArray, currentRoster: ByteArray) {
    val originalCredential = PublicBytes(originalCredential)
    val originalRoster = PublicBytes(originalRoster)
    val currentCredential = PublicBytes(currentCredential)
    val currentRoster = PublicBytes(currentRoster)
    init {
        identity(account.encoded())
        require(listOf(originalCredential, originalRoster, currentCredential, currentRoster).all { it.size in 1..8192 }) { "invalid signed identity record width" }
        require(originalRosterCheckpoint.version < scope.currentRoster.version || originalRosterCheckpoint == scope.currentRoster) { "original roster exceeds current scope" }
    }
}
enum class PolicyRenewalAbandonment { EXPIRED, ROSTER_ADVANCED }
/** Historical progress only. Pending never proves the journal has not committed. */
sealed interface PolicyRenewalStatus {
    data object Absent : PolicyRenewalStatus
    data class Pending(val operation: PolicyRenewalID, val statement: PolicyRenewalStatementID, val target: PolicyCheckpoint) : PolicyRenewalStatus
    data class Committed(val operation: PolicyRenewalID, val statement: PolicyRenewalStatementID, val target: PolicyCheckpoint) : PolicyRenewalStatus
    data class AbandonedUncommitted(val operation: PolicyRenewalID, val statement: PolicyRenewalStatementID, val target: PolicyCheckpoint,
        val reason: PolicyRenewalAbandonment, val observedRoster: RosterCheckpoint, val observedAt: Counter64) : PolicyRenewalStatus
}

/** Internal ABI copying only; never exposed as a portable persistence format. */
internal object PolicyRenewalCodec {
    private fun bad(message: String): Nothing = throw ContinuityBoundaryFailure(message)
    private fun buffer(bytes: ByteArray, length: Int): ByteBuffer {
        if (bytes.size != length) bad("independent policy record width differs")
        return ByteBuffer.wrap(bytes.clone()).order(ByteOrder.nativeOrder())
    }
    private fun ByteBuffer.bytes(length: Int) = ByteArray(length).also { get(it) }
    private fun ByteBuffer.counter() = Counter64.fromBits(long)
    private fun ByteBuffer.roster() = RosterCheckpoint(counter(), bytes(32))
    private fun ByteBuffer.policy() = PolicyCheckpoint(counter(), bytes(32))
    private fun ByteBuffer.scope(): PolicyRenewalScope {
        val operation = PolicyRenewalID(bytes(32)); val journal = JournalID(bytes(32))
        val owner = bytes(32); val original = bytes(32); val current = bytes(32)
        val roster = roster(); val originalPolicy = policy(); val previousPolicy = policy()
        val authorization = bytes(32)
        val previous = when (int) {
            0 -> { if (authorization.any { it != 0.toByte() }) bad("absent policy authorization is nonzero"); null }
            1 -> PolicyAuthorizationID(authorization)
            else -> bad("policy authorization presence differs")
        }
        if (int != 0) bad("reserved policy scope word is nonzero")
        return PolicyRenewalScope(operation, journal, owner, original, current, roster, originalPolicy, previousPolicy, previous)
    }
    private fun ByteBuffer.record(): ByteArray {
        val length = int; val bytes = bytes(8192)
        if (length !in 1..8192 || bytes.copyOfRange(length, 8192).any { it != 0.toByte() }) bad("policy public record length or tail differs")
        return bytes.copyOf(length)
    }
    private inline fun <T> nativeOutput(block: () -> T): T = try { block() } catch (failure: IllegalArgumentException) {
        throw ContinuityBoundaryFailure("invalid independent policy native output: ${failure.message}")
    }
    @JvmSynthetic internal fun decodeScope(bytes: ByteArray): PolicyRenewalScope = nativeOutput { buffer(bytes, 320).scope() }
    @JvmSynthetic internal fun decodeRequest(bytes: ByteArray): PolicyRenewalRequest = nativeOutput {
        val b = buffer(bytes, 33176)
        PolicyRenewalRequest(b.scope(), AccountID(b.bytes(32)), b.roster(), b.record(), b.record(), b.record(), b.record())
    }
    @JvmSynthetic internal fun decodePublicRecord(bytes: ByteArray): ByteArray = nativeOutput { buffer(bytes, 8196).record() }
    private fun ByteBuffer.checkpoint(version: Counter64, digest: PublicBytes) { putLong(version.bits()); put(digest.encoded()) }
    private fun ByteBuffer.scope(scope: PolicyRenewalScope) {
        put(scope.operation.encoded()); put(scope.journal.encoded()); put(scope.originalOwner.encoded())
        put(scope.originalCredential.encoded()); put(scope.currentCredential.encoded())
        checkpoint(scope.currentRoster.version, scope.currentRoster.digest)
        checkpoint(scope.originalPolicy.version, scope.originalPolicy.digest)
        checkpoint(scope.previousPolicy.version, scope.previousPolicy.digest)
        put(scope.previousAuthorization?.encoded() ?: ByteArray(32))
        putInt(if (scope.previousAuthorization == null) 0 else 1); putInt(0)
    }
    private fun ByteBuffer.record(record: PublicBytes) {
        val bytes = record.encoded(); putInt(bytes.size); put(bytes); position(position() + 8192 - bytes.size)
    }
    @JvmSynthetic internal fun encodeRequest(request: PolicyRenewalRequest): ByteArray {
        val b = ByteBuffer.allocate(33176).order(ByteOrder.nativeOrder())
        b.scope(request.scope); b.put(request.account.encoded()); b.checkpoint(request.originalRosterCheckpoint.version, request.originalRosterCheckpoint.digest)
        b.record(request.originalCredential); b.record(request.originalRoster); b.record(request.currentCredential); b.record(request.currentRoster)
        check(b.position() == 33176) { "independent policy ABI encoder width differs" }
        return b.array()
    }
    @JvmSynthetic internal fun decodeStatus(bytes: ByteArray): PolicyRenewalStatus = nativeOutput {
        val b = buffer(bytes, 160); val phase = b.int; val reason = b.int
        val operationBytes = b.bytes(32); val statementBytes = b.bytes(32)
        val targetVersion = b.counter(); val targetDigest = b.bytes(32)
        val rosterVersion = b.counter(); val rosterDigest = b.bytes(32); val at = b.counter()
        val noObservation = rosterVersion == Counter64.ZERO && rosterDigest.all { it == 0.toByte() } && at == Counter64.ZERO
        if (phase == 0) {
            if (reason != 0 || !noObservation || targetVersion != Counter64.ZERO ||
                listOf(operationBytes, statementBytes, targetDigest).any { a -> a.any { it != 0.toByte() } }) bad("absent policy status carries fields")
            PolicyRenewalStatus.Absent
        } else {
            val operation = PolicyRenewalID(operationBytes); val statement = PolicyRenewalStatementID(statementBytes)
            val target = PolicyCheckpoint(targetVersion, targetDigest)
            when (phase) {
                1, 2 -> {
                    if (reason != 0 || !noObservation) bad("pending/committed policy has abandonment fields")
                    if (phase == 1) PolicyRenewalStatus.Pending(operation, statement, target) else PolicyRenewalStatus.Committed(operation, statement, target)
                }
                3 -> {
                    if (at == Counter64.ZERO) bad("abandoned policy has no observation time")
                    val cause = when (reason) { 1 -> PolicyRenewalAbandonment.EXPIRED; 2 -> PolicyRenewalAbandonment.ROSTER_ADVANCED; else -> bad("unknown policy abandonment reason") }
                    PolicyRenewalStatus.AbandonedUncommitted(operation, statement, target, cause, RosterCheckpoint(rosterVersion, rosterDigest), at)
                }
                else -> bad("unknown independent policy phase")
            }
        }
    }
}
