// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Owned public issuer inputs. Retain the operation and complete request before
 * submission. This snapshot neither reserves a journal nor authenticates or
 * authorizes an issuer decision. Native ABI bytes are not a portable wire format. */
class CredentialRenewalRequest internal constructor(
    val operation: CredentialRenewalID, val journal: JournalID,
    originalOwner: ByteArray, originalPolicyDigest: ByteArray,
    val currentPolicy: PolicyCheckpoint, val currentPolicyAuthorization: PolicyAuthorizationID?,
    val previousRosterCheckpoint: RosterCheckpoint, val originalRosterCheckpoint: RosterCheckpoint,
    val previousValidFrom: Counter64, val previousValidUntil: Counter64, val account: AccountID,
    originalCredential: ByteArray, originalRoster: ByteArray, previousCredential: ByteArray, previousRoster: ByteArray,
) {
    val originalOwner = PublicBytes(originalOwner)
    val originalPolicyDigest = PublicBytes(originalPolicyDigest)
    val originalCredential = PublicBytes(originalCredential)
    val originalRoster = PublicBytes(originalRoster)
    val previousCredential = PublicBytes(previousCredential)
    val previousRoster = PublicBytes(previousRoster)
    init {
        require(listOf(journal.encoded(), account.encoded(), originalOwner, originalPolicyDigest).all {
            it.size == 32 && it.any { byte -> byte != 0.toByte() }
        }) { "credential issuer identity must be nonzero" }
        require(currentPolicyAuthorization != null || currentPolicy.digest == this.originalPolicyDigest) { "missing current policy authorization" }
        require(originalRosterCheckpoint.version < previousRosterCheckpoint.version || originalRosterCheckpoint == previousRosterCheckpoint) { "credential predecessor precedes original roster" }
        require(previousValidFrom < previousValidUntil && previousValidUntil.bits() != -1L) { "credential validity interval differs" }
        require(listOf(originalCredential, originalRoster, previousCredential, previousRoster).all { it.size in 1..8192 }) { "credential issuer record width differs" }
    }
}

internal object CredentialRequestCodec {
    private fun bad(message: String): Nothing = throw ContinuityBoundaryFailure(message)
    private fun ByteBuffer.bytes(length: Int) = ByteArray(length).also { get(it) }
    private fun ByteBuffer.counter() = Counter64.fromBits(long)
    private fun ByteBuffer.roster() = RosterCheckpoint(counter(), bytes(32))
    private fun ByteBuffer.record(): ByteArray {
        val length = int
        if (length !in 1..8192) bad("credential issuer record length differs")
        val value = bytes(8192)
        if (value.copyOfRange(length, value.size).any { it != 0.toByte() }) bad("credential issuer unused tail differs")
        return value.copyOf(length)
    }
    fun decode(bytes: ByteArray): CredentialRenewalRequest {
        if (bytes.size != 33120) bad("credential issuer request width differs")
        val input = ByteBuffer.wrap(bytes.clone()).order(ByteOrder.nativeOrder())
        try {
            val operation = CredentialRenewalID(input.bytes(32)); val journal = JournalID(input.bytes(32))
            val owner = input.bytes(32); val originalPolicy = input.bytes(32)
            val current = PolicyCheckpoint(input.counter(), input.bytes(32)); val authorization = input.bytes(32)
            val policyAuthorization = when (input.int) {
                0 -> { if (authorization.any { it != 0.toByte() }) bad("absent credential policy authority is nonzero"); null }
                1 -> PolicyAuthorizationID(authorization)
                else -> bad("credential policy authority presence differs")
            }
            if (input.int != 0) bad("credential issuer reserved word is nonzero")
            val value = CredentialRenewalRequest(operation, journal, owner, originalPolicy, current, policyAuthorization,
                input.roster(), input.roster(), input.counter(), input.counter(), AccountID(input.bytes(32)),
                input.record(), input.record(), input.record(), input.record())
            if (input.hasRemaining()) bad("credential issuer request has trailing fields")
            return value
        } catch (failure: IllegalArgumentException) {
            throw ContinuityBoundaryFailure("invalid credential issuer native output: ${failure.message}")
        }
    }
}
