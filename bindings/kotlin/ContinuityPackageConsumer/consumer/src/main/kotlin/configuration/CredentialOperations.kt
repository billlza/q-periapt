// SPDX-License-Identifier: Apache-2.0 OR MIT
package configuration

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Path

internal val credentialModes = setOf(
    "credential-identity", "credential-expired-request", "credential-expired",
    "credential-activation-unmanaged", "credential-activate", "credential-prepare",
    "credential-stage", "credential-stage-refused", "credential-commit",
    "credential-commit-closed", "credential-commit-unmanaged", "credential-commit-unknown",
    "credential-reconcile",
)

internal fun credentialIdentity(owner: ContinuityEnrollment): ByteArray {
    val status = owner.status()
    return status.signing.encoded() + checkNotNull(status.journal) { "credential renewal requires original journal" }.encoded()
}

private fun resultCode(code: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.nativeOrder()).putInt(code).array()

// Same-host public test readback shared with C; private JVM/native object
// layouts and struct padding are not part of the public wrapper contract.
internal fun credentialStatusBytes(value: CredentialRenewalStatus): ByteArray {
    val bytes = ByteBuffer.allocate(120).order(ByteOrder.nativeOrder())
    fun record(phase: Int, operation: CredentialRenewalID, statement: CredentialRenewalStatementID,
               checkpoint: RosterCheckpoint? = null, observed: Counter64 = Counter64.ZERO) {
        bytes.putInt(phase).put(operation.encoded()).put(statement.encoded()).putInt(0)
        if (checkpoint == null) bytes.put(ByteArray(40))
        else bytes.putLong(java.lang.Long.parseUnsignedLong(checkpoint.version.toString())).put(checkpoint.digest.encoded())
        bytes.putLong(java.lang.Long.parseUnsignedLong(observed.toString()))
    }
    when (value) {
        CredentialRenewalStatus.Absent -> bytes.put(ByteArray(120))
        is CredentialRenewalStatus.Pending -> record(1, value.operation, value.statement)
        is CredentialRenewalStatus.Committed -> record(2, value.operation, value.statement, value.target)
        is CredentialRenewalStatus.ExpiredUncommitted -> record(3, value.operation, value.statement, value.observedHead, value.observedAt)
        is CredentialRenewalStatus.Closed -> record(4, value.operation, value.statement, value.target)
    }
    check(!bytes.hasRemaining())
    return bytes.array()
}

private fun stageCredential(owner: ContinuityEnrollment, source: Path, refused: Boolean): ByteArray {
    val operation = CredentialRenewalID(exact(source, "credential-operation", 32))
    val pin = AccountPin(AccountID(exact(source, "trusted-account", 32)), exact(source, "enrollment-root", 1985),
        exact(source, "family", 32), RosterCheckpoint(counter(exact(source, "renewal-version", 8)), exact(source, "renewal-digest", 32)))
    val grant = load(source, "credential-renewal", 65536)
    if (refused) {
        grant[grant.lastIndex] = (grant.last().toInt() xor 1).toByte()
        expect(102) { owner.stageCredentialRenewal(grant, pin, operation) }
        expect(2) { owner.status() }
        return resultCode(102)
    }
    return credentialStatusBytes(owner.stageCredentialRenewal(grant, pin, operation))
}

private fun commitCredential(owner: ContinuityEnrollment, source: Path, mode: String): ByteArray {
    val operation = CredentialRenewalID(exact(source, "credential-operation", 32))
    val statement = CredentialRenewalStatementID(exact(source, "credential-statement", 32))
    if (mode == "credential-reconcile") return credentialStatusBytes(owner.reconcileWitnessedCredentialRenewal(operation, statement))
    val expected = when (mode) {
        "credential-commit-closed" -> 202
        "credential-commit-unmanaged" -> 211
        "credential-commit-unknown" -> 218
        "credential-commit" -> null
        else -> error("credential commit mode")
    }
    if (expected != null) {
        expect(expected) { owner.commitWitnessedCredentialRenewal(operation, statement) }
        expect(2) { owner.status() }
        return resultCode(expected)
    }
    return credentialStatusBytes(owner.commitWitnessedCredentialRenewal(operation, statement))
}

internal fun credentialOperation(owner: ContinuityEnrollment, source: Path, mode: String): ByteArray = when (mode) {
    "credential-identity" -> credentialIdentity(owner)
    "credential-expired-request" -> {
        expect(104) { owner.request() }; resultCode(104)
    }
    "credential-expired", "credential-activation-unmanaged" -> {
        val expected = if (mode == "credential-expired") 104 else 211
        expect(expected) { owner.activate().use { it.cancel() } }
        resultCode(expected)
    }
    "credential-activate" -> {
        val identity = credentialIdentity(owner)
        owner.activate().use { owner.close() }
        identity
    }
    "credential-prepare" -> owner.prepareWitnessedCredentialRenewal().encoded()
    "credential-stage", "credential-stage-refused" -> stageCredential(owner, source, mode == "credential-stage-refused")
    else -> commitCredential(owner, source, mode)
}
