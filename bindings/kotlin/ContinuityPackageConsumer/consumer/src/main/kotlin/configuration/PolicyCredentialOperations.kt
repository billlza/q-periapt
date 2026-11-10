// SPDX-License-Identifier: Apache-2.0 OR MIT
package configuration

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Path

internal val policyCredentialModes = setOf(
    "policy-credential-request", "policy-credential-next-request", "policy-credential-status",
    "policy-credential-stage", "policy-credential-stage-refused", "policy-credential-prepare",
    "policy-credential-commit-unknown", "policy-credential-commit", "policy-credential-reconcile",
    "policy-credential-close", "policy-credential-activate",
)

// Public field serialization for the same-host qualification fixture only.
private fun requestBytes(value: CredentialRenewalRequest): ByteArray {
    val out = ByteBuffer.allocate(33120).order(ByteOrder.nativeOrder())
    fun counter(value: Counter64) { out.putLong(java.lang.Long.parseUnsignedLong(value.toString())) }
    fun roster(value: RosterCheckpoint) { counter(value.version); out.put(value.digest.encoded()) }
    fun record(value: PublicBytes) {
        val bytes = value.encoded(); check(bytes.size in 1..8192)
        out.putInt(bytes.size).put(bytes).put(ByteArray(8192 - bytes.size))
    }
    out.put(value.operation.encoded()).put(value.journal.encoded()).put(value.originalOwner.encoded()).put(value.originalPolicyDigest.encoded())
    counter(value.currentPolicy.version); out.put(value.currentPolicy.digest.encoded())
    out.put(value.currentPolicyAuthorization?.encoded() ?: ByteArray(32)).putInt(if (value.currentPolicyAuthorization == null) 0 else 1).putInt(0)
    roster(value.previousRosterCheckpoint); roster(value.originalRosterCheckpoint)
    counter(value.previousValidFrom); counter(value.previousValidUntil); out.put(value.account.encoded())
    record(value.originalCredential); record(value.originalRoster); record(value.previousCredential); record(value.previousRoster)
    check(!out.hasRemaining()); return out.array()
}

internal fun policyCredentialOperation(owner: ContinuityEnrollment, source: Path, target: String,
    recoverable: Boolean, carrier: String?, mode: String): ByteArray {
    if (mode == "policy-credential-status") return credentialStatusBytes(owner.credentialRenewalStatus())
    val operation = CredentialRenewalID(exact(source, if (mode == "policy-credential-next-request") "credential-next-operation" else "credential-operation", 32))
    if (mode == "policy-credential-request" || mode == "policy-credential-next-request") {
        return requestBytes(if (carrier == null) owner.credentialRenewalRequest(operation) else owner.witnessedCredentialRenewalRequest(operation))
    }
    if (mode != "policy-credential-reconcile" && mode != "policy-credential-close") selectPolicyTarget(owner,source,target,recoverable)
    if (mode == "policy-credential-activate") {
        val identity = credentialIdentity(owner)
        owner.activatePolicyRenewal().use { owner.close() }
        return identity
    }
    if (mode == "policy-credential-stage" || mode == "policy-credential-stage-refused") {
        val grant = load(source,"credential-renewal",65536)
        val pin = AccountPin(AccountID(exact(source,"trusted-account",32)),exact(source,"enrollment-root",1985),exact(source,"family",32),
            RosterCheckpoint(counter(exact(source,"renewal-version",8)),exact(source,"renewal-digest",32)))
        if (mode == "policy-credential-stage-refused") {
            grant[grant.lastIndex] = (grant.last().toInt() xor 1).toByte()
            expect(102) { owner.stageContinuedCredentialRenewal(grant,pin,operation) }; expect(2) { owner.status() }
            return ByteBuffer.allocate(4).order(ByteOrder.nativeOrder()).putInt(102).array()
        }
        return credentialStatusBytes(owner.stageContinuedCredentialRenewal(grant,pin,operation))
    }
    val statement = CredentialRenewalStatementID(exact(source,"credential-statement",32))
    return when (mode) {
        "policy-credential-prepare" -> {
            val value = owner.prepareWitnessedPolicyContinuation()
            check(value.operation == operation && value.credentialStatement == statement && value.statement == statement &&
                value.policyStatement == null && !value.adoptsPolicy && value.independentPolicyStatement == PolicyRenewalStatementID(exact(source,"renewal-statement",32)))
            value.encoded()
        }
        "policy-credential-commit-unknown" -> {
            expect(218) { owner.commitWitnessedPolicyContinuation(operation,statement) }; expect(2) { owner.status() }
            ByteBuffer.allocate(4).order(ByteOrder.nativeOrder()).putInt(218).array()
        }
        "policy-credential-commit" -> credentialStatusBytes(owner.commitWitnessedPolicyContinuation(operation,statement))
        "policy-credential-reconcile" -> credentialStatusBytes(owner.reconcileWitnessedCredentialRenewal(operation,statement))
        "policy-credential-close" -> credentialStatusBytes(owner.closeWitnessedCredentialRenewal(operation,statement))
        else -> error("policy credential operation")
    }
}
