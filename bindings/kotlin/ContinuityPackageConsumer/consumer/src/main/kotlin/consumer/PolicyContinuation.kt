// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.file.Path

private fun policyDocument(path: Path): PolicyDocument {
    val records = FixtureRecords(path)
    val version = Counter64.parse(java.lang.Long.toUnsignedString(ByteBuffer.wrap(
        records.enrollmentExact("policy-version", 8)).long))
    return PolicyDocument(records.enrollmentExact("policy-root", 1985), records.enrollmentExact("family", 32),
        PolicyCheckpoint(version, records.enrollmentExact("policy-digest", 32)), records.read("protocol-policy"))
}

internal fun policyEnrollment(owner: ContinuityEnrollment, path: String, records: FixtureRecords,
                              mode: String, original: EnrollmentStatus): String {
    val targetPath = Path.of(path).resolve("continued-sdk")
    val target = policyDocument(targetPath)
    fun operation() = CredentialRenewalID(records.enrollmentExact("credential-operation", 32))
    fun statement() = CredentialRenewalStatementID(records.enrollmentExact("credential-statement", 32))
    if (mode == "enrollment-policy-recover-history" || mode == "enrollment-policy-history-pending") {
        if (mode == "enrollment-policy-history-pending") {
            refused(setOf(215)) { owner.recoverHistoricalPolicyContinuation(operation(), statement(), target) }
            refused(setOf(2)) { owner.status() }
            return "policy-history-pending"
        }
        val result = owner.recoverHistoricalPolicyContinuation(operation(), statement(), target)
        check(result is CredentialRenewalStatus.Committed) { "history did not report original Committed" }
        check(owner.status() == original && original.phase == EnrollmentPhase.ACTIVE) { "historical recovery changed registration" }
        return renewalStatus(result)
    }
    if (mode == "enrollment-policy-current-refused") {
        refused(setOf(104)) { owner.selectContinuedPolicy(targetPath.toString(), target) }
        return "policy-expired-current-refused"
    }
    owner.selectContinuedPolicy(targetPath.toString(), target)
    val result = when (mode) {
        "enrollment-policy-stage", "enrollment-policy-carry-stage", "enrollment-policy-stage-conflict" -> {
            val grant = records.read("credential-renewal")
            val pin = enrollmentPin(records, true)
            val staged = if (mode == "enrollment-policy-carry-stage") {
                owner.stageContinuedCredentialRenewal(grant, pin, operation())
            } else {
                val kind = records.enrollmentExact("policy-predecessor-kind", 1)[0].toInt()
                check(kind == 0 || kind == 1) { "policy predecessor kind" }
                val previousT = if (kind == 1) PolicyContinuationStatementID(
                    records.enrollmentExact("policy-predecessor-statement", 32)) else null
                val id = operation()
                val approvals = records.read("policy-approvals")
                val previous = policyDocument(Path.of(path).resolve("previous-policy"))
                val stage = { owner.stagePolicyContinuation(grant, pin, id, approvals, previous, previousT) }
                if (mode == "enrollment-policy-stage-conflict") {
                    refused(setOf(211)) { stage() }
                    refused(setOf(2)) { owner.status() }
                    return "policy-stage-conflict"
                }
                stage()
            }
            check(staged is CredentialRenewalStatus.Pending) { "policy stage did not retain Pending" }
            check(staged == owner.credentialRenewalStatus()) { "policy stage differs from original-operation readback" }
            staged
        }
        "enrollment-policy-witness-prepare" -> {
            val proposal = owner.prepareWitnessedPolicyContinuation()
            check(proposal == owner.prepareWitnessedPolicyContinuation()) { "policy witness preparation changed original target" }
            val bytes = proposal.encoded()
            check(bytes.size == 329 && proposal.adoptsPolicy && proposal.operation == operation() &&
                proposal.statement == statement()) { "policy witness proposal differs from original joint operation" }
            check(records.retain("policy-proposal", bytes, true)) { "policy proposal output already exists" }
            check(owner.status() == original) { "policy witness preparation changed registration" }
            return "policy-witness-prepared"
        }
        "enrollment-policy-witness-commit" -> owner.commitWitnessedPolicyContinuation(operation(), statement()).also {
            check(it is CredentialRenewalStatus.Committed) { "policy witness commit did not report Committed" }
            check(owner.status() == original) { "policy witness commit changed registration" }
        }
        "enrollment-policy-reconcile" -> owner.reconcilePolicyContinuation().also {
            check(it is CredentialRenewalStatus.Committed) { "policy reconciliation did not retain Committed" }
        }
        "enrollment-policy-activate" -> {
            owner.activatePolicyContinuation().use { successor ->
                owner.close()
                successor.nextAccountOperation()
                refused(setOf(2)) { owner.status() }
            }
            return "policy-device-active"
        }
        else -> error("unknown policy integration operation")
    }
    return renewalStatus(result)
}
