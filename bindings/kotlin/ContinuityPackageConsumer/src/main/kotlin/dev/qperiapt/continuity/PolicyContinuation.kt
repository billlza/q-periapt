// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

/** Independently provisioned protocol-policy checkpoint, distinct from a roster. */
class PolicyCheckpoint(val version: Counter64, digest: ByteArray) {
    val digest = PublicBytes(digest)
    init {
        require(version != Counter64.ZERO && version.bits() != -1L) { "invalid policy version" }
        require(this.digest.encoded().let { it.size == 32 && it.any { byte -> byte != 0.toByte() } }) { "invalid policy digest" }
    }
    override fun equals(other: Any?): Boolean = other is PolicyCheckpoint && version == other.version && digest == other.digest
    override fun hashCode(): Int = 31 * version.hashCode() + digest.hashCode()
}

/** Copied public document and independent pin. Native verification decides whether
 * this is current P1 or historical metadata; this value creates no runtime. */
class PolicyDocument(root: ByteArray, family: ByteArray, val checkpoint: PolicyCheckpoint, wire: ByteArray) {
    val root = PublicBytes(root)
    val family = PublicBytes(family)
    val wire = PublicBytes(wire)
    init {
        require(this.root.encoded().size == 1985) { "invalid policy root width" }
        require(this.family.encoded().let { it.size == 32 && it.any { byte -> byte != 0.toByte() } }) { "invalid policy family" }
        require(this.wire.encoded().size in 1..8192) { "policy document must contain 1..8192 bytes" }
    }
}

/** Joint account/policy statement T, distinct from a credential-only statement G. */
class PolicyContinuationStatementID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(encoded().any { it != 0.toByte() }) { "policy continuation statement must be nonzero" } }
}

enum class PolicyContinuationMode { CARRY, ADOPT }

private fun policyMetadata(length: Int, storage: ByteArray, proposal: Boolean): ByteArray {
    val legacy = if (proposal) 296 else 248
    val capacity = legacy + 33
    fun check(valid: Boolean) {
        if (!valid) throw ContinuityBoundaryFailure("malformed policy renewal metadata")
    }
    check(storage.size == capacity && (length == legacy || length == capacity))
    check(storage.copyOfRange(length, capacity).all { it == 0.toByte() })
    val wire = storage.copyOf(length)
    val prefix = if (proposal) "QPCRNP" else "QPCRNC"
    val tag = prefix + if (length == legacy) "01" else "02"
    check(wire.copyOfRange(0, 8).contentEquals(tag.toByteArray(Charsets.US_ASCII)))
    // Reuse every original common-field/head check; the old decoders still
    // reject v2 and accept only their own exact fixed-width records.
    val original = wire.copyOf(legacy)
    (prefix + "01").toByteArray(Charsets.US_ASCII).copyInto(original)
    if (proposal) CredentialRenewalProposal.decode(original) else CredentialRenewalCancellation.decode(original)
    if (length != legacy) {
        check(wire[legacy] == 0.toByte() || wire[legacy] == 1.toByte())
        check(wire.copyOfRange(legacy + 1, capacity).any { it != 0.toByte() })
    }
    return wire
}

/** Exact public proposal, not witness approval or operational authority. */
class PolicyRenewalProposal private constructor(private val value: ByteArray) {
    val operation = CredentialRenewalID(value.copyOfRange(136, 168))
    val credentialStatement = CredentialRenewalStatementID(value.copyOfRange(168, 200))
    val policyStatement = if (value.size == 329) PolicyContinuationStatementID(value.copyOfRange(297, 329)) else null
    val mode = if (value.size == 329) PolicyContinuationMode.entries[value[296].toInt()] else null
    val adoptsPolicy: Boolean get() = mode == PolicyContinuationMode.ADOPT
    val statement = CredentialRenewalStatementID(
        if (mode == PolicyContinuationMode.ADOPT) value.copyOfRange(297, 329) else credentialStatement.encoded())
    fun encoded(): ByteArray = value.clone()
    override fun equals(other: Any?): Boolean = other is PolicyRenewalProposal && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
    companion object {
        @JvmSynthetic internal fun decode(length: Int, storage: ByteArray): PolicyRenewalProposal =
            PolicyRenewalProposal(policyMetadata(length, storage.clone(), true))
    }
}

/** Exact target-free public metadata. No Closed or cleanup authority is inferred. */
class PolicyRenewalCancellation private constructor(private val value: ByteArray) {
    val operation = CredentialRenewalID(value.copyOfRange(136, 168))
    val credentialStatement = CredentialRenewalStatementID(value.copyOfRange(168, 200))
    val policyStatement = if (value.size == 281) PolicyContinuationStatementID(value.copyOfRange(249, 281)) else null
    val mode = if (value.size == 281) PolicyContinuationMode.entries[value[248].toInt()] else null
    val adoptsPolicy: Boolean get() = mode == PolicyContinuationMode.ADOPT
    val statement = CredentialRenewalStatementID(
        if (mode == PolicyContinuationMode.ADOPT) value.copyOfRange(249, 281) else credentialStatement.encoded())
    fun encoded(): ByteArray = value.clone()
    override fun equals(other: Any?): Boolean = other is PolicyRenewalCancellation && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
    companion object {
        @JvmSynthetic internal fun decode(length: Int, storage: ByteArray): PolicyRenewalCancellation =
            PolicyRenewalCancellation(policyMetadata(length, storage.clone(), false))
    }
}
