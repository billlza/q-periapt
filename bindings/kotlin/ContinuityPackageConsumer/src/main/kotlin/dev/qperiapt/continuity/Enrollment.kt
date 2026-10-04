// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

class SigningKeyID(bytes: ByteArray) : ContinuityID(bytes)

/** Approved local scope. Account authentication and approval remain independent. */
class EnrollmentIntent(root: ByteArray, device: ByteArray, val generation: Counter64,
                       family: ByteArray, val validFrom: Counter64, val validUntil: Counter64) {
    val root = PublicBytes(root)
    val device = PublicBytes(device)
    val family = PublicBytes(family)
    init {
        require(root.size == 1985 && device.size == 16 && family.size == 32) { "invalid enrollment input width" }
        require(device.any { it != 0.toByte() } && family.any { it != 0.toByte() }) { "zero enrollment scope" }
        require(generation != Counter64.ZERO && generation.bits() != -1L) { "invalid device generation" }
        require(validFrom < validUntil && validUntil.bits() != -1L) { "enrollment validity must be finite and nonempty" }
    }
}

/** An independently retained expectation; these bytes do not authenticate themselves. */
class RosterCheckpoint(val version: Counter64, digest: ByteArray) {
    val digest = PublicBytes(digest)
    init {
        require(version != Counter64.ZERO && version.bits() != -1L) { "invalid roster version" }
        require(digest.size == 32 && digest.any { it != 0.toByte() }) { "invalid roster digest" }
    }
    override fun equals(other: Any?): Boolean = other is RosterCheckpoint && version == other.version && digest == other.digest
    override fun hashCode(): Int = 31 * version.hashCode() + digest.hashCode()
}

/** Supply separately from the untrusted credential/roster response. */
class AccountPin(val account: AccountID, root: ByteArray, family: ByteArray, val checkpoint: RosterCheckpoint) {
    val root = PublicBytes(root)
    val family = PublicBytes(family)
    init {
        require(root.size == 1985 && family.size == 32 && family.any { it != 0.toByte() }
                && account.encoded().any { it != 0.toByte() }) { "invalid independent enrollment pin" }
    }
}

enum class EnrollmentPhase { PREPARING, REQUESTED, ACCEPTED, ACTIVATING, ACTIVE, REFRESHING }
data class RosterTransition(val previous: RosterCheckpoint, val next: RosterCheckpoint)
/** Durable progress only. Active does not establish current operational authority. */
data class EnrollmentStatus(val phase: EnrollmentPhase, val signing: SigningKeyID,
                            val journal: JournalID?, val refresh: RosterTransition?)
internal data class EnrollmentPreparation(val intent: EnrollmentIntent, val action: SetupIntent)

/** Original native registration. Explicit resume never selects identity recreation. */
class ContinuityEnrollment private constructor(native: NativeOwner) : AutoCloseable {
    private val reference = OwnerTransfer(native, "enrollment")
    companion object {
        fun provisionWrappingKey(path: String) = ContinuityNative.enrollmentKey(path)
        private fun prepare(path: String, intent: EnrollmentIntent, witness: WitnessCarrier, action: SetupIntent): ContinuityEnrollment =
            NativeOwner.prepare(path, 3, 0, witness, ::ContinuityEnrollment, enrollment = EnrollmentPreparation(intent, action))
        fun prepareCreate(path: String, intent: EnrollmentIntent, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityEnrollment =
            prepare(path, intent, witness, SetupIntent.CREATE)
        fun prepareResume(path: String, intent: EnrollmentIntent, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityEnrollment =
            prepare(path, intent, witness, SetupIntent.RESUME)
        private fun opened(owner: ContinuityEnrollment): ContinuityEnrollment {
            try { owner.finishOpen(); return owner } catch (failure: Throwable) {
                try { owner.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
        fun create(path: String, intent: EnrollmentIntent, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityEnrollment =
            opened(prepareCreate(path, intent, witness))
        fun resume(path: String, intent: EnrollmentIntent, witness: WitnessCarrier = WitnessCarrier.Local): ContinuityEnrollment =
            opened(prepareResume(path, intent, witness))
    }
    fun finishOpen() = reference.call { owner -> owner.call { ContinuityNative.simple(it, "finish_open") } }
    /** May race activation; join cancellation before using a returned successor. */
    fun cancel() = reference.call(cancellation = true) { owner -> owner.call { ContinuityNative.simple(it, "cancel") } }
    override fun close() = reference.close()
    fun status(): EnrollmentStatus = reference.call { owner -> owner.call { ContinuityNative.enrollmentStatus(it) } }
    fun request(): PublicBytes = reference.call { owner -> owner.call { ContinuityNative.enrollmentRequest(it) } }
    fun accept(certificate: ByteArray, roster: ByteArray, pin: AccountPin): JournalID =
        reference.call { owner -> owner.call { ContinuityNative.enrollmentAccept(it, certificate, roster, pin) } }
    fun prepareStorage(): InstallationPreparation = reference.call { owner -> owner.call { ContinuityNative.enrollmentStorage(it) } }
    fun refreshRoster(previous: RosterCheckpoint, roster: ByteArray, pin: AccountPin): EnrollmentStatus =
        reference.call { owner -> owner.call { ContinuityNative.enrollmentRefresh(it, previous, roster, pin) } }
    /** Passive original-operation progress; requires neither live policy nor TLS files. */
    fun credentialRenewalStatus(): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.credentialRenewalStatus(it) } }
    /** Persist a same-key target under the independently current pin and original
     * configured policy. Close/join the device first, then resume this original
     * enrollment. Required-witness targets need witnessed preparation and terminal
     * reconciliation before activation.
     */
    fun stageCredentialRenewal(wire: ByteArray, pin: AccountPin, operation: CredentialRenewalID): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.stageCredentialRenewal(it, wire, pin, operation) } }
    /** Reconcile retained intent, without revalidating an expired target as live
     * authority. This publishes no device and never infers absence from failure.
     */
    fun reconcileExpiredCredentialRenewal(operation: CredentialRenewalID,
                                         statement: CredentialRenewalStatementID): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.reconcileExpiredCredentialRenewal(it, operation, statement) } }
    /** Recover or prepare the exact original target for independent witness approval. */
    fun prepareWitnessedCredentialRenewal(): CredentialRenewalProposal =
        reference.call { owner -> owner.call { ContinuityNative.prepareWitnessedCredentialRenewal(it) } }
    /** New Commit requires current authority; terminal history releases no device. */
    fun commitWitnessedCredentialRenewal(operation: CredentialRenewalID,
                                        statement: CredentialRenewalStatementID): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.witnessedCredentialRenewal(it, operation, statement,
            ContinuityNative.WitnessRenewalAction.COMMIT) } }
    /** Close can lose to Applied, in which case the result remains Committed. */
    fun closeWitnessedCredentialRenewal(operation: CredentialRenewalID,
                                       statement: CredentialRenewalStatementID): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.witnessedCredentialRenewal(it, operation, statement,
            ContinuityNative.WitnessRenewalAction.CLOSE) } }
    /** Historical recovery sends neither Commit nor Close and releases no device. */
    fun reconcileWitnessedCredentialRenewal(operation: CredentialRenewalID,
                                           statement: CredentialRenewalStatementID): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.witnessedCredentialRenewal(it, operation, statement,
            ContinuityNative.WitnessRenewalAction.RECONCILE) } }
    /** Move the sole owning reference after native activation. On failure, close
     * this wrapper and resume the original state, which may already be Active.
     */
    fun activate(): ContinuityDevice = reference.transfer { owner ->
        val device = ContinuityDevice.activated(owner)
        owner.call { ContinuityNative.simple(it, "enrollment_activate") }
        device
    }
}
