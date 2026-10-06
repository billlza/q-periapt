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

enum class EnrollmentPhase { PREPARING, REQUESTED, ACCEPTED, ACTIVATING, ACTIVE, REFRESHING, ROSTER_RESOLVED }
data class RosterTransition(val previous: RosterCheckpoint, val next: RosterCheckpoint)
/** Durable progress only. Active does not establish current operational authority. */
data class EnrollmentStatus(val phase: EnrollmentPhase, val signing: SigningKeyID,
                            val journal: JournalID?, val refresh: RosterTransition?)
/** Original-operation history only. A higher head preserves unknown past adoption. */
enum class RosterRefreshOutcome { COMMITTED, EXPIRED_UNCOMMITTED, SUPERSEDED_UNCOMMITTED, SUPERSEDED_UNKNOWN }
data class RosterRefreshResolution(val outcome: RosterRefreshOutcome, val journal: JournalID,
    val previous: RosterCheckpoint, val target: RosterCheckpoint, val observed: RosterCheckpoint,
    val observedAt: Counter64)
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
    /** Original metadata recovery without device transfer, runtime or private signer.
     * After an admitted failure, close/resume and retry the same checkpoint pair. */
    fun resolveRosterRefresh(previous: RosterCheckpoint, target: RosterCheckpoint): RosterRefreshResolution =
        reference.call { owner -> owner.call { ContinuityNative.resolveRosterRefresh(it, previous, target) } }
    /** Read-only exact scope and signed identity material; creates no reservation. */
    fun policyRenewalRequest(operation: PolicyRenewalID): PolicyRenewalRequest =
        reference.call { owner -> owner.call { ContinuityNative.policyRenewalRequest(it, operation) } }
    /** Required-witness request; never falls back to the local profile. */
    fun witnessedPolicyRenewalRequest(operation: PolicyRenewalID): PolicyRenewalRequest =
        reference.call { owner -> owner.call { ContinuityNative.policyRenewalRequest(it, operation, witnessed = true) } }
    /** Select current target first; independent approval is still required. */
    fun prepareWitnessedPolicyRenewal(previous: PolicyDocument): IndependentPolicyProposal =
        reference.call { owner -> owner.call { ContinuityNative.prepareWitnessedPolicyRenewal(it, previous) } }
    /** Null means local absence only, never proof of no commit. */
    fun recoverWitnessedPolicyRenewalPreparation(): IndependentPolicyProposal? =
        reference.call { owner -> owner.call { ContinuityNative.recoverWitnessedPolicyRenewalPreparation(it) } }
    /** Historical metadata, without current runtime, private signer or application TLS. */
    fun witnessedPolicyRenewalProgress(): IndependentPolicyProgress =
        reference.call { owner -> owner.call { ContinuityNative.witnessedPolicyRenewalProgress(it) } }
    /** Exact independently approved target and current target authorization required. */
    fun commitWitnessedPolicyRenewal(proposal: IndependentPolicyProposal): IndependentPolicyState =
        reference.call { owner -> owner.call { ContinuityNative.independentPolicyCommand(it, proposal, "commit_witnessed_policy_renewal") } }
    /** Original history is persisted before terminal ACK and cleanup. */
    fun reconcileWitnessedPolicyRenewal(proposal: IndependentPolicyProposal): IndependentPolicyState =
        reference.call { owner -> owner.call { ContinuityNative.independentPolicyCommand(it, proposal, "reconcile_witnessed_policy_renewal") } }
    fun closeWitnessedPolicyRenewal(proposal: IndependentPolicyProposal): IndependentPolicyState =
        reference.call { owner -> owner.call { ContinuityNative.independentPolicyCommand(it, proposal, "close_witnessed_policy_renewal") } }
    fun policyRenewalStatus(): PolicyRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.policyRenewalStatus(it) } }
    /** Select current target first. Retain/retry the original request after Pending. */
    fun stagePolicyRenewal(request: PolicyRenewalRequest, originalPin: AccountPin, currentPin: AccountPin,
        approvals: ByteArray, previous: PolicyDocument): PolicyRenewalStatus {
        val copied = approvals.clone()
        return reference.call { owner -> owner.call { ContinuityNative.stagePolicyRenewal(it, request, originalPin, currentPin, copied, previous) } }
    }
    fun pendingPolicyRenewalApproval(operation: PolicyRenewalID): PublicBytes =
        reference.call { owner -> owner.call { ContinuityNative.pendingPolicyRenewalApproval(it, operation) } }
    fun reconcilePolicyRenewal(): PolicyRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.policyRenewalStatus(it, reconcile = true) } }
    /** Original historical fact only; no runtime/TLS/signer or Device transfer. */
    fun resolvePolicyRenewal(operation: PolicyRenewalID, statement: PolicyRenewalStatementID, target: PolicyDocument): PolicyRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.resolvePolicyRenewal(it, operation, statement, target) } }
    /** Transfers the same NativeOwner only after current native admission succeeds. */
    fun activatePolicyRenewal(): ContinuityDevice = reference.transfer { owner ->
        val device = ContinuityDevice.activated(owner)
        owner.call { ContinuityNative.simple(it, "activate_policy_renewal") }
        device
    }
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
    /** Reserve the staged grant without a target or witness dispatch. Independent
     * Closed approval and historical reconciliation must finish before journal use. */
    fun prepareWitnessedCredentialCancellation(): CredentialRenewalCancellation =
        reference.call { owner -> owner.call { ContinuityNative.prepareWitnessedCredentialCancellation(it) } }
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
    /** Select once per resumed owner. Original P0 stays in the enrollment files;
     * independently pinned P1 and its SDK runtime remain owned by native code.
     * Selection alone gives no session authority. */
    fun selectContinuedPolicy(path: String, document: PolicyDocument) =
        reference.call { owner -> owner.call { ContinuityNative.selectContinuedPolicy(it, path, document) } }
    /** Persist the exact G/T pair. previousT is absent only for original P0.
     * Both issuer approvals and the previous document are independent inputs. */
    fun stagePolicyContinuation(wire: ByteArray, pin: AccountPin, operation: CredentialRenewalID,
        approvals: ByteArray, previousDocument: PolicyDocument,
        previousT: PolicyContinuationStatementID? = null): CredentialRenewalStatus {
        val grantCopy = wire.clone(); val approvalsCopy = approvals.clone()
        return reference.call { owner -> owner.call {
            ContinuityNative.stagePolicyContinuation(it, grantCopy, pin, operation, approvalsCopy, previousDocument, previousT)
        } }
    }
    /** Advance G while carrying the already adopted T under selected current P1. */
    fun stageContinuedCredentialRenewal(wire: ByteArray, pin: AccountPin, operation: CredentialRenewalID): CredentialRenewalStatus {
        val copy = wire.clone()
        return reference.call { owner -> owner.call { ContinuityNative.stageContinuedCredentialRenewal(it, copy, pin, operation) } }
    }
    fun prepareWitnessedPolicyContinuation(): PolicyRenewalProposal =
        reference.call { owner -> owner.call { ContinuityNative.prepareWitnessedPolicyContinuation(it) } }
    fun prepareWitnessedPolicyCancellation(): PolicyRenewalCancellation =
        reference.call { owner -> owner.call { ContinuityNative.prepareWitnessedPolicyCancellation(it) } }
    /** Local original-transaction coordination only; returns metadata, no Device. */
    fun reconcilePolicyContinuation(): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.reconcilePolicyContinuation(it) } }
    /** New Commit needs selected current P1. Retain operation and transaction
     * statement after every unknown result; historical completion creates no owner. */
    fun commitWitnessedPolicyContinuation(operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.commitWitnessedPolicyContinuation(it, operation, statement) } }
    /** Complete only an exact existing local journal commit using pinned history.
     * Requires no policy selection, SDK runtime or TLS; never starts a new target. */
    fun recoverHistoricalPolicyContinuation(operation: CredentialRenewalID, statement: CredentialRenewalStatementID,
        targetDocument: PolicyDocument): CredentialRenewalStatus =
        reference.call { owner -> owner.call { ContinuityNative.recoverHistoricalPolicyContinuation(it, operation, statement, targetDocument) } }
    /** Transfer the same controlled signer/storage/P1 runtime after current native
     * G/T admission. Failure retains this sole closable wrapper; resume original
     * state after close. Existing sessions only; no fresh bootstrap capability. */
    fun activatePolicyContinuation(): ContinuityDevice = reference.transfer { owner ->
        val device = ContinuityDevice.activated(owner)
        owner.call { ContinuityNative.simple(it, "activate_policy_continuation") }
        device
    }
    /** Move the sole owning reference after native activation. On failure, close
     * this wrapper and resume the original state, which may already be Active.
     */
    fun activate(): ContinuityDevice = reference.transfer { owner ->
        val device = ContinuityDevice.activated(owner)
        owner.call { ContinuityNative.simple(it, "enrollment_activate") }
        device
    }
}
