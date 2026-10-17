// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

internal enum class SetupIntent { CREATE, RESUME }
class JournalID(bytes: ByteArray) : ContinuityID(bytes)
enum class InstallationPhase { CREATING, ACTIVE }
data class InstallationStatus(val phase: InstallationPhase, val journal: JournalID)
/** Public original enrollment inputs, not a signed receipt or enrollment permission. */
data class WitnessGenesis(val journal: JournalID, val subject: PublicBytes, val imageDigest: PublicBytes)
sealed interface InstallationPreparation {
    data class Local(val journal: JournalID) : InstallationPreparation
    data class RequiresEnrollment(val genesis: WitnessGenesis) : InstallationPreparation
}

/** Explicit original installation setup over independently prepared key,
 * credential, policy and TLS inputs. It grants no peer/message authority.
 */
class ContinuitySetup private constructor(native: NativeOwner) : AutoCloseable {
    private val reference = OwnerTransfer(native, "setup")
    companion object {
        private fun prepare(path: String, witness: WitnessCarrier, intent: SetupIntent): ContinuitySetup =
            NativeOwner.prepare(path, 3, 0, witness, ::ContinuitySetup, setup = intent)
        fun prepareCreate(path: String, witness: WitnessCarrier = WitnessCarrier.Local): ContinuitySetup =
            prepare(path, witness, SetupIntent.CREATE)
        fun prepareResume(path: String, witness: WitnessCarrier = WitnessCarrier.Local): ContinuitySetup =
            prepare(path, witness, SetupIntent.RESUME)
        private fun opened(setup: ContinuitySetup): ContinuitySetup {
            try { setup.finishOpen(); return setup } catch (failure: Throwable) {
                try { setup.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
        }
        fun create(path: String, witness: WitnessCarrier = WitnessCarrier.Local): ContinuitySetup = opened(prepareCreate(path, witness))
        fun resume(path: String, witness: WitnessCarrier = WitnessCarrier.Local): ContinuitySetup = opened(prepareResume(path, witness))
    }
    fun finishOpen() = reference.call { owner -> owner.call { ContinuityNative.simple(it, "finish_open") } }
    /** Cancellation admitted before/during transfer can also affect the returned
     * device. Join cancellation before treating a racing activation as usable.
     */
    fun cancel() = reference.call(cancellation = true) { owner -> owner.call { ContinuityNative.simple(it, "cancel") } }
    /** Successful transfer makes subsequent setup close harmless to its successor. */
    override fun close() = reference.close()
    fun status(): InstallationStatus = reference.call { owner -> owner.call { ContinuityNative.setupStatus(it) } }
    fun prepareStorage(): InstallationPreparation = reference.call { owner -> owner.call { ContinuityNative.setupStorage(it) } }
    /** Allocate the successor before native mutation, then transfer the same
     * owning reference. Failed activation leaves setup available for cancel/close;
     * reconcile through a new resume of the original configuration.
     */
    fun activate(): ContinuityDevice = reference.transfer { owner ->
        val device = ContinuityDevice.activated(owner)
        owner.call { ContinuityNative.simple(it, "setup_activate") }
        device
    }
}
