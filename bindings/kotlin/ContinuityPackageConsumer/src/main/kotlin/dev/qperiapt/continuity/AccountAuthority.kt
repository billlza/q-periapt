// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

class AccountAuthorityID(bytes: ByteArray) : ContinuityID(bytes)
class ApplicationAccountID(bytes: ByteArray) : ContinuityID(bytes)

/** Original host registry identity and independently supplied witness pin. */
class AccountAuthorityTrust(val identity: AccountAuthorityID, family: ByteArray,
                            witness: ByteArray, publicKey: ByteArray) {
    val family = PublicBytes(family)
    val witness = PublicBytes(witness)
    val publicKey = PublicBytes(publicKey)
    init {
        require(family.size == 32 && witness.size == 32 && publicKey.size == 1985) { "invalid authority input width" }
        require(listOf(identity.encoded(), this.family.encoded(), this.witness.encoded()).all { bytes ->
            bytes.any { it != 0.toByte() }
        }) { "zero authority scope" }
    }
}

/** Expected public mapping; it grants no authority without the original live store. */
data class AccountAuthorityCheckpoint(val application: ApplicationAccountID, val revision: Counter64, val account: AccountID) {
    init {
        require(revision != Counter64.ZERO && revision.bits() != -1L &&
            application.encoded().any { it != 0.toByte() } && account.encoded().any { it != 0.toByte() }) {
            "invalid authority checkpoint"
        }
    }
}

/** Host-owned registry. Keep it reachable until all selected children finish.
 * Use close/use deterministically; Cleaner is a backstop. Children never retain
 * this registry. Close/final cleanup revokes admission, and reopening does not
 * revive previously selected children. Cancel affects this owner's calls only.
 */
class ContinuityAccountAuthority private constructor(private val native: NativeOwner) : AutoCloseable {
    companion object {
        fun provisionWrappingKey(path: String) = AccountAuthorityNative.provisionKey(path)
        fun prepareCreate(path: String, trust: AccountAuthorityTrust): ContinuityAccountAuthority =
            NativeOwner.prepareOwned({ AccountAuthorityNative.prepare(path, trust, true) }, ::ContinuityAccountAuthority)
        fun prepareOpen(path: String, trust: AccountAuthorityTrust): ContinuityAccountAuthority =
            NativeOwner.prepareOwned({ AccountAuthorityNative.prepare(path, trust, false) }, ::ContinuityAccountAuthority)
    }
    fun finishOpen() = native.call { ContinuityNative.simple(it, "finish_open") }
    fun cancel() = native.call { ContinuityNative.simple(it, "cancel") }
    override fun close() = native.close()
    fun checkpoint(application: ApplicationAccountID): AccountAuthorityCheckpoint =
        native.call { AccountAuthorityNative.checkpoint(it, application) }
    fun associate(application: ApplicationAccountID, pin: AccountPin, certificate: ByteArray, roster: ByteArray): AccountAuthorityCheckpoint {
        require(certificate.size in 1..8192 && roster.size in 1..65536) { "invalid authority association width" }
        require(application.encoded().any { it != 0.toByte() }) { "zero application account" }
        val copiedCertificate = certificate.clone(); val copiedRoster = roster.clone()
        return native.call { AccountAuthorityNative.associate(it, application, pin, copiedCertificate, copiedRoster) }
    }
    @JvmSynthetic internal fun select(enrollment: NativeOwner, checkpoint: AccountAuthorityCheckpoint) =
        native.call { registry -> enrollment.call { AccountAuthorityNative.select(it, registry, checkpoint) } }
}
