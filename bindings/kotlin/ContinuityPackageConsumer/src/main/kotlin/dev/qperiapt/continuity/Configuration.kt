// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

/** Original host SDK trust, obtained independently of installation files or incoming responses. */
class SdkPolicyTrust private constructor(
    @get:JvmSynthetic internal val mode: Int,
    @get:JvmSynthetic internal val scope: PublicBytes,
    @get:JvmSynthetic internal val root: PublicBytes,
    @get:JvmSynthetic internal val recoveryRoot: PublicBytes,
) {
    companion object {
        fun fixed(root: ByteArray): SdkPolicyTrust {
            require(root.size == 1952) { "invalid SDK root width" }
            return SdkPolicyTrust(1, PublicBytes(ByteArray(32)), PublicBytes(root), PublicBytes(byteArrayOf()))
        }
        fun recoverable(scope: ByteArray, initialRoot: ByteArray, recoveryRoot: ByteArray): SdkPolicyTrust {
            require(scope.size == 32 && scope.any { it != 0.toByte() } && initialRoot.size == 1952 && recoveryRoot.size == 1952) {
                "invalid original SDK recovery trust"
            }
            return SdkPolicyTrust(2, PublicBytes(scope), PublicBytes(initialRoot), PublicBytes(recoveryRoot))
        }
    }
}

/** Exact signed initial policy and optional original recovery enrollment, never a requested update. */
class InitialSdkPolicy(trust: SdkPolicyTrust, policy: ByteArray, signature: ByteArray, recoveryEnrollment: ByteArray? = null) {
    @get:JvmSynthetic internal val trust = trust
    @get:JvmSynthetic internal val policy: PublicBytes
    @get:JvmSynthetic internal val signature: PublicBytes
    @get:JvmSynthetic internal val enrollment: PublicBytes
    init {
        require(policy.size in 1..65536 && signature.size == 3309) { "invalid initial SDK policy width" }
        require(if (trust.mode == 1) recoveryEnrollment == null else recoveryEnrollment?.size == 3309) {
            "recovery enrollment must match original SDK trust mode"
        }
        this.policy = PublicBytes(policy); this.signature = PublicBytes(signature)
        enrollment = PublicBytes(recoveryEnrollment ?: byteArrayOf())
    }
}

/** Owned DER input snapshot. Close after configuration preparation or enrollment dispatch.
 * Closing clears this object's key copy; already admitted synchronous calls retain their
 * own scoped copy. Caller arrays and historical JVM/GC copies are outside this guarantee.
 * Certificate/key matching is checked by native finishOpen or witness preparation.
 */
class LocalTlsIdentity(certificate: ByteArray, privateKey: ByteArray) : AutoCloseable {
    @get:JvmSynthetic internal val certificate: PublicBytes
    private val monitor = Any()
    private var key: ByteArray?
    init {
        require(certificate.size in 1..8192 && privateKey.size in 1..8192) { "invalid local TLS DER width" }
        this.certificate = PublicBytes(certificate); key = privateKey.clone()
    }
    @JvmSynthetic internal fun <T> withKey(body: (ByteArray) -> T): T {
        val copy = synchronized(monitor) { checkNotNull(key) { "local TLS identity is closed" }.clone() }
        try { return body(copy) } finally { copy.fill(0) }
    }
    override fun close() { synchronized(monitor) { key?.fill(0); key = null } }
}

/** Preparation copies these inputs; finishOpen validates and atomically publishes
 * configuration, SDK state and wrapping key. It grants no registration or traffic permission.
 * The host owns tls and may close it after prepareCreate/prepareReconcile returns.
 */
class InstallationConfiguration(
    @get:JvmSynthetic internal val sdk: InitialSdkPolicy,
    @get:JvmSynthetic internal val protocolPolicy: PolicyDocument,
    @get:JvmSynthetic internal val tls: LocalTlsIdentity,
)

/** Independently trusted witness pin and explicit endpoint. No network reply or enrollment is implied. */
class ConfigurationWitness private constructor(
    @get:JvmSynthetic internal val carrier: Int,
    @get:JvmSynthetic internal val identity: PublicBytes,
    @get:JvmSynthetic internal val publicKey: PublicBytes,
    @get:JvmSynthetic internal val address: String,
    @get:JvmSynthetic internal val timeoutMilliseconds: Int,
    @get:JvmSynthetic internal val peer: PublicBytes,
    @get:JvmSynthetic internal val tls: LocalTlsIdentity?,
    @get:JvmSynthetic internal val name: String?,
) {
    companion object {
        private fun validate(identity: ByteArray, key: ByteArray, timeout: Int) {
            require(identity.size == 32 && identity.any { it != 0.toByte() } && key.size == 1985 && timeout in 1..10000) {
                "invalid original witness pin or timeout"
            }
        }
        fun signedTCP(identity: ByteArray, publicKey: ByteArray, address: String, timeoutMilliseconds: Int): ConfigurationWitness {
            validate(identity, publicKey, timeoutMilliseconds)
            return ConfigurationWitness(1, PublicBytes(identity), PublicBytes(publicKey), address, timeoutMilliseconds,
                PublicBytes(byteArrayOf()), null, null)
        }
        fun mutualTLS(identity: ByteArray, publicKey: ByteArray, address: String, timeoutMilliseconds: Int,
                      peerCertificate: ByteArray, serverName: String, localIdentity: LocalTlsIdentity): ConfigurationWitness {
            validate(identity, publicKey, timeoutMilliseconds)
            require(peerCertificate.size in 1..8192) { "invalid witness TLS peer certificate width" }
            return ConfigurationWitness(2, PublicBytes(identity), PublicBytes(publicKey), address, timeoutMilliseconds,
                PublicBytes(peerCertificate), localIdentity, serverName)
        }
    }
}

/** One configuration/SDK lease. Creation, exact initial reconciliation and current-open
 * are distinct. No failure permits missing-state repair or key regeneration.
 * Calls are synchronous. Use close/use deterministically; Cleaner is a backstop.
 */
class ContinuityConfiguration private constructor(native: NativeOwner) : AutoCloseable {
    private val reference = OwnerTransfer(native, "configuration")
    companion object {
        fun prepareCreate(path: String, input: InstallationConfiguration): ContinuityConfiguration =
            NativeOwner.prepareConfiguration({ ContinuityNative.prepareConfiguration(path, input, false) }, ::ContinuityConfiguration)
        /** Compare original independently retained inputs after an unknown publication result. */
        fun prepareReconcile(path: String, input: InstallationConfiguration): ContinuityConfiguration =
            NativeOwner.prepareConfiguration({ ContinuityNative.prepareConfiguration(path, input, true) }, ::ContinuityConfiguration)
        /** Committed SDK state under original host trust; no initial-policy replay or sidecar trust. */
        fun prepareOpen(path: String, trust: SdkPolicyTrust, protocolPolicy: PolicyDocument): ContinuityConfiguration =
            NativeOwner.prepareConfiguration({ ContinuityNative.prepareConfigurationOpen(path, trust, protocolPolicy) }, ::ContinuityConfiguration)
    }
    fun finishOpen() = reference.call { owner -> owner.call { ContinuityNative.simple(it, "finish_open") } }
    fun cancel() = reference.call(cancellation = true) { owner -> owner.call { ContinuityNative.simple(it, "cancel") } }
    override fun close() = reference.close()
    private fun enrollment(intent: EnrollmentIntent, witness: ConfigurationWitness?, mode: Int): ContinuityEnrollment =
        reference.transfer { owner ->
            val successor = ContinuityEnrollment.configured(owner)
            owner.call { ContinuityNative.beginConfiguredEnrollment(it, intent, mode, witness) }
            successor
        }
    /** Missing witness input permits original inspection only, never required-witness activation. */
    fun createEnrollment(intent: EnrollmentIntent, witness: ConfigurationWitness? = null): ContinuityEnrollment =
        enrollment(intent, witness, 1)
    fun resumeEnrollment(intent: EnrollmentIntent, witness: ConfigurationWitness? = null): ContinuityEnrollment =
        enrollment(intent, witness, 2)
    /** Moves this target lease into the original enrollment, then closes the empty source slot.
     * Selection is not durable approval/adoption. An admitted failure may consume both owners;
     * close their handles and explicitly reopen their original inputs and intent.
     */
    fun selectContinuationTarget(enrollment: ContinuityEnrollment) = reference.transfer { owner ->
        enrollment.selectConfiguration(owner)
        owner.close()
    }
}
