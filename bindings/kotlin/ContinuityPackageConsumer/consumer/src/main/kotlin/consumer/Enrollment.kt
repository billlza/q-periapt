// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.nio.ByteBuffer
import java.nio.file.Path

internal fun FixtureRecords.enrollmentExact(name: String, count: Int): ByteArray = read(name).also {
    check(it.size == count) { "enrollment public input width: $name" }
}
private fun counter(bytes: ByteArray): Counter64 {
    check(bytes.size == 8)
    return Counter64.parse(java.lang.Long.toUnsignedString(ByteBuffer.wrap(bytes).long))
}
private fun intent(records: FixtureRecords): EnrollmentIntent {
    val bytes = records.enrollmentExact("enrollment-intent", 72)
    return EnrollmentIntent(records.enrollmentExact("enrollment-root", 1985), bytes.copyOfRange(0, 16),
        counter(bytes.copyOfRange(16, 24)), bytes.copyOfRange(24, 56),
        counter(bytes.copyOfRange(56, 64)), counter(bytes.copyOfRange(64, 72)))
}
internal fun enrollmentPin(records: FixtureRecords, renewal: Boolean): AccountPin {
    val original = intent(records)
    return AccountPin(AccountID(records.enrollmentExact("trusted-account", 32)), original.root.encoded(), original.family.encoded(),
        RosterCheckpoint(counter(records.enrollmentExact(if (renewal) "renewal-version" else "trusted-roster-version", 8)),
            records.enrollmentExact(if (renewal) "renewal-digest" else "trusted-roster-digest", 32)))
}
private fun status(value: EnrollmentStatus): String =
    "enrollment-phase:${value.phase.ordinal + 1}\n${hex(value.signing)}\n${value.journal?.let(::hex) ?: "0".repeat(64)}"
private fun refusal(code: Int, operation: () -> Unit): ContinuityFailure {
    try { operation() } catch (failure: ContinuityFailure) {
        check(failure.code == code) { "enrollment refused with another native error: $failure" }
        return failure
    }
    error("enrollment operation unexpectedly succeeded")
}
internal fun enrollmentShapeRefusal(operation: () -> Unit) {
    try { operation() } catch (_: IllegalArgumentException) { return }
    error("invalid enrollment shape was accepted")
}
internal enum class EnrollmentPolicy { ORIGINAL, JOINT, INDEPENDENT }
private fun ContinuityEnrollment.activate(policy: EnrollmentPolicy): ContinuityDevice = when (policy) {
    EnrollmentPolicy.ORIGINAL -> activate(); EnrollmentPolicy.JOINT -> activatePolicyContinuation(); EnrollmentPolicy.INDEPENDENT -> activatePolicyRenewal()
}
private data class TransferredEnrollment(val device: ContinuityDevice, val old: WeakReference<ContinuityEnrollment>)
private fun transfer(path: String, witness: WitnessCarrier, queue: ReferenceQueue<ContinuityEnrollment>,
                     policy: EnrollmentPolicy): TransferredEnrollment =
    ContinuityEnrollment.resume(path, intent(FixtureRecords(Path.of(path))), witness).use { owner ->
        val old = WeakReference(owner, queue)
        val device = if (policy != EnrollmentPolicy.ORIGINAL) {
            val target = Path.of(path).resolve(if (policy == EnrollmentPolicy.JOINT) "continued-sdk" else "independent-sdk")
            owner.selectContinuedPolicy(target.toString(), policyDocument(target))
            owner.activate(policy)
        } else owner.activate()
        try {
            owner.close()
            refused(setOf(2)) { owner.status() }
            refused(setOf(2)) { owner.activate(policy) }
            refused(setOf(2)) { owner.cancel() }
            TransferredEnrollment(device, old)
        } catch (failure: Throwable) {
            try { device.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
            throw failure
        }
    }

/** Drop the old public registration wrapper, then prove its one native owner
 * remains usable through the successor. This is a bounded GC observation only.
 */
internal fun enrollmentParent(path: String, witness: WitnessCarrier, policy: EnrollmentPolicy = EnrollmentPolicy.ORIGINAL): ContinuityDevice {
    val queue = ReferenceQueue<ContinuityEnrollment>()
    val transferred = transfer(path, witness, queue, policy)
    try {
        val before = collectionCount()
        var queued = false
        for (round in 0 until 32) {
            pressure()
            val observed = queue.poll()
            if (observed != null) {
                check(observed === transferred.old && queue.poll() == null) { "unexpected enrollment collection" }
                queued = true
                break
            }
            Thread.sleep(10)
        }
        check(queued && transferred.old.get() == null && collectionCount() > before) { "old enrollment not collected within 32 rounds" }
        transferred.device.nextAccountOperation()
        val marker = when (policy) { EnrollmentPolicy.ORIGINAL -> "kotlin-enrollment-transfer"; EnrollmentPolicy.JOINT -> "kotlin-policy-enrollment-transfer"; EnrollmentPolicy.INDEPENDENT -> "kotlin-independent-policy-transfer" }
        FixtureRecords(Path.of(path)).retain(marker,
            "old-registration-collected original-device-live\n".toByteArray(), true)
        return transferred.device
    } catch (failure: Throwable) {
        try { transferred.device.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        throw failure
    }
}

internal fun enrollment(args: List<String>, witness: WitnessCarrier): String {
    require(args.size in 2..4) { "enrollment fixture arguments" }
    val mode = args[0]; val path = args[1]; val records = FixtureRecords(Path.of(path))
    when (mode) {
        "enrollment-key" -> { ContinuityEnrollment.provisionWrappingKey(path); return "enrollment-key" }
        "enrollment-key-conflict" -> {
            refused(setOf(211)) { ContinuityEnrollment.provisionWrappingKey(path) }
            return "enrollment-key-refused:211"
        }
        "enrollment-refuse-resume", "enrollment-refuse-create" -> {
            val creating = mode == "enrollment-refuse-create"
            val wanted = if (creating) 211 else 204
            val pending = if (creating) ContinuityEnrollment.prepareCreate(path, intent(records), witness)
                else ContinuityEnrollment.prepareResume(path, intent(records), witness)
            pending.use { owner -> refused(setOf(wanted)) { owner.finishOpen() }; refused(setOf(2)) { owner.status() } }
            return "enrollment-open-refused:$wanted"
        }
        "enrollment-activate", "enrollment-hold" -> {
            var retained: ContinuityOwner? = null
            val batch = try {
                enrollmentParent(path, witness).use { device ->
                    val batch = device.nextAccountOperation()
                    if (mode == "enrollment-hold") {
                        require(args.size in 3..4)
                        if (args.size == 4) {
                            device.openPeer(args[3], PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR).use {
                                retained = device.openPeer(args[3], PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR)
                            }
                        }
                        check(records.retain("enrollment-held", byteArrayOf(49), true))
                        waitMarker(args[2])
                    }
                    batch
                }.also {
                    retained?.let { peer -> refused(setOf(2)) { peer.nextMessage(SessionID(ByteArray(32) { 1 })) } }
                }
            } catch (failure: Throwable) {
                try { retained?.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
                throw failure
            }
            retained?.close()
            return "enrollment-active\n${hex(batch)}"
        }
    }
    val owner = if (mode == "enrollment-create") ContinuityEnrollment.create(path, intent(records), witness)
        else ContinuityEnrollment.resume(path, intent(records), witness)
    return owner.use {
        val original = it.status()
        if (mode.startsWith("enrollment-witnessed-roster-")) {
            require(args.size == 2)
            return@use witnessedRosterEnrollment(it, path, records, mode.removePrefix("enrollment-witnessed-roster-"))
        }
        if (mode.startsWith("enrollment-independent-policy-")) {
            require(args.size == 2)
            return@use independentPolicyEnrollment(it, path, records, mode.removePrefix("enrollment-independent-policy-"))
        }
        if (mode.startsWith("enrollment-policy-")) {
            require(args.size == 2) { "policy continuation arguments" }
            return@use policyEnrollment(it, path, records, mode, original)
        }
        if (mode.startsWith("enrollment-credential-")) {
            require(args.size == 2) { "credential renewal arguments" }
            return@use credentialEnrollment(it, records, mode, original)
        }
        when (mode) {
            "enrollment-create" -> check(original.phase == EnrollmentPhase.PREPARING)
            "enrollment-request" -> {
                val request = it.request()
                check(request.encoded().size == 5506 && request == it.request())
                check(records.retain("enrollment-request", request.encoded(), true))
            }
            "enrollment-request-retry" -> {
                val request = it.request().encoded()
                check(request.contentEquals(records.read("enrollment-request")))
                check(records.retain("enrollment-reopened-request", request, true))
            }
            "enrollment-accept", "enrollment-reject-signature" -> {
                val certificate = records.read("grant-certificate"); val roster = records.read("grant-roster")
                val trusted = enrollmentPin(records, false)
                enrollmentShapeRefusal { it.accept(ByteArray(0), roster, trusted) }
                enrollmentShapeRefusal { it.accept(certificate, ByteArray(0), trusted) }
                check(it.status() == original)
                if (mode == "enrollment-reject-signature") {
                    certificate[certificate.lastIndex] = (certificate.last().toInt() xor 1).toByte()
                    refused(setOf(102)) { it.accept(certificate, roster, trusted) }
                    refused(setOf(2)) { it.status() }
                    return@use "enrollment-signature-refused"
                }
                it.accept(certificate, roster, trusted)
            }
            "enrollment-storage" -> {
                val first = it.prepareStorage(); check(first == it.prepareStorage())
                val journal: JournalID; val subject: ByteArray; val digest: ByteArray
                when (first) {
                    is InstallationPreparation.Local -> { journal = first.journal; subject = ByteArray(96); digest = ByteArray(32) }
                    is InstallationPreparation.RequiresEnrollment -> {
                        journal = first.genesis.journal; subject = first.genesis.subject.encoded(); digest = first.genesis.imageDigest.encoded()
                    }
                }
                check(journal == original.journal)
                check(records.retain("enrollment-genesis-subject", subject, true))
                check(records.retain("enrollment-genesis-digest", digest, true))
            }
            "enrollment-refresh" -> {
                val previous = enrollmentPin(records, false).checkpoint; val next = enrollmentPin(records, true)
                enrollmentShapeRefusal { it.refreshRoster(previous, ByteArray(0), next) }
                check(it.status() == original)
                val updated = it.refreshRoster(previous, records.read("renewal-roster"), next)
                check(updated.phase == EnrollmentPhase.REFRESHING && updated.refresh == RosterTransition(previous, next.checkpoint))
            }
            "enrollment-activate-error" -> {
                require(args.size == 3 && args[2] in setOf("216", "218", "702", "104"))
                val wanted = args[2].toInt()
                val failure = refusal(wanted) { it.activate().use { error("refused registration released a device") } }
                val name = when (wanted) {
                    218 -> "enrollment-authority-refusal"
                    216 -> "enrollment-required-refusal"
                    104 -> "enrollment-policy-refusal"
                    else -> "enrollment-activation-refusal"
                }
                check(records.retain(name,
                    failure.diagnostic.toByteArray(), true))
                refused(setOf(2)) { it.status() }
                refused(setOf(2)) { it.activate() }
                return@use "enrollment-activation-refused:$wanted"
            }
            "enrollment-cancel-activate" -> {
                require(args.size == 3 && witness != WitnessCarrier.Local)
                val elapsed = cancelledInvocation(218, {
                    waitMarker(args[2])
                    refused(setOf(3)) { it.status() }
                    refused(setOf(3)) { it.activate() }
                    refused(setOf(3)) { it.close() }
                }, it::cancel) { it.activate().use { error("cancelled registration activated") } }
                cancellationMilliseconds(elapsed)
                refused(setOf(2)) { it.status() }
                return@use "enrollment-activation-cancelled"
            }
            "enrollment-cancel" -> {
                it.cancel(); refused(setOf(302)) { it.request() }
                return@use "enrollment-cancelled"
            }
            "enrollment-status" -> Unit
            else -> error("unknown enrollment fixture command")
        }
        status(it.status())
    }
}
