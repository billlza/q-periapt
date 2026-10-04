// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.charset.CharacterCodingException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class OwnerTests {
    private fun fails(code: Int, action: () -> Unit) {
        assertEquals(code, assertFailsWith<ContinuityFailure>(block = action).code)
    }
    @Test fun identifiersAreTypedImmutablePublicValues() {
        val bytes = ByteArray(32) { it.toByte() }
        val session = SessionID(bytes)
        bytes.fill(7)
        val read = session.encoded()
        assertEquals(0, read[0].toInt())
        read.fill(9)
        assertEquals(SessionID(ByteArray(32) { it.toByte() }), session)
        assertNotEquals<ContinuityID>(MessageID(session.encoded()), session)
        assertFailsWith<IllegalArgumentException> { SessionID(ByteArray(31)) }
        assertEquals(32, InitiationID.random().encoded().size)
    }
    @Test fun unsignedCountersRetainTheirWholeRange() {
        val maximum = Counter64.parse("18446744073709551615")
        assertEquals("18446744073709551615", maximum.toString())
        assertTrue(maximum > Counter64.of(Long.MAX_VALUE))
        assertEquals(maximum, Counter64.fromBits(-1))
        for (value in listOf("-1", "+1", "01", "", "18446744073709551616")) {
            assertFailsWith<IllegalArgumentException> { Counter64.parse(value) }
        }
        assertFailsWith<IllegalArgumentException> { Counter64.of(-1) }
    }
    @Test fun structuresMatchThe64BitNativeContract() {
        assertEquals(mapOf(
            "error" to (524L to 4L), "witness" to (24L to 8L), "options" to (24L to 8L),
            "setup_status" to (36L to 4L), "setup_preparation" to (164L to 4L),
            "enrollment_intent" to (88L to 8L), "checkpoint" to (40L to 8L), "enrollment_pin" to (120L to 8L),
            "enrollment_status" to (152L to 8L), "enrollment_request" to (8196L to 4L),
            "credential_renewal_status" to (120L to 8L),
            "credential_renewal_proposal" to (296L to 1L),
            "served" to (72L to 4L), "header" to (200L to 8L), "epoch" to (104L to 8L),
            "reserved" to (48L to 8L), "unconfirmed" to (64L to 1L),
            "delivery" to (48L to 8L), "status" to (36L to 4L),
            "account_target" to (40L to 8L), "account_delivery" to (88L to 4L),
            "account_cleanup_header" to (72L to 4L), "account_cleanup_member" to (136L to 8L),
        ), ContinuityNative.layouts())
    }
    private fun enrollmentRoot(): ByteArray {
        val point = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        return ByteArray(1952) { 1 } + point.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    private fun enrollmentIntent(): EnrollmentIntent = EnrollmentIntent(enrollmentRoot(), ByteArray(16) { 2 },
        Counter64.of(1), ByteArray(32) { 3 }, Counter64.ZERO, Counter64.parse("18446744073709551614"))
    @Test fun enrollmentCopiesApprovedInputsAndRejectsInvalidScope() {
        val root = enrollmentRoot(); val device = ByteArray(16) { 2 }; val family = ByteArray(32) { 3 }
        val original = root.clone()
        val intent = EnrollmentIntent(root, device, Counter64.parse("9223372036854775808"), family,
            Counter64.ZERO, Counter64.parse("18446744073709551614"))
        root.fill(0); device.fill(0); family.fill(0)
        intent.root.encoded().fill(0)
        assertContentEquals(original, intent.root.encoded())
        assertContentEquals(ByteArray(16) { 2 }, intent.device.encoded())
        assertContentEquals(ByteArray(32) { 3 }, intent.family.encoded())
        for (version in listOf(Counter64.ZERO, Counter64.parse("18446744073709551615"))) {
            assertFailsWith<IllegalArgumentException> { RosterCheckpoint(version, ByteArray(32) { 1 }) }
        }
        assertFailsWith<IllegalArgumentException> { RosterCheckpoint(Counter64.of(1), ByteArray(32)) }
        assertFailsWith<IllegalArgumentException> {
            EnrollmentIntent(original, ByteArray(16), Counter64.of(1), intent.family.encoded(), Counter64.ZERO, Counter64.of(1))
        }
        assertFailsWith<IllegalArgumentException> {
            EnrollmentIntent(original, intent.device.encoded(), Counter64.of(1), intent.family.encoded(), Counter64.of(1), Counter64.of(1))
        }
    }
    @Test fun enrollmentPhaseAndRequestDecodingRefuseContradictoryNativeOutput() {
        val signing = ByteArray(32) { 4 }; val journal = ByteArray(32) { 5 }; val empty = ByteArray(40)
        fun checkpoint(version: Long) = ByteBuffer.allocate(40).order(ByteOrder.nativeOrder())
            .putLong(version).put(ByteArray(32) { 6 }).array()
        for (phase in 1..5) {
            val selectedJournal = if (phase < 3) ByteArray(32) else journal
            val status = ContinuityNative.decodeEnrollmentStatus(phase, signing, selectedJournal, empty, empty)
            assertEquals(EnrollmentPhase.entries[phase - 1], status.phase)
            assertEquals(phase >= 3, status.journal != null)
            assertEquals(null, status.refresh)
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeEnrollmentStatus(phase, signing, if (phase < 3) journal else ByteArray(32), empty, empty)
            }
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeEnrollmentStatus(phase, signing, selectedJournal, checkpoint(1), empty)
            }
        }
        val status = ContinuityNative.decodeEnrollmentStatus(6, signing, journal, checkpoint(Long.MAX_VALUE), checkpoint(Long.MIN_VALUE))
        assertEquals(Counter64.parse("9223372036854775808"), status.refresh?.next?.version)
        for ((previous, next) in listOf(empty to empty, checkpoint(2) to checkpoint(1), checkpoint(1) to checkpoint(1))) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeEnrollmentStatus(6, signing, journal, previous, next) }
        }
        for (phase in listOf(0, 7, -1)) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeEnrollmentStatus(phase, signing, journal, empty, empty) }
        }
        assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeEnrollmentStatus(1, ByteArray(32), ByteArray(32), empty, empty) }
        val request = ByteArray(8192).also { it[0] = 1 }
        assertContentEquals(byteArrayOf(1), ContinuityNative.decodeEnrollmentRequest(1, request).encoded())
        for (length in listOf(0, -1, 8193)) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeEnrollmentRequest(length, request) }
        }
        request[1] = 2
        assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeEnrollmentRequest(1, request) }
    }
    @Test fun pendingEnrollmentSharesCapacityAndCancellationConsumesOnlyAdmission() {
        val owners = mutableListOf<ContinuityEnrollment>()
        try {
            repeat(64) { owners.add(ContinuityEnrollment.prepareCreate("/unused", enrollmentIntent())) }
            fails(4) { ContinuitySetup.prepareCreate("/unused") }
            while (owners.isNotEmpty()) {
                val owner = owners.removeAt(0)
                owner.use {
                    fails(6) { it.status() }
                    fails(6) { it.activate() }
                    it.cancel()
                    fails(302) { it.finishOpen() }
                    fails(2) { it.activate() }
                }
                fails(2) { owner.status() }
            }
            ContinuityDevice.prepare("/unused").use { it.cancel() }
        } finally {
            var failure: Throwable? = null
            for (owner in owners) try { owner.close() } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
            failure?.let { throw it }
        }
    }
    @Test fun originalEnrollmentRequestPersistsWithoutPolicyOrTlsConfiguration() {
        val directory = Files.createTempDirectory("qperiapt-enrollment-unit-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toRealPath()
        val path = directory.toString(); val intent = enrollmentIntent()
        try {
            ContinuityEnrollment.provisionWrappingKey(path)
            lateinit var signing: SigningKeyID
            lateinit var request: PublicBytes
            ContinuityEnrollment.create(path, intent).use { owner ->
                assertEquals(EnrollmentPhase.PREPARING, owner.status().phase)
                assertEquals(CredentialRenewalStatus.Absent, owner.credentialRenewalStatus())
                request = owner.request()
                val state = owner.status(); signing = state.signing
                assertEquals(EnrollmentPhase.REQUESTED, state.phase)
                assertEquals(null, state.journal)
                assertEquals(5506, request.encoded().size)
                assertEquals(request, owner.request())
                val pin = AccountPin(AccountID(ByteArray(32) { 1 }), intent.root.encoded(), intent.family.encoded(),
                    RosterCheckpoint(Counter64.of(1), ByteArray(32) { 2 }))
                assertFailsWith<IllegalArgumentException> { owner.accept(ByteArray(0), byteArrayOf(1), pin) }
                assertEquals(state, owner.status())
            }
            ContinuityEnrollment.resume(path, intent).use { owner ->
                assertEquals(signing, owner.status().signing)
                assertEquals(request, owner.request())
                assertEquals(CredentialRenewalStatus.Absent, owner.credentialRenewalStatus())
            }
            fails(211) { ContinuityEnrollment.provisionWrappingKey(path) }
            fails(211) { ContinuityEnrollment.create(path, intent) }
            assertTrue(!Files.exists(directory.resolve("installation.redb")))
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) } }
        }
    }
    @Test fun pendingOwnersRejectWorkAndCancellationNeverActivates() {
        val owners = listOf(
            ContinuityOwner.prepare("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH),
            ContinuityOwner.prepareReopen("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH, SessionID(ByteArray(32) { 73 })),
        )
        for (owner in owners) {
            try {
                fails(101) { owner.messageStatus(SessionID(ByteArray(32)), MessageID(ByteArray(32))) }
                fails(6) { owner.listen("127.0.0.1:0") }
                owner.cancel()
                fails(302) { owner.finishOpen() }
                fails(2) { owner.finishOpen() }
            } finally { owner.close() }
            fails(2) { owner.cancel() }
            fails(2) { owner.close() }
        }
        fails(1) {
            ContinuityOwner.prepareReopen("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH, SessionID(ByteArray(32)))
        }
    }
    @Test fun pendingSetupSharesCapacityAndCannotActivateAfterCancellation() {
        repeat(128) { ContinuitySetup.prepareCreate("/unused").use { it.cancel() } }
        val owners = mutableListOf<ContinuitySetup>()
        try {
            repeat(64) { owners.add(if (it % 2 == 0) ContinuitySetup.prepareCreate("/unused") else ContinuitySetup.prepareResume("/unused")) }
            fails(4) { ContinuityDevice.prepare("/unused") }
            while (owners.isNotEmpty()) {
                val owner = owners.removeAt(0)
                owner.use {
                    fails(6) { it.status() }
                    fails(6) { it.prepareStorage() }
                    fails(6) { it.activate() }
                    it.cancel()
                    fails(302) { it.finishOpen() }
                    fails(2) { it.activate() }
                }
                fails(2) { owner.status() }
                fails(2) { owner.close() }
            }
            ContinuityDevice.prepare("/unused").use { it.cancel() }
        } finally {
            var failure: Throwable? = null
            for (owner in owners) try { owner.close() } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
            failure?.let { throw it }
        }
    }
    @Test fun installationStatusRejectsUnknownPhaseAndZeroJournal() {
        val journal = ByteArray(32) { 1 }
        for ((code, phase) in listOf(1 to InstallationPhase.CREATING, 2 to InstallationPhase.ACTIVE)) {
            assertEquals(InstallationStatus(phase, JournalID(journal)), ContinuityNative.decodeSetupStatus(code, journal))
        }
        for (phase in listOf(0, 3, 256, -1)) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeSetupStatus(phase, journal) }
        }
        for (invalid in listOf(ByteArray(32), ByteArray(31) { 1 })) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeSetupStatus(1, invalid) }
        }
    }
    @Test fun originalGenesisRejectsMisbindingAndUnexpectedWitnessMetadata() {
        val journal = ByteArray(32) { 7 }
        val subject = journal + ByteArray(32) { 8 } + ByteArray(32) { 9 }
        val digest = ByteArray(32) { 10 }
        assertEquals(InstallationPreparation.Local(JournalID(journal)),
            ContinuityNative.decodeSetupPreparation(1, journal, ByteArray(96), ByteArray(32)))
        val expected = InstallationPreparation.RequiresEnrollment(WitnessGenesis(JournalID(journal), PublicBytes(subject), PublicBytes(digest)))
        val decoded = ContinuityNative.decodeSetupPreparation(2, journal, subject, digest)
        assertEquals(expected, decoded)
        for (offset in listOf(0, 32, 64)) {
            val malformed = subject.clone().also { it.fill(0, offset, offset + 32) }
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeSetupPreparation(2, journal, malformed, digest) }
        }
        for (protection in listOf(0, 1, 3, 258, -1)) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeSetupPreparation(protection, journal, subject, digest) }
        }
        for ((j, s, d) in listOf(Triple(ByteArray(32), subject, digest), Triple(journal, ByteArray(95), digest),
                                Triple(journal, subject, ByteArray(31)), Triple(journal, subject, ByteArray(32)))) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeSetupPreparation(2, j, s, d) }
        }
        journal.fill(0); subject.fill(0); digest.fill(0)
        assertEquals(expected, decoded)
    }
    @Test fun failedOpenReleasesTheOriginalOwnerSlot() {
        repeat(128) {
            fails(203) { ContinuityOwner.open("relative", PrekeyQuality.ONE_TIME_BOTH) }
        }
        val owner = ContinuityOwner.prepare("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH)
        try {
            fails(500) { owner.finishOpen() }
            fails(2) { owner.finishOpen() }
        } finally { owner.close() }
    }
    @Test fun bothKindsShareCapacityAndDrainRemainsAvailable() {
        val owners = mutableListOf<AutoCloseable>()
        try {
            repeat(64) { index ->
                owners.add(if (index % 2 == 0) ContinuityOwner.prepare("/absent-continuity-jvm-probe", PrekeyQuality.ONE_TIME_BOTH)
                    else ContinuityRecoveryOwner.prepare("/absent-continuity-jvm-probe"))
            }
            fails(4) { ContinuityRecoveryOwner.prepare("/absent-continuity-jvm-probe") }
            val first = owners.removeAt(0)
            first.close()
            ContinuityRecoveryOwner.prepare("/absent-continuity-jvm-probe").use { it.cancel() }
        } finally {
            var failure: Throwable? = null
            for (owner in owners) try { owner.close() } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
            failure?.let { throw it }
        }
    }
    @Test fun recoveryCancellationAndClosedStateKeepTheirNativeKinds() {
        val owner = ContinuityRecoveryOwner.prepare("/absent-continuity-jvm-probe")
        try {
            fails(6) { owner.sessionCount() }
            owner.cancel()
            fails(302) { owner.finishOpen() }
        } finally { owner.close() }
        fails(2) { owner.sessionCount() }
    }
    @Test fun textAndApplicationRefusalsCannotSilentlyCoerceInvalidInput() {
        assertFailsWith<IllegalArgumentException> { WitnessCarrier.SignedTCP("127.0.0.1:1", 0) }
        assertFailsWith<IllegalArgumentException> { ApplicationCommitRefusal(0, "not committed") }
        assertFailsWith<CharacterCodingException> {
            ContinuityOwner.prepare("/bad\uD800", PrekeyQuality.ONE_TIME_BOTH)
        }
        assertFailsWith<IllegalArgumentException> {
            ContinuityOwner.prepare("/bad\u0000", PrekeyQuality.ONE_TIME_BOTH)
        }
        val original = byteArrayOf(1, 2, 3)
        val delivery = ApplicationDelivery(SessionID(ByteArray(32)), MessageID(ByteArray(32)), original)
        original.fill(0)
        assertContentEquals(byteArrayOf(1, 2, 3), delivery.plaintext())
    }
    @Test fun devicePreparationCannotGrantPeerAuthorityAndSharesCapacity() {
        repeat(128) { ContinuityDevice.prepare("/unused").use { it.cancel() } }
        val devices = mutableListOf<ContinuityDevice>()
        try {
            repeat(64) { devices.add(ContinuityDevice.prepare("/unused")) }
            fails(4) { ContinuityRecoveryOwner.prepare("/unused") }
            val first = devices.removeAt(0)
            first.use {
                fails(6) { it.preparePeer("/unused", PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.INITIATOR) }
                fails(6) { it.nextAccountOperation() }
                it.cancel()
                fails(302) { it.finishOpen() }
            }
            fails(2) { first.preparePeer("/unused", PrekeyQuality.ONE_TIME_BOTH, BootstrapRole.RESPONDER) }
            ContinuityDevice.prepare("/unused").use { it.cancel() }
        } finally {
            var failure: Throwable? = null
            for (device in devices) try { device.close() } catch (error: Throwable) {
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
            failure?.let { throw it }
        }
    }
    @Test fun aggregateStatusPreservesReportsAndRejectsMalformedOutput() {
        val zero = ByteArray(32)
        val report = ByteArray(32) { 9 }
        val id = AccountAbandonmentID(report)
        val states = listOf(AccountStatus.Absent, AccountStatus.Reserved, AccountStatus.Committed,
            AccountStatus.Abandoning(id), AccountStatus.Abandoned(id), AccountStatus.Retired)
        for ((state, value) in states.withIndex()) {
            assertEquals(value, ContinuityNative.decodeAccountStatus(state, if (state in 3..4) report else zero))
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeAccountStatus(state, if (state in 3..4) zero else report)
            }
        }
        for (state in listOf(-1, 6, 255, 256, 259)) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeAccountStatus(state, zero) }
        }
        assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeAccountStatus(0, byteArrayOf(0)) }
        assertNotEquals<ContinuityID>(AccountOperationID(report), AccountID(report))
    }
    @Test fun accountCleanupCannotAcquireAuthorityFromPendingCancelledOrClosedOwner() {
        val owner = ContinuityRecoveryOwner.prepare("/unused")
        val operation = AccountOperationID(ByteArray(32) { 1 })
        val report = AccountAbandonmentID(ByteArray(32) { 2 })
        val actions: List<() -> Unit> = listOf(
            { owner.selectAccount(operation) }, { owner.beginAccountCleanup() }, { owner.accountCleanupStatus() },
            { owner.accountMemberAt(0) }, { owner.accountReservation(0) }, { owner.accountEpochAt(0, 0) },
            { owner.accountUnconfirmedAt(0, 0, 0) }, { owner.accountDeliveryAt(0, 0, 0) },
            { owner.accountSkippedPosition(0, 0, 0) }, { owner.acknowledgeAccount(report) }, { owner.retireAccount() },
        )
        try {
            for (action in actions) fails(6, action)
            for (index in listOf(-1L, 0x1_0000_0000L)) {
                assertFailsWith<IllegalArgumentException> { owner.accountMemberAt(index) }
                assertFailsWith<IllegalArgumentException> { owner.accountReservation(index) }
                assertFailsWith<IllegalArgumentException> { owner.accountEpochAt(0, index) }
                assertFailsWith<IllegalArgumentException> { owner.accountUnconfirmedAt(0, 0, index) }
                assertFailsWith<IllegalArgumentException> { owner.accountDeliveryAt(0, index, 0) }
                assertFailsWith<IllegalArgumentException> { owner.accountSkippedPosition(index, 0, 0) }
            }
            owner.cancel()
            fails(302) { owner.finishOpen() }
            for (action in actions) fails(2, action)
        } finally { owner.close() }
        for (action in actions) fails(2, action)
    }
    @Test fun accountDeliveryRequiresSelectedSessionAndTypedRetainedOutcomes() {
        val session = SessionID(ByteArray(32) { 7 })
        val device = ByteArray(16) { 1 }
        val message = ByteArray(32) { 2 }
        val outcomes = listOf(AccountDeliveryOutcome.Consumed(Consumption.CONFIRMED),
            AccountDeliveryOutcome.Consumed(Consumption.PREFIX_PENDING), AccountDeliveryOutcome.ResolutionPending,
            AccountDeliveryOutcome.DeliveryUnknown, AccountDeliveryOutcome.HistoryRetired, AccountDeliveryOutcome.ReservationAbandoned)
        for ((index, outcome) in outcomes.withIndex()) {
            val result = ContinuityNative.decodeAccountDelivery(device, session.encoded(), message, index + 1,
                if (index == 1) 1 else 0, session)
            assertEquals(outcome, result.outcome)
            assertEquals(session, result.session)
            assertEquals(MessageID(message), result.message)
        }
        for ((outcome, exchanges) in listOf(2 to 0, 1 to 9, 1 to -1, 7 to 1)) {
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeAccountDelivery(device, session.encoded(), message, outcome, exchanges, session)
            }
        }
        for ((observedDevice, observedSession, observedMessage) in listOf(
            Triple(ByteArray(16), session.encoded(), message), Triple(device, ByteArray(32) { 8 }, message),
            Triple(device, session.encoded(), ByteArray(32)), Triple(device, session.encoded(), ByteArray(31)))) {
            assertFailsWith<ContinuityBoundaryFailure> {
                ContinuityNative.decodeAccountDelivery(observedDevice, observedSession, observedMessage, 1, 1, session)
            }
        }
    }
}
