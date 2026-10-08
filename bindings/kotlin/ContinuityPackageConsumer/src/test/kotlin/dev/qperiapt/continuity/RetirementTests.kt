// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class RetirementTests {
    @Test fun retirementLayoutsMatchTheNativeContract() {
        assertEquals(mapOf("authority_subject" to 64L, "authority_receipt" to 160L,
            "proposal_reserved" to 357L, "report_id" to 16L), ContinuityNative.retiredOffsets())
        val layouts = ContinuityNative.layouts()
        assertEquals(176L to 8L, layouts.getValue("retired_authority"))
        assertEquals(313L to 1L, layouts.getValue("retired_inventory"))
        assertEquals(360L to 4L, layouts.getValue("retired_proposal"))
        assertEquals(48L to 8L, layouts.getValue("retired_report_info"))
    }
    @Test fun retirementAuthorityOwnsInputsAndRejectsBadWidths() {
        val witness = ByteArray(32) { 1 }; val key = ByteArray(1985) { 2 }
        val replacement = ByteArray(57794) { 3 }; val subject = ByteArray(96) { 4 }; val receipt = ByteArray(3754) { 5 }
        val authority = RetiredEnrollmentAuthority(witness, key, replacement, subject, receipt)
        witness[0] = 0; key[0] = 0; replacement[0] = 0; subject[0] = 0; receipt[0] = 0
        assertEquals(1.toByte(), authority.witness.encoded()[0]); assertEquals(2.toByte(), authority.publicKey.encoded()[0])
        assertEquals(3.toByte(), authority.replacement.encoded()[0]); assertEquals(4.toByte(), authority.subject.encoded()[0])
        assertEquals(5.toByte(), authority.receipt.encoded()[0])
        val copy = authority.receipt.encoded(); copy[0] = 0
        assertEquals(5.toByte(), authority.receipt.encoded()[0])
        for (bad in listOf(ByteArray(0), ByteArray(57795))) {
            assertFailsWith<IllegalArgumentException> { RetiredEnrollmentAuthority(witness, key, bad, subject, receipt) }
        }
        assertFailsWith<IllegalArgumentException> { RetiredEnrollmentAuthority(ByteArray(31), key, replacement, subject, receipt) }
        assertFailsWith<IllegalArgumentException> { RetiredEnrollmentAuthority(witness, ByteArray(1984), replacement, subject, receipt) }
        assertFailsWith<IllegalArgumentException> { RetiredEnrollmentAuthority(witness, key, replacement, ByteArray(95), receipt) }
        assertFailsWith<IllegalArgumentException> { RetiredEnrollmentAuthority(witness, key, replacement, subject, ByteArray(3753)) }
    }
    @Test fun retirementProposalRejectsDirtyAbsenceAndPreservesIdentity() {
        assertNull(ContinuityNative.decodeRetiredProposal(0, ByteArray(353), ByteArray(3)))
        val bytes = "QPRRPT01QPRCLP01".toByteArray(Charsets.US_ASCII) + ByteArray(305) { 1 } + ByteArray(32) { 7 }
        val proposal = checkNotNull(ContinuityNative.decodeRetiredProposal(1, bytes, ByteArray(3)))
        bytes[0] = 0
        assertEquals('Q'.code.toByte(), proposal.bytes.encoded()[0])
        assertContentEquals(ByteArray(32) { 7 }, proposal.report.encoded())
        assertContentEquals(proposal.bytes.encoded().copyOfRange(8, 321), proposal.inventory.bytes.encoded())
        for ((present, value, padding) in listOf(Triple(2, proposal.bytes.encoded(), ByteArray(3)),
            Triple(0, proposal.bytes.encoded(), ByteArray(3)), Triple(1, proposal.bytes.encoded(), byteArrayOf(0, 0, 1)),
            Triple(1, bytes, ByteArray(3)), Triple(1, ByteArray(352), ByteArray(3)),
            Triple(1, proposal.bytes.encoded().copyOfRange(0, 321) + ByteArray(32), ByteArray(3)))) {
            assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeRetiredProposal(present, value, padding) }
        }
    }
    @Test fun retirementReportKeepsCompleteBytesAndRejectsUnknownStates() {
        val bytes = "QPRDMD01".toByteArray(Charsets.US_ASCII) + ByteArray(400) { 9 }; val id = ByteArray(32) { 7 }
        val report = RetiredDeviceReport.decode(bytes.size.toLong(), 2, 0, id, bytes)
        bytes[0] = 0; id[0] = 0
        assertEquals('Q'.code.toByte(), report.canonicalBytes.encoded()[0]); assertEquals(7.toByte(), report.report.encoded()[0])
        val original = report.canonicalBytes.encoded(); val originalID = report.report.encoded()
        val v2 = "QPRDMD02".toByteArray(Charsets.US_ASCII) + original.copyOfRange(8, original.size)
        assertContentEquals(v2, RetiredDeviceReport.decode(v2.size.toLong(), 2, 0, originalID, v2).canonicalBytes.encoded())
        val unknown = "QPRDMD03".toByteArray(Charsets.US_ASCII) + original.copyOfRange(8, original.size)
        assertFailsWith<ContinuityBoundaryFailure> { RetiredDeviceReport.decode(unknown.size.toLong(), 2, 0, originalID, unknown) }
        for (length in listOf(-1L, 0L, 322L, 8388609L, Long.MAX_VALUE)) {
            assertFailsWith<ContinuityBoundaryFailure> { RetiredDeviceReport.decode(length, 2, 0, originalID, original) }
        }
        for (views in listOf(-1, 0, 3, Int.MAX_VALUE)) {
            assertFailsWith<ContinuityBoundaryFailure> { RetiredDeviceReport.decode(original.size.toLong(), views, 0, originalID, original) }
        }
        assertFailsWith<ContinuityBoundaryFailure> { RetiredDeviceReport.decode(original.size.toLong(), 1, 1, originalID, original) }
        assertFailsWith<ContinuityBoundaryFailure> { RetiredDeviceReport.decode(original.size.toLong(), 1, 0, ByteArray(32), original) }
        assertFailsWith<ContinuityBoundaryFailure> { RetiredDeviceReport.decode(original.size.toLong(), 1, 0, originalID, bytes) }
        assertEquals(RetiredErasureState.RETAINED, ContinuityNative.decodeRetiredState(0))
        assertEquals(RetiredErasureState.ERASED, ContinuityNative.decodeRetiredState(1))
        for (value in listOf(-1, 2, Int.MAX_VALUE)) assertFailsWith<ContinuityBoundaryFailure> { ContinuityNative.decodeRetiredState(value) }
    }
}
