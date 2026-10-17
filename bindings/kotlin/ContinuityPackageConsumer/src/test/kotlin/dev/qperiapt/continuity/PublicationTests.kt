// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PublicationTests {
    private fun plan(): PublicationPlan = PublicationPlan(ByteArray(32) { 99 }, Counter64.of(100), Counter64.of(200),
        listOf(PublicationKey(PublicationKeyKind.SIGNED_CLASSICAL, Counter64.of(100), Counter64.of(200)),
               PublicationKey(PublicationKeyKind.LAST_RESORT_PQ, Counter64.of(100), Counter64.of(200))))
    @Test fun publicationLayoutsAndCompletePlanRetainUnsignedInputs() {
        val layouts = ContinuityNative.layouts()
        assertEquals(56L to 8L, layouts.getValue("publication_key"))
        assertEquals(72L to 8L, layouts.getValue("publication_plan"))
        assertEquals(104L to 4L, layouts.getValue("publication_status"))
        val input = ByteArray(32) { 99 }; val keys = plan().keys.toMutableList()
        val plan = PublicationPlan(input, Counter64.of(100), Counter64.of(200), keys)
        input[0] = 0; keys.clear()
        assertEquals(99.toByte(), plan.directory.encoded()[0]); assertEquals(2, plan.keys.size)
        assertTrue(ContinuityNative.publicationSizeBound(plan) in 3668L..10000L)
        val from = Counter64.parse("9223372036854775808"); val until = Counter64.parse("18446744073709551614")
        val high = PublicationPlan(ByteArray(32) { 1 }, from, until,
            listOf(PublicationKey(PublicationKeyKind.SIGNED_CLASSICAL, from, until), PublicationKey(PublicationKeyKind.LAST_RESORT_PQ, from, until)))
        assertEquals(ContinuityNative.publicationSizeBound(plan), ContinuityNative.publicationSizeBound(high))
        assertFailsWith<IllegalArgumentException> { PublicationPlan(ByteArray(31), from, until, high.keys) }
        assertFailsWith<IllegalArgumentException> { PublicationPlan(ByteArray(32), from, until, high.keys) }
        assertFailsWith<IllegalArgumentException> { PublicationKey(PublicationKeyKind.ONE_TIME_PQ, until, from) }
        assertFailsWith<IllegalArgumentException> { PublicationPlan(ByteArray(32) { 1 }, Counter64.of(101), Counter64.of(200), plan.keys) }
        val reused = PrekeyInventoryID(ByteArray(32) { 2 })
        assertFailsWith<IllegalArgumentException> { PublicationPlan(ByteArray(32) { 1 }, from, until,
            listOf(PublicationKey(PublicationKeyKind.SIGNED_CLASSICAL, from, until, reused), PublicationKey(PublicationKeyKind.LAST_RESORT_PQ, from, until, reused))) }
    }
    @Test fun publicationStatesRefuseDirtyAbsenceAndUnknownCompletion() {
        val zero = ByteArray(32); val nonzero = ByteArray(32) { 1 }
        fun decode(s: Int, r: Int = 0, i: ByteArray = zero, m: ByteArray = zero, a: ByteArray = zero) =
            ContinuityNative.decodePublicationStatus(s, r, i, m, a)
        assertEquals(PublicationStatus.Absent, decode(0)); assertEquals(PublicationStatus.Retired, decode(3))
        assertEquals(PublicationStatus.Reserved(PublicBytes(nonzero)), decode(1, i = nonzero))
        assertEquals(PublicationStatus.Prepared(PublicBytes(nonzero), PublicBytes(nonzero), PublicBytes(nonzero)), decode(2, i = nonzero, m = nonzero, a = nonzero))
        for (state in listOf(-1, 4, Int.MAX_VALUE)) assertFailsWith<ContinuityBoundaryFailure> { decode(state) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(0, i = nonzero) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(3, a = nonzero) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(1, i = nonzero, m = nonzero) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(2, i = nonzero, a = nonzero) }
        assertFailsWith<ContinuityBoundaryFailure> { decode(0, r = 1) }
    }
    private fun fixture(): ByteArray {
        var bytes = "QPPUBA01".toByteArray(Charsets.US_ASCII) + ByteArray(32) { 1 } + ByteArray(32) { 2 } + ByteArray(32) { 3 }
        bytes += byteArrayOf(0, 0, 14, 83) + ByteArray(3667) { 4 } + byteArrayOf(0, 2)
        bytes += ByteArray(32) { 5 } + ByteArray(32) { 6 }
        for (index in 0..1) bytes += byteArrayOf(0, 62, 0, index.toByte()) + ByteArray(60) { 7 }
        return bytes
    }
    @Test fun completePublicationCopiesBytesAndRefusesTruncationSubstitutionAndTail() {
        val id = PrekeyPublicationID(ByteArray(32) { 1 }); val bytes = fixture(); val plan = plan()
        val result = PreparedPublication.decode(bytes, id, plan)
        assertContentEquals(bytes, result.canonicalBytes.encoded()); assertEquals(2, result.membershipProofs.size)
        assertContentEquals(ByteArray(32) { 5 }, result.inventoryRequests[0].encoded())
        bytes[0] = 0; assertEquals('Q'.code.toByte(), result.canonicalBytes.encoded()[0])
        val copied = result.manifest.encoded(); copied[0] = 0; assertEquals(4.toByte(), result.manifest.encoded()[0])
        for (wrong in listOf(bytes, fixture().dropLast(1).toByteArray(), fixture() + byteArrayOf(1), fixture().copyOf(8))) {
            assertFailsWith<ContinuityBoundaryFailure> { PreparedPublication.decode(wrong, id, plan) }
        }
        assertFailsWith<ContinuityBoundaryFailure> { PreparedPublication.decode(fixture(), PrekeyPublicationID(ByteArray(32) { 9 }), plan) }
        val reordered = fixture(); reordered[reordered.size - 61] = 0
        assertFailsWith<ContinuityBoundaryFailure> { PreparedPublication.decode(reordered, id, plan) }
    }
    @Test fun pendingDeviceCannotPublishAndClosurePreservesNoAuthority() {
        val device = ContinuityDevice.prepare("/not-an-enrolled-device")
        val id = PrekeyPublicationID(ByteArray(32) { 1 })
        assertFailsWith<ContinuityFailure> { device.nextPublication() }
        assertFailsWith<ContinuityFailure> { device.preparePublication(id, plan()) }
        device.cancel()
        assertFailsWith<ContinuityFailure> { device.publicationStatus(id) }
        device.close()
        assertFailsWith<ContinuityFailure> { device.nextPublication() }
    }
}
