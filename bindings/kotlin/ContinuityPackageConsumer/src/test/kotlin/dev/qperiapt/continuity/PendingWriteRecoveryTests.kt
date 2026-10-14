// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PendingWriteRecoveryTests {
    // Framing only, never a valid signed/native approval.
    private fun fixture(): Pair<ByteArray, ByteArray> {
        val proposal = "QPWRPL01".toByteArray(Charsets.US_ASCII) + ByteArray(385) { 7 }
        val metadata = ByteBuffer.allocate(569).put("QPWRMD01".toByteArray(Charsets.US_ASCII))
            .put(proposal, 8, 353).putLong(96).put(ByteArray(96)).putLong(96).put(ByteArray(96)).array()
        return proposal to metadata
    }
    @Test fun pendingRequestOwnsCompleteDataAndMatchesNativeLayout() {
        assertEquals(436L to 404L, PendingWriteRecoveryNative.layout())
        val (proposal, metadata) = fixture()
        val request = PendingWriteRecoveryRequest(proposal, ByteArray(32) { 2 }, metadata, byteArrayOf(1))
        proposal.fill(0); metadata.fill(0); request.metadata.encoded().fill(0)
        assertContentEquals(fixture().first, request.proposal.encoded())
        assertContentEquals(fixture().second, request.metadata.encoded())
    }
    @Test fun pendingRequestRejectsScopeTruncationExtensionAndOverflow() {
        val (proposal, metadata) = fixture()
        val invalid = mutableListOf(metadata.copyOf(568), metadata + byteArrayOf(0))
        invalid += metadata.clone().also { it[8] = 99 }
        invalid += metadata.clone().also { ByteBuffer.wrap(it).putLong(361, -1) }
        invalid += metadata.clone().also { ByteBuffer.wrap(it).putLong(465, Long.MAX_VALUE) }
        for (bytes in invalid) assertFailsWith<ContinuityBoundaryFailure> {
            PendingWriteRecoveryRequest(proposal, ByteArray(32), bytes, byteArrayOf(1))
        }
    }
    @Test fun pendingRequestRejectsMissingOwnerAndOversizedInputBeforeDispatch() {
        assertEquals(2, assertFailsWith<ContinuityFailure> { PendingWriteRecoveryNative.request(0) }.code)
        assertFailsWith<IllegalArgumentException> { PendingWriteRecoveryNative.confirm(0, ByteArray(392), ByteArray(1)) }
    }
}
