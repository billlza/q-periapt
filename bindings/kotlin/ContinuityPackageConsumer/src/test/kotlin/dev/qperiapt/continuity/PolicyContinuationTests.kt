// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

class PolicyContinuationTests {
    private fun number(bytes: ByteArray, at: Int, value: Long) {
        ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).putLong(at, value)
    }
    private fun metadata(proposal: Boolean, mode: Int?): ByteArray {
        val legacy = if (proposal) 296 else 248
        val bytes = ByteArray(legacy + if (mode == null) 0 else 33) { 1 }
        ((if (proposal) "QPCRNP" else "QPCRNC") + if (mode == null) "01" else "02")
            .toByteArray(Charsets.US_ASCII).copyInto(bytes)
        number(bytes, 200, -2L); number(bytes, 208, if (proposal) -3L else -2L)
        if (proposal) {
            number(bytes, 248, -2L); number(bytes, 256, -2L); bytes[264] = 2
        }
        if (mode != null) {
            bytes[legacy] = mode.toByte()
            bytes.fill(7, legacy + 1)
        }
        return bytes
    }
    private fun record(bytes: ByteArray, proposal: Boolean): ByteArray {
        val result = ByteArray(if (proposal) 336 else 288)
        ByteBuffer.wrap(result).order(ByteOrder.nativeOrder()).putInt(bytes.size)
        bytes.copyInto(result, 4)
        // Deliberately nonzero C alignment padding must be ignored.
        result.fill(0x55, if (proposal) 333 else 285)
        return result
    }
    private fun decode(bytes: ByteArray, proposal: Boolean): ByteArray =
        if (proposal) ContinuityNative.decodePolicyProposalRecord(bytes).encoded()
        else ContinuityNative.decodePolicyCancellationRecord(bytes).encoded()

    @Test fun independentPolicyDocumentOwnsInputsAndPreservesUnsignedCheckpoint() {
        val root = ByteArray(1985) { 1 }; val family = ByteArray(32) { 2 }
        val digest = ByteArray(32) { 3 }; val wire = ByteArray(8192) { 4 }
        val version = Counter64.parse("18446744073709551614")
        val point = PolicyCheckpoint(version, digest)
        val document = PolicyDocument(root, family, point, wire)
        root.fill(0); family.fill(0); digest.fill(0); wire.fill(0)
        document.root.encoded().fill(0); document.wire.encoded().fill(0)
        assertContentEquals(ByteArray(1985) { 1 }, document.root.encoded())
        assertContentEquals(ByteArray(32) { 2 }, document.family.encoded())
        assertContentEquals(ByteArray(32) { 3 }, document.checkpoint.digest.encoded())
        assertContentEquals(ByteArray(8192) { 4 }, document.wire.encoded())
        assertEquals(version, document.checkpoint.version)
        for (invalid in listOf(Counter64.ZERO, Counter64.parse("18446744073709551615"))) {
            assertFailsWith<IllegalArgumentException> { PolicyCheckpoint(invalid, ByteArray(32) { 1 }) }
        }
        for (invalid in listOf(ByteArray(31), ByteArray(32), ByteArray(33))) {
            assertFailsWith<IllegalArgumentException> { PolicyCheckpoint(Counter64.of(1), invalid) }
            assertFailsWith<IllegalArgumentException> { PolicyContinuationStatementID(invalid) }
        }
        for (length in listOf(0, 8193)) {
            assertFailsWith<IllegalArgumentException> { PolicyDocument(ByteArray(1985), ByteArray(32) { 1 }, point, ByteArray(length)) }
        }
        assertFailsWith<IllegalArgumentException> { PolicyDocument(ByteArray(1984), ByteArray(32) { 1 }, point, byteArrayOf(1)) }
        assertFailsWith<IllegalArgumentException> { PolicyDocument(ByteArray(1985), ByteArray(32), point, byteArrayOf(1)) }
        val t = PolicyContinuationStatementID(ByteArray(32) { 1 })
        assertNotEquals<ContinuityID>(CredentialRenewalStatementID(t.encoded()), t)
    }

    @Test fun policyLayoutsAndRecordPaddingMatchInstalledHeader() {
        assertEquals(mapOf("root" to 0L, "root_length" to 8L, "family" to 16L, "version" to 48L,
            "digest" to 56L, "wire" to 88L, "wire_length" to 96L), ContinuityNative.policyDocumentOffsets())
        for (proposal in listOf(false, true)) {
            for (mode in listOf(null, 0, 1)) {
                val original = metadata(proposal, mode)
                val raw = record(original, proposal)
                val decoded = decode(raw, proposal)
                raw.fill(0)
                assertContentEquals(original, decoded)
            }
        }
    }

    @Test fun adoptCarryAndLegacyKeepDifferentTransactionStatements() {
        for (mode in listOf(null, 0, 1)) {
            val proposal = ContinuityNative.decodePolicyProposalRecord(record(metadata(true, mode), true))
            val cancellation = ContinuityNative.decodePolicyCancellationRecord(record(metadata(false, mode), false))
            assertEquals(mode == 1, proposal.adoptsPolicy)
            assertEquals(mode == 1, cancellation.adoptsPolicy)
            assertContentEquals(ByteArray(32) { if (mode == 1) 7 else 1 }, proposal.statement.encoded())
            assertEquals(proposal.statement, cancellation.statement)
            assertEquals(proposal.operation, cancellation.operation)
            assertEquals(proposal.credentialStatement, cancellation.credentialStatement)
            if (mode == null) { assertNull(proposal.policyStatement); assertNull(cancellation.policyStatement) }
            else {
                assertEquals(PolicyContinuationStatementID(ByteArray(32) { 7 }), proposal.policyStatement)
                assertEquals(proposal.policyStatement, cancellation.policyStatement)
            }
            val before = proposal.encoded(); proposal.encoded().fill(0)
            assertContentEquals(before, proposal.encoded())
        }
    }

    @Test fun extendedGrammarRejectsWrongLengthsTagsModesZeroBindingsAndNonzeroUnusedTail() {
        for (proposal in listOf(false, true)) {
            val base = if (proposal) 296 else 248
            val original = record(metadata(proposal, 1), proposal)
            val mutations = mutableListOf(original.copyOf(original.size - 1), original + byteArrayOf(0))
            for (length in listOf(-1, 0, base - 1, base + 1, base + 32, base + 34)) {
                mutations += original.clone().also { ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putInt(length) }
            }
            // Valid shorter length with v2 tag or a nonzero declared unused tail.
            mutations += original.clone().also { ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putInt(base) }
            mutations += record(metadata(proposal, null), proposal).also { it[4 + base] = 1 }
            mutations += original.clone().also { it[4 + base] = 2 }
            for (offset in listOf(0, 8, 40, 72, 104, 136, 168, 216, base + 1)) {
                mutations += original.clone().also { it.fill(0, 4 + offset, 4 + offset + if (offset == 0) 8 else 32) }
            }
            for (offset in listOf(200, 208)) {
                mutations += original.clone().also { number(it, 4 + offset, 0) }
                mutations += original.clone().also { number(it, 4 + offset, -1L) }
            }
            if (proposal) mutations += original.clone().also { number(it, 4 + 256, 1) }
            for (wrong in mutations) assertFailsWith<ContinuityBoundaryFailure> { decode(wrong, proposal) }
            if (proposal) assertFailsWith<ContinuityBoundaryFailure> { CredentialRenewalProposal.decode(metadata(true, 1)) }
            else assertFailsWith<ContinuityBoundaryFailure> { CredentialRenewalCancellation.decode(metadata(false, 1)) }
        }
    }

    @Test fun policyFfmInputsReachRealNativeBoundaryWithoutReplacingPreparedOwner() {
        val point = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        val root = ByteArray(1952) { 1 } + point.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val family = ByteArray(32) { 3 }
        val intent = EnrollmentIntent(root, ByteArray(16) { 2 }, Counter64.of(1), family,
            Counter64.ZERO, Counter64.parse("18446744073709551614"))
        val pin = AccountPin(AccountID(ByteArray(32) { 1 }), root, family, RosterCheckpoint(Counter64.of(1), ByteArray(32) { 2 }))
        val document = PolicyDocument(root, family, PolicyCheckpoint(Counter64.of(1), ByteArray(32) { 4 }), byteArrayOf(1))
        val operation = CredentialRenewalID(ByteArray(32) { 5 })
        val statement = CredentialRenewalStatementID(ByteArray(32) { 6 })
        ContinuityEnrollment.prepareResume("/unused", intent).use { owner ->
            for (length in listOf(0, 65537)) {
                assertFailsWith<IllegalArgumentException> { owner.stageContinuedCredentialRenewal(ByteArray(length), pin, operation) }
                assertFailsWith<IllegalArgumentException> { owner.stagePolicyContinuation(ByteArray(length), pin, operation, byteArrayOf(1), document) }
            }
            for (length in listOf(0, 7747)) {
                assertFailsWith<IllegalArgumentException> { owner.stagePolicyContinuation(byteArrayOf(1), pin, operation, ByteArray(length), document) }
            }
            for (length in listOf(1, 7746)) {
                for (previous in listOf(null, PolicyContinuationStatementID(ByteArray(32) { 7 }))) {
                    assertEquals(103, assertFailsWith<ContinuityFailure> {
                        owner.stagePolicyContinuation(byteArrayOf(1), pin, operation, ByteArray(length), document, previous)
                    }.code)
                }
            }
            assertEquals(103, assertFailsWith<ContinuityFailure> { owner.stageContinuedCredentialRenewal(ByteArray(65536), pin, operation) }.code)
            assertEquals(103, assertFailsWith<ContinuityFailure> { owner.selectContinuedPolicy("/unused", document) }.code)
            assertEquals(103, assertFailsWith<ContinuityFailure> { owner.recoverHistoricalPolicyContinuation(operation, statement, document) }.code)
            for (call in listOf<() -> Unit>(
                { owner.prepareWitnessedPolicyContinuation() }, { owner.prepareWitnessedPolicyCancellation() },
                { owner.reconcilePolicyContinuation() }, { owner.commitWitnessedPolicyContinuation(operation, statement) },
                { owner.activatePolicyContinuation().close() })) {
                assertEquals(6, assertFailsWith<ContinuityFailure>(block = call).code)
            }
            assertEquals(6, assertFailsWith<ContinuityFailure> { owner.credentialRenewalStatus() }.code)
            owner.cancel()
            assertEquals(302, assertFailsWith<ContinuityFailure> { owner.finishOpen() }.code)
            assertEquals(2, assertFailsWith<ContinuityFailure> { owner.status() }.code)
        }
        // Decoder tests above use public synthetic grammar only, never fabricated
        // signature verification or mocked successful enrollment/activation.
    }
}
