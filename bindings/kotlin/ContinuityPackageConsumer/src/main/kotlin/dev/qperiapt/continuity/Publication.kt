// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

class PrekeyPublicationID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(bytes.any { it != 0.toByte() }) { "zero publication ID" } }
}
class PrekeyInventoryID(bytes: ByteArray) : ContinuityID(bytes) {
    init { require(bytes.any { it != 0.toByte() }) { "zero inventory ID" } }
}
enum class PublicationKeyKind(val code: Int) {
    SIGNED_CLASSICAL(1), ONE_TIME_CLASSICAL(2), LAST_RESORT_PQ(3), ONE_TIME_PQ(4)
}
/** Complete immutable public member intent. Native admission checks reuse availability. */
data class PublicationKey(val kind: PublicationKeyKind, val validFrom: Counter64, val validUntil: Counter64,
                          val reusedRequest: PrekeyInventoryID? = null) {
    init { require(validFrom < validUntil && validUntil.bits() != -1L) { "finite nonempty member interval required" } }
}
/** Retain the original ID and plan before dispatch. Directory expectation must be independently trusted. */
class PublicationPlan(directory: ByteArray, val validFrom: Counter64, val validUntil: Counter64, keys: List<PublicationKey>) {
    val directory = PublicBytes(directory)
    val keys: List<PublicationKey> = java.util.List.copyOf(keys)
    init {
        require(directory.size == 32 && directory.any { it != 0.toByte() }) { "invalid directory expectation" }
        require(validFrom < validUntil && validUntil.bits() != -1L) { "finite nonempty manifest interval required" }
        require(this.keys.size in 1..1024 && this.keys.all { validFrom <= it.validFrom && it.validUntil <= validUntil }) { "invalid complete member plan" }
        require(this.keys.any { it.kind == PublicationKeyKind.SIGNED_CLASSICAL } &&
                this.keys.any { it.kind == PublicationKeyKind.LAST_RESORT_PQ }) { "required reusable roles missing" }
        val reused = this.keys.mapNotNull { it.reusedRequest }
        require(reused.distinct().size == reused.size) { "duplicate reused inventory request" }
    }
}
/** Local history only. Prepared does not promise current permission or remote publication. */
sealed interface PublicationStatus {
    data object Absent : PublicationStatus
    data object Retired : PublicationStatus
    data class Reserved(val intent: PublicBytes) : PublicationStatus
    data class Prepared(val intent: PublicBytes, val manifest: PublicBytes, val artifact: PublicBytes) : PublicationStatus
}
/** Native-verified public result. Decoding this wrapper is not independent signature or freshness verification. */
class PreparedPublication private constructor(val id: PrekeyPublicationID, val intent: PublicBytes, val artifact: PublicBytes,
    val canonicalBytes: PublicBytes, val manifest: PublicBytes, requests: List<PrekeyInventoryID>, proofs: List<PublicBytes>) {
    /** Original plan order, distinct from proof order. */
    val inventoryRequests: List<PrekeyInventoryID> = java.util.List.copyOf(requests)
    /** Canonical manifest leaf order. */
    val membershipProofs: List<PublicBytes> = java.util.List.copyOf(proofs)
    companion object {
        @JvmSynthetic internal fun decode(bytes: ByteArray, expected: PrekeyPublicationID, plan: PublicationPlan): PreparedPublication {
            fun refuse(): Nothing = throw ContinuityBoundaryFailure("malformed complete publication artifact")
            if (bytes.size > 2 * 1024 * 1024) refuse()
            var position = 0
            fun take(count: Int): ByteArray {
                if (count < 0 || count > bytes.size - position) refuse()
                return bytes.copyOfRange(position, position + count).also { position += count }
            }
            fun number(count: Int): Long = take(count).fold(0L) { value, b -> (value shl 8) or (b.toLong() and 255) }
            if (!take(8).contentEquals("QPPUBA01".toByteArray(Charsets.US_ASCII)) || !take(32).contentEquals(expected.encoded())) refuse()
            val intent = take(32); val artifact = take(32)
            if (intent.all { it == 0.toByte() } || artifact.all { it == 0.toByte() }) refuse()
            val length = number(4)
            if (length != 3667L) refuse()
            val manifest = take(length.toInt())
            if (number(2) != plan.keys.size.toLong()) refuse()
            val requests = plan.keys.map { key ->
                val id = take(32)
                if (id.all { it == 0.toByte() }) refuse()
                PrekeyInventoryID(id).also { if (key.reusedRequest != null && key.reusedRequest != it) refuse() }
            }
            if (requests.distinct().size != requests.size) refuse()
            val proofs = plan.keys.indices.map { index ->
                val size = number(2)
                if (size !in 62L..1534L) refuse()
                val proof = take(size.toInt())
                if ((proof[0].toInt() and 255) * 256 + (proof[1].toInt() and 255) != index) refuse()
                PublicBytes(proof)
            }
            if (position != bytes.size) refuse()
            return PreparedPublication(expected, PublicBytes(intent), PublicBytes(artifact), PublicBytes(bytes), PublicBytes(manifest), requests, proofs)
        }
    }
}
