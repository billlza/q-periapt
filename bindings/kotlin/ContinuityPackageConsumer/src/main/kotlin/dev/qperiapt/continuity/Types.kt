// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.security.SecureRandom

/** Immutable public correlation bytes; an ID never grants operational authority. */
sealed class ContinuityID protected constructor(bytes: ByteArray) {
    private val value: ByteArray
    init {
        require(bytes.size == 32) { "an ID contains exactly 32 bytes" }
        value = bytes.clone()
    }
    fun encoded(): ByteArray = value.clone()
    final override fun equals(other: Any?): Boolean =
        other is ContinuityID && javaClass == other.javaClass && value.contentEquals(other.value)
    final override fun hashCode(): Int = 31 * javaClass.hashCode() + value.contentHashCode()
}
class InitiationID(bytes: ByteArray) : ContinuityID(bytes) {
    companion object {
        fun random(): InitiationID = InitiationID(ByteArray(32).also { SecureRandom().nextBytes(it) })
    }
}
class SessionID(bytes: ByteArray) : ContinuityID(bytes)
class MessageID(bytes: ByteArray) : ContinuityID(bytes)
class ClosureReportID(bytes: ByteArray) : ContinuityID(bytes)

/** A complete unsigned 64-bit counter, including values above signed Long.MAX_VALUE. */
class Counter64 private constructor(private val value: Long) : Comparable<Counter64> {
    override fun toString(): String = java.lang.Long.toUnsignedString(value)
    override fun equals(other: Any?): Boolean = other is Counter64 && value == other.value
    override fun hashCode(): Int = value.hashCode()
    override fun compareTo(other: Counter64): Int = java.lang.Long.compareUnsigned(value, other.value)
    @JvmSynthetic internal fun bits(): Long = value
    companion object {
        val ZERO: Counter64 = Counter64(0)
        fun of(value: Long): Counter64 {
            require(value >= 0) { "use parse for unsigned values above Long.MAX_VALUE" }
            return Counter64(value)
        }
        fun parse(decimal: String): Counter64 {
            require(decimal.matches(Regex("0|[1-9][0-9]{0,19}"))) { "counter must be canonical unsigned decimal" }
            return Counter64(java.lang.Long.parseUnsignedLong(decimal))
        }
        @JvmSynthetic internal fun fromBits(value: Long): Counter64 = Counter64(value)
    }
}

class PublicBytes(bytes: ByteArray) {
    private val value = bytes.clone()
    fun encoded(): ByteArray = value.clone()
    override fun equals(other: Any?): Boolean = other is PublicBytes && value.contentEquals(other.value)
    override fun hashCode(): Int = value.contentHashCode()
}

enum class PrekeyQuality(val code: Int) {
    ONE_TIME_BOTH(1), REUSABLE_BOTH(2), SIGNED_CLASSICAL_ONE_TIME_PQ(3), ONE_TIME_CLASSICAL_LAST_RESORT_PQ(4),
}
sealed interface WitnessCarrier {
    data object Local : WitnessCarrier
    data class SignedTCP(val address: String, val timeoutMilliseconds: Int) : WitnessCarrier {
        init { require(timeoutMilliseconds in 1..10000) { "witness timeout must be 1..10000 ms" } }
    }
    data class MutualTLS(val address: String, val timeoutMilliseconds: Int) : WitnessCarrier {
        init { require(timeoutMilliseconds in 1..10000) { "witness timeout must be 1..10000 ms" } }
    }
}
enum class MessageStatus(val code: Int) {
    ABSENT(0), RESERVED(1), COMMITTED(2), ACKNOWLEDGED(3), RESOLUTION_PENDING(4),
    DELIVERY_UNKNOWN(5), RESERVATION_ABANDONED(6),
}
enum class Consumption(val code: Int) { CONFIRMED(1), PREFIX_PENDING(2) }
data class Establishment(val session: SessionID, val exchanges: Int)
data class SendResult(val consumption: Consumption, val exchanges: Int)
enum class SessionRole(val code: Int) { INITIATOR(1), RESPONDER(2) }
data class ClosureHeader(
    val peerGeneration: Counter64, val confirmedEpoch: Counter64, val sendingEpoch: Counter64,
    val receivingEpoch: Counter64, val pendingEpoch: Counter64?, val role: SessionRole,
    val reservedCount: Long, val epochCount: Long, val session: SessionID, val context: PublicBytes,
    val report: ClosureReportID, val peerAccount: PublicBytes, val peerDevice: PublicBytes,
)
sealed interface ClosureStatus {
    data object Open : ClosureStatus
    data class Pending(val report: ClosureReportID) : ClosureStatus
    data class Closed(val report: ClosureReportID) : ClosureStatus
}
sealed interface EpochResolution {
    data object Unrequested : EpochResolution
    data class Pending(val report: ClosureReportID) : EpochResolution
    data class Acknowledged(val report: ClosureReportID) : EpochResolution
}
data class ClosureEpoch(
    val epoch: Counter64, val acknowledgedBefore: Counter64, val sent: Counter64,
    val consumedBefore: Counter64, val received: Counter64, val peerSent: Counter64?,
    val resolution: EpochResolution, val unconfirmedCount: Long, val deliveryCount: Long, val skippedCount: Long,
)
data class ReservedLoss(val message: MessageID, val plaintextBytes: Counter64, val associatedDataBytes: Counter64)
data class UnconfirmedLoss(val message: MessageID, val ciphertextDigest: PublicBytes)
data class DeliveryLoss(val message: MessageID, val index: Counter64, val plaintextBytes: Counter64)
sealed interface Served {
    data class Bootstrap(val session: SessionID) : Served
    data class Message(val session: SessionID, val message: MessageID, val duplicate: Boolean) : Served
}
class ApplicationDelivery(val session: SessionID, val message: MessageID, plaintext: ByteArray) {
    private val bytes = plaintext.clone()
    fun plaintext(): ByteArray = bytes.clone()
}
fun interface ApplicationCommit {
    /** Return only after effect and session/message deduplication are durably committed together. */
    fun commit(delivery: ApplicationDelivery)
}
class ContinuityFailure(val operation: String, val code: Int, val diagnostic: String, val truncated: Boolean) :
    RuntimeException("$operation: $diagnostic (status $code)")
class ContinuityCallbackFailure(val nativeFailure: ContinuityFailure, cause: Throwable) :
    RuntimeException("application callback failed; native status ${nativeFailure.code}", cause)
class ApplicationCommitRefusal(val status: Int, message: String) : RuntimeException(message) {
    init { require(status != 0) { "zero would acknowledge a committed application effect" } }
}
class ContinuityBoundaryFailure(message: String) : IllegalStateException(message)
