// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

/** Independent account/roster approval and exact device generation; a bundle cannot select these. */
class PeerDeviceExpectation(val account: AccountPin, device: ByteArray, val generation: Counter64) {
    val device: PublicBytes
    init {
        require(device.size == 16 && device.any { it != 0.toByte() } && generation != Counter64.ZERO) {
            "peer device must be a nonzero 16-byte ID with a nonzero generation"
        }
        this.device = PublicBytes(device)
    }
}

/** Immutable copied public input. Host expectations remain separate from the untrusted signed bundle.
 * A prepared descriptor does not authenticate a TLS endpoint or authorize traffic.
 */
class PeerConfiguration(val initiator: PeerDeviceExpectation, val responder: PeerDeviceExpectation,
    directory: ByteArray, bundle: ByteArray, tlsPeerCertificate: ByteArray, val tlsPeerName: String) {
    val directory: PublicBytes
    val bundle: PublicBytes
    val tlsPeerCertificate: PublicBytes
    init {
        require(directory.size == 32 && directory.any { it != 0.toByte() }) { "invalid independent directory expectation" }
        require(bundle.size in 1..65536 && tlsPeerCertificate.size in 1..8192) { "peer public input exceeds its bound" }
        require(tlsPeerName.encodeToByteArray(throwOnInvalidSequence = true).size in 1..128 && '\u0000' !in tlsPeerName) {
            "peer TLS name must contain 1..128 UTF-8 bytes without NUL"
        }
        this.directory = PublicBytes(directory)
        this.bundle = PublicBytes(bundle)
        this.tlsPeerCertificate = PublicBytes(tlsPeerCertificate)
    }
}
