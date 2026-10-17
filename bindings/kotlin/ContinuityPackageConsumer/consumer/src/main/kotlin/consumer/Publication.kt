// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.file.Path
import java.util.HexFormat

private fun publicationText(status: PublicationStatus): String {
    val zero = ByteArray(32)
    val state: Int; val intent: ByteArray; val manifest: ByteArray; val artifact: ByteArray
    when (status) {
        PublicationStatus.Absent -> { state = 0; intent = zero; manifest = zero; artifact = zero }
        PublicationStatus.Retired -> { state = 3; intent = zero; manifest = zero; artifact = zero }
        is PublicationStatus.Reserved -> { state = 1; intent = status.intent.encoded(); manifest = zero; artifact = zero }
        is PublicationStatus.Prepared -> { state = 2; intent = status.intent.encoded(); manifest = status.manifest.encoded(); artifact = status.artifact.encoded() }
    }
    val hex = HexFormat.of()
    return "publication-state:$state\n${hex.formatHex(intent)}\n${hex.formatHex(manifest)}\n${hex.formatHex(artifact)}"
}
internal fun publicationCommand(args: List<String>, parent: String, witness: WitnessCarrier): String {
    require(args.size in 2..3 && args[1] == parent) { "original publication parent arguments" }
    val records = FixtureRecords(Path.of(parent), 2 * 1024 * 1024)
    return enrollmentParent(parent, witness).use { device ->
        if (args[0] == "publication-next") {
            require(args.size == 2); return@use hex(device.nextPublication())
        }
        require(args.size == 3) { "original publication ID missing" }
        val id = PrekeyPublicationID(decode(args[2]))
        when (args[0]) {
            "publication-status" -> publicationText(device.publicationStatus(id))
            "publication-retire" -> {
                val bytes = records.read("publication-artifact")
                check(bytes.size >= 104 && bytes.copyOfRange(0,8).contentEquals("QPPUBA01".toByteArray()) &&
                    bytes.copyOfRange(8,40).contentEquals(id.encoded())) { "host-retained publication identity" }
                publicationText(device.retirePublication(id, bytes.copyOfRange(72,104)))
            }
            "publication-prepare", "publication-retry", "publication-cancel" -> {
                val bytes = records.enrollmentExact("publication-plan",48)
                fun counter(start: Int) = Counter64.parse(java.lang.Long.toUnsignedString(ByteBuffer.wrap(bytes,start,8).long))
                val from = counter(32); val until = counter(40)
                val plan = PublicationPlan(bytes.copyOfRange(0,32), from, until,
                    PublicationKeyKind.entries.map { PublicationKey(it, from, until) })
                if (args[0] == "publication-cancel") {
                    device.cancel(); refused(setOf(302)) { device.preparePublication(id,plan) }; "publication-cancelled"
                } else {
                    val prepared = device.preparePublication(id,plan)
                    val status = device.publicationStatus(id)
                    check(status is PublicationStatus.Prepared && status.intent == prepared.intent && status.artifact == prepared.artifact) { "publication commitments differ" }
                    records.retain(if (args[0] == "publication-retry") "publication-retry" else "publication-artifact", prepared.canonicalBytes.encoded(),true)
                    publicationText(status)
                }
            }
            else -> error("unknown publication command")
        }
    }
}
