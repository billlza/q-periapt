// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.APPEND
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions

/** Qualification-only phase receipt in the harness-owned POSIX probe log. */
private fun setupIOPhase(phase: Int) {
    require(System.getenv("QPC_TEST_SYNC_ACTION") == "io" && phase in 1..4) { "setup I/O phase requires its owned probe" }
    val path = Path.of(requireNotNull(System.getenv("QPC_TEST_SYNC_LOG")))
    require(path.isAbsolute)
    val before = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    check(before.isRegularFile && before.fileKey() != null && before.size() in 1..65536) { "setup I/O phase receipt shape" }
    check(Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rw-------"))
    val bytes = "phase $phase 0\n".toByteArray(Charsets.US_ASCII)
    FileChannel.open(path, WRITE, APPEND, NOFOLLOW_LINKS).use { channel ->
        check(channel.size() == before.size()) { "setup I/O phase receipt changed" }
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) check(channel.write(buffer) > 0) { "setup I/O phase write made no progress" }
        val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        check(before.fileKey() == after.fileKey() && after.size() == before.size() + bytes.size && channel.size() == after.size()) {
            "setup I/O phase receipt changed during append"
        }
    }
}

internal fun setupIOActivate(path: String, witness: WitnessCarrier): String {
    val setup = ContinuitySetup.prepareResume(path, witness)
    var successor: ContinuityDevice? = null
    try {
        setupIOPhase(1)
        var code = 0
        try { setup.finishOpen() } catch (failure: ContinuityFailure) {
            if (failure.code != 204) throw failure
            code = failure.code
        }
        if (code == 0) {
            setupIOPhase(2)
            try { successor = setup.activate() } catch (failure: ContinuityFailure) {
                if (failure.code != 207) throw failure
                code = failure.code
            }
        }
        refused(setOf(2)) { setup.status() }
        refused(setOf(2)) { setup.prepareStorage() }
        val device = successor
        val batch = if (device != null) {
            check(code == 0) { "failed setup I/O retained successor" }
            device.nextAccountOperation()
        } else {
            check(code == 204 || code == 207) { "setup I/O omitted successor" }
            null // The explicit native error means no operational owner was released.
        }
        setupIOPhase(3)
        setup.close()
        if (device != null) {
            device.close()
            refused(setOf(2)) { device.nextAccountOperation() }
        }
        setupIOPhase(4)
        return if (batch != null) "setup-io:0\n${hex(batch)}" else "setup-io:$code"
    } catch (failure: Throwable) {
        try { setup.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        try { successor?.close() } catch (disposal: Throwable) { failure.addSuppressed(disposal) }
        throw failure
    }
}
