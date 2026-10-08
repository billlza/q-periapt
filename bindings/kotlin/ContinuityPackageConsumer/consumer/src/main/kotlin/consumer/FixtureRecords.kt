// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions

/** Test-host records in a harness-owned, trusted local POSIX directory.
 * Effect and original identity share one no-clobber file. This fixture is not a
 * production database or protection against adversarial parent-directory moves.
 */
internal class FixtureRecords(private val directory: Path, private val maximumBytes: Int = 1_048_576) {
    init { require(directory.isAbsolute && Files.isDirectory(directory, NOFOLLOW_LINKS) && maximumBytes in 1..8_388_608) }
    private fun name(value: String): Path {
        require(value.matches(Regex("[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}"))) { "invalid record name" }
        return directory.resolve(value)
    }
    private fun syncDirectory() = FileChannel.open(directory, READ, NOFOLLOW_LINKS).use { it.force(true) }
    private fun existing(path: Path): ByteArray? {
        val before = try { Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS) }
            catch (_: NoSuchFileException) { return null }
        check(before.isRegularFile && before.size() in 1..maximumBytes.toLong()) { "invalid record shape" }
        return FileChannel.open(path, READ, WRITE, NOFOLLOW_LINKS).use { channel ->
            check(channel.size() == before.size()) { "record changed before read" }
            val buffer = ByteBuffer.allocate(before.size().toInt() + 1)
            while (buffer.hasRemaining()) {
                val count = channel.read(buffer)
                if (count == -1) break
                check(count > 0) { "record read made no progress" }
            }
            val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            check(buffer.position().toLong() == before.size() && channel.size() == before.size() &&
                before.fileKey() != null && before.fileKey() == after.fileKey() &&
                before.size() == after.size() && before.lastModifiedTime() == after.lastModifiedTime()) {
                "retained record changed"
            }
            channel.force(true)
            syncDirectory()
            buffer.array().copyOf(buffer.position())
        }
    }
    fun read(value: String): ByteArray = existing(name(value)) ?: error("original record absent")
    fun retain(value: String, bytes: ByteArray, create: Boolean): Boolean {
        require(bytes.size in 1..maximumBytes) { "record length outside fixture bound" }
        val path = name(value)
        existing(path)?.let {
            check(it.contentEquals(bytes)) { "retained original record conflicts" }
            return false
        }
        check(create) { "original retained record unavailable" }
        val temporary = Files.createTempFile(directory, ".$value.", ".tmp",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        // use preserves a cleanup failure as a suppressed cause of a write failure.
        return AutoCloseable { Files.delete(temporary); syncDirectory() }.use {
            FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) check(channel.write(buffer) > 0) { "record write made no progress" }
                channel.force(true)
            }
            val created = try { Files.createLink(path, temporary); true }
                catch (_: FileAlreadyExistsException) { false }
            check(read(value).contentEquals(bytes)) { "published original record conflicts" }
            created
        }
    }
}
