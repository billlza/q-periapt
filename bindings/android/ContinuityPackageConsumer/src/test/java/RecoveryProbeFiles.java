// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Set;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.require;

/** Test-host durable, deduplicated records in a harness-owned POSIX directory.
 * Writers cooperate through one exclusive lock; atomic rename avoids hard links
 * that Android app storage can reject. Busy writers fail without replacing data.
 * This is not a production database or protection against parent-directory moves.
 */
final class RecoveryProbeFiles {
    private final Path directory;
    RecoveryProbeFiles(Path directory) { this.directory=directory; }
    private Path path(String name) {
        require(name.matches("[a-z0-9-]{1,128}"),"record name");return directory.resolve(name);
    }
    private void sync() throws Exception {
        try(FileChannel channel=FileChannel.open(directory,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)) {channel.force(true);}
    }
    byte[] read(String name) throws Exception {
        try(FileChannel file=FileChannel.open(path(name),StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)) {
            long size=file.size();require(size>0 && size<=1048576,"record size");
            ByteBuffer bytes=ByteBuffer.allocate((int)size);
            while(bytes.hasRemaining()) require(file.read(bytes)>0,"truncated record");
            require(file.size()==size && file.read(ByteBuffer.allocate(1))==-1,"record changed");file.force(true);sync();return bytes.array();
        }
    }
    void retain(String name,byte[] bytes,boolean create) throws Exception {
        require(bytes.length>0 && bytes.length<=1048576,"record bound");
        try(FileChannel gate=FileChannel.open(directory.resolve(".host-records.lock"),
                Set.of(StandardOpenOption.CREATE,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            try(FileLock lock=gate.tryLock()) {
                if(lock==null)throw new java.io.IOException("host record writer busy");
                require(lock.isValid(),"host record writer lock");retainLocked(name,bytes,create);
            }
        }
    }
    private void retainLocked(String name,byte[] bytes,boolean create) throws Exception {
        try {require(Arrays.equals(read(name),bytes),"original record conflict");return;}
        catch(NoSuchFileException absent) {if(!create) throw absent;}
        Path temporary=Files.createTempFile(directory,"."+name,".tmp",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Throwable primary=null;
        try {
            try(FileChannel file=FileChannel.open(temporary,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer body=ByteBuffer.wrap(bytes);while(body.hasRemaining()) require(file.write(body)>0,"record write stalled");file.force(true);
            }
            Files.move(temporary,path(name),StandardCopyOption.ATOMIC_MOVE);
            require(Arrays.equals(read(name),bytes),"published record changed");
        } catch(Throwable failure) {primary=failure;throw failure;}
        finally {
            try {Files.deleteIfExists(temporary);sync();}
            catch(Throwable cleanup) {if(primary!=null) primary.addSuppressed(cleanup);else throw cleanup;}
        }
    }
}
