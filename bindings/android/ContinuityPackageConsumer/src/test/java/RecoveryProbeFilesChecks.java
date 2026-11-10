// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/** Durable host accounting is required before the SDK may acknowledge cleanup. */
public final class RecoveryProbeFilesChecks {
    private RecoveryProbeFilesChecks() { }
    public static void main(String[] args) throws Exception {
        if(args.length==1) {
            try {new RecoveryProbeFiles(Path.of(args[0])).retain("original",new byte[]{9},true);}
            catch(java.io.IOException busy) {
                if(!busy.getMessage().equals("host record writer busy"))throw busy;
                System.exit(73);return;
            }
            throw new AssertionError("other process bypassed writer lock");
        }
        Path directory=Files.createTempDirectory("qpc-host-records-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        RecoveryProbeFiles records=new RecoveryProbeFiles(directory);byte[] original={1,2,3,4};
        records.retain("original",original,true);records.retain("original",original,true);records.retain("original",original,false);
        if(!Arrays.equals(records.read("original"),original))throw new AssertionError("original record changed");
        try {records.retain("original",new byte[]{9},true);throw new IllegalStateException("conflicting report replaced original");}
        catch(AssertionError expected) {if(!expected.getMessage().equals("original record conflict"))throw expected;}
        try {records.retain("absent",original,false);throw new AssertionError("missing report fabricated");}
        catch(java.nio.file.NoSuchFileException expected) {if(Files.exists(directory.resolve("absent")))throw new AssertionError("absent was published",expected);}
        try(FileChannel gate=FileChannel.open(directory.resolve(".host-records.lock"),StandardOpenOption.WRITE);FileLock lock=gate.lock()) {
            if(!lock.isValid())throw new AssertionError("lock invalid");
            Process child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),RecoveryProbeFilesChecks.class.getName(),directory.toString()).inheritIO().start();
            if(!child.waitFor(10,TimeUnit.SECONDS)) {child.destroyForcibly();child.waitFor();throw new AssertionError("busy writer did not terminate");}
            if(child.exitValue()!=73)throw new AssertionError("busy writer status changed");
        }
        if(!Arrays.equals(records.read("original"),original))throw new AssertionError("busy writer replaced original");
        records.retain("second",new byte[]{5},true);
        for(String name:new String[]{"original","second",".host-records.lock"})Files.delete(directory.resolve(name));
        Files.delete(directory);
        System.out.println("host-record-retention:passed");
    }
}
