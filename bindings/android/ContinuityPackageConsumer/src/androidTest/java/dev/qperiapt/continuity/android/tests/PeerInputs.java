// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import android.os.Bundle;
import android.system.Os;
import android.system.OsConstants;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Qualification transport for public peer expectations, never native private state. */
final class PeerInputs {
    private PeerInputs() { }
    private static byte[] decoded(Bundle arguments, String name, int minimum, int maximum) {
        String encoded = arguments.getString(name);
        if (encoded == null || encoded.length() > ((maximum + 2) / 3) * 4) throw new IllegalArgumentException("public input " + name);
        byte[] bytes = android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP);
        if (bytes.length < minimum || bytes.length > maximum
                || !android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP).equals(encoded)) {
            throw new IllegalArgumentException("public input encoding " + name);
        }
        return bytes;
    }
    private static void original(File path, byte[] bytes) throws Exception {
        try { Files.write(path.toPath(), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); }
        catch (java.nio.file.FileAlreadyExistsException exists) {
            if (!Arrays.equals(bytes, Files.readAllBytes(path.toPath()))) throw new IllegalStateException("original public input changed", exists);
        }
    }
    static void install(File inputs, Bundle arguments, String operation) throws Exception {
        File peer = new File(inputs, "peer");
        try { Os.mkdir(peer.getPath(), 0700); }
        catch (android.system.ErrnoException exists) { if (exists.errno != OsConstants.EEXIST) throw exists; }
        android.system.StructStat stat = Os.lstat(peer.getPath());
        if (!OsConstants.S_ISDIR(stat.st_mode) || (stat.st_mode & 0777) != 0700 || stat.st_uid != android.os.Process.myUid()) {
            throw new IllegalStateException("peer input directory");
        }
        String[] fields = {"account", "root", "roster-version", "roster-digest", "device", "generation"};
        int[] widths = {32,1985,8,32,16,8};
        for (String prefix : new String[] {"initiator", "responder"}) for (int i = 0; i < fields.length; ++i) {
            String name = prefix + "-" + fields[i]; original(new File(peer, name), decoded(arguments, "peer-" + name, widths[i], widths[i]));
        }
        for (String name : new String[] {"family", "directory"}) original(new File(peer, name), decoded(arguments, "peer-" + name, 32, 32));
        original(new File(peer, "bootstrap.bundle"), decoded(arguments, "peer-bootstrap.bundle", 1, 65536));
        original(new File(peer, "tls-peer"), decoded(arguments, "peer-tls-peer", 1, 8192));
        original(new File(peer, "tls-peer-name"), decoded(arguments, "peer-tls-peer-name", 1, 128));
        if (operation.equals("peer-unassociated")) return;
        // Transport address may change. It never selects TLS or account trust.
        Files.write(new File(inputs, "connection-address").toPath(), decoded(arguments, "connection-address", 1, 128));
        String identity = operation.equals("peer-connect") ? "connection-initiation" : "connection-session";
        original(new File(inputs, identity), decoded(arguments, identity, 32, 32));
        if (operation.equals("peer-retry")) original(new File(inputs, "connection-message"), decoded(arguments, "connection-message", 32, 32));
    }
    static void installApproval(File inputs, Bundle arguments) throws Exception {
        original(new File(inputs, "authority-peer-application"), decoded(arguments, "authority-peer-application", 32, 32));
        original(new File(inputs, "peer/approved-certificate"), decoded(arguments, "peer-approved-certificate", 1, 8192));
        original(new File(inputs, "peer/approved-roster"), decoded(arguments, "peer-approved-roster", 1, 65536));
    }
}
