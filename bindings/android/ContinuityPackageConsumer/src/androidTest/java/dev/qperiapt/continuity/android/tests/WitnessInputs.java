// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import android.os.Bundle;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Test-only input transfer. TLS credentials stay inside the selected app's private directory. */
final class WitnessInputs {
    private WitnessInputs() { }
    static byte[] decoded(Bundle arguments, String name, int minimum, int maximum) {
        String encoded = arguments.getString(name);
        if (encoded == null || encoded.length() > ((maximum + 2) / 3) * 4) throw new IllegalArgumentException("witness input " + name);
        byte[] bytes = android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP);
        if (bytes.length < minimum || bytes.length > maximum
                || !android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP).equals(encoded)) {
            Arrays.fill(bytes, (byte) 0);
            throw new IllegalArgumentException("witness input encoding " + name);
        }
        return bytes;
    }
    static void install(File inputs, Bundle arguments, String name, int minimum, int maximum, boolean original) throws Exception {
        byte[] bytes = decoded(arguments, name, minimum, maximum);
        try {
            File path = new File(inputs, name);
            if (!original) { Files.write(path.toPath(), bytes); return; }
            try { Files.write(path.toPath(), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); }
            catch (java.nio.file.FileAlreadyExistsException exists) {
                byte[] previous = Files.readAllBytes(path.toPath());
                try { if (!Arrays.equals(bytes, previous)) throw new IllegalStateException("original witness input changed: " + name, exists); }
                finally { Arrays.fill(previous, (byte) 0); }
            }
        } finally { Arrays.fill(bytes, (byte) 0); }
    }
    static void install(File inputs, Bundle arguments) throws Exception {
        byte[] selected = decoded(arguments, "witness-carrier", 3, 6);
        String carrier = new String(selected, StandardCharsets.US_ASCII);
        if (!(carrier.equals("signed") || carrier.equals("tls"))) throw new IllegalArgumentException("witness carrier");
        install(inputs, arguments, "witness-id", 32, 32, true);
        install(inputs, arguments, "witness-public", 1985, 1985, true);
        install(inputs, arguments, "witness-address", 1, 128, false);
        install(inputs, arguments, "witness-carrier", 3, 6, false);
        if (carrier.equals("tls")) {
            for (String name : new String[] {"witness-tls-cert", "witness-tls-key", "witness-tls-peer"})
                install(inputs, arguments, name, 1, 8192, true);
            install(inputs, arguments, "witness-tls-name", 1, 128, true);
        }
    }
    static void installAuthority(File inputs, Bundle arguments, String operation) throws Exception {
        install(inputs, arguments, "authority-id", 32, 32, true);
        install(inputs, arguments, "authority-application", 32, 32, true);
        if (!operation.equals("authority-create")) install(inputs, arguments, "authority-checkpoint", 72, 72, true);
    }
    static void installCredential(File inputs, Bundle arguments, String operation) throws Exception {
        if (operation.startsWith("credential-policy-")) {
            if(operation.equals("credential-policy-stage")) {
                for(String name:new String[]{"credential-operation","credential-statement","renewal-digest"}) install(inputs,arguments,name,32,32,true);
                install(inputs,arguments,"renewal-version",8,8,true);install(inputs,arguments,"credential-renewal",1,65536,true);
            }
            return;
        }
        if (operation.equals("credential-identity") || operation.equals("credential-status") || operation.startsWith("credential-peer-") || operation.startsWith("credential-remote-") || operation.startsWith("credential-terminal-")) return;
        for (String name : new String[] {"credential-operation", "credential-statement", "renewal-digest"})
            install(inputs, arguments, name, 32, 32, true);
        install(inputs, arguments, "renewal-version", 8, 8, true);
        install(inputs, arguments, "credential-renewal", 1, 65536, true);
    }
    static void installRemoteCredential(File inputs, Bundle arguments, String operation) throws Exception {
        if (operation.equals("credential-remote-uncertain")) return;
        install(inputs,arguments,"remote-message",32,32,true);
        if (operation.equals("credential-remote-admit") || operation.equals("credential-remote-reopen")) {
            install(inputs,arguments,"remote-grant",1,65536,true);
            install(inputs,arguments,"remote-operation",32,32,true);
            install(inputs,arguments,"remote-version",8,8,true);
            install(inputs,arguments,"remote-digest",32,32,true);
        }
        if (operation.equals("credential-remote-reopen")) install(inputs,arguments,"remote-next",32,32,true);
    }
    static void installTerminalCredential(File inputs, Bundle arguments, String operation) throws Exception {
        if (operation.equals("credential-terminal-close-committed") || operation.equals("credential-terminal-expiry-committed")) return;
        for(String name:new String[]{"terminal-operation","terminal-statement"}) install(inputs,arguments,name,32,32,true);
        if(operation.equals("credential-terminal-stage")) {
            install(inputs,arguments,"terminal-grant",1,65536,true);
            install(inputs,arguments,"terminal-version",8,8,true);
            install(inputs,arguments,"terminal-digest",32,32,true);
        }
    }
    static void installLocalCredential(File inputs, Bundle arguments, String operation) throws Exception {
        if(operation.equals("credential-local-active") || operation.equals("credential-local-send")) install(inputs,arguments,"local-next-message",32,32,true);
        if(operation.equals("credential-local-stage") || operation.equals("credential-local-rejected") || operation.equals("credential-local-next-stage") || operation.equals("credential-local-next-stage-blocked")) {
            String prefix=operation.startsWith("credential-local-next-")?"local-second-":"local-first-";
            for(String name:new String[]{"operation","statement","digest"}) install(inputs,arguments,prefix+name,32,32,true);
            install(inputs,arguments,prefix+"version",8,8,true);
            install(inputs,arguments,prefix+"grant",1,65536,true);
        }
    }

}
