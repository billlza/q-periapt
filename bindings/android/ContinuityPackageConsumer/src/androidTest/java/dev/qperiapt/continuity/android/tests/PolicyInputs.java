// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import android.os.Bundle;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Explicit, bounded input transfer for the policy-renewal qualification APK only. */
final class PolicyInputs {
    private PolicyInputs() { }
    private static final String[] BASE = {"sdk-policy", "sdk-signature", "sdk-root", "family", "policy-root",
        "policy-version", "policy-digest", "protocol-policy", "tls-cert", "tls-key", "enrollment-root", "enrollment-intent"};
    private static final int[] MINIMUM = {1,3309,1952,32,1985,8,32,1,1,1,1985,72};
    private static final int[] MAXIMUM = {65536,3309,1952,32,1985,8,32,8192,8192,8192,1985,72};
    static void initial(File inputs, Bundle arguments, String profile) throws Exception {
        if (!"policy-create".equals(arguments.getString("operation"))) throw new IllegalStateException("original policy inputs are absent");
        for (int i = 0; i < BASE.length; ++i) WitnessInputs.install(inputs, arguments, BASE[i], MINIMUM[i], MAXIMUM[i], true);
        if (profile.equals("recoverable")) {
            WitnessInputs.install(inputs, arguments, "recovery-scope", 32, 32, true);
            WitnessInputs.install(inputs, arguments, "recovery-root", 1952, 1952, true);
            WitnessInputs.install(inputs, arguments, "recovery-enrollment", 3309, 3309, true);
        }
    }
    private static void copyOriginal(File source, File target, String name) throws Exception {
        byte[] bytes = Files.readAllBytes(new File(source, name).toPath());
        try {
            try { Files.write(new File(target, name).toPath(), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE); }
            catch (java.nio.file.FileAlreadyExistsException exists) {
                byte[] previous = Files.readAllBytes(new File(target, name).toPath());
                try {
                    if (!Arrays.equals(bytes, previous)) throw new IllegalStateException("original target input changed: " + name, exists);
                } finally { Arrays.fill(previous, (byte)0); }
            }
        } finally { Arrays.fill(bytes, (byte)0); }
    }
    static void install(File inputs, Bundle arguments, String operation, String profile) throws Exception {
        byte[] encoded = WitnessInputs.decoded(arguments, "witness-carrier", 3, 6);
        String carrier = new String(encoded, StandardCharsets.US_ASCII);
        if (carrier.equals("local")) WitnessInputs.install(inputs, arguments, "witness-carrier", 5, 5, true);
        else if (carrier.equals("signed") || carrier.equals("tls")) {
            WitnessInputs.install(inputs, arguments);
            if (!operation.equals("policy-create")) WitnessInputs.installAuthority(inputs, arguments, operation);
        } else throw new IllegalArgumentException("policy witness carrier");
        if (operation.equals("policy-target-create")) {
            File target = new File(inputs, "policy-target");
            if (!target.mkdir() && !target.isDirectory()) throw new IllegalStateException("target input directory");
            for (String name : new String[] {"sdk-policy", "sdk-signature", "sdk-root", "family", "policy-root", "tls-cert", "tls-key"}) copyOriginal(inputs, target, name);
            if (profile.equals("recoverable")) for (String name : new String[] {"recovery-scope", "recovery-root", "recovery-enrollment"}) copyOriginal(inputs, target, name);
            Bundle fields = new Bundle();
            for (String name : new String[] {"policy-version", "policy-digest", "protocol-policy"})
                fields.putString(name, arguments.getString("target-" + name));
            WitnessInputs.install(target, fields, "policy-version", 8, 8, true);
            WitnessInputs.install(target, fields, "policy-digest", 32, 32, true);
            WitnessInputs.install(target, fields, "protocol-policy", 1, 8192, true);
        }
        if (operation.equals("policy-request")) WitnessInputs.install(inputs, arguments, "renewal-operation", 32, 32, true);
        if (operation.startsWith("policy-stage")) {
            WitnessInputs.install(inputs, arguments, "renewal-request", 33176, 33176, true);
            WitnessInputs.install(inputs, arguments, "renewal-approvals", 7618, 7618, true);
            WitnessInputs.install(inputs, arguments, "renewal-statement", 32, 32, true);
        }
        if (operation.startsWith("policy-witness-") && !operation.equals("policy-witness-prepare") && !operation.equals("policy-witness-recover"))
            WitnessInputs.install(inputs, arguments, "renewal-proposal", 296, 296, true);
        if (operation.startsWith("policy-peer-")) PeerInputs.install(inputs, arguments, operation.substring("policy-".length()));
        if (operation.startsWith("policy-credential-")) {
            String name = operation.equals("policy-credential-next-request") ? "credential-next-operation" : "credential-operation";
            WitnessInputs.install(inputs, arguments, name, 32, 32, true);
            if (!operation.equals("policy-credential-request") && !operation.equals("policy-credential-next-request")
                    && !operation.equals("policy-credential-request-local-refused")) {
                for (String field : new String[] {"credential-statement", "renewal-digest"})
                    WitnessInputs.install(inputs, arguments, field, 32, 32, true);
                WitnessInputs.install(inputs, arguments, "renewal-version", 8, 8, true);
                WitnessInputs.install(inputs, arguments, "credential-renewal", 1, 65536, true);
            }
        }
    }
}
