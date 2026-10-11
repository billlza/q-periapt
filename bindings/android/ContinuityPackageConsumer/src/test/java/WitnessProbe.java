// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Original registration with explicit remote witness trust, never a local fallback. */
public final class WitnessProbe {
    private WitnessProbe() { }
    private static ConfigurationWitness witness(Path inputs, String mode) throws Exception {
        if (mode.equals("witness-missing")) return null;
        byte[] id = read(inputs, "witness-id");
        if (mode.equals("witness-wrong")) id[0] ^= 1;
        byte[] key = read(inputs, "witness-public");
        String address = new String(read(inputs, "witness-address"), StandardCharsets.US_ASCII);
        String carrier = new String(read(inputs, "witness-carrier"), StandardCharsets.US_ASCII);
        require(carrier.equals("signed"), "explicit signed witness carrier");
        return ConfigurationWitness.signedTcp(id, key, address, 3000);
    }
    private static void run(Path inputs, Path installation, Path output, String profile, String mode,
            ConfigurationWitness witness) throws Exception {
        boolean create = mode.equals("witness-create"), recovery = profile.equals("recoverable");
        require(recovery || profile.equals("fixed"), "profile");
        // Run on the owning endpoint: its installation may be on a phone,
        // and unrelated mutable sidecars cannot replace caller-supplied pins.
        if (mode.equals("witness-active-reopen")) {
            for (String name : new String[] {"witness-id", "witness-public"})
                publish(installation.resolve(name), new byte[32]);
        }
        EnrollmentIntent intent = intent(inputs);
        try (ContinuityConfiguration configuration = configuration(inputs, installation, recovery, create)) {
            configuration.finishOpen();
            if (mode.equals("witness-wrong")) {
                failed(103, () -> configuration.resumeEnrollment(intent, witness));
                publish(output, new byte[] {1}); return;
            }
            try (ContinuityEnrollment enrollment = create ? configuration.createEnrollment(intent, witness)
                    : configuration.resumeEnrollment(intent, witness)) {
                byte[] original = enrollment.request();
                switch (mode) {
                    case "witness-create", "witness-resume" -> {
                        require(enrollment.status().phase() == EnrollmentStatus.Phase.REQUESTED, "original requested state");
                        publish(output, original);
                    }
                    case "witness-prepare" -> {
                        AccountPin pin = new AccountPin(read(inputs, "trusted-account"), read(inputs, "enrollment-root"),
                            read(inputs, "family"), counter(ByteBuffer.wrap(read(inputs, "trusted-roster-version"))), read(inputs, "trusted-roster-digest"));
                        byte[] journal = enrollment.accept(read(inputs, "grant-certificate"), read(inputs, "grant-roster"), pin);
                        StoragePreparation storage = enrollment.prepareStorage();
                        require(storage.requiresWitnessEnrollment() && Arrays.equals(journal, storage.journalId()), "witness preparation");
                        publish(output, ByteBuffer.allocate(164).putInt(2).put(journal).put(storage.witnessSubject()).put(storage.imageDigest()).array());
                    }
                    case "witness-missing", "witness-bad-receipt" -> {
                        failed(mode.equals("witness-missing") ? 216 : 218, enrollment::activate);
                        publish(output, original);
                    }
                    case "witness-activate", "witness-active-reopen" -> {
                        if (mode.equals("witness-active-reopen")) require(enrollment.status().phase() == EnrollmentStatus.Phase.ACTIVE, "durable active phase");
                        try (ContinuityDevice active = enrollment.activate()) { active.cancel(); }
                        publish(output, original);
                    }
                    default -> throw new IllegalArgumentException("witness mode");
                }
            }
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("inputs installation profile mode result");
        Path inputs = Path.of(args[0]), installation = Path.of(args[1]), output = Path.of(args[4]);
        String carrier = new String(read(inputs, "witness-carrier"), StandardCharsets.US_ASCII);
        if (carrier.equals("tls") && !args[3].equals("witness-missing")) {
            try (ConfigurationInputs.LocalTlsIdentity tls = new ConfigurationInputs.LocalTlsIdentity(
                    read(inputs, "witness-tls-cert"), read(inputs, "witness-tls-key"))) {
                byte[] id = read(inputs, "witness-id"); if (args[3].equals("witness-wrong")) id[0] ^= 1;
                ConfigurationWitness witness = ConfigurationWitness.mutualTls(id, read(inputs, "witness-public"),
                    new String(read(inputs, "witness-address"), StandardCharsets.US_ASCII), 3000, read(inputs, "witness-tls-peer"),
                    new String(read(inputs, "witness-tls-name"), StandardCharsets.US_ASCII), tls);
                run(inputs, installation, output, args[2], args[3], witness);
            }
        } else run(inputs, installation, output, args[2], args[3], witness(inputs, args[3]));
        System.out.println(args[2] + ":" + args[3] + ":passed");
    }
}
