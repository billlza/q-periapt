// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Independent process consumer: the account issuer runs outside this process and device. */
public final class EnrollmentProbe {
    private EnrollmentProbe() { }
    static byte[] read(Path root, String name) throws Exception { return Files.readAllBytes(root.resolve(name)); }
    static Counter64 counter(ByteBuffer input) { return new Counter64(Long.toUnsignedString(input.getLong())); }
    static void require(boolean ok, String reason) { if (!ok) throw new AssertionError(reason); }
    static void failed(int code, Runnable call) {
        try { call.run(); }
        catch (ContinuityFailure failure) { require(failure.code() == code, "native " + failure.code() + ": " + failure); return; }
        throw new AssertionError("expected native " + code);
    }
    static void publish(Path target, byte[] bytes) throws Exception {
        try (FileChannel file = FileChannel.open(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer remaining = ByteBuffer.wrap(bytes);
            while (remaining.hasRemaining()) file.write(remaining);
            file.force(true);
        }
    }
    static EnrollmentIntent intent(Path inputs) throws Exception {
        return intent(inputs, false);
    }
    private static EnrollmentIntent intent(Path inputs, boolean foreignFamily) throws Exception {
        byte[] root = read(inputs, "enrollment-root");
        byte[] wire = read(inputs, "enrollment-intent"); require(wire.length == 72, "intent width");
        ByteBuffer reader = ByteBuffer.wrap(wire);
        byte[] device = new byte[16]; reader.get(device); Counter64 generation = counter(reader);
        byte[] family = new byte[32]; reader.get(family); Counter64 from = counter(reader), until = counter(reader);
        if (foreignFamily) family[0] ^= 1;
        return new EnrollmentIntent(root, device, generation, family, from, until);
    }
    static ContinuityConfiguration configuration(Path inputs, Path installation, boolean recovery, boolean create) throws Exception {
        ConfigurationInputs.SdkTrust trust = recovery
            ? ConfigurationInputs.SdkTrust.recoverable(read(inputs, "recovery-scope"), read(inputs, "sdk-root"), read(inputs, "recovery-root"))
            : ConfigurationInputs.SdkTrust.fixed(read(inputs, "sdk-root"));
        ConfigurationInputs.ProtocolPolicy protocol = new ConfigurationInputs.ProtocolPolicy(read(inputs, "family"),
            read(inputs, "policy-root"), counter(ByteBuffer.wrap(read(inputs, "policy-version"))).toString(),
            read(inputs, "policy-digest"), read(inputs, "protocol-policy"));
        ContinuityConfiguration configuration;
        if (create) {
            try (ConfigurationInputs.LocalTlsIdentity tls = new ConfigurationInputs.LocalTlsIdentity(read(inputs, "tls-cert"), read(inputs, "tls-key"))) {
                ConfigurationInputs.Initial initial = new ConfigurationInputs.Initial(trust, read(inputs, "sdk-policy"),
                    read(inputs, "sdk-signature"), recovery ? read(inputs, "recovery-enrollment") : new byte[0], protocol, tls);
                configuration = ContinuityConfiguration.prepareCreate(installation.toString(), initial);
            }
        } else configuration = ContinuityConfiguration.prepareOpen(installation.toString(), trust, protocol);
        return configuration;
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("inputs installation profile mode result");
        Path inputs = Path.of(args[0]), installation = Path.of(args[1]), output = Path.of(args[4]);
        boolean recovery = args[2].equals("recoverable");
        require(recovery || args[2].equals("fixed"), "profile");
        byte[] root = read(inputs, "enrollment-root"), family = read(inputs, "family");
        EnrollmentIntent intent = intent(inputs);
        boolean create = args[3].equals("enrollment-create");
        ContinuityConfiguration configuration = configuration(inputs, installation, recovery, create);
        try {
            configuration.finishOpen();
            if (create) {
                EnrollmentIntent foreign = intent(inputs, true);
                failed(103, () -> configuration.createEnrollment(foreign, null));
            }
            ContinuityEnrollment enrollment = create ? configuration.createEnrollment(intent, null) : configuration.resumeEnrollment(intent, null);
            try {
                configuration.close(); // Transferred source close cannot revoke enrollment.
                failed(2, configuration::cancel);
                switch (args[3]) {
                    case "enrollment-create", "enrollment-resume" -> {
                        byte[] request = enrollment.request();
                        require(enrollment.status().phase() == EnrollmentStatus.Phase.REQUESTED, "requested phase");
                        publish(output, request);
                    }
                    case "enrollment-reject", "enrollment-activate" -> {
                        AccountPin pin = new AccountPin(read(inputs, "trusted-account"), root, family,
                            counter(ByteBuffer.wrap(read(inputs, "trusted-roster-version"))), read(inputs, "trusted-roster-digest"));
                        byte[] certificate = read(inputs, "grant-certificate"), roster = read(inputs, "grant-roster");
                        if (args[3].equals("enrollment-reject")) {
                            certificate[certificate.length - 1] ^= 1;
                            failed(102, () -> enrollment.accept(certificate, roster, pin));
                            failed(2, enrollment::status);
                            publish(output, new byte[] {1});
                        } else {
                            byte[] request = enrollment.request();
                            byte[] journal = enrollment.accept(certificate, roster, pin);
                            require(enrollment.status().phase() == EnrollmentStatus.Phase.ACCEPTED, "accepted phase");
                            StoragePreparation storage = enrollment.prepareStorage();
                            require(!storage.requiresWitnessEnrollment() && Arrays.equals(journal, storage.journalId()), "local preparation");
                            try (ContinuityDevice active = enrollment.activate()) {
                                enrollment.close(); // Transferred source close cannot revoke device.
                                failed(2, enrollment::status);
                                active.cancel();
                            }
                            publish(output, request);
                        }
                    }
                    case "enrollment-active-reopen" -> {
                        require(enrollment.status().phase() == EnrollmentStatus.Phase.ACTIVE, "durable active phase");
                        try (ContinuityDevice active = enrollment.activate()) { active.cancel(); }
                        publish(output, new byte[] {1});
                    }
                    default -> throw new IllegalArgumentException("enrollment operation");
                }
            } finally { enrollment.close(); }
        } finally { configuration.close(); }
        System.out.println(args[2] + ":" + args[3] + ":passed");
    }
}
