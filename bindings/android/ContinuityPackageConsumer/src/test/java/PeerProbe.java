// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.LinkOption;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntConsumer;

/** Public-API client and server over the same original registration. */
public final class PeerProbe {
    private PeerProbe() { }
    private static final byte[] PAYLOAD = "persisted before process exit".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] AD = "configuration-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static byte[] read(Path root, String name) throws Exception { return Files.readAllBytes(root.resolve(name)); }
    private static Counter64 counter(byte[] bytes) { return new Counter64(Long.toUnsignedString(ByteBuffer.wrap(bytes).getLong())); }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private static void publish(Path path, byte[] bytes) throws Exception {
        try (FileChannel file = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer input = ByteBuffer.wrap(bytes); while (input.hasRemaining()) file.write(input); file.force(true);
        }
    }
    static ContinuityDevice device(Path inputs, Path path, boolean recovery) throws Exception {
        ConfigurationInputs.SdkTrust trust = recovery
            ? ConfigurationInputs.SdkTrust.recoverable(read(inputs, "recovery-scope"), read(inputs, "sdk-root"), read(inputs, "recovery-root"))
            : ConfigurationInputs.SdkTrust.fixed(read(inputs, "sdk-root"));
        ConfigurationInputs.ProtocolPolicy protocol = new ConfigurationInputs.ProtocolPolicy(read(inputs, "family"), read(inputs, "policy-root"),
            counter(read(inputs, "policy-version")).toString(), read(inputs, "policy-digest"), read(inputs, "protocol-policy"));
        byte[] wire = read(inputs, "enrollment-intent"); require(wire.length == 72, "intent width");
        EnrollmentIntent intent = new EnrollmentIntent(read(inputs, "enrollment-root"), Arrays.copyOfRange(wire, 0, 16),
            counter(Arrays.copyOfRange(wire, 16, 24)), Arrays.copyOfRange(wire, 24, 56),
            counter(Arrays.copyOfRange(wire, 56, 64)), counter(Arrays.copyOfRange(wire, 64, 72)));
        try (ContinuityConfiguration configuration = ContinuityConfiguration.prepareOpen(path.toString(), trust, protocol)) {
            configuration.finishOpen();
            try (ContinuityEnrollment enrollment = configuration.resumeEnrollment(intent, null)) {
                require(enrollment.status().phase() == EnrollmentStatus.Phase.ACTIVE, "original active registration");
                return enrollment.activate();
            }
        }
    }
    static AccountPin account(Path inputs, String prefix) throws Exception {
        return new AccountPin(read(inputs, prefix + "-account"), read(inputs, prefix + "-root"), read(inputs, "family"),
            counter(read(inputs, prefix + "-roster-version")), read(inputs, prefix + "-roster-digest"));
    }
    private static PeerConfiguration.Device expectation(Path inputs, String prefix) throws Exception {
        return new PeerConfiguration.Device(account(inputs, prefix), read(inputs, prefix + "-device"), counter(read(inputs, prefix + "-generation")));
    }
    static PeerConfiguration configuration(Path inputs) throws Exception {
        return new PeerConfiguration(expectation(inputs, "initiator"), expectation(inputs, "responder"), read(inputs, "directory"),
            read(inputs, "bootstrap.bundle"), read(inputs, "tls-peer"), new String(read(inputs, "tls-peer-name"), java.nio.charset.StandardCharsets.UTF_8));
    }
    static void client(ContinuityDevice device, Path inputs, String mode, Path output) throws Exception {
        PeerConfiguration config = configuration(inputs.resolve("peer"));
        Ids.Session session = mode.equals("peer-connect") ? null : new Ids.Session(read(inputs, "connection-session"));
        try (ContinuityPeer peer = session == null
                ? device.preparePeer(config, PeerConfiguration.Quality.ONE_TIME_BOTH, PeerConfiguration.Role.INITIATOR)
                : device.preparePeerReopen(config, PeerConfiguration.Quality.ONE_TIME_BOTH, PeerConfiguration.Role.INITIATOR, session)) {
            peer.finishOpen(); exchange(peer, inputs, mode, session, output);
        }
    }
    static void unassociated(ContinuityDevice device, Path inputs, Path output) throws Exception {
        try (ContinuityPeer peer = device.preparePeer(configuration(inputs.resolve("peer")), PeerConfiguration.Quality.ONE_TIME_BOTH,
                PeerConfiguration.Role.INITIATOR)) {
            EnrollmentProbe.failed(201, peer::finishOpen);
            publish(output, ByteBuffer.allocate(4).putInt(201).array());
        }
    }
    private static void exchange(ContinuityPeer peer, Path inputs, String mode, Ids.Session session, Path output) throws Exception {
        String address = new String(read(inputs, "connection-address"), java.nio.charset.StandardCharsets.US_ASCII);
        switch (mode) {
                    case "peer-rekey" -> {
                        Counter64 epoch = peer.rekey(address, session, new Counter64("1"));
                        require(epoch.equals(new Counter64("1")), "epoch"); publish(output, new byte[] {1});
                    }
                    case "peer-send" -> {
                        Ids.Message original = new Ids.Message(read(inputs, "connection-message"));
                        require(peer.messageStatus(session, original) == ContinuityPeer.MessageStatus.ACKNOWLEDGED, "original message is not durably acknowledged");
                        Ids.Message fresh = peer.nextMessage(session);
                        require(!fresh.equals(original), "fresh send reused original message");
                        byte[] payload = "continued after pending recovery".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        require(peer.send(address, session, fresh, payload, AD).consumption() == ContinuityPeer.Consumption.CONFIRMED, "fresh consumption not confirmed");
                        require(peer.messageStatus(session, fresh) == ContinuityPeer.MessageStatus.ACKNOWLEDGED, "fresh acknowledgement not durable");
                        publish(output, ByteBuffer.allocate(64).put(session.encoded()).put(fresh.encoded()).array());
                    }
                    case "peer-connect" -> publish(output, peer.establish(address, new Ids.Initiation(read(inputs, "connection-initiation"))).session().encoded());
                    case "peer-uncertain", "peer-retry" -> {
                        Ids.Message message = mode.equals("peer-uncertain") ? peer.nextMessage(session) : new Ids.Message(read(inputs, "connection-message"));
                        if (mode.equals("peer-uncertain")) {
                            try { peer.send(address, session, message, PAYLOAD, AD); throw new AssertionError("crashed receiver acknowledged"); }
                            catch (ContinuityFailure failure) {
                                require(failure.code() == 309 || failure.code() == 310 || failure.code() == 311 || failure.code() == 303, "unexpected send failure " + failure.code());
                            }
                            require(peer.messageStatus(session, message) == ContinuityPeer.MessageStatus.COMMITTED, "original message not committed");
                        } else {
                            require(peer.send(address, session, message, PAYLOAD, AD).consumption() == ContinuityPeer.Consumption.CONFIRMED, "consumption not confirmed");
                            require(peer.messageStatus(session, message) == ContinuityPeer.MessageStatus.ACKNOWLEDGED, "acknowledgment not durable");
                        }
                        byte[] result = new byte[64]; System.arraycopy(session.encoded(), 0, result, 0, 32); System.arraycopy(message.encoded(), 0, result, 32, 32);
                        publish(output, result);
                    }
            default -> throw new IllegalArgumentException("client exchange mode");
        }
    }
    public static void main(String[] args) throws Exception {
        run(args, port -> {
            try {
                Path staging = Path.of(args[4] + ".ready.pending");
                publish(staging, Integer.toString(port).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                Files.move(staging, Path.of(args[4] + ".ready"), java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            }
            catch (Exception failure) { throw new IllegalStateException(failure); }
        });
    }
    public static void run(String[] args, IntConsumer ready) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("inputs installation profile mode result");
        Path inputs = Path.of(args[0]), path = Path.of(args[1]), output = Path.of(args[4]); String mode = args[3];
        boolean recoverable = args[2].equals("recoverable"); require(recoverable || args[2].equals("fixed"), "profile");
        PeerConfiguration config = configuration(inputs.resolve("peer"));
        Ids.Session session = mode.equals("peer-connect") ? null : new Ids.Session(read(inputs, "connection-session"));
        if (mode.equals("peer-cancel")) {
            CancellationProbe.run(inputs, path, recoverable, session, config);
            publish(output, new byte[] {1});
            System.out.println(args[2] + ":" + mode + ":passed");
            return;
        }
        try (ContinuityDevice device = device(inputs, path, recoverable)) {
            try (ContinuityPeer peer = session == null
                    ? device.preparePeer(config, PeerConfiguration.Quality.ONE_TIME_BOTH, PeerConfiguration.Role.INITIATOR)
                    : device.preparePeerReopen(config, PeerConfiguration.Quality.ONE_TIME_BOTH, PeerConfiguration.Role.INITIATOR, session)) {
                peer.finishOpen();
                String address = new String(read(inputs, "connection-address"), java.nio.charset.StandardCharsets.US_ASCII);
                switch (mode) {
                    case "peer-connect", "peer-uncertain", "peer-retry", "peer-rekey", "peer-send" -> exchange(peer, inputs, mode, session, output);
                    case "peer-serve" -> {
                        AtomicInteger calls = new AtomicInteger(); byte[][] borrowed = new byte[1][];
                        java.io.IOException original = new java.io.IOException("application result uncertain after durable effect");
                        ApplicationCommit commit = (s, m, bytes) -> {
                            require(s.equals(session), "incoming session"); borrowed[0] = bytes;
                            byte[] record = new byte[64 + bytes.length]; System.arraycopy(s.encoded(), 0, record, 0, 32);
                            System.arraycopy(m.encoded(), 0, record, 32, 32); System.arraycopy(bytes, 0, record, 64, bytes.length);
                            Path effect = output.resolveSibling("reverse-effect");
                            try { publish(effect, record); }
                            catch (java.nio.file.FileAlreadyExistsException exists) { require(Arrays.equals(record, Files.readAllBytes(effect)), "effect changed on retry"); }
                            try (FileChannel directory = FileChannel.open(effect.getParent(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) { directory.force(true); }
                            if (calls.incrementAndGet() == 1) throw original;
                        };
                        ready.accept(peer.listen("127.0.0.1:0"));
                        try { peer.serve(commit); throw new AssertionError("callback refusal was acknowledged"); }
                        catch (ContinuityFailure failure) { require(failure.code() == 308 && failure.getCause() == original, "callback failure was lost"); }
                        require(borrowed[0] != null && Arrays.equals(borrowed[0], new byte[borrowed[0].length]), "callback plaintext not cleared");
                        Served consumed = peer.serve(commit);
                        require(consumed.kind() == Served.Kind.MESSAGE && !consumed.duplicate() && calls.get() == 2, "original callback retry");
                        require(Arrays.equals(borrowed[0], new byte[borrowed[0].length]), "successful callback plaintext not cleared");
                        publish(output, Files.readAllBytes(output.resolveSibling("reverse-effect")));
                    }
                    default -> throw new IllegalArgumentException("peer operation");
                }
            }
        }
        System.out.println(args[2] + ":" + mode + ":passed");
    }
}
