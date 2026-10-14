// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Public configured enrollment only; the independent controller owns approval. */
public final class PendingWriteProbe {
    private PendingWriteProbe() { }

    private static byte[] complete(PendingWriteRecoveryRequest request) {
        byte[] proposal = request.proposal(), binding = request.binding();
        byte[] metadata = request.metadata(), signed = request.signedRequest();
        require(proposal.length == 393 && binding.length == 32
                && metadata.length >= 569 && metadata.length <= 8388608
                && signed.length > 0 && signed.length <= 8192, "complete pending request bounds");
        // Reconstruct the public C request-info framing from public Java fields;
        // no package-private owner, handle, JNI entry or native storage is used.
        return ByteBuffer.allocate(436 + metadata.length + signed.length)
            .putInt(metadata.length).putInt(signed.length).put(proposal).put(new byte[3])
            .put(binding).put(metadata).put(signed).array();
    }
    private static void run(Path inputs, Path installation, Path output, String profile,
            String mode, ConfigurationWitness witness) throws Exception {
        require(witness != null, "original witness required");
        try (ContinuityConfiguration configuration = configuration(inputs, installation,
                profile.equals("recoverable"), false)) {
            configuration.finishOpen();
            try (ContinuityEnrollment enrollment = configuration.resumeEnrollment(intent(inputs), witness);
                    ContinuityAccountAuthority registry = AuthorityProbe.open(inputs, installation)) {
                enrollment.selectAccountAuthority(registry, AuthorityProbe.expected(inputs));
                switch (mode) {
                case "pending-identity" -> publish(output, enrollment.request());
                case "pending-request" -> publish(output, complete(enrollment.pendingWriteRecoveryRequest()));
                case "pending-request-absent" -> {
                    failed(201, enrollment::pendingWriteRecoveryRequest);
                    publish(output, ByteBuffer.allocate(4).putInt(201).array());
                }
                case "pending-activate-expired" -> {
                    failed(104, enrollment::activate);
                    publish(output, ByteBuffer.allocate(4).putInt(104).array());
                }
                case "pending-roster-unknown" -> {
                    Path peer = inputs.resolve("peer");
                    AccountPin pin = new AccountPin(read(peer, "responder-account"), read(peer, "responder-root"),
                        read(inputs, "family"), counter(ByteBuffer.wrap(read(inputs, "remote-roster-version"))),
                        read(inputs, "remote-roster-digest"));
                    byte[] roster = read(inputs, "remote-roster");
                    try (ContinuityDevice device = enrollment.activate()) {
                        failed(218, () -> device.admitPeerRoster(roster, pin));
                    }
                    publish(output, ByteBuffer.allocate(4).putInt(218).array());
                }
                case "pending-confirm", "pending-confirm-damaged", "pending-confirm-unapproved" -> {
                    byte[] proposal = read(inputs, "pending-proposal"), metadata = read(inputs, "pending-metadata");
                    if (mode.equals("pending-confirm-damaged")) metadata[metadata.length - 1] ^= 1;
                    int refused = mode.equals("pending-confirm-damaged") ? 102
                        : mode.equals("pending-confirm-unapproved") ? 103 : 0;
                    if (refused == 0) {
                        enrollment.confirmPendingWriteRecovery(proposal, metadata);
                        publish(output, new byte[] {1});
                    } else {
                        failed(refused, () -> enrollment.confirmPendingWriteRecovery(proposal, metadata));
                        publish(output, ByteBuffer.allocate(4).putInt(refused).array());
                    }
                }
                default -> throw new IllegalArgumentException("pending write mode");
                }
            }
        }
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 5 && (args[2].equals("fixed") || args[2].equals("recoverable")), "pending write arguments");
        Path inputs = Path.of(args[0]), installation = Path.of(args[1]), output = Path.of(args[4]);
        WitnessProbe.withWitness(inputs, args[3], witness -> run(inputs, installation, output, args[2], args[3], witness));
        System.out.println(args[2] + ":" + args[3] + ":passed");
    }
}
