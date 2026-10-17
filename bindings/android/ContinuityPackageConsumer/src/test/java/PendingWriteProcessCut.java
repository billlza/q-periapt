// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Abrupt application process exit, never a successful confirmation receipt. */
final class PendingWriteProcessCut {
    private PendingWriteProcessCut() { }
    private static void cut(Path output, byte[] binding, int phase, PendingWriteProbe.CutObserver observer) throws Exception {
        require(binding.length == 32 && (phase == 1 || phase == 2), "pending cut identity");
        byte[] receipt = ByteBuffer.allocate(41).put("QPPCUT01".getBytes(StandardCharsets.US_ASCII))
            .put((byte)phase).put(binding).array();
        publish(output, receipt);
        observer.beforeHalt(receipt.clone());
        Runtime.getRuntime().halt(77);
        throw new AssertionError("pending process cut returned");
    }
    static void run(ContinuityEnrollment enrollment, Path inputs, Path output, String mode,
            PendingWriteProbe.CutObserver observer) throws Exception {
        byte[] proposal = read(inputs, "pending-proposal"), metadata = read(inputs, "pending-metadata");
        PendingWriteRecoveryRequest request = enrollment.pendingWriteRecoveryRequest();
        require(Arrays.equals(proposal, request.proposal()) && Arrays.equals(metadata, request.metadata()), "original cut request");
        if (mode.equals("pending-confirm-process-cut")) {
            PendingWriteCancellation.run(enrollment, inputs, proposal, metadata, control -> {
                control.getOutputStream().write(4); control.getOutputStream().flush();
                cut(output, request.binding(), 1, observer);
            });
            throw new AssertionError("held Query cut returned");
        }
        require(mode.equals("pending-confirm-result-cut"), "pending process cut mode");
        enrollment.confirmPendingWriteRecovery(proposal, metadata);
        // The API returned, but the application has published no success result.
        // This is not a cut inside the database commit or a power-loss test.
        cut(output, request.binding(), 2, observer);
    }
}
