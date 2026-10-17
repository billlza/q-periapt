// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Public cancellation after an independently observed, withheld Query reply. */
final class PendingWriteCancellation {
    @FunctionalInterface interface HeldQueryAction { void run(Socket control) throws Exception; }
    private PendingWriteCancellation() { }
    static void run(ContinuityEnrollment enrollment, Path inputs, byte[] proposal, byte[] metadata) throws Exception {
        run(enrollment, inputs, proposal, metadata, control -> { });
    }
    static void run(ContinuityEnrollment enrollment, Path inputs, byte[] proposal, byte[] metadata,
            HeldQueryAction held) throws Exception {
        PendingWriteRecoveryRequest request = enrollment.pendingWriteRecoveryRequest();
        require(Arrays.equals(request.proposal(), proposal) && Arrays.equals(request.metadata(), metadata), "original cancellation request");
        byte[] token = read(inputs, "cancel-control-token");
        require(token.length == 32, "cancellation control token");
        String address = new String(read(inputs, "cancel-control-address"), StandardCharsets.US_ASCII);
        require(address.matches("127\\.0\\.0\\.1:[1-9][0-9]{0,4}"), "cancellation control address");
        int port = Integer.parseInt(address.substring(address.lastIndexOf(':') + 1));
        require(port <= 65535, "cancellation control port");
        AtomicReference<Throwable> result = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try {
                enrollment.confirmPendingWriteRecovery(proposal, metadata);
                result.set(new AssertionError("held Query unexpectedly completed"));
            } catch (Throwable failure) { result.set(failure); }
        }, "continuity-pending-query");
        worker.setDaemon(true);
        try (Socket control = new Socket()) {
            control.connect(new InetSocketAddress("127.0.0.1", port), 3000);
            control.setSoTimeout(3000);
            control.getOutputStream().write("QPCCAN01".getBytes(StandardCharsets.US_ASCII));
            control.getOutputStream().write(token);
            control.getOutputStream().write(request.binding());
            control.getOutputStream().flush();
            worker.start();
            Throwable primary = null;
            try {
                require(control.getInputStream().read() == 1, "witness did not reach exact Query barrier");
                require(worker.isAlive(), "Query returned before cancellation");
                failed(3, enrollment::close);
                held.run(control);
                AtomicReference<Throwable> cancellation = new AtomicReference<>();
                Thread canceller = new Thread(() -> {
                    try { enrollment.cancel(); }
                    catch (Throwable failure) { cancellation.set(failure); }
                }, "continuity-pending-canceller");
                canceller.setDaemon(true); canceller.start(); canceller.join(5000);
                require(!canceller.isAlive() && cancellation.get() == null, "cancellation blocked or failed: " + cancellation.get());
                worker.join(5000);
                require(!worker.isAlive(), "cancellation did not release held Query");
                // Dispatch cancellation retains the witness outcome error. It
                // must not claim that the original pending write was undone.
                require(result.get() instanceof ContinuityFailure && ((ContinuityFailure)result.get()).code() == 218,
                    "held Query did not retain witness uncertainty: " + result.get());
                ContinuityFailure failure = (ContinuityFailure) result.get();
                require(!failure.diagnosticTruncated() && failure.getMessage().endsWith(
                    "witness dispatch cancelled; reconcile original command"), "missing native cancellation cause");
                // Only after the actual SDK result can the TLS fixture release
                // its retained encrypted response and finish its worker.
                control.getOutputStream().write(2); control.getOutputStream().flush();
                require(control.getInputStream().read() == 3 && control.getInputStream().read() == -1,
                    "cancellation release acknowledgement");
            } catch (Throwable failure) {
                primary = failure;
                throw failure;
            } finally {
                if (worker.isAlive()) {
                    try {
                        enrollment.cancel(); worker.join(5000);
                        require(!worker.isAlive(), "pending Query cleanup deadline");
                    } catch (Throwable cleanup) {
                        if (primary != null) primary.addSuppressed(cleanup);
                        else throw cleanup;
                    }
                }
            }
        }
    }
}
