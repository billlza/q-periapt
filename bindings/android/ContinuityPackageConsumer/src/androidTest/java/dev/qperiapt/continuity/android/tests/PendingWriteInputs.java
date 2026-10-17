// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import android.os.Bundle;
import java.io.File;

/** Original public qualification inputs; the SDK's metadata limit is independent. */
final class PendingWriteInputs {
    private PendingWriteInputs() { }
    static void install(File inputs, Bundle arguments, String operation) throws Exception {
        WitnessInputs.install(inputs, arguments);
        WitnessInputs.installAuthority(inputs, arguments, operation);
        switch (operation) {
        case "pending-request", "pending-identity", "pending-request-absent", "pending-activate-expired":
            break;
        case "pending-roster-unknown":
            WitnessInputs.install(inputs, arguments, "remote-roster", 1, 65536, true);
            WitnessInputs.install(inputs, arguments, "remote-roster-version", 8, 8, true);
            WitnessInputs.install(inputs, arguments, "remote-roster-digest", 32, 32, true);
            break;
        case "pending-confirm", "pending-confirm-damaged", "pending-confirm-unapproved", "pending-confirm-cancelled", "pending-confirm-inflight", "pending-confirm-process-cut", "pending-confirm-result-cut":
            WitnessInputs.install(inputs, arguments, "pending-proposal", 393, 393, true);
            // This one-peer scenario is bounded by the qualification IPC channel.
            // Larger SDK requests require a separate file/stream transport check.
            WitnessInputs.install(inputs, arguments, "pending-metadata", 569, 65536, true);
            if (operation.equals("pending-confirm-inflight") || operation.equals("pending-confirm-process-cut")) {
                WitnessInputs.install(inputs, arguments, "cancel-control-token", 32, 32, true);
                WitnessInputs.install(inputs, arguments, "cancel-control-address", 1, 128, false);
            }
            break;
        default: throw new IllegalArgumentException("pending write qualification operation");
        }
    }
}
