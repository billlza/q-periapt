// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;
import android.os.Bundle;
import java.io.File;

/** Public retirement approvals only. Original device storage never enters this transfer. */
final class RetirementInputs {
    private RetirementInputs() { }
    static void install(File inputs, Bundle arguments, String operation) throws Exception {
        if (!operation.startsWith("retired-owned-")) throw new IllegalArgumentException("retirement operation");
        if (operation.equals("retired-owned-operational-denied")) {
            WitnessInputs.install(inputs, arguments); return;
        }
        WitnessInputs.install(inputs, arguments, "witness-id", 32, 32, true);
        WitnessInputs.install(inputs, arguments, "witness-public", 1985, 1985, true);
        WitnessInputs.install(inputs, arguments, "witness-subject", 96, 96, true);
        WitnessInputs.install(inputs, arguments, "retirement-proposal", 1, 57794, true);
        WitnessInputs.install(inputs, arguments, "retirement-receipt", 3754, 3754, true);
        if (operation.equals("retired-owned-inventory") || operation.equals("retired-owned-cancelled")) return;
        WitnessInputs.install(inputs, arguments, "retirement-inventory-receipt", 3690, 3690, true);
        if (operation.equals("retired-owned-prepare-report")) return;
        WitnessInputs.install(inputs, arguments, "retirement-report-proposal", 353, 353, true);
        WitnessInputs.install(inputs, arguments, "retirement-report-receipt", 3730, 3730, true);
        if (operation.equals("retired-owned-journal-unknown") || operation.equals("retired-owned-signer-unknown") || operation.equals("retired-owned-verify"))
            WitnessInputs.install(inputs, arguments, "retirement-ack", 3730, 3730, true);
    }
}
