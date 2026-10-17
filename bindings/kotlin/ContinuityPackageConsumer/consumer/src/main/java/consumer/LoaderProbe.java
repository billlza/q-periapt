// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer;

import dev.qperiapt.continuity.ContinuityOwner;
import dev.qperiapt.continuity.PrekeyQuality;
import dev.qperiapt.continuity.WitnessCarrier;
import java.nio.file.Path;

public final class LoaderProbe {
    private LoaderProbe() {}

    public static void main(String[] args) throws Exception {
        var actual = Path.of(ContinuityOwner.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        var expected = Path.of(System.getProperty("qperiapt.expectedJar")).toRealPath();
        if (!actual.equals(expected) || !"dev.qperiapt.continuity".equals(ContinuityOwner.class.getModule().getName())) {
            throw new IllegalStateException("installed JAR or named module differs");
        }
        try (var owner = ContinuityOwner.Companion.prepare("/absent-continuity-module-probe",
                PrekeyQuality.ONE_TIME_BOTH, WitnessCarrier.Local.INSTANCE)) {
            owner.cancel();
        }
        System.out.println("INSTALLED_CONTINUITY_JAVA_MODULE_PASS");
        if (System.out.checkError()) throw new IllegalStateException("module probe output failed");
    }
}
