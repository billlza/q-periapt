// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer;

import dev.qperiapt.QPeriaptHybrid;
import dev.qperiapt.QPeriaptKey;
import dev.qperiapt.QPeriaptRuntime;
import java.nio.file.Files;
import java.nio.file.Path;

public final class LoaderProbe {
    private LoaderProbe() {}
    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getProperty("sdk.fixtures"));
        if (QPeriaptHybrid.INSTANCE.runtimeAbiVersion() != 2) throw new AssertionError("ABI");
        if (!QPeriaptHybrid.INSTANCE.runtimeVersion().equals("0.2.0")) throw new AssertionError("Native version");
        if (!QPeriaptRuntime.class.getModule().getName().equals("dev.qperiapt.hybrid")) {
            throw new AssertionError("Module path identity");
        }
        if (!Files.isSameFile(Path.of(QPeriaptRuntime.class.getProtectionDomain().getCodeSource().getLocation().toURI()),
                Path.of(System.getProperty("sdk.expectedJar")))) throw new AssertionError("JAR identity");
        try (QPeriaptRuntime runtime = QPeriaptRuntime.Companion.fromSignedPolicy(
                Files.readAllBytes(root.resolve("enabled.policy")), Files.readAllBytes(root.resolve("enabled.signature")),
                Files.readAllBytes(root.resolve("root")), new byte[0], 32, 4);
             QPeriaptKey key = runtime.generateKey()) {
            if (key.publicKey().encoded().length != 1216) throw new AssertionError("Public key");
        }
        System.out.println("INSTALLED_JAVA_MODULE_PATH_PASS");
    }
}
