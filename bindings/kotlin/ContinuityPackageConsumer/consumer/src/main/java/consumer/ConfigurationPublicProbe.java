// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer;
import dev.qperiapt.continuity.*;
public final class ConfigurationPublicProbe {
 public static void invoke(String path, InstallationConfiguration input, SdkPolicyTrust trust, PolicyDocument policy,
                           EnrollmentIntent intent, ConfigurationWitness witness, ContinuityEnrollment existing) {
  try (ContinuityConfiguration configuration = ContinuityConfiguration.Companion.prepareCreate(path, input)) {
   configuration.finishOpen();
   try (ContinuityEnrollment registration = configuration.createEnrollment(intent, witness)) { registration.request(); }
  }
  try (ContinuityConfiguration configuration = ContinuityConfiguration.Companion.prepareReconcile(path, input)) { configuration.finishOpen(); }
  try (ContinuityConfiguration configuration = ContinuityConfiguration.Companion.prepareOpen(path, trust, policy)) {
   configuration.finishOpen(); configuration.selectContinuationTarget(existing);
  }
 }
 public static void main(String[] args) {
  LocalTlsIdentity tls = new LocalTlsIdentity(new byte[]{1}, new byte[]{2}); tls.close();
  System.out.println("QPC_CONFIGURATION_JAVA_PUBLIC_PASS");
 }
}
