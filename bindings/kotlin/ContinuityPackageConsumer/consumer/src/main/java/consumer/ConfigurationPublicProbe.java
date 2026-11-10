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
 public static void roots(ContinuityAccountAuthority authority, ContinuityDevice device,
                          ContinuityEnrollment enrollment, String path, EnrollmentIntent intent,
                          RootReplacementScope scope, RootReplacementPlan plan,
                          RootReplacementTransition transition, RootReplacementAdoption adoption, byte[] receipt) {
  authority.beginRootReplacement(device, scope, plan);
  authority.resumeRootReplacement(path, intent, scope, plan);
  authority.rootReplacementState(); authority.bindRootFreeze(receipt);
  authority.retainRootRetirement(receipt); authority.retainRootNoncommit(receipt);
  authority.transitionRoot(transition); authority.adoptRoot(adoption);
  authority.resumeRootTransition(path, intent, scope, transition);
  authority.resumeRootAdoption(path, intent, scope, adoption);
  try (ContinuityDevice successor = authority.activateRootSuccessor(enrollment)) { successor.cancel(); }
  authority.retiredInventory(); authority.retiredReportProposal(); authority.retiredAcknowledgementProposal();
  authority.prepareRetiredReport(receipt); authority.loadRetiredReport(receipt, receipt);
  authority.prepareRetiredAcknowledgement(receipt, receipt, receipt);
  authority.retiredJournalState(); authority.retiredSignerState(); authority.eraseRetiredJournal(receipt);
  authority.prepareRetiredSignerErasure(receipt); authority.eraseRetiredSigner();
 }
 public static void main(String[] args) {
  LocalTlsIdentity tls = new LocalTlsIdentity(new byte[]{1}, new byte[]{2}); tls.close();
  byte[] scope = new byte[32]; scope[0] = 1;
  AccountAuthorityTrust authority = new AccountAuthorityTrust(new AccountAuthorityID(scope), scope, scope, new byte[1985]);
  AccountAuthorityCheckpoint checkpoint = new AccountAuthorityCheckpoint(new ApplicationAccountID(scope),
      Counter64.Companion.parse("18446744073709551614"), new AccountID(scope));
  scope[0] = 2;
  if (authority.getFamily().encoded()[0] != 1 || !checkpoint.getRevision().toString().equals("18446744073709551614")) {
   throw new AssertionError("registry public inputs changed");
  }
  System.out.println("QPC_CONFIGURATION_JAVA_PUBLIC_PASS");
 }
}
