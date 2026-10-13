// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Original target-free G expectation; neither Closed evidence nor cleanup permission. */
public final class PolicyRenewalCancellation {
    private final CredentialMetadata metadata;
    private PolicyRenewalCancellation(CredentialMetadata metadata) { this.metadata = metadata; }
    static PolicyRenewalCancellation fromNative(byte[] wire) { return new PolicyRenewalCancellation(CredentialMetadata.framed(wire, false)); }
    public byte[] encoded() { return metadata.encoded(); }
    public Ids.CredentialRenewal operation() { return metadata.operation; }
    public Ids.CredentialStatement credentialStatement() { return metadata.credential; }
    public Ids.CredentialStatement statement() { return metadata.statement; }
    /** Null unless this record binds a joint-T authorization. */
    public Ids.PolicyContinuationStatement policyStatement() { return metadata.continuation; }
    /** Null unless this G retains an independently adopted P. */
    public Ids.PolicyStatement independentPolicyStatement() { return metadata.independent; }
    public boolean adoptsPolicy() { return metadata.adopts; }
}
