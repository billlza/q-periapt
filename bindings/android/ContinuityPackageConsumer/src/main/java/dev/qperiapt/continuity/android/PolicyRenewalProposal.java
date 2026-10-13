// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Original G coordination with optional joint T or retained independent P.
 * Possession never supplies witness approval or current traffic authority. */
public final class PolicyRenewalProposal {
    private final CredentialMetadata metadata;
    private PolicyRenewalProposal(CredentialMetadata metadata) { this.metadata = metadata; }
    static PolicyRenewalProposal fromNative(byte[] wire) { return new PolicyRenewalProposal(CredentialMetadata.framed(wire, true)); }
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
