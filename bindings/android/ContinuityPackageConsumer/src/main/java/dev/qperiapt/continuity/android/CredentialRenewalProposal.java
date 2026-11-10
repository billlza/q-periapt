// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Exact public expectation for independent witness approval; possession is not approval. */
public final class CredentialRenewalProposal {
    private final CredentialMetadata metadata;
    CredentialRenewalProposal(byte[] bytes) {
        metadata = new CredentialMetadata(bytes, true, false);
    }
    public byte[] encoded() { return metadata.encoded(); }
    public Ids.CredentialRenewal operation() { return metadata.operation; }
    public Ids.CredentialStatement statement() { return metadata.statement; }
}
