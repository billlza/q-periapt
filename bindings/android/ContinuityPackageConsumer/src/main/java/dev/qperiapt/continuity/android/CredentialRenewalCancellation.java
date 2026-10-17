// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Original target-free expectation. It neither proves Closed nor grants cleanup permission. */
public final class CredentialRenewalCancellation {
    private final CredentialMetadata metadata;
    CredentialRenewalCancellation(byte[] bytes) {
        metadata = new CredentialMetadata(bytes, false, false);
    }
    public byte[] encoded() { return metadata.encoded(); }
    public Ids.CredentialRenewal operation() { return metadata.operation; }
    public Ids.CredentialStatement statement() { return metadata.statement; }
}
