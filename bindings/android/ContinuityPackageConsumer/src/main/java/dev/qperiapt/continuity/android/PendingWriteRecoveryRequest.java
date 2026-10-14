// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Complete original request. Retain all fields before independent approval.
 * Metadata includes private account/device linkage; these bytes grant no authority. */
public final class PendingWriteRecoveryRequest {
    private final byte[] proposal, binding, metadata, signedRequest;
    PendingWriteRecoveryRequest(byte[] wire) {
        if (wire.length < 436 + 569 + 1 || wire.length > 436 + 8388608 + 8192)
            throw new IllegalStateException("native pending write frame width");
        ByteBuffer input = ByteBuffer.wrap(wire);
        int metadataLength = input.getInt(), signedLength = input.getInt();
        if (metadataLength < 569 || metadataLength > 8388608 || signedLength < 1 || signedLength > 8192 ||
            wire.length != 436 + metadataLength + signedLength || wire[401] != 0 || wire[402] != 0 || wire[403] != 0)
            throw new IllegalStateException("native pending write field bounds");
        proposal = Arrays.copyOfRange(wire, 8, 401); binding = Arrays.copyOfRange(wire, 404, 436);
        metadata = Arrays.copyOfRange(wire, 436, 436 + metadataLength);
        signedRequest = Arrays.copyOfRange(wire, 436 + metadataLength, wire.length);
        if (!WireHeader.matches(proposal, "QPWRPL01") || !WireHeader.matches(metadata, "QPWRMD01"))
            throw new IllegalStateException("native pending write encoding");
        for (int i = 8; i < 361; ++i) if (proposal[i] != metadata[i])
            throw new IllegalStateException("native pending write scope differs");
        ByteBuffer views = ByteBuffer.wrap(metadata); views.position(361);
        for (int i = 0; i < 2; ++i) {
            if (views.remaining() < 8) throw new IllegalStateException("truncated pending write view length");
            long length = views.getLong();
            if (length < 96 || length > views.remaining()) throw new IllegalStateException("pending write view bound");
            views.position(views.position() + (int)length);
        }
        if (views.hasRemaining()) throw new IllegalStateException("pending write trailing view bytes");
    }
    public byte[] proposal() { return proposal.clone(); }
    public byte[] binding() { return binding.clone(); }
    public byte[] metadata() { return metadata.clone(); }
    public byte[] signedRequest() { return signedRequest.clone(); }
}
