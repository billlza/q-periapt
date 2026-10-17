// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Exact bound proposal, or a separately approved committed winner. */
public final class RootReplacementProposal {
    private final byte[] bytes;
    public RootReplacementProposal(byte[] approved) {
        bytes = ConfigurationInputs.copy(approved, 8, 65536, "approved root proposal");
        if (!header(bytes)) throw new IllegalArgumentException("root proposal header");
    }
    private static boolean header(byte[] bytes) {
        return WireHeader.matches(bytes, "QPARPL01") || WireHeader.matches(bytes, "QPARPL02");
    }
    public byte[] encoded() { return bytes.clone(); }
    static RootReplacementProposal fromNative(byte[] wire) {
        if (wire.length != 65540) throw new IllegalStateException("native root proposal width");
        int length = ByteBuffer.wrap(wire).getInt();
        if (length < 8 || length > 65536) throw new IllegalStateException("native root proposal length");
        byte[] bytes = Arrays.copyOfRange(wire, 4, 4 + length);
        if (!header(bytes)) throw new IllegalStateException("native root proposal header");
        for (int i = 4 + length; i < wire.length; ++i)
            if (wire[i] != 0) throw new IllegalStateException("native root proposal tail");
        return new RootReplacementProposal(bytes);
    }
}
