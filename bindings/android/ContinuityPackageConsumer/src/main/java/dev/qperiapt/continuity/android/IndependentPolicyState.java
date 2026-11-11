// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Authenticated witness history. UNAVAILABLE never means no commit. */
public enum IndependentPolicyState {
    PREPARED, APPLIED, CLOSED, ACKNOWLEDGED, UNAVAILABLE;
    static IndependentPolicyState fromNative(byte[] wire) {
        if (wire.length != 4) throw new IllegalStateException("native policy witness state width");
        int value = java.nio.ByteBuffer.wrap(wire).getInt();
        if (value < 1 || value > 5) throw new IllegalStateException("native policy witness state");
        return values()[value - 1];
    }
}
