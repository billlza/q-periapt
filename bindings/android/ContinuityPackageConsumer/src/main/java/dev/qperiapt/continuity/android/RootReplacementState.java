// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;

/** Durable history only; COMMITTED does not grant current successor traffic authority. */
public enum RootReplacementState {
    PREPARING, PENDING, COMMITTED, CLOSED;
    static RootReplacementState decode(byte[] wire) {
        if (wire.length != 4) throw new IllegalStateException("native root state width");
        int state = ByteBuffer.wrap(wire).getInt();
        if (state < 1 || state > 4) throw new IllegalStateException("native root state value");
        return values()[state - 1];
    }
}
