// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Logical state only; retained pages, backups and wrapping keys are separate. */
public enum RetiredErasureState {
    RETAINED, ERASED;
    static RetiredErasureState decode(byte[] bytes) {
        if (bytes.length != 4) throw new IllegalStateException("native retirement state width");
        int code = java.nio.ByteBuffer.wrap(bytes).getInt();
        if (code < 0 || code > 1) throw new IllegalStateException("native retirement state");
        return values()[code];
    }
}
