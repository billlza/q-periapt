// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Historical witness result; no value grants a current traffic lease. */
public enum RosterRefreshState {
    PREPARED, APPLIED, CLOSED, ACKNOWLEDGED, UNAVAILABLE;
    static RosterRefreshState fromNative(byte[] bytes) {
        if (bytes.length != 4) throw new IllegalStateException("native roster result width");
        int code = java.nio.ByteBuffer.wrap(bytes).getInt();
        if (code < 1 || code > 5) throw new IllegalStateException("native roster result");
        return values()[code - 1];
    }
}
