// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Original public expectation; its bytes alone grant no witness authority. */
public final class RetiredInventory {
    private final byte[] bytes;
    RetiredInventory(byte[] bytes) {
        if (bytes.length != 313 || !WireHeader.matches(bytes, "QPRCLP01"))
            throw new IllegalStateException("native retirement inventory");
        this.bytes = bytes.clone();
    }
    public byte[] encoded() { return bytes.clone(); }
}
