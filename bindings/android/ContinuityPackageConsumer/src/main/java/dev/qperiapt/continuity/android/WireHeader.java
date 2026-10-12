// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Shared public framing only; a matching header grants no authority. */
final class WireHeader {
    private WireHeader() { }
    static boolean matches(byte[] bytes, String expected) {
        if (bytes.length < expected.length()) return false;
        for (int i = 0; i < expected.length(); ++i) if (bytes[i] != (byte)expected.charAt(i)) return false;
        return true;
    }
}
