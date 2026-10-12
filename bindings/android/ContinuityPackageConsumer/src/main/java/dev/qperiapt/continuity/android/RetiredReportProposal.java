// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Original inventory plus a keyed report identity; requires a signed witness receipt. */
public final class RetiredReportProposal {
    private final byte[] bytes;
    private final RetiredInventory inventory;
    private final Ids.RetiredReport report;
    private RetiredReportProposal(byte[] bytes) {
        if (bytes.length != 353 || !magic(bytes, "QPRRPT01")
                || !EnrollmentIntent.nonzero(Arrays.copyOfRange(bytes, 321, 353)))
            throw new IllegalStateException("native retirement proposal");
        inventory = new RetiredInventory(Arrays.copyOfRange(bytes, 8, 321));
        report = new Ids.RetiredReport(Arrays.copyOfRange(bytes, 321, 353));
        this.bytes = bytes.clone();
    }
    static boolean magic(byte[] bytes, String expected) {
        if (bytes.length < expected.length()) return false;
        for (int i = 0; i < expected.length(); ++i) if (bytes[i] != (byte)expected.charAt(i)) return false;
        return true;
    }
    static RetiredReportProposal decode(byte[] wire, boolean required) {
        if (wire.length != 360 || wire[357] != 0 || wire[358] != 0 || wire[359] != 0)
            throw new IllegalStateException("native retirement proposal frame");
        int present = ByteBuffer.wrap(wire).getInt();
        byte[] bytes = Arrays.copyOfRange(wire, 4, 357);
        if (present == 0) {
            if (required || EnrollmentIntent.nonzero(bytes)) throw new IllegalStateException("native proposal absence");
            return null;
        }
        if (present != 1) throw new IllegalStateException("native proposal presence");
        return new RetiredReportProposal(bytes);
    }
    public byte[] encoded() { return bytes.clone(); }
    public RetiredInventory inventory() { return inventory; }
    public Ids.RetiredReport report() { return report; }
}
