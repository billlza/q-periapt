// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** One authenticated exchange; duplicate consumption does not invoke the application again. */
public final class Served {
    public enum Kind { BOOTSTRAP, MESSAGE }
    private final Kind kind;
    private final Ids.Session session;
    private final Ids.Message message;
    private final boolean duplicate;
    Served(byte[] wire) {
        if (wire.length != 72) malformed();
        int code = ByteBuffer.wrap(wire).getInt(), repeated = ByteBuffer.wrap(wire, 68, 4).getInt();
        if ((code != 1 && code != 2) || repeated < 0 || repeated > 1) malformed();
        kind = code == 1 ? Kind.BOOTSTRAP : Kind.MESSAGE; duplicate = repeated == 1;
        session = new Ids.Session(Arrays.copyOfRange(wire, 4, 36));
        byte[] id = Arrays.copyOfRange(wire, 36, 68);
        if (code == 1) {
            if (duplicate || EnrollmentIntent.nonzero(id)) malformed();
            message = null;
        } else message = new Ids.Message(id);
    }
    private static void malformed() { throw new IllegalStateException("malformed native served record"); }
    public Kind kind() { return kind; }
    public Ids.Session session() { return session; }
    /** Null for BOOTSTRAP. */
    public Ids.Message message() { return message; }
    public boolean duplicate() { return duplicate; }
}
