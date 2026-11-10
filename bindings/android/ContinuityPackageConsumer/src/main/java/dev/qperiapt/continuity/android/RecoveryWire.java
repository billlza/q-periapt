// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;

/** Fixed-size JNI framing, distinct from any durable or authenticated serialization. */
final class RecoveryWire {
    private final ByteBuffer input;
    RecoveryWire(byte[] bytes,int size) {
        if(bytes==null || bytes.length!=size) malformed();
        input=ByteBuffer.wrap(bytes.clone());
    }
    static void malformed() { throw new IllegalStateException("malformed native recovery record"); }
    byte[] bytes(int length) { byte[] out=new byte[length];input.get(out);return out; }
    byte[] identity() { byte[] value=bytes(32);nonzero(value);return value; }
    Counter64 counter() { return Counter64.fromBits(input.getLong()); }
    int count(int maximum) { int value=input.getInt();if(value<0 || value>maximum) malformed();return value; }
    void zero() { if(input.getInt()!=0) malformed(); }
    static Counter64 optional(int present,Counter64 value) {
        if(present<0 || present>1 || (present==0 && value.bits!=0)) malformed();
        return present==0 ? null : value;
    }
    static void nonzero(byte[] value) { if(!EnrollmentIntent.nonzero(value)) malformed(); }
}
