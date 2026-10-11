// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.math.BigInteger;
import java.util.Objects;

/** Exact unsigned 64-bit value, including values above Java's signed long maximum. */
public final class Counter64 implements Comparable<Counter64> {
    final long bits;
    private final String decimal;
    public Counter64(String decimal) {
        Objects.requireNonNull(decimal, "counter");
        if (!decimal.matches("0|[1-9][0-9]{0,19}")) throw new IllegalArgumentException("unsigned counter");
        BigInteger value = new BigInteger(decimal);
        if (value.bitLength() > 64) throw new IllegalArgumentException("unsigned counter overflow");
        bits = value.longValue(); this.decimal = decimal;
    }
    static Counter64 fromBits(long bits) {
        BigInteger value = BigInteger.valueOf(bits & Long.MAX_VALUE);
        if (bits < 0) value = value.setBit(63);
        return new Counter64(value.toString());
    }
    @Override public int compareTo(Counter64 other) {
        long left = bits ^ Long.MIN_VALUE, right = other.bits ^ Long.MIN_VALUE;
        return left < right ? -1 : left == right ? 0 : 1;
    }
    @Override public String toString() { return decimal; }
    @Override public boolean equals(Object other) { return other instanceof Counter64 && ((Counter64) other).bits == bits; }
    @Override public int hashCode() { return (int) (bits ^ (bits >>> 32)); }
}
