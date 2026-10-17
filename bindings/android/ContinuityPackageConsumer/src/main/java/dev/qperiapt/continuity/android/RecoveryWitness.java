// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Carrier for recovery under the ORIGINAL protected witness pin/credentials.
 * No constructor replaces trust or falls back from required witness protection.
 */
public final class RecoveryWitness {
    final int carrier,timeout;
    private final byte[] address;
    private RecoveryWitness(int carrier,String endpoint,int timeout) {
        this.carrier=carrier;this.timeout=timeout;
        address=carrier==0 ? new byte[0] : Native.path(endpoint);
        if(address.length>128 || (carrier==0 ? timeout!=0 : timeout<1 || timeout>10000))
            throw new IllegalArgumentException("recovery witness endpoint/timeout");
    }
    public static RecoveryWitness local() { return new RecoveryWitness(0,null,0); }
    public static RecoveryWitness signedTcp(String endpoint,int timeoutMilliseconds) { return new RecoveryWitness(1,endpoint,timeoutMilliseconds); }
    public static RecoveryWitness mutualTls(String endpoint,int timeoutMilliseconds) { return new RecoveryWitness(2,endpoint,timeoutMilliseconds); }
    byte[] address() { return address.clone(); }
}
