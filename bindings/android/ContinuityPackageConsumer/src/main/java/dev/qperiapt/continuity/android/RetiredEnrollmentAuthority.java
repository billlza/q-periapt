// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Independently retained witness pin and exact original replacement/retirement proof.
 * Width checks grant no authority; native preparation authenticates these inputs.
 */
public final class RetiredEnrollmentAuthority {
    private final byte[][] inputs;
    public RetiredEnrollmentAuthority(byte[] witness, byte[] publicKey, byte[] replacement,
            byte[] subject, byte[] receipt) {
        inputs = new byte[][] {
            ConfigurationInputs.copy(witness, 32, 32, "witness identity"),
            ConfigurationInputs.copy(publicKey, 1985, 1985, "witness public key"),
            ConfigurationInputs.copy(replacement, 1, 57794, "original replacement proof"),
            ConfigurationInputs.copy(subject, 96, 96, "original witness subject"),
            ConfigurationInputs.copy(receipt, 3754, 3754, "permanent retirement receipt")};
    }
    byte[][] snapshot() {
        byte[][] result = new byte[inputs.length][];
        for (int i = 0; i < inputs.length; ++i) result[i] = inputs[i].clone();
        return result;
    }
}
