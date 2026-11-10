// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Native reason and bounded diagnostic. Failure never proves an operation did not commit. */
public final class ContinuityFailure extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String operation;
    private final int code;
    private final boolean truncated;
    ContinuityFailure(String operation, int code, String diagnostic, boolean truncated) {
        super(diagnostic); this.operation = operation; this.code = code; this.truncated = truncated;
    }
    public String operation() { return operation; }
    public int code() { return code; }
    public boolean diagnosticTruncated() { return truncated; }
}
