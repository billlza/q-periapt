// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Explicit current policy choice. SELECTED requires selectContinuedPolicy; no fallback. */
public enum RosterPolicySource {
    ORIGINAL(0), SELECTED(1);
    final int code;
    RosterPolicySource(int code) { this.code = code; }
}
