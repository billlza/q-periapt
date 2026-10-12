// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** A retained peer and original session. Native admission requires every target
 * to be a distinct live child of the selected device and the complete signed
 * recipient roster. Constructing this value grants no authority.
 */
public final class AccountTarget {
    private final ContinuityPeer peer;
    private final Ids.Session session;
    public AccountTarget(ContinuityPeer peer, Ids.Session session) {
        this.peer = java.util.Objects.requireNonNull(peer, "peer");
        this.session = java.util.Objects.requireNonNull(session, "original session");
    }
    public ContinuityPeer peer() { return peer; }
    public Ids.Session session() { return session; }
}
